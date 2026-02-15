"""
ClipForge — Multi-Platform Video Downloader & Trimmer (Vercel Serverless)
Supports: YouTube, Twitter/X, Instagram, TikTok
Uses yt-dlp as a Python library (not CLI) for Vercel compatibility.
"""

import os
import re
import uuid
import time
import mimetypes
import shutil
from pathlib import Path
from urllib.parse import urlparse
from flask import Flask, request, jsonify, send_file

import logging

import yt_dlp
from supabase import create_client

logger = logging.getLogger("clipforge")

app = Flask(__name__)

# ── Supabase ─────────────────────────────────────────────────────────────────
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "")
sb = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

TEMP_DIR = Path("/tmp/clipforge")
TEMP_DIR.mkdir(exist_ok=True)

# ── Security: rate limit tracking (per-IP, in-memory) ────────────────────────
_rate_limit = {}  # ip -> (count, window_start)
RATE_LIMIT_MAX = 15       # max requests per window
RATE_LIMIT_WINDOW = 60    # window in seconds
RATE_LIMIT_MAX_ENTRIES = 10000  # prevent unbounded growth
MAX_URL_LENGTH = 2048
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB


# ── Security: HTTP response headers ──────────────────────────────────────────
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' https: data:; "
        "frame-src https://www.youtube.com; "
        "connect-src 'self'"
    )
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

# Allowed hostname patterns per platform (SSRF protection)
ALLOWED_HOSTS = {
    "youtube":    re.compile(r'^(www\.)?(youtube\.com|youtu\.be|m\.youtube\.com)$', re.I),
    "twitter":    re.compile(r'^(www\.)?(twitter\.com|x\.com|mobile\.twitter\.com|mobile\.x\.com)$', re.I),
    "instagram":  re.compile(r'^(www\.)?(instagram\.com|m\.instagram\.com)$', re.I),
    "tiktok":     re.compile(r'^(www\.)?(tiktok\.com|vm\.tiktok\.com|m\.tiktok\.com)$', re.I),
    "twitch":     re.compile(r'^(www\.)?(twitch\.tv|clips\.twitch\.tv|m\.twitch\.tv)$', re.I),
    "soundcloud": re.compile(r'^(www\.)?(soundcloud\.com|m\.soundcloud\.com)$', re.I),
}


def check_rate_limit(ip):
    """Returns True if rate limited. Prunes stale entries to prevent unbounded growth."""
    now = time.time()

    # Prune stale entries periodically
    if len(_rate_limit) > RATE_LIMIT_MAX_ENTRIES:
        stale_keys = [k for k, (_, ws) in _rate_limit.items() if now - ws > RATE_LIMIT_WINDOW]
        for k in stale_keys:
            del _rate_limit[k]

    if ip in _rate_limit:
        count, window_start = _rate_limit[ip]
        if now - window_start > RATE_LIMIT_WINDOW:
            _rate_limit[ip] = (1, now)
            return False
        if count >= RATE_LIMIT_MAX:
            return True
        _rate_limit[ip] = (count + 1, window_start)
    else:
        _rate_limit[ip] = (1, now)
    return False


_cleanup_counter = 0
_CLEANUP_EVERY_N = 5  # only run cleanup every Nth request

def cleanup_old_files(max_age_seconds=300):
    global _cleanup_counter
    _cleanup_counter += 1
    if _cleanup_counter % _CLEANUP_EVERY_N != 0:
        return
    now = time.time()
    if TEMP_DIR.exists():
        for item in TEMP_DIR.iterdir():
            try:
                if now - item.stat().st_mtime > max_age_seconds:
                    if item.is_dir():
                        shutil.rmtree(item, ignore_errors=True)
                    else:
                        item.unlink(missing_ok=True)
            except Exception:
                pass


def validate_url(url):
    """Validate URL against SSRF and injection attacks. Returns (platform, error)."""
    if not url or not isinstance(url, str):
        return None, "No URL provided."

    if len(url) > MAX_URL_LENGTH:
        return None, "URL is too long."

    # Block non-http(s) schemes (file://, ftp://, data://, etc.)
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return None, "Only HTTP/HTTPS URLs are allowed."

    # Must have a valid host
    host = parsed.hostname
    if not host:
        return None, "Invalid URL."

    # Detect platform
    platform = detect_platform(url)
    if not platform:
        return None, "Unsupported URL. Paste a YouTube, Twitter/X, Instagram, TikTok, Twitch, or SoundCloud link."

    # Verify hostname matches the detected platform (SSRF protection)
    if not ALLOWED_HOSTS[platform].match(host):
        return None, f"Invalid hostname for {platform}."

    return platform, None


def detect_platform(url):
    url_lower = url.lower()
    if re.search(r'(youtube\.com|youtu\.be)', url_lower):
        return "youtube"
    if re.search(r'(twitter\.com|x\.com)', url_lower):
        return "twitter"
    if re.search(r'instagram\.com', url_lower):
        return "instagram"
    if re.search(r'(tiktok\.com|vm\.tiktok)', url_lower):
        return "tiktok"
    if re.search(r'twitch\.tv', url_lower):
        return "twitch"
    if re.search(r'soundcloud\.com', url_lower):
        return "soundcloud"
    return None


def extract_video_id(url):
    patterns = [
        r'(?:youtube\.com/watch\?v=|youtu\.be/|youtube\.com/embed/|youtube\.com/shorts/)([a-zA-Z0-9_-]{11})',
    ]
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)
    return None


def time_to_seconds(time_str):
    """Safely parse MM:SS or HH:MM:SS, clamped to sane limits. Returns None for invalid input."""
    if not isinstance(time_str, str) or not re.match(r'^\d{1,2}(:\d{1,2}){1,2}$', time_str.strip()):
        return None
    parts = time_str.strip().split(":")
    parts = [int(p) for p in parts]
    if len(parts) == 2:
        secs = parts[0] * 60 + parts[1]
    elif len(parts) == 3:
        secs = parts[0] * 3600 + parts[1] * 60 + parts[2]
    else:
        return None
    return max(0, min(secs, 36000))  # clamp to 10 hours max


def safe_ydl_opts(extra_opts=None):
    """Base yt-dlp options with security hardening."""
    opts = {
        "quiet": True,
        "no_warnings": True,
        "noplaylist": True,
        "socket_timeout": 30,
        "nocheckcertificate": False,
        # Disable dangerous features
        "no_exec": True,
        "no_color": True,
        "geo_bypass": False,
        "max_filesize": MAX_FILE_SIZE,
        # Prevent loading config files from disk
        "ignoreerrors": False,
        "no_config": True,
    }
    if extra_opts:
        opts.update(extra_opts)
    return opts


def build_format_string(quality="720p", fmt="mp4", is_trim=False):
    """Build yt-dlp format string from quality/format preferences."""
    RESOLUTION_MAP = {"360p": 360, "480p": 480, "720p": 720, "1080p": 1080, "best": None}
    height = RESOLUTION_MAP.get(quality, 720)

    if fmt == "mp3":
        return "bestaudio/best", [{"key": "FFmpegExtractAudio", "preferredcodec": "mp3", "preferredquality": "192"}]

    if fmt == "webm":
        if height:
            fmt_str = f"best[ext=webm][height<={height}]/best[height<={height}]/best"
        else:
            fmt_str = "best[ext=webm]/best"
        return fmt_str, []

    # Default: mp4
    if height:
        fmt_str = f"best[ext=mp4][height<={height}]/best[height<={height}]/best"
    else:
        fmt_str = "best[ext=mp4]/best"
    return fmt_str, []


def find_downloaded_file(directory, prefix):
    """Find the first file in directory starting with prefix, with path traversal protection."""
    resolved_dir = directory.resolve()
    for f in directory.iterdir():
        if f.name.startswith(prefix) and f.is_file():
            # Ensure file is actually inside the expected directory
            if f.resolve().parent == resolved_dir:
                return f
    return None


def cleanup_job_dir(job_dir):
    """Remove a job directory after serving the file."""
    try:
        shutil.rmtree(job_dir, ignore_errors=True)
    except Exception:
        pass


# ── Serve frontend ───────────────────────────────────────────────────────────

@app.route("/")
def index():
    return INDEX_HTML


# ── API: Video Info (all platforms) ──────────────────────────────────────────

@app.route("/api/video-info", methods=["POST"])
def video_info():
    # Rate limit
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    if check_rate_limit(client_ip):
        return jsonify({"error": "Too many requests. Please wait a moment."}), 429

    # Parse body
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request body."}), 400

    url = data.get("url", "")

    # Validate URL (SSRF + scheme + host checks)
    platform, err = validate_url(url)
    if err:
        return jsonify({"error": err}), 400

    try:
        opts = safe_ydl_opts({"skip_download": True})

        with yt_dlp.YoutubeDL(opts) as ydl:
            info = ydl.extract_info(url, download=False)

        if not info:
            return jsonify({"error": f"Could not fetch video info from {platform.title()}."}), 400

        yt_id = extract_video_id(url) if platform == "youtube" else None

        title = info.get("title") or ""
        if not title:
            desc = info.get("description") or "Untitled"
            title = desc[:80]

        return jsonify({
            "id": yt_id or info.get("id", "unknown"),
            "platform": platform,
            "title": title or "Untitled",
            "duration": info.get("duration") or 0,
            "thumbnail": info.get("thumbnail", ""),
            "channel": info.get("uploader") or info.get("uploader_id") or "Unknown",
        })
    except yt_dlp.utils.DownloadError:
        return jsonify({"error": "Could not fetch video info. The URL may be invalid or the video may be unavailable."}), 400
    except Exception:
        return jsonify({"error": "An unexpected error occurred while fetching video info."}), 500


# ── API: Download (full video, no trim) ──────────────────────────────────────

@app.route("/api/download-full", methods=["POST"])
def download_full():
    cleanup_old_files()

    # Rate limit
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    if check_rate_limit(client_ip):
        return jsonify({"error": "Too many requests. Please wait a moment."}), 429

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request body."}), 400

    url = data.get("url", "")
    quality = data.get("quality", "720p")
    fmt = data.get("format", "mp4")
    platform, err = validate_url(url)
    if err:
        return jsonify({"error": err}), 400

    job_id = uuid.uuid4().hex[:12]
    job_dir = TEMP_DIR / job_id
    job_dir.mkdir(exist_ok=True)

    try:
        output_template = str(job_dir / "video.%(ext)s")
        format_str, postprocessors = build_format_string(quality, fmt, is_trim=False)

        dl_opts = {
            "format": format_str,
            "outtmpl": output_template,
        }
        if postprocessors:
            dl_opts["postprocessors"] = postprocessors

        opts = safe_ydl_opts(dl_opts)

        with yt_dlp.YoutubeDL(opts) as ydl:
            ydl.download([url])

        dl_file = find_downloaded_file(job_dir, "video")
        if not dl_file:
            return jsonify({"error": "Downloaded file not found."}), 500

        # Check file size
        if dl_file.stat().st_size > MAX_FILE_SIZE:
            cleanup_job_dir(job_dir)
            return jsonify({"error": "File too large (>100MB)."}), 413

        ext = dl_file.suffix or ".mp4"
        mime = mimetypes.guess_type(dl_file.name)[0] or "application/octet-stream"
        return send_file(
            str(dl_file),
            as_attachment=True,
            download_name=f"{platform}_{job_id}{ext}",
            mimetype=mime,
        )

    except yt_dlp.utils.DownloadError:
        cleanup_job_dir(job_dir)
        return jsonify({"error": "Download failed. The video may be unavailable or restricted."}), 500
    except Exception:
        cleanup_job_dir(job_dir)
        logger.exception("download-full error")
        return jsonify({"error": "An unexpected error occurred during download."}), 500


# ── API: Trim (works for any platform with duration) ─────────────────────────

@app.route("/api/trim", methods=["POST"])
def trim_video():
    cleanup_old_files()

    # Rate limit
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    if check_rate_limit(client_ip):
        return jsonify({"error": "Too many requests. Please wait a moment."}), 429

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request body."}), 400

    url = data.get("url", "")
    start_time = data.get("start", "0:00")
    end_time = data.get("end", "0:00")
    quality = data.get("quality", "720p")
    fmt = data.get("format", "mp4")

    platform, err = validate_url(url)
    if err:
        return jsonify({"error": err}), 400

    start_sec = time_to_seconds(start_time)
    end_sec = time_to_seconds(end_time)

    if start_sec is None or end_sec is None:
        return jsonify({"error": "Invalid time format. Use MM:SS or HH:MM:SS."}), 400

    duration = end_sec - start_sec

    if duration <= 0:
        return jsonify({"error": "End time must be after start time."}), 400

    if duration > 600:
        return jsonify({"error": "Clips are limited to 10 minutes max."}), 400

    job_id = uuid.uuid4().hex[:12]
    job_dir = TEMP_DIR / job_id
    job_dir.mkdir(exist_ok=True)

    try:
        output_template = str(job_dir / "clip.%(ext)s")
        format_str, postprocessors = build_format_string(quality, fmt, is_trim=True)

        dl_opts = {
            "format": format_str,
            "outtmpl": output_template,
            "download_ranges": yt_dlp.utils.download_range_func(
                None, [(start_sec, end_sec)]
            ),
            "force_keyframes_at_cuts": True,
        }
        if postprocessors:
            dl_opts["postprocessors"] = postprocessors

        opts = safe_ydl_opts(dl_opts)

        with yt_dlp.YoutubeDL(opts) as ydl:
            ydl.download([url])

        clip_file = find_downloaded_file(job_dir, "clip")
        if not clip_file:
            return jsonify({"error": "Downloaded file not found."}), 500

        if clip_file.stat().st_size > MAX_FILE_SIZE:
            cleanup_job_dir(job_dir)
            return jsonify({"error": "File too large (>100MB)."}), 413

        ext = clip_file.suffix or ".mp4"
        mime = mimetypes.guess_type(clip_file.name)[0] or "application/octet-stream"
        return send_file(
            str(clip_file),
            as_attachment=True,
            download_name=f"clip_{job_id}{ext}",
            mimetype=mime,
        )

    except yt_dlp.utils.DownloadError:
        cleanup_job_dir(job_dir)
        return jsonify({"error": "Trim failed. The video may be unavailable or the format unsupported."}), 500
    except Exception:
        cleanup_job_dir(job_dir)
        logger.exception("trim error")
        return jsonify({"error": "An unexpected error occurred during trimming."}), 500


# ── Supabase: Upload to storage + save metadata ──────────────────────────────

def upload_to_library(file_path, metadata):
    """Upload a video file to Supabase Storage and save metadata to the clips table."""
    try:
        file_path = Path(file_path)
        ext = file_path.suffix or ".mp4"
        storage_name = f"{uuid.uuid4().hex[:16]}{ext}"
        mime = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"

        # Upload file to storage
        with open(file_path, "rb") as f:
            sb.storage.from_("clips").upload(
                path=storage_name,
                file=f.read(),
                file_options={"content-type": mime},
            )

        # Get public URL
        public_url = sb.storage.from_("clips").get_public_url(storage_name)

        # Save metadata
        row = {
            "title": metadata.get("title", "Untitled")[:200],
            "platform": metadata.get("platform", "unknown"),
            "source_url": metadata.get("source_url", "")[:2048],
            "thumbnail": metadata.get("thumbnail", "")[:2048],
            "channel": metadata.get("channel", "")[:200],
            "duration": metadata.get("duration", 0),
            "trim_start": metadata.get("trim_start"),
            "trim_end": metadata.get("trim_end"),
            "mode": metadata.get("mode", "download"),
            "file_path": storage_name,
            "file_size": file_path.stat().st_size,
            "file_ext": ext,
            "tags": metadata.get("tags"),
            "is_favorite": False,
        }
        if metadata.get("user_id"):
            row["user_id"] = metadata["user_id"]

        result = sb.table("clips").insert(row).execute()
        return {"success": True, "url": public_url, "id": result.data[0]["id"] if result.data else None}
    except Exception as e:
        return {"success": False, "error": str(e)[:200]}


# ── API: Save to Library (after download/trim) ───────────────────────────────

@app.route("/api/save-to-library", methods=["POST"])
def save_to_library():
    """Download (and optionally trim) a video, then upload to Supabase."""
    cleanup_old_files()

    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    if check_rate_limit(client_ip):
        return jsonify({"error": "Too many requests. Please wait a moment."}), 429

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request body."}), 400

    url = data.get("url", "")
    mode = data.get("mode", "download")
    title = data.get("title", "Untitled")
    platform_name = data.get("platform", "")
    thumbnail = data.get("thumbnail", "")
    channel = data.get("channel", "")
    vid_duration = data.get("duration", 0)
    tags = data.get("tags")  # comma-separated string or None
    quality = data.get("quality", "720p")
    fmt = data.get("format", "mp4")

    platform, err = validate_url(url)
    if err:
        return jsonify({"error": err}), 400

    job_id = uuid.uuid4().hex[:12]
    job_dir = TEMP_DIR / job_id
    job_dir.mkdir(exist_ok=True)

    try:
        if mode == "trim":
            start_time = data.get("start", "0:00")
            end_time = data.get("end", "0:00")
            start_sec = time_to_seconds(start_time)
            end_sec = time_to_seconds(end_time)

            if start_sec is None or end_sec is None:
                return jsonify({"error": "Invalid time format."}), 400
            if end_sec - start_sec <= 0:
                return jsonify({"error": "End time must be after start time."}), 400
            if end_sec - start_sec > 600:
                return jsonify({"error": "Clips limited to 10 minutes."}), 400

            output_template = str(job_dir / "clip.%(ext)s")
            format_str, postprocessors = build_format_string(quality, fmt, is_trim=True)
            dl_opts = {
                "format": format_str,
                "outtmpl": output_template,
                "download_ranges": yt_dlp.utils.download_range_func(None, [(start_sec, end_sec)]),
                "force_keyframes_at_cuts": True,
            }
            if postprocessors:
                dl_opts["postprocessors"] = postprocessors
            opts = safe_ydl_opts(dl_opts)

            with yt_dlp.YoutubeDL(opts) as ydl:
                ydl.download([url])

            dl_file = find_downloaded_file(job_dir, "clip")
        else:
            output_template = str(job_dir / "video.%(ext)s")
            format_str, postprocessors = build_format_string(quality, fmt, is_trim=False)
            dl_opts = {
                "format": format_str,
                "outtmpl": output_template,
            }
            if postprocessors:
                dl_opts["postprocessors"] = postprocessors
            opts = safe_ydl_opts(dl_opts)

            with yt_dlp.YoutubeDL(opts) as ydl:
                ydl.download([url])

            dl_file = find_downloaded_file(job_dir, "video")

        if not dl_file:
            return jsonify({"error": "Downloaded file not found."}), 500

        if dl_file.stat().st_size > MAX_FILE_SIZE:
            cleanup_job_dir(job_dir)
            return jsonify({"error": "File too large (>100MB)."}), 413

        # Upload to Supabase
        user_id = require_auth()
        result = upload_to_library(dl_file, {
            "title": title,
            "platform": platform,
            "source_url": url,
            "thumbnail": thumbnail,
            "channel": channel,
            "duration": vid_duration,
            "trim_start": data.get("start") if mode == "trim" else None,
            "trim_end": data.get("end") if mode == "trim" else None,
            "mode": mode,
            "tags": tags,
            "user_id": user_id,
        })

        cleanup_job_dir(job_dir)

        if not result["success"]:
            return jsonify({"error": f"Upload failed: {result['error']}"}), 500

        return jsonify({
            "success": True,
            "url": result["url"],
            "id": result["id"],
        })

    except yt_dlp.utils.DownloadError:
        cleanup_job_dir(job_dir)
        return jsonify({"error": "Download failed. The video may be unavailable."}), 500
    except Exception:
        cleanup_job_dir(job_dir)
        logger.exception("save-to-library error")
        return jsonify({"error": "An unexpected error occurred."}), 500


# ── API: Library (list / delete) ──────────────────────────────────────────────

@app.route("/api/library", methods=["GET"])
def get_library():
    """Return saved clips, newest first, with optional pagination."""
    user_id = require_auth()
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 20, type=int), 50)
    offset = (page - 1) * per_page

    try:
        query = sb.table("clips").select("*", count="exact")
        if user_id:
            query = query.eq("user_id", user_id)
        query = query.order("created_at", desc=True).range(offset, offset + per_page - 1)
        result = query.execute()
        clips = result.data or []
        total = result.count or len(clips)
        # Add public URL to each clip
        for clip in clips:
            clip["download_url"] = sb.storage.from_("clips").get_public_url(clip["file_path"])
        return jsonify({"clips": clips, "total": total, "has_more": offset + per_page < total})
    except Exception:
        logger.exception("get library error")
        return jsonify({"clips": [], "total": 0, "has_more": False, "error": "Could not load library."}), 500


@app.route("/api/library/<clip_id>", methods=["DELETE"])
def delete_clip(clip_id):
    """Delete a clip from storage and database."""
    # Validate UUID format
    if not re.match(r'^[a-f0-9-]{36}$', clip_id):
        return jsonify({"error": "Invalid clip ID."}), 400

    user_id = require_auth()
    try:
        # Get the clip to find the file path
        query = sb.table("clips").select("file_path").eq("id", clip_id)
        if user_id:
            query = query.eq("user_id", user_id)
        result = query.execute()
        if not result.data:
            return jsonify({"error": "Clip not found."}), 404

        file_path = result.data[0]["file_path"]

        # Delete from storage
        try:
            sb.storage.from_("clips").remove([file_path])
        except Exception:
            pass  # Storage file may already be gone

        # Delete from database
        delete_q = sb.table("clips").delete().eq("id", clip_id)
        if user_id:
            delete_q = delete_q.eq("user_id", user_id)
        delete_q.execute()

        return jsonify({"success": True})
    except Exception:
        logger.exception("delete clip error")
        return jsonify({"error": "Could not delete clip."}), 500


# ── API: Toggle favorite ──────────────────────────────────────────────────────

@app.route("/api/library/<clip_id>/favorite", methods=["PATCH"])
def toggle_favorite(clip_id):
    """Toggle the is_favorite flag on a clip."""
    if not re.match(r'^[a-f0-9-]{36}$', clip_id):
        return jsonify({"error": "Invalid clip ID."}), 400

    user_id = require_auth()
    try:
        query = sb.table("clips").select("is_favorite").eq("id", clip_id)
        if user_id:
            query = query.eq("user_id", user_id)
        result = query.execute()
        if not result.data:
            return jsonify({"error": "Clip not found."}), 404

        current = result.data[0].get("is_favorite", False)
        update_q = sb.table("clips").update({"is_favorite": not current}).eq("id", clip_id)
        if user_id:
            update_q = update_q.eq("user_id", user_id)
        update_q.execute()
        return jsonify({"success": True, "is_favorite": not current})
    except Exception:
        logger.exception("toggle favorite error")
        return jsonify({"error": "Could not update favorite."}), 500


# ── API: Bulk delete ──────────────────────────────────────────────────────────

@app.route("/api/library/bulk-delete", methods=["POST"])
def bulk_delete():
    """Delete multiple clips from storage and database."""
    data = request.get_json(silent=True)
    if not data or not isinstance(data.get("ids"), list):
        return jsonify({"error": "Invalid request. Provide {\"ids\": [...]}"}), 400

    ids = data["ids"]
    if len(ids) > 50:
        return jsonify({"error": "Too many IDs (max 50)."}), 400

    # Validate all IDs
    for cid in ids:
        if not re.match(r'^[a-f0-9-]{36}$', cid):
            return jsonify({"error": f"Invalid clip ID: {cid}"}), 400

    user_id = require_auth()
    deleted = 0
    try:
        # Get file paths for storage cleanup
        query = sb.table("clips").select("id, file_path").in_("id", ids)
        if user_id:
            query = query.eq("user_id", user_id)
        result = query.execute()
        if result.data:
            file_paths = [r["file_path"] for r in result.data if r.get("file_path")]
            # Delete from storage
            if file_paths:
                try:
                    sb.storage.from_("clips").remove(file_paths)
                except Exception:
                    pass  # Some files may already be gone

            # Delete from database
            delete_q = sb.table("clips").delete().in_("id", ids)
            if user_id:
                delete_q = delete_q.eq("user_id", user_id)
            delete_q.execute()
            deleted = len(result.data)

        return jsonify({"success": True, "deleted": deleted})
    except Exception:
        logger.exception("bulk delete error")
        return jsonify({"error": "Could not delete clips."}), 500


# ── API: Edit clip metadata ───────────────────────────────────────────────────

@app.route("/api/library/<clip_id>", methods=["PATCH"])
def edit_clip(clip_id):
    """Update clip title and/or tags."""
    if not re.match(r'^[a-f0-9-]{36}$', clip_id):
        return jsonify({"error": "Invalid clip ID."}), 400

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request body."}), 400

    # Build update dict
    updates = {}
    if "title" in data:
        updates["title"] = str(data["title"])[:200]
    if "tags" in data:
        updates["tags"] = str(data["tags"])[:500] if data["tags"] else None

    if not updates:
        return jsonify({"error": "Nothing to update."}), 400

    # Auth check (if auth enabled)
    user_id = require_auth()
    try:
        query = sb.table("clips").update(updates).eq("id", clip_id)
        if user_id:
            query = query.eq("user_id", user_id)
        result = query.execute()
        if not result.data:
            return jsonify({"error": "Clip not found."}), 404
        return jsonify({"success": True})
    except Exception:
        logger.exception("edit clip error")
        return jsonify({"error": "Could not update clip."}), 500


# ── Auth helpers ─────────────────────────────────────────────────────────────

SUPABASE_JWT_SECRET = os.environ.get("SUPABASE_JWT_SECRET", "")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_KEY", "")

# Anon client for auth operations
try:
    import jwt as pyjwt
    anon_sb = create_client(SUPABASE_URL, SUPABASE_ANON_KEY) if SUPABASE_ANON_KEY else None
except Exception:
    pyjwt = None
    anon_sb = None


def get_current_user():
    """Extract user_id from JWT Bearer token. Returns user_id or None."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer ") or not pyjwt or not SUPABASE_JWT_SECRET:
        return None
    token = auth_header[7:]
    try:
        payload = pyjwt.decode(token, SUPABASE_JWT_SECRET, algorithms=["HS256"], audience="authenticated")
        return payload.get("sub")
    except Exception:
        return None


def require_auth():
    """Returns user_id if authenticated, None otherwise (graceful degradation)."""
    return get_current_user()


# ── API: Auth routes ─────────────────────────────────────────────────────────

@app.route("/api/auth/signup", methods=["POST"])
def auth_signup():
    if not anon_sb:
        return jsonify({"error": "Auth not configured."}), 503
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request."}), 400
    email = data.get("email", "").strip()
    password = data.get("password", "")
    if not email or not password:
        return jsonify({"error": "Email and password required."}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters."}), 400
    try:
        result = anon_sb.auth.sign_up({"email": email, "password": password})
        if result.user:
            return jsonify({"success": True, "message": "Account created. Check your email to confirm."})
        return jsonify({"error": "Signup failed."}), 400
    except Exception as e:
        return jsonify({"error": str(e)[:200]}), 400


@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    if not anon_sb:
        return jsonify({"error": "Auth not configured."}), 503
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request."}), 400
    email = data.get("email", "").strip()
    password = data.get("password", "")
    if not email or not password:
        return jsonify({"error": "Email and password required."}), 400
    try:
        result = anon_sb.auth.sign_in_with_password({"email": email, "password": password})
        if result.session:
            return jsonify({
                "success": True,
                "access_token": result.session.access_token,
                "refresh_token": result.session.refresh_token,
                "user": {"id": result.user.id, "email": result.user.email},
            })
        return jsonify({"error": "Login failed."}), 401
    except Exception as e:
        return jsonify({"error": str(e)[:200]}), 401


@app.route("/api/auth/refresh", methods=["POST"])
def auth_refresh():
    if not anon_sb:
        return jsonify({"error": "Auth not configured."}), 503
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request."}), 400
    refresh_token = data.get("refresh_token", "")
    if not refresh_token:
        return jsonify({"error": "Refresh token required."}), 400
    try:
        result = anon_sb.auth.refresh_session(refresh_token)
        if result.session:
            return jsonify({
                "success": True,
                "access_token": result.session.access_token,
                "refresh_token": result.session.refresh_token,
            })
        return jsonify({"error": "Refresh failed."}), 401
    except Exception as e:
        return jsonify({"error": str(e)[:200]}), 401


# ── Frontend HTML ────────────────────────────────────────────────────────────

INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ClipForge</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>✂</text></svg>">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}

:root {
  --bg-deep: #0a0a0b;
  --bg-panel: #111113;
  --bg-surface: #18181b;
  --bg-elevated: #1e1e21;
  --bg-hover: #252528;
  --border: rgba(255, 255, 255, 0.08);
  --border-light: rgba(255, 255, 255, 0.12);
  --border-focus: rgba(0, 229, 160, 0.5);
  --text-primary: #ececf0;
  --text-secondary: #9898a0;
  --text-muted: #5c5c66;
  --accent: #00e5a0;
  --accent-dim: rgba(0, 229, 160, 0.1);
  --accent-glow: rgba(0, 229, 160, 0.25);
  --accent-secondary: #34d399;
  --danger: #f43f5e;
  --danger-dim: rgba(244, 63, 94, 0.1);
  --timeline-bg: #18181b;
  --timeline-region: rgba(0, 229, 160, 0.12);
  --yt: #ff0033;
  --tw: #1d9bf0;
  --ig: #e1306c;
  --tk: #00f2ea;
  --twitch: #9146ff;
  --sc: #ff5500;
  --radius-sm: 6px;
  --radius-md: 10px;
  --radius-lg: 14px;
}

html { font-size: 15px; scroll-behavior: smooth; }

body {
  font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
  background: var(--bg-deep);
  color: var(--text-primary);
  min-height: 100vh;
  overflow-x: hidden;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  line-height: 1.55;
  letter-spacing: -0.01em;
}

.app-container {
  max-width: 1400px;
  margin: 0 auto;
  padding: 1.5rem 1.5rem 4rem;
}

.app-columns {
  display: grid;
  grid-template-columns: 1fr 380px;
  gap: 1.5rem;
  align-items: start;
}

.col-editor {
  min-width: 0;
}

.col-library {
  position: sticky;
  top: 1.5rem;
  max-height: calc(100vh - 3rem);
  overflow-y: auto;
  scrollbar-width: thin;
  scrollbar-color: rgba(255,255,255,0.06) transparent;
}
.col-library::-webkit-scrollbar { width: 4px; }
.col-library::-webkit-scrollbar-track { background: transparent; }
.col-library::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.08); border-radius: 10px; }
.col-library::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.14); }

/* ── Header ─────────────────────────────────────── */
.header {
  text-align: center;
  margin-bottom: 2rem;
  padding-bottom: 1.5rem;
  border-bottom: 1px solid var(--border);
  animation: fadeIn 0.6s ease-out;
}

.logo {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.7rem;
  letter-spacing: 3px;
  text-transform: uppercase;
  color: var(--accent);
  margin-bottom: 0.5rem;
  font-weight: 500;
}

.header h1 {
  font-size: 1.9rem;
  font-weight: 700;
  letter-spacing: -0.5px;
  line-height: 1.2;
  color: var(--text-primary);
}

.header p {
  color: var(--text-muted);
  font-size: 0.9rem;
  margin-top: 0.35rem;
  font-weight: 400;
}

/* ── Platform pills ─────────────────────────────── */
.platforms {
  display: flex;
  justify-content: center;
  gap: 0.4rem;
  margin-top: 0.8rem;
  flex-wrap: wrap;
}

.platform-pill {
  display: flex;
  align-items: center;
  gap: 0.3rem;
  padding: 0.3rem 0.7rem;
  border-radius: 100px;
  font-size: 0.75rem;
  font-weight: 500;
  border: 1px solid var(--border);
  background: transparent;
  color: var(--text-muted);
  transition: all 0.2s ease;
  cursor: default;
}

.platform-pill svg { width: 13px; height: 13px; opacity: 0.5; transition: opacity 0.2s; }
.platform-pill.yt svg { color: var(--yt); }
.platform-pill.tw svg { color: var(--tw); }
.platform-pill.ig svg { color: var(--ig); }
.platform-pill.tk svg { color: var(--tk); }
.platform-pill.twitch svg { color: var(--twitch); }
.platform-pill.sc svg { color: var(--sc); }

.platform-pill.active {
  border-color: var(--accent);
  background: var(--accent-dim);
  color: var(--text-primary);
}
.platform-pill.active svg { opacity: 1; }

/* ── Panels ─────────────────────────────────────── */
.panel {
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 1.25rem;
  margin-bottom: 1rem;
  animation: fadeIn 0.4s ease-out backwards;
  transition: border-color 0.2s;
}
.panel:hover {
  border-color: var(--border-light);
}

.panel-label {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.65rem;
  letter-spacing: 1.5px;
  text-transform: uppercase;
  color: var(--text-muted);
  margin-bottom: 1rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.panel-label .dot {
  width: 5px; height: 5px;
  border-radius: 50%;
  background: var(--accent);
}

/* ── Platform badge ── */
.platform-badge {
  display: none;
  align-items: center;
  gap: 0.4rem;
  margin-bottom: 1rem;
  padding: 0.35rem 0.7rem;
  border-radius: 100px;
  font-size: 0.75rem;
  font-weight: 500;
  animation: fadeIn 0.3s ease-out;
}
.platform-badge.visible { display: inline-flex; }
.platform-badge svg { width: 14px; height: 14px; }
.platform-badge.youtube   { background: rgba(255,0,51,0.1); color: var(--yt); border: 1px solid rgba(255,0,51,0.2); }
.platform-badge.twitter   { background: rgba(29,155,240,0.1); color: var(--tw); border: 1px solid rgba(29,155,240,0.2); }
.platform-badge.instagram { background: rgba(225,48,108,0.1); color: var(--ig); border: 1px solid rgba(225,48,108,0.2); }
.platform-badge.tiktok    { background: rgba(0,242,234,0.1); color: var(--tk); border: 1px solid rgba(0,242,234,0.2); }
.platform-badge.twitch    { background: rgba(145,70,255,0.1); color: var(--twitch); border: 1px solid rgba(145,70,255,0.2); }
.platform-badge.soundcloud { background: rgba(255,85,0,0.1); color: var(--sc); border: 1px solid rgba(255,85,0,0.2); }

/* ── URL Input ──────────────────────────────────── */
.url-group {
  display: flex;
  gap: 0.5rem;
}

.url-input {
  flex: 1;
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 0.75rem 1rem;
  color: var(--text-primary);
  font-family: inherit;
  font-size: 0.9rem;
  outline: none;
  transition: border-color 0.2s, box-shadow 0.2s;
}
.url-input::placeholder { color: var(--text-muted); }
.url-input:focus {
  border-color: var(--border-focus);
  box-shadow: 0 0 0 3px var(--accent-dim);
}

.btn-load {
  background: var(--accent);
  color: var(--bg-deep);
  border: none;
  border-radius: var(--radius-sm);
  padding: 0.75rem 1.5rem;
  font-family: inherit;
  font-weight: 600;
  font-size: 0.9rem;
  cursor: pointer;
  transition: all 0.2s ease;
  white-space: nowrap;
}
.btn-load:hover {
  filter: brightness(1.1);
  box-shadow: 0 4px 16px var(--accent-glow);
}
.btn-load:active { transform: scale(0.98); }
.btn-load:disabled {
  opacity: 0.3;
  cursor: not-allowed;
}

/* ── Video Preview ──────────────────────────────── */
.preview-section { display: none; }
.preview-section.visible { display: block; animation: fadeIn 0.3s ease-out; }

.video-meta {
  display: flex;
  align-items: start;
  gap: 1rem;
  margin-bottom: 1rem;
}

.video-thumb {
  width: 160px;
  min-width: 160px;
  aspect-ratio: 16/9;
  border-radius: var(--radius-sm);
  object-fit: cover;
  border: 1px solid var(--border);
}

.video-info h3 {
  font-size: 0.95rem;
  font-weight: 600;
  line-height: 1.35;
  margin-bottom: 0.2rem;
  word-break: break-word;
}

.video-info .channel {
  color: var(--text-secondary);
  font-size: 0.85rem;
}

.video-info .duration-badge {
  display: inline-block;
  margin-top: 0.5rem;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.7rem;
  background: var(--accent-dim);
  color: var(--accent);
  padding: 0.2rem 0.6rem;
  border-radius: var(--radius-sm);
  border: 1px solid rgba(0, 229, 160, 0.2);
  font-weight: 500;
}

.player-wrap {
  position: relative;
  width: 100%;
  aspect-ratio: 16/9;
  border-radius: var(--radius-md);
  overflow: hidden;
  border: 1px solid var(--border);
  background: #000;
}

.player-wrap iframe {
  width: 100%;
  height: 100%;
  border: none;
}

.player-wrap .no-embed {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 100%;
  height: 100%;
  color: var(--text-muted);
  font-size: 0.85rem;
  text-align: center;
  padding: 1.5rem;
  background: var(--bg-surface);
}

/* ── Mode Toggle ─────────────── */
.mode-toggle {
  display: none;
  gap: 2px;
  margin-bottom: 1rem;
  background: var(--bg-surface);
  border-radius: var(--radius-sm);
  padding: 3px;
  border: 1px solid var(--border);
}
.mode-toggle.visible { display: flex; }

.mode-btn {
  flex: 1;
  padding: 0.55rem;
  border: none;
  border-radius: 4px;
  background: transparent;
  color: var(--text-muted);
  font-family: inherit;
  font-size: 0.85rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.15s ease;
  text-align: center;
}

.mode-btn:hover { color: var(--text-secondary); }

.mode-btn.active {
  background: var(--bg-elevated);
  color: var(--text-primary);
  box-shadow: 0 1px 4px rgba(0,0,0,0.3);
}

/* ── Timeline ───────────────────────────────────── */
.timeline-section { display: none; }
.timeline-section.visible { display: block; animation: fadeIn 0.3s ease-out; }

.time-controls {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.75rem;
  margin-bottom: 1rem;
}

.time-field label {
  display: block;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.65rem;
  letter-spacing: 1px;
  text-transform: uppercase;
  color: var(--text-muted);
  margin-bottom: 0.35rem;
}

.time-field input {
  width: 100%;
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 0.6rem 0.75rem;
  color: var(--text-primary);
  font-family: 'JetBrains Mono', monospace;
  font-size: 1.05rem;
  font-weight: 500;
  text-align: center;
  outline: none;
  transition: border-color 0.2s, box-shadow 0.2s;
}
.time-field input:focus {
  border-color: var(--border-focus);
  box-shadow: 0 0 0 3px var(--accent-dim);
}

.timeline-track {
  position: relative;
  height: 52px;
  background: var(--timeline-bg);
  border-radius: var(--radius-sm);
  margin: 0.75rem 0 0.5rem;
  overflow: hidden;
  border: 1px solid var(--border);
  cursor: pointer;
}

.timeline-waveform {
  position: absolute;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 2px;
  padding: 0 10px;
  opacity: 0.15;
}

.timeline-waveform .bar {
  width: 2.5px;
  border-radius: 2px;
  background: var(--accent);
}

.timeline-region {
  position: absolute;
  top: 0;
  bottom: 0;
  background: var(--timeline-region);
  border-left: 2px solid var(--accent);
  border-right: 2px solid var(--accent);
  transition: left 0.15s, width 0.15s;
}

.timeline-region::before {
  content: '';
  position: absolute;
  inset: 0;
  background: linear-gradient(180deg, rgba(0,229,160,0.06) 0%, transparent 100%);
}

.timeline-handle {
  position: absolute;
  top: 0;
  bottom: 0;
  width: 16px;
  cursor: ew-resize;
  z-index: 5;
  display: flex;
  align-items: center;
  justify-content: center;
}

.timeline-handle::after {
  content: '';
  width: 4px;
  height: 24px;
  border-radius: 4px;
  background: var(--accent);
  transition: height 0.2s, box-shadow 0.2s;
}

.timeline-handle:hover::after {
  height: 32px;
  box-shadow: 0 0 12px var(--accent-glow);
}

.timeline-labels {
  display: flex;
  justify-content: space-between;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.65rem;
  color: var(--text-muted);
}

.clip-duration {
  text-align: center;
  margin-top: 0.75rem;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.8rem;
  color: var(--text-secondary);
}
.clip-duration span { color: var(--accent); font-weight: 500; }

/* ── Action Buttons ─────────────────────────────── */
.action-section { display: none; }
.action-section.visible { display: block; animation: fadeIn 0.3s ease-out; }

.btn-action {
  width: 100%;
  padding: 0.85rem;
  background: var(--accent);
  color: var(--bg-deep);
  border: none;
  border-radius: var(--radius-sm);
  font-family: inherit;
  font-size: 0.95rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s ease;
}
.btn-action:hover {
  filter: brightness(1.1);
  box-shadow: 0 4px 20px var(--accent-glow);
}
.btn-action:active { transform: scale(0.98); }
.btn-action:disabled {
  opacity: 0.35;
  cursor: not-allowed;
}

/* ── Progress ───────────────────────────────────── */
.progress-section { display: none; }
.progress-section.visible { display: block; animation: fadeIn 0.3s ease-out; }

.progress-bar-track {
  height: 3px;
  background: var(--bg-elevated);
  border-radius: 100px;
  overflow: hidden;
  margin: 1rem 0;
}

.progress-bar-fill {
  height: 100%;
  background: var(--accent);
  border-radius: 100px;
  width: 0%;
  animation: indeterminate 2s ease-in-out infinite;
}

@keyframes indeterminate {
  0% { width: 5%; margin-left: 0; }
  50% { width: 35%; margin-left: 35%; }
  100% { width: 5%; margin-left: 95%; }
}

.progress-status {
  font-size: 0.8rem;
  color: var(--text-secondary);
  text-align: center;
}

.progress-status .spinner {
  display: inline-block;
  width: 12px;
  height: 12px;
  border: 2px solid rgba(255,255,255,0.1);
  border-top-color: var(--accent);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
  vertical-align: middle;
  margin-right: 0.4rem;
}

/* ── Download Ready ─────────────────────────────── */
.download-section { display: none; text-align: center; }
.download-section.visible { display: block; animation: fadeIn 0.4s ease-out; }

.download-icon {
  width: 56px;
  height: 56px;
  margin: 0 auto 1rem;
  border-radius: 50%;
  background: var(--accent-dim);
  border: 1px solid rgba(0, 229, 160, 0.2);
  display: flex;
  align-items: center;
  justify-content: center;
}

.download-icon svg { width: 24px; height: 24px; stroke: var(--accent); }

.btn-download {
  display: inline-block;
  padding: 0.7rem 2rem;
  background: var(--accent);
  color: var(--bg-deep);
  border: none;
  border-radius: var(--radius-sm);
  font-family: inherit;
  font-size: 0.9rem;
  font-weight: 600;
  cursor: pointer;
  text-decoration: none;
  transition: all 0.2s ease;
}
.btn-download:hover {
  filter: brightness(1.1);
  box-shadow: 0 4px 16px var(--accent-glow);
}

.success-text {
  color: var(--accent);
  font-size: 1.1rem;
  font-weight: 600;
  margin-bottom: 0.2rem;
}

.reset-link {
  display: inline-block;
  margin-top: 1rem;
  color: var(--text-muted);
  font-size: 0.8rem;
  cursor: pointer;
  transition: color 0.2s;
  background: none;
  border: none;
  font-family: inherit;
  text-decoration: underline;
  text-underline-offset: 3px;
}
.reset-link:hover { color: var(--text-secondary); }

/* ── Error ──────────────────────────────────────── */
.error-msg {
  display: none;
  background: var(--danger-dim);
  border: 1px solid rgba(244, 63, 94, 0.2);
  border-radius: var(--radius-sm);
  padding: 0.65rem 0.85rem;
  color: var(--danger);
  font-size: 0.8rem;
  margin-top: 0.75rem;
}
.error-msg.visible { display: block; animation: fadeIn 0.2s ease-out; }

.limit-note {
  text-align: center;
  font-size: 0.75rem;
  color: var(--text-muted);
  margin-top: 0.5rem;
}

/* ── Save to Library Button ────────────────────── */
.btn-save-library {
  display: inline-block;
  padding: 0.55rem 1.2rem;
  background: transparent;
  color: var(--text-secondary);
  border: 1px solid var(--border-light);
  border-radius: var(--radius-sm);
  font-family: inherit;
  font-size: 0.8rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s ease;
  margin-top: 0.5rem;
}
.btn-save-library:hover {
  border-color: var(--accent);
  color: var(--accent);
  background: var(--accent-dim);
}
.btn-save-library:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}
.btn-save-library.saved {
  background: var(--accent-dim);
  border-color: var(--accent);
  color: var(--accent);
  pointer-events: none;
}

/* ── Save Dialog ──────────────────────────────── */
.save-dialog {
  display: none;
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 1rem;
  margin-top: 1rem;
  text-align: left;
  animation: fadeIn 0.2s ease-out;
}
.save-dialog.visible { display: block; }

.save-dialog label {
  display: block;
  font-size: 0.75rem;
  font-weight: 500;
  color: var(--text-secondary);
  margin-bottom: 0.35rem;
}

.save-dialog input[type="text"] {
  width: 100%;
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 0.6rem 0.75rem;
  color: var(--text-primary);
  font-family: inherit;
  font-size: 0.85rem;
  outline: none;
  transition: border-color 0.2s, box-shadow 0.2s;
  margin-bottom: 1rem;
}
.save-dialog input[type="text"]:focus {
  border-color: var(--border-focus);
  box-shadow: 0 0 0 3px var(--accent-dim);
}

.tag-input-wrap {
  display: flex;
  flex-wrap: wrap;
  gap: 0.3rem;
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 0.5rem 0.6rem;
  margin-bottom: 1rem;
  min-height: 40px;
  cursor: text;
  transition: border-color 0.2s, box-shadow 0.2s;
  align-items: center;
}
.tag-input-wrap:focus-within {
  border-color: var(--border-focus);
  box-shadow: 0 0 0 3px var(--accent-dim);
}

.tag-chip {
  display: inline-flex;
  align-items: center;
  gap: 0.25rem;
  background: var(--accent-dim);
  color: var(--accent);
  border: 1px solid rgba(0, 229, 160, 0.2);
  border-radius: var(--radius-sm);
  padding: 0.15rem 0.5rem;
  font-size: 0.7rem;
  font-weight: 500;
  white-space: nowrap;
}
.tag-chip .tag-remove {
  cursor: pointer;
  opacity: 0.5;
  font-size: 0.85rem;
  line-height: 1;
  transition: opacity 0.15s;
}
.tag-chip .tag-remove:hover { opacity: 1; }

.tag-input-field {
  flex: 1;
  min-width: 70px;
  background: transparent;
  border: none;
  color: var(--text-primary);
  font-family: inherit;
  font-size: 0.8rem;
  outline: none;
}
.tag-input-field::placeholder { color: var(--text-muted); }

.save-dialog-actions {
  display: flex;
  gap: 0.4rem;
}

.btn-confirm-save {
  flex: 1;
  padding: 0.6rem;
  background: var(--accent);
  color: var(--bg-deep);
  border: none;
  border-radius: var(--radius-sm);
  font-family: inherit;
  font-size: 0.85rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s ease;
}
.btn-confirm-save:hover { filter: brightness(1.1); box-shadow: 0 2px 12px var(--accent-glow); }
.btn-confirm-save:active { transform: scale(0.98); }
.btn-confirm-save:disabled { opacity: 0.35; cursor: not-allowed; }

.btn-cancel-save {
  padding: 0.6rem 1rem;
  background: transparent;
  color: var(--text-muted);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  font-family: inherit;
  font-size: 0.85rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.15s;
}
.btn-cancel-save:hover { border-color: var(--border-light); color: var(--text-secondary); }

/* ── Library ───────────────────────────────────── */
.library-section {
  animation: fadeIn 0.5s ease-out backwards;
}

/* ── Library Toolbar ──────────────────────────── */
.library-toolbar {
  margin-bottom: 1rem;
}

.library-search {
  width: 100%;
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 0.55rem 0.75rem;
  color: var(--text-primary);
  font-family: inherit;
  font-size: 0.8rem;
  outline: none;
  transition: border-color 0.2s, box-shadow 0.2s;
  margin-bottom: 0.6rem;
}
.library-search::placeholder { color: var(--text-muted); }
.library-search:focus { border-color: var(--border-focus); box-shadow: 0 0 0 3px var(--accent-dim); }

.library-filters {
  display: flex;
  gap: 0.25rem;
  flex-wrap: wrap;
  margin-bottom: 0.6rem;
}

.filter-pill {
  padding: 0.25rem 0.6rem;
  border-radius: 100px;
  font-size: 0.7rem;
  font-weight: 500;
  border: 1px solid var(--border);
  background: transparent;
  color: var(--text-muted);
  cursor: pointer;
  transition: all 0.15s ease;
}
.filter-pill:hover { border-color: var(--border-light); color: var(--text-secondary); }
.filter-pill.active { border-color: var(--accent); background: var(--accent-dim); color: var(--accent); }

.library-sort-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 0.6rem;
}

.library-sort {
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 0.3rem 0.5rem;
  color: var(--text-secondary);
  font-family: inherit;
  font-size: 0.7rem;
  outline: none;
  cursor: pointer;
}
.library-sort option { background: var(--bg-surface); color: var(--text-primary); }

.btn-select-all {
  background: transparent;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 0.3rem 0.6rem;
  color: var(--text-muted);
  font-size: 0.7rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.15s;
}
.btn-select-all:hover { border-color: var(--border-light); color: var(--text-secondary); }

.library-stats {
  font-size: 0.75rem;
  color: var(--text-muted);
  margin-bottom: 0.75rem;
}

.library-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(155px, 1fr));
  gap: 0.6rem;
}

.library-empty {
  grid-column: 1 / -1;
  text-align: center;
  padding: 2.5rem 1rem;
  color: var(--text-muted);
  font-size: 0.85rem;
}

/* ── Clip Card ─────────────────────────────────── */
.clip-card {
  position: relative;
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  overflow: hidden;
  transition: border-color 0.2s, box-shadow 0.2s;
  animation: fadeIn 0.3s ease-out backwards;
}
.clip-card:hover {
  border-color: var(--border-light);
  box-shadow: 0 4px 20px rgba(0,0,0,0.3);
}
.clip-card.selected { border-color: var(--accent); box-shadow: 0 0 0 1px var(--accent); }

.clip-card-thumb {
  position: relative;
  width: 100%;
  aspect-ratio: 16/9;
  background: var(--bg-elevated);
  overflow: hidden;
}
.clip-card-thumb img {
  width: 100%;
  height: 100%;
  object-fit: cover;
}
.clip-card-thumb .clip-platform-tag {
  position: absolute;
  bottom: 6px;
  left: 6px;
  font-size: 0.6rem;
  font-weight: 600;
  padding: 0.15rem 0.4rem;
  border-radius: 4px;
  text-transform: uppercase;
  letter-spacing: 0.3px;
}
.clip-platform-tag.youtube { background: rgba(255,0,51,0.9); color: #fff; }
.clip-platform-tag.twitter { background: rgba(29,155,240,0.9); color: #fff; }
.clip-platform-tag.instagram { background: rgba(225,48,108,0.9); color: #fff; }
.clip-platform-tag.tiktok { background: rgba(0,242,234,0.9); color: #000; }
.clip-platform-tag.twitch { background: rgba(145,70,255,0.9); color: #fff; }
.clip-platform-tag.soundcloud { background: rgba(255,85,0,0.9); color: #fff; }

.clip-card-thumb .clip-mode-tag {
  position: absolute;
  bottom: 6px;
  right: 6px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.55rem;
  font-weight: 500;
  padding: 0.15rem 0.4rem;
  border-radius: 4px;
  background: rgba(0,0,0,0.7);
  color: var(--text-secondary);
}

/* Checkbox overlay */
.clip-checkbox {
  position: absolute;
  top: 6px;
  left: 6px;
  width: 18px;
  height: 18px;
  border-radius: 4px;
  border: 1.5px solid rgba(255,255,255,0.35);
  background: rgba(0,0,0,0.5);
  cursor: pointer;
  z-index: 3;
  opacity: 0;
  transition: opacity 0.15s;
  display: flex;
  align-items: center;
  justify-content: center;
}
.clip-card:hover .clip-checkbox,
.clip-card.selected .clip-checkbox,
.bulk-mode .clip-checkbox { opacity: 1; }
.clip-checkbox.checked {
  background: var(--accent);
  border-color: var(--accent);
}
.clip-checkbox.checked::after {
  content: '';
  width: 5px;
  height: 9px;
  border: solid var(--bg-deep);
  border-width: 0 2px 2px 0;
  transform: rotate(45deg) translate(-1px, -1px);
}

/* Favorite star */
.clip-favorite {
  position: absolute;
  top: 6px;
  right: 6px;
  width: 26px;
  height: 26px;
  border-radius: 50%;
  background: rgba(0,0,0,0.5);
  border: none;
  cursor: pointer;
  z-index: 3;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 0.8rem;
  transition: all 0.15s ease;
  opacity: 0;
  color: rgba(255,255,255,0.5);
}
.clip-card:hover .clip-favorite { opacity: 1; }
.clip-favorite.active { opacity: 1; color: #ffd700; }
.clip-favorite:hover { transform: scale(1.1); }

.clip-card-body {
  padding: 0.6rem;
}
.clip-card-body h4 {
  font-size: 0.75rem;
  font-weight: 600;
  line-height: 1.3;
  margin-bottom: 0.2rem;
  overflow: hidden;
  text-overflow: ellipsis;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
}

.clip-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 0.2rem;
  margin-bottom: 0.3rem;
}
.clip-tags .clip-tag {
  font-size: 0.55rem;
  font-weight: 500;
  padding: 0.1rem 0.35rem;
  border-radius: 3px;
  background: var(--bg-elevated);
  color: var(--text-secondary);
  border: 1px solid var(--border);
}

.clip-card-body .clip-meta {
  font-size: 0.65rem;
  color: var(--text-muted);
  margin-bottom: 0.4rem;
}

.clip-card-actions {
  display: flex;
  gap: 0.3rem;
}
.clip-card-actions a, .clip-card-actions button {
  flex: 1;
  padding: 0.35rem;
  border-radius: 4px;
  font-size: 0.65rem;
  font-weight: 500;
  text-align: center;
  cursor: pointer;
  transition: all 0.15s ease;
  text-decoration: none;
}
.clip-btn-dl {
  background: transparent;
  color: var(--text-secondary);
  border: 1px solid var(--border-light);
}
.clip-btn-dl:hover { background: var(--accent); color: var(--bg-deep); border-color: var(--accent); }

.clip-btn-del {
  background: transparent;
  color: var(--text-muted);
  border: 1px solid var(--border);
}
.clip-btn-del:hover { border-color: var(--danger); color: var(--danger); background: var(--danger-dim); }

/* ── Bulk Action Bar ──────────────────────────── */
.bulk-bar {
  display: none;
  position: sticky;
  bottom: 0;
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 0.6rem 0.85rem;
  margin-top: 0.6rem;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
  animation: fadeIn 0.2s ease-out;
  z-index: 10;
}
.bulk-bar.visible { display: flex; }

.bulk-bar-info {
  font-size: 0.75rem;
  color: var(--text-secondary);
  font-weight: 500;
}

.bulk-bar-actions { display: flex; gap: 0.35rem; }

.bulk-btn {
  padding: 0.35rem 0.7rem;
  border-radius: 4px;
  font-size: 0.7rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.15s ease;
  border: 1px solid;
}
.bulk-btn-download {
  background: transparent;
  color: var(--accent);
  border-color: rgba(0, 229, 160, 0.3);
}
.bulk-btn-download:hover { background: var(--accent); color: var(--bg-deep); border-color: var(--accent); }
.bulk-btn-delete {
  background: transparent;
  color: var(--danger);
  border-color: rgba(244, 63, 94, 0.3);
}
.bulk-btn-delete:hover { background: var(--danger-dim); border-color: var(--danger); }

/* ── Quality/Format Picker ──────────────────────── */
.quality-section { display: none; margin-bottom: 1rem; }
.quality-section.visible { display: block; animation: fadeIn 0.3s ease-out; }
.quality-row { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem; }
.quality-label {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.65rem;
  letter-spacing: 1px;
  text-transform: uppercase;
  color: var(--text-muted);
  min-width: 55px;
}
.quality-group { display: flex; gap: 0.25rem; flex-wrap: wrap; }
.quality-pill, .format-pill {
  padding: 0.3rem 0.65rem;
  border-radius: 100px;
  font-size: 0.72rem;
  font-weight: 500;
  border: 1px solid var(--border);
  background: transparent;
  color: var(--text-muted);
  cursor: pointer;
  transition: all 0.15s ease;
}
.quality-pill:hover, .format-pill:hover { border-color: var(--border-light); color: var(--text-secondary); }
.quality-pill.active, .format-pill.active { border-color: var(--accent); background: var(--accent-dim); color: var(--accent); }

/* ── Edit Modal ────────────────────────────────── */
.edit-modal-overlay {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.6);
  backdrop-filter: blur(4px);
  z-index: 100;
  align-items: center;
  justify-content: center;
}
.edit-modal-overlay.visible { display: flex; animation: fadeIn 0.2s ease-out; }
.edit-modal {
  background: var(--bg-panel);
  border: 1px solid var(--border-light);
  border-radius: var(--radius-lg);
  padding: 1.5rem;
  width: 420px;
  max-width: 90vw;
  max-height: 80vh;
  overflow-y: auto;
}
.edit-modal h3 { font-size: 1rem; font-weight: 600; margin-bottom: 1rem; }
.edit-modal label {
  display: block;
  font-size: 0.75rem;
  font-weight: 500;
  color: var(--text-secondary);
  margin-bottom: 0.35rem;
}
.edit-modal input[type="text"] {
  width: 100%;
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 0.6rem 0.75rem;
  color: var(--text-primary);
  font-family: inherit;
  font-size: 0.85rem;
  outline: none;
  transition: border-color 0.2s, box-shadow 0.2s;
  margin-bottom: 1rem;
}
.edit-modal input[type="text"]:focus { border-color: var(--border-focus); box-shadow: 0 0 0 3px var(--accent-dim); }
.edit-modal-actions { display: flex; gap: 0.4rem; margin-top: 0.5rem; }
.edit-modal-actions .btn-confirm-save { flex: 1; }

/* ── Toast Notifications ───────────────────────── */
.toast-container {
  position: fixed;
  bottom: 1.5rem;
  right: 1.5rem;
  z-index: 200;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  pointer-events: none;
}
.toast {
  pointer-events: auto;
  padding: 0.65rem 1rem;
  border-radius: var(--radius-sm);
  font-size: 0.8rem;
  font-weight: 500;
  color: var(--text-primary);
  animation: toastIn 0.3s ease-out;
  max-width: 320px;
}
.toast.toast-success { background: rgba(0,229,160,0.15); border: 1px solid rgba(0,229,160,0.3); color: var(--accent); }
.toast.toast-error { background: var(--danger-dim); border: 1px solid rgba(244,63,94,0.3); color: var(--danger); }
.toast.toast-info { background: var(--bg-elevated); border: 1px solid var(--border-light); }
.toast.toast-out { animation: toastOut 0.3s ease-in forwards; }
@keyframes toastIn { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: translateY(0); } }
@keyframes toastOut { from { opacity: 1; transform: translateY(0); } to { opacity: 0; transform: translateY(12px); } }

/* ── Auth Modal ────────────────────────────────── */
.auth-modal-overlay {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.6);
  backdrop-filter: blur(4px);
  z-index: 100;
  align-items: center;
  justify-content: center;
}
.auth-modal-overlay.visible { display: flex; animation: fadeIn 0.2s ease-out; }
.auth-modal {
  background: var(--bg-panel);
  border: 1px solid var(--border-light);
  border-radius: var(--radius-lg);
  padding: 1.75rem;
  width: 380px;
  max-width: 90vw;
}
.auth-modal h3 { font-size: 1.1rem; font-weight: 600; margin-bottom: 1.25rem; text-align: center; }
.auth-input {
  width: 100%;
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 0.7rem 0.85rem;
  color: var(--text-primary);
  font-family: inherit;
  font-size: 0.9rem;
  outline: none;
  transition: border-color 0.2s, box-shadow 0.2s;
  margin-bottom: 0.75rem;
}
.auth-input:focus { border-color: var(--border-focus); box-shadow: 0 0 0 3px var(--accent-dim); }
.auth-input::placeholder { color: var(--text-muted); }
.auth-error { display: none; color: var(--danger); font-size: 0.8rem; margin-bottom: 0.75rem; }
.auth-error.visible { display: block; }
.auth-submit {
  width: 100%;
  padding: 0.75rem;
  background: var(--accent);
  color: var(--bg-deep);
  border: none;
  border-radius: var(--radius-sm);
  font-family: inherit;
  font-size: 0.9rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s ease;
  margin-bottom: 0.75rem;
}
.auth-submit:hover { filter: brightness(1.1); box-shadow: 0 4px 16px var(--accent-glow); }
.auth-submit:disabled { opacity: 0.35; cursor: not-allowed; }
.auth-toggle {
  text-align: center;
  font-size: 0.8rem;
  color: var(--text-muted);
}
.auth-toggle a {
  color: var(--accent);
  cursor: pointer;
  text-decoration: underline;
  text-underline-offset: 2px;
}
.user-bar {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.8rem;
}
.user-bar .user-email { color: var(--text-secondary); font-weight: 500; }
.user-bar .btn-logout {
  background: transparent;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 0.25rem 0.6rem;
  color: var(--text-muted);
  font-size: 0.7rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.15s;
  font-family: inherit;
}
.user-bar .btn-logout:hover { border-color: var(--danger); color: var(--danger); }
.btn-login-header {
  background: transparent;
  border: 1px solid var(--accent);
  border-radius: var(--radius-sm);
  padding: 0.3rem 0.8rem;
  color: var(--accent);
  font-size: 0.75rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.15s;
  font-family: inherit;
}
.btn-login-header:hover { background: var(--accent-dim); }

/* ── Skeleton Loading ──────────────────────────── */
.skeleton-card {
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  overflow: hidden;
}
.skeleton-thumb {
  width: 100%;
  aspect-ratio: 16/9;
  background: var(--bg-elevated);
  animation: shimmer 1.5s ease-in-out infinite;
}
.skeleton-line {
  height: 10px;
  margin: 0.5rem 0.6rem;
  border-radius: 4px;
  background: var(--bg-elevated);
  animation: shimmer 1.5s ease-in-out infinite;
}
.skeleton-line.short { width: 60%; }
@keyframes shimmer {
  0%, 100% { opacity: 0.4; }
  50% { opacity: 0.8; }
}

/* ── Load More ─────────────────────────────────── */
.btn-load-more {
  display: none;
  width: 100%;
  padding: 0.6rem;
  margin-top: 0.75rem;
  background: transparent;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  color: var(--text-secondary);
  font-family: inherit;
  font-size: 0.8rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.15s;
}
.btn-load-more:hover { border-color: var(--accent); color: var(--accent); background: var(--accent-dim); }
.btn-load-more.visible { display: block; }

/* ── Animations ─────────────────────────────────── */
@keyframes fadeIn {
  from { opacity: 0; transform: translateY(4px); }
  to { opacity: 1; transform: translateY(0); }
}

@keyframes spin { to { transform: rotate(360deg); } }

/* ── Responsive ─────────────────────────────────── */
@media (max-width: 1024px) {
  .app-columns { grid-template-columns: 1fr; }
  .col-library { position: static; max-height: none; }
}
</style>
</head>
<body>

<div class="app-container">

  <!-- Header -->
  <header class="header">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.5rem">
      <div class="logo">ClipForge</div>
      <div id="userArea">
        <button type="button" class="btn-login-header" id="btnLoginHeader" onclick="showAuthModal('login')">Log in</button>
      </div>
    </div>
    <h1>Download & Trim Videos</h1>
    <p>Paste a link from any supported platform, trim it or download it directly.</p>
    <div class="platforms">
      <div class="platform-pill yt" id="pillYt">
        <svg viewBox="0 0 24 24" fill="currentColor"><path d="M23.5 6.2a3 3 0 0 0-2.1-2.1C19.5 3.5 12 3.5 12 3.5s-7.5 0-9.4.6A3 3 0 0 0 .5 6.2 31.4 31.4 0 0 0 0 12a31.4 31.4 0 0 0 .5 5.8 3 3 0 0 0 2.1 2.1c1.9.5 9.4.5 9.4.5s7.5 0 9.4-.6a3 3 0 0 0 2.1-2.1A31.4 31.4 0 0 0 24 12a31.4 31.4 0 0 0-.5-5.8zM9.6 15.5V8.5l6.3 3.5-6.3 3.5z"/></svg>
        YouTube
      </div>
      <div class="platform-pill tw" id="pillTw">
        <svg viewBox="0 0 24 24" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>
        Twitter / X
      </div>
      <div class="platform-pill ig" id="pillIg">
        <svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2.16c3.2 0 3.58.01 4.85.07 3.25.15 4.77 1.69 4.92 4.92.06 1.27.07 1.65.07 4.85s-.01 3.58-.07 4.85c-.15 3.23-1.66 4.77-4.92 4.92-1.27.06-1.65.07-4.85.07s-3.58-.01-4.85-.07c-3.26-.15-4.77-1.7-4.92-4.92-.06-1.27-.07-1.65-.07-4.85s.01-3.58.07-4.85C2.38 3.86 3.9 2.31 7.15 2.23 8.42 2.17 8.8 2.16 12 2.16zM12 0C8.74 0 8.33.01 7.05.07 2.7.27.27 2.7.07 7.05.01 8.33 0 8.74 0 12s.01 3.67.07 4.95c.2 4.36 2.62 6.78 6.98 6.98C8.33 23.99 8.74 24 12 24s3.67-.01 4.95-.07c4.35-.2 6.78-2.62 6.98-6.98.06-1.28.07-1.69.07-4.95s-.01-3.67-.07-4.95c-.2-4.35-2.63-6.78-6.98-6.98C15.67.01 15.26 0 12 0zm0 5.84A6.16 6.16 0 1 0 18.16 12 6.16 6.16 0 0 0 12 5.84zM12 16a4 4 0 1 1 4-4 4 4 0 0 1-4 4zm6.4-11.85a1.44 1.44 0 1 0 1.44 1.44 1.44 1.44 0 0 0-1.44-1.44z"/></svg>
        Instagram
      </div>
      <div class="platform-pill tk" id="pillTk">
        <svg viewBox="0 0 24 24" fill="currentColor"><path d="M19.59 6.69a4.83 4.83 0 0 1-3.77-4.25V2h-3.45v13.67a2.89 2.89 0 0 1-2.88 2.5 2.89 2.89 0 0 1-2.89-2.89 2.89 2.89 0 0 1 2.89-2.89c.28 0 .54.04.79.1v-3.5a6.37 6.37 0 0 0-.79-.05A6.34 6.34 0 0 0 3.15 15a6.34 6.34 0 0 0 6.34 6.34 6.34 6.34 0 0 0 6.34-6.34V8.1a8.16 8.16 0 0 0 4.76 1.52v-3.4a4.85 4.85 0 0 1-1-.07z"/></svg>
        TikTok
      </div>
      <div class="platform-pill twitch" id="pillTwitch">
        <svg viewBox="0 0 24 24" fill="currentColor"><path d="M11.571 4.714h1.715v5.143H11.57zm4.715 0H18v5.143h-1.714zM6 0L1.714 4.286v15.428h5.143V24l4.286-4.286h3.428L22.286 12V0zm14.571 11.143l-3.428 3.428h-3.429l-3 3v-3H6.857V1.714h13.714z"/></svg>
        Twitch
      </div>
      <div class="platform-pill sc" id="pillSc">
        <svg viewBox="0 0 24 24" fill="currentColor"><path d="M1.175 12.225c-.051 0-.094.046-.101.1l-.233 2.154.233 2.105c.007.058.05.098.101.098.05 0 .09-.04.099-.098l.255-2.105-.27-2.154c-.009-.06-.05-.1-.1-.1m-.899.828c-.06 0-.091.037-.104.094L0 14.479l.172 1.308c.013.06.045.094.104.094.057 0 .09-.037.104-.093l.2-1.31-.2-1.326c-.014-.057-.047-.094-.104-.094m1.81-1.153c-.074 0-.12.06-.12.135l-.217 2.443.217 2.36c0 .074.046.135.12.135.073 0 .119-.06.119-.135l.241-2.36-.241-2.443c0-.075-.046-.135-.12-.135m.943-.424c-.074 0-.135.065-.143.14l-.2 2.866.2 2.775c.008.074.07.14.143.14.074 0 .135-.066.143-.14l.227-2.775-.227-2.866c-.008-.075-.07-.14-.143-.14m.975-.263c-.09 0-.158.074-.158.166l-.176 3.13.176 2.992c0 .09.067.165.158.165.09 0 .157-.074.165-.165l.2-2.993-.2-3.13c-.008-.09-.074-.165-.165-.165m1.02-.296c-.1 0-.18.082-.18.182l-.156 3.427.156 3.083c0 .1.08.182.18.182.098 0 .178-.082.186-.182l.176-3.083-.176-3.427c-.008-.1-.088-.182-.186-.182m1.057-.191c-.112 0-.2.09-.2.2l-.143 3.618.143 3.14c0 .112.088.2.2.2.111 0 .2-.088.2-.2l.159-3.14-.16-3.618c0-.111-.088-.2-.2-.2m1.099.018c-.12 0-.217.098-.217.218l-.118 3.4.118 3.167c0 .12.097.217.217.217s.217-.097.217-.217l.131-3.167-.131-3.4c0-.12-.097-.218-.217-.218m1.123-.473c-.133 0-.24.108-.24.24l-.1 3.855.1 3.208c0 .134.107.241.24.241s.24-.107.24-.24l.114-3.21-.114-3.854c0-.133-.107-.241-.24-.241m1.14-.12c-.146 0-.26.116-.26.262l-.085 3.975.085 3.233c0 .146.114.262.26.262.144 0 .26-.116.26-.262l.096-3.233-.096-3.975c0-.146-.116-.262-.26-.262m1.175-.213c-.158 0-.283.126-.283.283l-.07 4.188.07 3.246c0 .158.126.283.283.283.158 0 .283-.126.283-.283l.078-3.246-.078-4.188c0-.157-.125-.283-.283-.283m1.21-.362c-.17 0-.307.137-.307.307l-.053 4.55.053 3.253c0 .17.138.307.308.307.17 0 .307-.137.307-.307l.06-3.253-.06-4.55c0-.17-.137-.307-.307-.307m1.251.065c-.183 0-.33.148-.33.33l-.04 4.154.04 3.265c0 .183.147.33.33.33.182 0 .33-.147.33-.33l.044-3.265-.044-4.154c0-.182-.148-.33-.33-.33m1.281-.29c-.197 0-.354.158-.354.354l-.025 4.444.025 3.27c0 .196.157.353.354.353.195 0 .353-.157.353-.353l.028-3.27-.028-4.443c0-.197-.158-.355-.353-.355m1.318-.133c-.208 0-.375.168-.375.375l-.01 4.577.01 3.273c0 .208.167.375.375.375.209 0 .375-.167.375-.375l.012-3.273-.012-4.577c0-.207-.166-.375-.375-.375m3.472 2.168c-.26 0-.5.057-.727.156a3.055 3.055 0 0 0-3.057-2.884c-.21 0-.415.025-.612.074-.132.03-.165.073-.165.145v5.784c0 .076.06.14.135.148h4.426a2.17 2.17 0 0 0 2.17-2.172 2.17 2.17 0 0 0-2.17-2.251z"/></svg>
        SoundCloud
      </div>
    </div>
  </header>

  <div class="app-columns">

    <!-- ═══ LEFT COLUMN: Editor ═══ -->
    <div class="col-editor">

      <!-- URL Input -->
      <div class="panel">
        <label class="panel-label" for="urlInput"><span class="dot"></span> Source</label>
        <div class="url-group">
          <input type="text" class="url-input" id="urlInput"
                 placeholder="Paste a YouTube, Twitter, Instagram, TikTok, Twitch, or SoundCloud URL..."
                 spellcheck="false" autocomplete="off">
          <button type="button" class="btn-load" id="btnLoad" onclick="loadVideo()">Load</button>
        </div>
        <div class="error-msg" id="urlError"></div>
      </div>

      <!-- Video Preview -->
      <div class="panel preview-section" id="previewSection">
        <div class="panel-label"><span class="dot"></span> Preview</div>
        <div class="platform-badge" id="platformBadge"></div>
        <div class="video-meta">
          <img class="video-thumb" id="videoThumb" src="" alt="">
          <div class="video-info">
            <h3 id="videoTitle"></h3>
            <div class="channel" id="videoChannel"></div>
            <div class="duration-badge" id="videoDuration"></div>
          </div>
        </div>
        <div class="player-wrap" id="playerWrap">
          <iframe id="ytPlayer" src="" allow="autoplay; encrypted-media" allowfullscreen sandbox="allow-scripts allow-same-origin allow-popups"></iframe>
        </div>
      </div>

      <!-- Mode Toggle -->
      <div class="mode-toggle" id="modeToggle">
        <button type="button" class="mode-btn active" id="modeDownload" onclick="setMode('download')">Download Full</button>
        <button type="button" class="mode-btn" id="modeTrim" onclick="setMode('trim')">Trim & Download</button>
      </div>

      <!-- Quality/Format Picker -->
      <div class="quality-section" id="qualitySection">
        <div class="quality-row">
          <span class="quality-label">Quality</span>
          <div class="quality-group" id="qualityGroup">
            <button type="button" class="quality-pill" data-q="360p">360p</button>
            <button type="button" class="quality-pill" data-q="480p">480p</button>
            <button type="button" class="quality-pill active" data-q="720p">720p</button>
            <button type="button" class="quality-pill" data-q="1080p">1080p</button>
            <button type="button" class="quality-pill" data-q="best">Best</button>
          </div>
        </div>
        <div class="quality-row">
          <span class="quality-label">Format</span>
          <div class="quality-group" id="formatGroup">
            <button type="button" class="format-pill active" data-f="mp4">MP4</button>
            <button type="button" class="format-pill" data-f="webm">WebM</button>
            <button type="button" class="format-pill" data-f="mp3">MP3</button>
          </div>
        </div>
      </div>

      <!-- Timeline (trim mode) -->
      <div class="panel timeline-section" id="timelineSection">
        <div class="panel-label"><span class="dot"></span> Trim Range</div>
        <div class="time-controls">
          <div class="time-field">
            <label for="startInput">Start Time</label>
            <input type="text" id="startInput" value="0:00" placeholder="0:00">
          </div>
          <div class="time-field">
            <label for="endInput">End Time</label>
            <input type="text" id="endInput" value="0:00" placeholder="0:00">
          </div>
        </div>
        <div class="timeline-track" id="timelineTrack">
          <div class="timeline-waveform" id="waveform"></div>
          <div class="timeline-region" id="timelineRegion"></div>
          <div class="timeline-handle" id="handleStart" style="left: 0%" tabindex="0" role="slider" aria-label="Trim start" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"></div>
          <div class="timeline-handle" id="handleEnd" style="left: 100%" tabindex="0" role="slider" aria-label="Trim end" aria-valuemin="0" aria-valuemax="100" aria-valuenow="100"></div>
        </div>
        <div class="timeline-labels">
          <span>0:00</span>
          <span id="totalDurationLabel">0:00</span>
        </div>
        <div class="clip-duration">Clip length: <span id="clipDuration">0:00</span></div>
      </div>

      <!-- Action Button -->
      <div class="action-section" id="actionSection">
        <button type="button" class="btn-action" id="btnAction" onclick="startAction()">
          Download Video
        </button>
        <div class="limit-note" id="limitNote"></div>
        <div class="error-msg" id="trimError"></div>
      </div>

      <!-- Progress -->
      <div class="panel progress-section" id="progressSection">
        <div class="panel-label"><span class="dot"></span> Processing</div>
        <div class="progress-bar-track">
          <div class="progress-bar-fill" id="progressFill"></div>
        </div>
        <div class="progress-status" id="progressStatus">
          <span class="spinner"></span> Downloading video...
        </div>
      </div>

      <!-- Download + Save Dialog -->
      <div class="panel download-section" id="downloadSection">
        <div class="download-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
            <polyline points="7 10 12 15 17 10"/>
            <line x1="12" y1="15" x2="12" y2="3"/>
          </svg>
        </div>
        <div class="success-text">Your video is ready!</div>
        <p style="color:var(--text-muted);font-size:0.9rem;margin-bottom:0.75rem" id="downloadInfo"></p>
        <a class="btn-download" id="btnDownload" href="#">Download MP4</a>
        <br>
        <button type="button" class="btn-save-library" id="btnSaveLibrary" onclick="openSaveDialog()">Save to Library</button>

        <!-- Save Dialog -->
        <div class="save-dialog" id="saveDialog">
          <label for="saveTitleInput">Title</label>
          <input type="text" id="saveTitleInput" placeholder="Clip title..." maxlength="200">

          <label>Tags <span style="font-size:0.7rem;font-weight:400;color:var(--text-muted)">(Enter to add, max 10)</span></label>
          <div class="tag-input-wrap" id="tagInputWrap" onclick="document.getElementById('tagField').focus()">
            <input type="text" class="tag-input-field" id="tagField" placeholder="Add a tag...">
          </div>

          <div class="save-dialog-actions">
            <button type="button" class="btn-confirm-save" id="btnConfirmSave" onclick="saveToLibrary()">Confirm & Save</button>
            <button type="button" class="btn-cancel-save" onclick="closeSaveDialog()">Cancel</button>
          </div>
        </div>

        <br>
        <button type="button" class="reset-link" onclick="resetAll()">Download another video</button>
      </div>

    </div><!-- /col-editor -->

    <!-- ═══ RIGHT COLUMN: Library ═══ -->
    <div class="col-library">
      <div class="panel library-section" id="librarySection">
        <div class="panel-label"><span class="dot"></span> My Library</div>

        <div class="library-toolbar">
          <input type="text" class="library-search" id="librarySearch" placeholder="Search clips by title or tag..." oninput="applyLibraryView()">
          <div class="library-filters" id="libraryFilters">
            <button type="button" class="filter-pill active" onclick="setFilter('all')">All</button>
            <button type="button" class="filter-pill" onclick="setFilter('youtube')">YouTube</button>
            <button type="button" class="filter-pill" onclick="setFilter('twitter')">Twitter</button>
            <button type="button" class="filter-pill" onclick="setFilter('instagram')">Instagram</button>
            <button type="button" class="filter-pill" onclick="setFilter('tiktok')">TikTok</button>
            <button type="button" class="filter-pill" onclick="setFilter('twitch')">Twitch</button>
            <button type="button" class="filter-pill" onclick="setFilter('soundcloud')">SoundCloud</button>
          </div>
          <div class="library-sort-row">
            <select class="library-sort" id="librarySort" onchange="applyLibraryView()">
              <option value="newest">Newest</option>
              <option value="oldest">Oldest</option>
              <option value="largest">Largest</option>
              <option value="smallest">Smallest</option>
            </select>
            <button type="button" class="btn-select-all" id="btnSelectAll" onclick="toggleSelectAll()">Select All</button>
          </div>
        </div>

        <div class="library-stats" id="libraryStats"></div>
        <div class="library-grid" id="libraryGrid">
          <div class="library-empty" id="libraryEmpty">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="width:40px;height:40px;color:var(--text-muted);margin-bottom:0.75rem">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
            </svg>
            <p>No saved clips yet</p>
            <p style="font-size:0.8rem;color:var(--text-muted);margin-top:0.25rem">Download or trim a video and save it to your library</p>
          </div>
        </div>

        <button type="button" class="btn-load-more" id="btnLoadMore" onclick="loadMoreClips()">Load more</button>

        <!-- Bulk Action Bar -->
        <div class="bulk-bar" id="bulkBar">
          <span class="bulk-bar-info" id="bulkBarInfo">0 selected</span>
          <div class="bulk-bar-actions">
            <button type="button" class="bulk-btn bulk-btn-download" onclick="bulkDownload()">Download</button>
            <button type="button" class="bulk-btn bulk-btn-delete" onclick="bulkDelete()">Delete</button>
          </div>
        </div>
      </div>
    </div><!-- /col-library -->

  </div><!-- /app-columns -->

</div>

<!-- Edit Modal -->
<div class="edit-modal-overlay" id="editModalOverlay" onclick="if(event.target===this)closeEditModal()">
  <div class="edit-modal">
    <h3>Edit Clip</h3>
    <input type="hidden" id="editClipId">
    <label for="editTitleInput">Title</label>
    <input type="text" id="editTitleInput" placeholder="Clip title..." maxlength="200">
    <label>Tags <span style="font-size:0.7rem;font-weight:400;color:var(--text-muted)">(Enter to add)</span></label>
    <div class="tag-input-wrap" id="editTagInputWrap" onclick="document.getElementById('editTagField').focus()">
      <input type="text" class="tag-input-field" id="editTagField" placeholder="Add a tag...">
    </div>
    <div class="edit-modal-actions">
      <button type="button" class="btn-confirm-save" onclick="saveEdit()">Save Changes</button>
      <button type="button" class="btn-cancel-save" onclick="closeEditModal()">Cancel</button>
    </div>
  </div>
</div>

<!-- Auth Modal -->
<div class="auth-modal-overlay" id="authModalOverlay" onclick="if(event.target===this)closeAuthModal()">
  <div class="auth-modal">
    <h3 id="authModalTitle">Log In</h3>
    <input type="email" class="auth-input" id="authEmail" placeholder="Email address">
    <input type="password" class="auth-input" id="authPassword" placeholder="Password">
    <div class="auth-error" id="authError"></div>
    <button type="button" class="auth-submit" id="authSubmit" onclick="submitAuth()">Log In</button>
    <div class="auth-toggle">
      <span id="authToggleText">Don't have an account?</span>
      <a id="authToggleLink" onclick="toggleAuthMode()">Sign up</a>
    </div>
  </div>
</div>

<!-- Toast Container -->
<div class="toast-container" id="toastContainer"></div>

<script>
let videoDuration = 0;
let videoId = '';
let currentPlatform = '';
let currentMode = 'download';
let dragging = null;

// Quality/format state
let currentQuality = '720p';
let currentFormat = 'mp4';

// Library state
let allClips = [];
let currentFilter = 'all';
let selectedClipIds = new Set();
let saveTags = [];
let editTags = [];
let libraryPage = 1;
let libraryHasMore = false;

// Auth state
let authMode = 'login'; // 'login' or 'signup'

const PLATFORM_LABELS = {
  youtube:    'YouTube',
  twitter:    'Twitter / X',
  instagram:  'Instagram',
  tiktok:     'TikTok',
  twitch:     'Twitch',
  soundcloud: 'SoundCloud',
};

const PLATFORM_ICONS = {
  youtube:   '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M23.5 6.2a3 3 0 0 0-2.1-2.1C19.5 3.5 12 3.5 12 3.5s-7.5 0-9.4.6A3 3 0 0 0 .5 6.2 31.4 31.4 0 0 0 0 12a31.4 31.4 0 0 0 .5 5.8 3 3 0 0 0 2.1 2.1c1.9.5 9.4.5 9.4.5s7.5 0 9.4-.6a3 3 0 0 0 2.1-2.1A31.4 31.4 0 0 0 24 12a31.4 31.4 0 0 0-.5-5.8zM9.6 15.5V8.5l6.3 3.5-6.3 3.5z"/></svg>',
  twitter:   '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>',
  instagram: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2.16c3.2 0 3.58.01 4.85.07 3.25.15 4.77 1.69 4.92 4.92.06 1.27.07 1.65.07 4.85s-.01 3.58-.07 4.85c-.15 3.23-1.66 4.77-4.92 4.92-1.27.06-1.65.07-4.85.07s-3.58-.01-4.85-.07c-3.26-.15-4.77-1.7-4.92-4.92-.06-1.27-.07-1.65-.07-4.85s.01-3.58.07-4.85C2.38 3.86 3.9 2.31 7.15 2.23 8.42 2.17 8.8 2.16 12 2.16zM12 0C8.74 0 8.33.01 7.05.07 2.7.27.27 2.7.07 7.05.01 8.33 0 8.74 0 12s.01 3.67.07 4.95c.2 4.36 2.62 6.78 6.98 6.98C8.33 23.99 8.74 24 12 24s3.67-.01 4.95-.07c4.35-.2 6.78-2.62 6.98-6.98.06-1.28.07-1.69.07-4.95s-.01-3.67-.07-4.95c-.2-4.35-2.63-6.78-6.98-6.98C15.67.01 15.26 0 12 0zm0 5.84A6.16 6.16 0 1 0 18.16 12 6.16 6.16 0 0 0 12 5.84zM12 16a4 4 0 1 1 4-4 4 4 0 0 1-4 4zm6.4-11.85a1.44 1.44 0 1 0 1.44 1.44 1.44 1.44 0 0 0-1.44-1.44z"/></svg>',
  tiktok:    '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M19.59 6.69a4.83 4.83 0 0 1-3.77-4.25V2h-3.45v13.67a2.89 2.89 0 0 1-2.88 2.5 2.89 2.89 0 0 1-2.89-2.89 2.89 2.89 0 0 1 2.89-2.89c.28 0 .54.04.79.1v-3.5a6.37 6.37 0 0 0-.79-.05A6.34 6.34 0 0 0 3.15 15a6.34 6.34 0 0 0 6.34 6.34 6.34 6.34 0 0 0 6.34-6.34V8.1a8.16 8.16 0 0 0 4.76 1.52v-3.4a4.85 4.85 0 0 1-1-.07z"/></svg>',
  twitch:    '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M11.571 4.714h1.715v5.143H11.57zm4.715 0H18v5.143h-1.714zM6 0L1.714 4.286v15.428h5.143V24l4.286-4.286h3.428L22.286 12V0zm14.571 11.143l-3.428 3.428h-3.429l-3 3v-3H6.857V1.714h13.714z"/></svg>',
  soundcloud:'<svg viewBox="0 0 24 24" fill="currentColor"><path d="M1.175 12.225c-.051 0-.094.046-.101.1l-.233 2.154.233 2.105c.007.058.05.098.101.098.05 0 .09-.04.099-.098l.255-2.105-.27-2.154c-.009-.06-.05-.1-.1-.1m-.899.828c-.06 0-.091.037-.104.094L0 14.479l.172 1.308c.013.06.045.094.104.094.057 0 .09-.037.104-.093l.2-1.31-.2-1.326c-.014-.057-.047-.094-.104-.094m1.81-1.153c-.074 0-.12.06-.12.135l-.217 2.443.217 2.36c0 .074.046.135.12.135.073 0 .119-.06.119-.135l.241-2.36-.241-2.443c0-.075-.046-.135-.12-.135m.943-.424c-.074 0-.135.065-.143.14l-.2 2.866.2 2.775c.008.074.07.14.143.14.074 0 .135-.066.143-.14l.227-2.775-.227-2.866c-.008-.075-.07-.14-.143-.14m.975-.263c-.09 0-.158.074-.158.166l-.176 3.13.176 2.992c0 .09.067.165.158.165.09 0 .157-.074.165-.165l.2-2.993-.2-3.13c-.008-.09-.074-.165-.165-.165m1.02-.296c-.1 0-.18.082-.18.182l-.156 3.427.156 3.083c0 .1.08.182.18.182.098 0 .178-.082.186-.182l.176-3.083-.176-3.427c-.008-.1-.088-.182-.186-.182m1.057-.191c-.112 0-.2.09-.2.2l-.143 3.618.143 3.14c0 .112.088.2.2.2.111 0 .2-.088.2-.2l.159-3.14-.16-3.618c0-.111-.088-.2-.2-.2m1.099.018c-.12 0-.217.098-.217.218l-.118 3.4.118 3.167c0 .12.097.217.217.217s.217-.097.217-.217l.131-3.167-.131-3.4c0-.12-.097-.218-.217-.218m1.123-.473c-.133 0-.24.108-.24.24l-.1 3.855.1 3.208c0 .134.107.241.24.241s.24-.107.24-.24l.114-3.21-.114-3.854c0-.133-.107-.241-.24-.241m1.14-.12c-.146 0-.26.116-.26.262l-.085 3.975.085 3.233c0 .146.114.262.26.262.144 0 .26-.116.26-.262l.096-3.233-.096-3.975c0-.146-.116-.262-.26-.262m1.175-.213c-.158 0-.283.126-.283.283l-.07 4.188.07 3.246c0 .158.126.283.283.283.158 0 .283-.126.283-.283l.078-3.246-.078-4.188c0-.157-.125-.283-.283-.283m1.21-.362c-.17 0-.307.137-.307.307l-.053 4.55.053 3.253c0 .17.138.307.308.307.17 0 .307-.137.307-.307l.06-3.253-.06-4.55c0-.17-.137-.307-.307-.307m1.251.065c-.183 0-.33.148-.33.33l-.04 4.154.04 3.265c0 .183.147.33.33.33.182 0 .33-.147.33-.33l.044-3.265-.044-4.154c0-.182-.148-.33-.33-.33m1.281-.29c-.197 0-.354.158-.354.354l-.025 4.444.025 3.27c0 .196.157.353.354.353.195 0 .353-.157.353-.353l.028-3.27-.028-4.443c0-.197-.158-.355-.353-.355m1.318-.133c-.208 0-.375.168-.375.375l-.01 4.577.01 3.273c0 .208.167.375.375.375.209 0 .375-.167.375-.375l.012-3.273-.012-4.577c0-.207-.166-.375-.375-.375m3.472 2.168c-.26 0-.5.057-.727.156a3.055 3.055 0 0 0-3.057-2.884c-.21 0-.415.025-.612.074-.132.03-.165.073-.165.145v5.784c0 .076.06.14.135.148h4.426a2.17 2.17 0 0 0 2.17-2.172 2.17 2.17 0 0 0-2.17-2.251z"/></svg>',
};

// ── Detect platform from URL ────────────────
function detectPlatform(url) {
  url = url.toLowerCase();
  if (/youtube\.com|youtu\.be/.test(url)) return 'youtube';
  if (/twitter\.com|x\.com/.test(url)) return 'twitter';
  if (/instagram\.com/.test(url)) return 'instagram';
  if (/tiktok\.com|vm\.tiktok/.test(url)) return 'tiktok';
  if (/twitch\.tv/.test(url)) return 'twitch';
  if (/soundcloud\.com/.test(url)) return 'soundcloud';
  return null;
}

// ── Highlight platform pill on input ────────
document.getElementById('urlInput').addEventListener('input', function() {
  const p = detectPlatform(this.value);
  document.querySelectorAll('.platform-pill').forEach(el => el.classList.remove('active'));
  if (p === 'youtube') document.getElementById('pillYt').classList.add('active');
  else if (p === 'twitter') document.getElementById('pillTw').classList.add('active');
  else if (p === 'instagram') document.getElementById('pillIg').classList.add('active');
  else if (p === 'tiktok') document.getElementById('pillTk').classList.add('active');
  else if (p === 'twitch') document.getElementById('pillTwitch').classList.add('active');
  else if (p === 'soundcloud') document.getElementById('pillSc').classList.add('active');
  // Auto-select MP3 for SoundCloud
  if (p === 'soundcloud') {
    currentFormat = 'mp3';
    updateFormatPills();
  }
});

// ── Load Video ──────────────────────────────
async function loadVideo() {
  const url = document.getElementById('urlInput').value.trim();
  const btn = document.getElementById('btnLoad');
  document.getElementById('urlError').classList.remove('visible');

  if (!url) { showError('urlError', 'Please paste a video URL.'); return; }

  const platform = detectPlatform(url);
  if (!platform) {
    showError('urlError', 'Unsupported URL. Paste a YouTube, Twitter/X, Instagram, TikTok, Twitch, or SoundCloud link.');
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Loading...';

  try {
    const resp = await fetch('/api/video-info', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    const data = await resp.json();

    if (!resp.ok) { showError('urlError', data.error || 'Failed to load video.'); return; }

    currentPlatform = data.platform || platform;
    videoId = data.id;
    videoDuration = data.duration || 0;

    // Platform badge
    const badge = document.getElementById('platformBadge');
    badge.className = `platform-badge visible ${currentPlatform}`;
    badge.textContent = '';
    const iconHtml = PLATFORM_ICONS[currentPlatform];
    if (iconHtml) {
      const iconWrapper = document.createElement('span');
      iconWrapper.innerHTML = iconHtml;  // safe: hardcoded SVG constants only
      badge.appendChild(iconWrapper);
    }
    const labelSpan = document.createElement('span');
    labelSpan.textContent = PLATFORM_LABELS[currentPlatform] || currentPlatform;
    badge.appendChild(labelSpan);

    // Video meta
    document.getElementById('videoThumb').src = data.thumbnail || '';
    document.getElementById('videoThumb').alt = 'Thumbnail for ' + (data.title || 'video');
    document.getElementById('videoTitle').textContent = data.title || 'Untitled';
    document.getElementById('videoChannel').textContent = data.channel || '';
    document.getElementById('videoDuration').textContent = videoDuration ? formatTime(videoDuration) : 'N/A';

    // Player — only YouTube gets embed
    const playerWrap = document.getElementById('playerWrap');
    const ytPlayer = document.getElementById('ytPlayer');
    const safeVideoId = /^[a-zA-Z0-9_-]{11}$/.test(videoId) ? videoId : null;
    if (currentPlatform === 'youtube' && safeVideoId) {
      ytPlayer.src = `https://www.youtube.com/embed/${safeVideoId}?rel=0&modestbranding=1`;
      ytPlayer.style.display = '';
      const noEmbed = playerWrap.querySelector('.no-embed');
      if (noEmbed) noEmbed.remove();
    } else {
      ytPlayer.style.display = 'none';
      ytPlayer.src = '';
      let noEmbed = playerWrap.querySelector('.no-embed');
      if (!noEmbed) {
        noEmbed = document.createElement('div');
        noEmbed.className = 'no-embed';
        playerWrap.appendChild(noEmbed);
      }
      noEmbed.textContent = `Preview not available for ${PLATFORM_LABELS[currentPlatform]}. Use the original link to preview.`;
    }

    // Timeline defaults
    document.getElementById('startInput').value = '0:00';
    document.getElementById('endInput').value = videoDuration ? formatTime(videoDuration) : '0:00';
    document.getElementById('totalDurationLabel').textContent = videoDuration ? formatTime(videoDuration) : '0:00';
    document.getElementById('clipDuration').textContent = videoDuration ? formatTime(videoDuration) : '0:00';

    // Show sections
    document.getElementById('previewSection').classList.add('visible');
    document.getElementById('modeToggle').classList.add('visible');
    document.getElementById('qualitySection').classList.add('visible');
    document.getElementById('actionSection').classList.add('visible');

    // Default mode: download for short videos / non-YT, trim for YT
    if (currentPlatform === 'youtube' && videoDuration > 30) {
      setMode('trim');
    } else {
      setMode('download');
    }

    generateWaveform();
    updateTimeline();
  } catch (e) {
    showError('urlError', 'Network error — is the server running?');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Load';
  }
}

// ── Mode toggle ─────────────────────────────
function setMode(mode) {
  currentMode = mode;
  document.getElementById('modeDownload').classList.toggle('active', mode === 'download');
  document.getElementById('modeTrim').classList.toggle('active', mode === 'trim');

  const btn = document.getElementById('btnAction');
  const note = document.getElementById('limitNote');

  if (mode === 'trim') {
    document.getElementById('timelineSection').classList.add('visible');
    btn.textContent = 'Trim & Download';
    note.textContent = 'Max clip length: 10 minutes';

    // Hide trim option if no duration
    if (!videoDuration) {
      showError('trimError', 'Trim not available — video duration unknown.');
      setMode('download');
      return;
    }
  } else {
    document.getElementById('timelineSection').classList.remove('visible');
    btn.textContent = 'Download Video';
    note.textContent = '';
  }
}

// ── Timeline ────────────────────────────────
function generateWaveform() {
  const container = document.getElementById('waveform');
  container.innerHTML = '';
  for (let i = 0; i < 120; i++) {
    const bar = document.createElement('div');
    bar.className = 'bar';
    bar.style.height = (8 + Math.random() * 30) + 'px';
    container.appendChild(bar);
  }
}

function updateTimeline() {
  if (!videoDuration) return;
  const startSec = parseTime(document.getElementById('startInput').value);
  const endSec = parseTime(document.getElementById('endInput').value);
  const startPct = (startSec / videoDuration) * 100;
  const endPct = (endSec / videoDuration) * 100;

  document.getElementById('timelineRegion').style.left = startPct + '%';
  document.getElementById('timelineRegion').style.width = (endPct - startPct) + '%';
  document.getElementById('handleStart').style.left = `calc(${startPct}% - 7px)`;
  document.getElementById('handleEnd').style.left = `calc(${endPct}% - 7px)`;
  document.getElementById('clipDuration').textContent = formatTime(Math.max(0, endSec - startSec));
}

['handleStart', 'handleEnd'].forEach(id => {
  const el = document.getElementById(id);
  el.addEventListener('mousedown', e => { e.preventDefault(); dragging = id; });
  el.addEventListener('touchstart', e => { dragging = id; }, { passive: true });
});

function handleMove(clientX) {
  if (!dragging) return;
  const track = document.getElementById('timelineTrack');
  const rect = track.getBoundingClientRect();
  let pct = Math.max(0, Math.min(100, ((clientX - rect.left) / rect.width) * 100));
  const sec = (pct / 100) * videoDuration;

  if (dragging === 'handleStart') {
    document.getElementById('startInput').value = formatTime(Math.floor(sec));
  } else {
    document.getElementById('endInput').value = formatTime(Math.floor(sec));
  }
  updateTimeline();
}

document.addEventListener('mousemove', e => handleMove(e.clientX));
document.addEventListener('touchmove', e => handleMove(e.touches[0].clientX), { passive: true });
document.addEventListener('mouseup', () => { dragging = null; });
document.addEventListener('touchend', () => { dragging = null; });
// Keyboard support for timeline handles
['handleStart', 'handleEnd'].forEach(id => {
  document.getElementById(id).addEventListener('keydown', e => {
    if (!videoDuration) return;
    const step = e.shiftKey ? 10 : 1;  // hold Shift for 10s steps
    const inputId = id === 'handleStart' ? 'startInput' : 'endInput';
    let sec = parseTime(document.getElementById(inputId).value);
    if (e.key === 'ArrowRight' || e.key === 'ArrowUp') {
      e.preventDefault();
      sec = Math.min(sec + step, videoDuration);
      document.getElementById(inputId).value = formatTime(sec);
      updateTimeline();
    } else if (e.key === 'ArrowLeft' || e.key === 'ArrowDown') {
      e.preventDefault();
      sec = Math.max(sec - step, 0);
      document.getElementById(inputId).value = formatTime(sec);
      updateTimeline();
    }
  });
});

document.getElementById('startInput').addEventListener('input', updateTimeline);
document.getElementById('endInput').addEventListener('input', updateTimeline);

// ── Action (Download or Trim) ───────────────
async function startAction() {
  const url = document.getElementById('urlInput').value.trim();
  const errEl = document.getElementById('trimError');
  errEl.classList.remove('visible');

  const btn = document.getElementById('btnAction');
  btn.disabled = true;
  document.getElementById('progressSection').classList.add('visible');
  document.getElementById('actionSection').classList.remove('visible');

  let endpoint, body, infoText;

  if (currentMode === 'trim') {
    const start = document.getElementById('startInput').value.trim();
    const end = document.getElementById('endInput').value.trim();

    if (parseTime(end) <= parseTime(start)) {
      showError('trimError', 'End time must be after start time.');
      restoreAction();
      return;
    }
    if (parseTime(end) - parseTime(start) > 600) {
      showError('trimError', 'Clips are limited to 10 minutes max.');
      restoreAction();
      return;
    }

    endpoint = '/api/trim';
    body = { url, start, end, quality: currentQuality, format: currentFormat };
    infoText = `Trimmed from ${start} to ${end}`;
    document.getElementById('progressStatus').innerHTML =
      '<span class="spinner"></span> Downloading & trimming your clip...';
  } else {
    endpoint = '/api/download-full';
    body = { url, quality: currentQuality, format: currentFormat };
    infoText = `Full video from ${PLATFORM_LABELS[currentPlatform] || 'source'}`;
    document.getElementById('progressStatus').innerHTML =
      '<span class="spinner"></span> Downloading video...';
  }

  try {
    const resp = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!resp.ok) {
      let errMsg = 'Download failed.';
      try { const d = await resp.json(); errMsg = d.error || errMsg; } catch {}
      throw new Error(errMsg);
    }

    const blob = await resp.blob();

    // Revoke previous blob URL if any
    const dlBtn = document.getElementById('btnDownload');
    if (dlBtn.href && dlBtn.href.startsWith('blob:')) {
      URL.revokeObjectURL(dlBtn.href);
    }

    const downloadUrl = URL.createObjectURL(blob);

    // Detect file extension from Content-Disposition or fallback to .mp4
    let fileExt = '.mp4';
    const disposition = resp.headers.get('Content-Disposition');
    if (disposition) {
      const match = disposition.match(/filename="?[^"]*(\.\w+)"?/);
      if (match) fileExt = match[1];
    }

    document.getElementById('progressSection').classList.remove('visible');
    document.getElementById('downloadInfo').textContent = infoText;
    dlBtn.href = downloadUrl;
    dlBtn.setAttribute('download',
      `${currentPlatform}_${videoId || 'video'}${fileExt}`);
    dlBtn.textContent = `Download ${fileExt.replace('.', '').toUpperCase()}`;
    document.getElementById('downloadSection').classList.add('visible');

  } catch (e) {
    showError('trimError', e.message);
    restoreAction();
  }
}

function restoreAction() {
  document.getElementById('progressSection').classList.remove('visible');
  document.getElementById('actionSection').classList.add('visible');
  document.getElementById('btnAction').disabled = false;
}

function resetAll() {
  // Revoke blob URL to free memory
  const dlBtn = document.getElementById('btnDownload');
  if (dlBtn.href && dlBtn.href.startsWith('blob:')) {
    URL.revokeObjectURL(dlBtn.href);
  }
  dlBtn.href = '#';
  dlBtn.textContent = 'Download MP4';

  // Reset save button + dialog
  const saveBtn = document.getElementById('btnSaveLibrary');
  saveBtn.disabled = false;
  saveBtn.textContent = 'Save to Library';
  saveBtn.classList.remove('saved');
  saveBtn.style.display = '';
  closeSaveDialog();
  const confirmBtn = document.getElementById('btnConfirmSave');
  confirmBtn.disabled = false;
  confirmBtn.textContent = 'Confirm & Save';
  saveTags = [];

  ['previewSection','timelineSection','actionSection','progressSection','downloadSection'].forEach(id =>
    document.getElementById(id).classList.remove('visible'));
  document.getElementById('modeToggle').classList.remove('visible');
  document.getElementById('qualitySection').classList.remove('visible');
  document.getElementById('urlInput').value = '';
  document.getElementById('urlInput').focus();
  document.getElementById('btnAction').disabled = false;
  document.querySelectorAll('.platform-pill').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.error-msg').forEach(el => el.classList.remove('visible'));
  videoDuration = 0;
  videoId = '';
  currentPlatform = '';
  currentMode = 'download';
  currentQuality = '720p';
  currentFormat = 'mp4';
  updateQualityPills();
  updateFormatPills();
}

// ── Utilities ───────────────────────────────
function formatTime(sec) {
  sec = Math.max(0, Math.round(sec));
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  if (h > 0) return h + ':' + String(m).padStart(2, '0') + ':' + String(s).padStart(2, '0');
  return m + ':' + String(s).padStart(2, '0');
}

function parseTime(str) {
  const parts = str.split(':').map(Number);
  if (parts.some(isNaN)) return 0;
  if (parts.length === 3) return parts[0] * 3600 + parts[1] * 60 + (parts[2] || 0);
  if (parts.length === 2) return parts[0] * 60 + (parts[1] || 0);
  return 0;
}

function showError(id, msg) {
  const el = document.getElementById(id);
  el.textContent = msg;
  el.classList.add('visible');
}

document.getElementById('urlInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') loadVideo();
});

// ── Save Dialog ─────────────────────────────

function openSaveDialog() {
  const dialog = document.getElementById('saveDialog');
  const titleInput = document.getElementById('saveTitleInput');
  titleInput.value = document.getElementById('videoTitle').textContent || '';
  saveTags = [];
  renderSaveTags();
  dialog.classList.add('visible');
  document.getElementById('btnSaveLibrary').style.display = 'none';
  titleInput.focus();
}

function closeSaveDialog() {
  document.getElementById('saveDialog').classList.remove('visible');
  document.getElementById('btnSaveLibrary').style.display = '';
}

function renderSaveTags() {
  const wrap = document.getElementById('tagInputWrap');
  wrap.querySelectorAll('.tag-chip').forEach(el => el.remove());
  const field = document.getElementById('tagField');
  saveTags.forEach((tag, i) => {
    const chip = document.createElement('span');
    chip.className = 'tag-chip';
    chip.innerHTML = escapeHtml(tag) + '<span class="tag-remove">&times;</span>';
    chip.querySelector('.tag-remove').onclick = () => { saveTags.splice(i, 1); renderSaveTags(); };
    wrap.insertBefore(chip, field);
  });
}

document.getElementById('tagField').addEventListener('keydown', function(e) {
  if ((e.key === 'Enter' || e.key === ',') && this.value.trim()) {
    e.preventDefault();
    const tag = this.value.trim().replace(/,/g, '').substring(0, 30);
    if (tag && saveTags.length < 10 && !saveTags.includes(tag)) {
      saveTags.push(tag);
      renderSaveTags();
    }
    this.value = '';
  }
  if (e.key === 'Backspace' && !this.value && saveTags.length > 0) {
    saveTags.pop();
    renderSaveTags();
  }
});

// ── Library ─────────────────────────────────

async function saveToLibrary() {
  const btn = document.getElementById('btnConfirmSave');
  btn.disabled = true;
  btn.textContent = 'Saving...';

  const url = document.getElementById('urlInput').value.trim();
  const customTitle = document.getElementById('saveTitleInput').value.trim() || 'Untitled';
  const tagsStr = saveTags.length > 0 ? saveTags.join(',') : null;

  const body = {
    url,
    mode: currentMode,
    title: customTitle,
    platform: currentPlatform,
    thumbnail: document.getElementById('videoThumb').src,
    channel: document.getElementById('videoChannel').textContent,
    duration: videoDuration,
    tags: tagsStr,
    quality: currentQuality,
    format: currentFormat,
  };

  if (currentMode === 'trim') {
    body.start = document.getElementById('startInput').value.trim();
    body.end = document.getElementById('endInput').value.trim();
  }

  try {
    const resp = await authFetch('/api/save-to-library', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await resp.json();

    if (!resp.ok) {
      showToast(data.error || 'Save failed', 'error');
      btn.textContent = 'Save Failed';
      btn.disabled = false;
      setTimeout(() => { btn.textContent = 'Confirm & Save'; }, 2000);
      return;
    }

    closeSaveDialog();
    const saveBtn = document.getElementById('btnSaveLibrary');
    saveBtn.textContent = 'Saved!';
    saveBtn.classList.add('saved');
    saveBtn.style.display = '';
    showToast('Clip saved to library!', 'success');
    loadLibrary();
  } catch (e) {
    showToast('Save failed — network error', 'error');
    btn.textContent = 'Save Failed';
    btn.disabled = false;
    setTimeout(() => { btn.textContent = 'Confirm & Save'; }, 2000);
  }
}

async function loadLibrary(append = false) {
  if (!append) {
    libraryPage = 1;
    // Show cached data immediately
    const cached = localStorage.getItem('clipforge_library');
    if (cached) {
      try {
        allClips = JSON.parse(cached);
        applyLibraryView();
      } catch(e) {}
    } else {
      showLibrarySkeleton();
    }
  }

  try {
    const resp = await authFetch('/api/library?page=' + libraryPage + '&per_page=20');
    const data = await resp.json();
    if (append) {
      allClips = allClips.concat(data.clips || []);
    } else {
      allClips = data.clips || [];
    }
    libraryHasMore = data.has_more || false;
    // Cache
    localStorage.setItem('clipforge_library', JSON.stringify(allClips));
    applyLibraryView();
    // Show/hide load more
    const btn = document.getElementById('btnLoadMore');
    btn.classList.toggle('visible', libraryHasMore);
  } catch (e) {
    // silently fail if network error
  }
}

function loadMoreClips() {
  libraryPage++;
  loadLibrary(true);
}

function showLibrarySkeleton() {
  const grid = document.getElementById('libraryGrid');
  const empty = document.getElementById('libraryEmpty');
  empty.style.display = 'none';
  grid.querySelectorAll('.clip-card, .skeleton-card').forEach(el => el.remove());
  for (let i = 0; i < 4; i++) {
    const sk = document.createElement('div');
    sk.className = 'skeleton-card';
    sk.innerHTML = '<div class="skeleton-thumb"></div><div class="skeleton-line"></div><div class="skeleton-line short"></div>';
    grid.appendChild(sk);
  }
}

function applyLibraryView() {
  const search = (document.getElementById('librarySearch').value || '').toLowerCase();
  const sort = document.getElementById('librarySort').value;

  let filtered = allClips.filter(c => {
    // Platform filter
    if (currentFilter !== 'all' && c.platform !== currentFilter) return false;
    // Search filter
    if (search) {
      const title = (c.title || '').toLowerCase();
      const tags = (c.tags || '').toLowerCase();
      if (!title.includes(search) && !tags.includes(search)) return false;
    }
    return true;
  });

  // Sort
  filtered.sort((a, b) => {
    if (sort === 'newest') return new Date(b.created_at) - new Date(a.created_at);
    if (sort === 'oldest') return new Date(a.created_at) - new Date(b.created_at);
    if (sort === 'largest') return (b.file_size || 0) - (a.file_size || 0);
    if (sort === 'smallest') return (a.file_size || 0) - (b.file_size || 0);
    return 0;
  });

  // Pin favorites to top
  const favs = filtered.filter(c => c.is_favorite);
  const rest = filtered.filter(c => !c.is_favorite);
  filtered = [...favs, ...rest];

  renderLibrary(filtered);
}

function setFilter(platform) {
  currentFilter = platform;
  document.querySelectorAll('#libraryFilters .filter-pill').forEach(el => {
    el.classList.toggle('active', el.textContent.trim().toLowerCase().replace(/ \/ .*/, '').replace('all', 'all') ===
      (platform === 'all' ? 'all' : platform));
  });
  // Simpler: re-apply active by matching
  const pills = document.querySelectorAll('#libraryFilters .filter-pill');
  const labels = ['all', 'youtube', 'twitter', 'instagram', 'tiktok', 'twitch', 'soundcloud'];
  pills.forEach((el, i) => el.classList.toggle('active', labels[i] === platform));
  applyLibraryView();
}

async function toggleFavorite(clipId) {
  try {
    const resp = await authFetch('/api/library/' + clipId + '/favorite', { method: 'PATCH' });
    const data = await resp.json();
    if (data.success) {
      const clip = allClips.find(c => c.id === clipId);
      if (clip) clip.is_favorite = data.is_favorite;
      applyLibraryView();
    }
  } catch (e) { /* ignore */ }
}

function onClipSelectChange(clipId) {
  if (selectedClipIds.has(clipId)) {
    selectedClipIds.delete(clipId);
  } else {
    selectedClipIds.add(clipId);
  }
  updateBulkBar();
  // Update card visual
  document.querySelectorAll('.clip-card').forEach(card => {
    const cb = card.querySelector('.clip-checkbox');
    if (!cb) return;
    const id = cb.dataset.clipId;
    card.classList.toggle('selected', selectedClipIds.has(id));
    cb.classList.toggle('checked', selectedClipIds.has(id));
  });
}

function toggleSelectAll() {
  const grid = document.getElementById('libraryGrid');
  const visibleIds = [];
  grid.querySelectorAll('.clip-checkbox').forEach(cb => visibleIds.push(cb.dataset.clipId));

  const allSelected = visibleIds.length > 0 && visibleIds.every(id => selectedClipIds.has(id));
  if (allSelected) {
    visibleIds.forEach(id => selectedClipIds.delete(id));
  } else {
    visibleIds.forEach(id => selectedClipIds.add(id));
  }
  updateBulkBar();
  // Update visuals
  grid.querySelectorAll('.clip-card').forEach(card => {
    const cb = card.querySelector('.clip-checkbox');
    if (!cb) return;
    const id = cb.dataset.clipId;
    card.classList.toggle('selected', selectedClipIds.has(id));
    cb.classList.toggle('checked', selectedClipIds.has(id));
  });
}

function updateBulkBar() {
  const bar = document.getElementById('bulkBar');
  const info = document.getElementById('bulkBarInfo');
  const container = document.getElementById('librarySection');
  if (selectedClipIds.size > 0) {
    bar.classList.add('visible');
    container.classList.add('bulk-mode');
    info.textContent = selectedClipIds.size + ' selected';
  } else {
    bar.classList.remove('visible');
    container.classList.remove('bulk-mode');
  }
}

async function bulkDelete() {
  if (!confirm('Delete ' + selectedClipIds.size + ' clip(s) permanently?')) return;
  try {
    const resp = await authFetch('/api/library/bulk-delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: Array.from(selectedClipIds) }),
    });
    if (resp.ok) {
      selectedClipIds.clear();
      updateBulkBar();
      showToast('Clips deleted', 'success');
      loadLibrary();
    }
  } catch (e) { /* ignore */ }
}

function bulkDownload() {
  const clips = allClips.filter(c => selectedClipIds.has(c.id));
  clips.forEach((clip, i) => {
    setTimeout(() => {
      const a = document.createElement('a');
      a.href = clip.download_url;
      a.download = (clip.title || 'clip') + (clip.file_ext || '.mp4');
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    }, i * 500);
  });
}

function renderLibrary(clips) {
  const grid = document.getElementById('libraryGrid');
  const empty = document.getElementById('libraryEmpty');
  const stats = document.getElementById('libraryStats');

  grid.querySelectorAll('.clip-card, .skeleton-card').forEach(el => el.remove());

  if (clips.length === 0) {
    empty.style.display = '';
    stats.textContent = currentFilter !== 'all' || document.getElementById('librarySearch').value
      ? 'No clips match your filters'
      : '';
    return;
  }

  empty.style.display = 'none';
  const totalSize = clips.reduce((sum, c) => sum + (c.file_size || 0), 0);
  stats.textContent = clips.length + ' clip' + (clips.length !== 1 ? 's' : '') + ' \u00b7 ' + formatFileSize(totalSize);

  clips.forEach((clip, i) => {
    const card = document.createElement('div');
    card.className = 'clip-card' + (selectedClipIds.has(clip.id) ? ' selected' : '');
    card.style.animationDelay = (i * 0.03) + 's';

    const trimInfo = clip.trim_start && clip.trim_end
      ? clip.trim_start + ' \u2192 ' + clip.trim_end
      : 'Full video';

    const date = new Date(clip.created_at);
    const dateStr = date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });

    // Build tags HTML
    let tagsHtml = '';
    if (clip.tags) {
      const tagArr = clip.tags.split(',').map(t => t.trim()).filter(Boolean);
      if (tagArr.length) {
        tagsHtml = '<div class="clip-tags">' +
          tagArr.map(t => '<span class="clip-tag">' + escapeHtml(t) + '</span>').join('') +
          '</div>';
      }
    }

    const isChecked = selectedClipIds.has(clip.id);
    const isFav = clip.is_favorite;

    card.innerHTML =
      '<div class="clip-card-thumb">' +
        '<div class="clip-checkbox' + (isChecked ? ' checked' : '') + '" data-clip-id="' + clip.id + '" onclick="event.stopPropagation();onClipSelectChange(\'' + clip.id + '\')"></div>' +
        '<button type="button" class="clip-favorite' + (isFav ? ' active' : '') + '" onclick="event.stopPropagation();toggleFavorite(\'' + clip.id + '\')" title="Favorite">' + (isFav ? '\u2605' : '\u2606') + '</button>' +
        (clip.thumbnail ? '<img src="' + escapeAttr(clip.thumbnail) + '" alt="' + escapeAttr(clip.title) + '">' : '') +
        '<span class="clip-platform-tag ' + clip.platform + '">' + (PLATFORM_LABELS[clip.platform] || clip.platform) + '</span>' +
      '</div>' +
      '<div class="clip-card-body">' +
        '<h4 style="cursor:pointer" onclick="openEditModal(\'' + clip.id + '\')" title="Click to edit">' + escapeHtml(clip.title) + '</h4>' +
        tagsHtml +
        '<div class="clip-meta">' + escapeHtml(clip.channel || '') + ' \u00b7 ' + dateStr + ' \u00b7 ' + formatFileSize(clip.file_size || 0) + '</div>' +
        '<div class="clip-card-actions">' +
          '<a class="clip-btn-dl" href="' + escapeAttr(clip.download_url) + '" download="' + escapeAttr(clip.title + (clip.file_ext || '.mp4')) + '">Download</a>' +
          '<button type="button" class="clip-btn-del" onclick="deleteClip(\'' + clip.id + '\', this)">Delete</button>' +
        '</div>' +
      '</div>';

    grid.appendChild(card);
  });
}

async function deleteClip(id, btnEl) {
  if (!confirm('Delete this clip permanently?')) return;
  btnEl.textContent = '...';
  btnEl.disabled = true;

  try {
    const resp = await authFetch('/api/library/' + id, { method: 'DELETE' });
    if (resp.ok) {
      const card = btnEl.closest('.clip-card');
      card.style.opacity = '0';
      card.style.transform = 'scale(0.9)';
      selectedClipIds.delete(id);
      updateBulkBar();
      showToast('Clip deleted', 'success');
      setTimeout(() => { card.remove(); loadLibrary(); }, 300);
    }
  } catch (e) {
    btnEl.textContent = 'Error';
  }
}

function formatFileSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function escapeAttr(str) {
  return str.replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/'/g,'&#39;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ── Quality/Format Pill Handlers ────────────
document.querySelectorAll('#qualityGroup .quality-pill').forEach(btn => {
  btn.addEventListener('click', () => {
    currentQuality = btn.dataset.q;
    updateQualityPills();
  });
});

document.querySelectorAll('#formatGroup .format-pill').forEach(btn => {
  btn.addEventListener('click', () => {
    currentFormat = btn.dataset.f;
    updateFormatPills();
  });
});

function updateQualityPills() {
  document.querySelectorAll('#qualityGroup .quality-pill').forEach(p =>
    p.classList.toggle('active', p.dataset.q === currentQuality));
}

function updateFormatPills() {
  document.querySelectorAll('#formatGroup .format-pill').forEach(p =>
    p.classList.toggle('active', p.dataset.f === currentFormat));
  // MP3: hide quality row + hide trim section
  const qRow = document.querySelector('#qualityGroup').parentElement;
  if (currentFormat === 'mp3') {
    qRow.style.display = 'none';
    if (currentMode === 'trim') setMode('download');
    document.getElementById('modeTrim').style.display = 'none';
  } else {
    qRow.style.display = '';
    document.getElementById('modeTrim').style.display = '';
  }
}

// ── Toast Notifications ────────────────────
function showToast(message, type = 'info', duration = 3500) {
  const container = document.getElementById('toastContainer');
  const toast = document.createElement('div');
  toast.className = 'toast toast-' + type;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.classList.add('toast-out');
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

// ── Edit Modal ─────────────────────────────
function openEditModal(clipId) {
  const clip = allClips.find(c => c.id === clipId);
  if (!clip) return;
  document.getElementById('editClipId').value = clipId;
  document.getElementById('editTitleInput').value = clip.title || '';
  editTags = clip.tags ? clip.tags.split(',').map(t => t.trim()).filter(Boolean) : [];
  renderEditTags();
  document.getElementById('editModalOverlay').classList.add('visible');
  document.getElementById('editTitleInput').focus();
}

function closeEditModal() {
  document.getElementById('editModalOverlay').classList.remove('visible');
}

function renderEditTags() {
  const wrap = document.getElementById('editTagInputWrap');
  wrap.querySelectorAll('.tag-chip').forEach(el => el.remove());
  const field = document.getElementById('editTagField');
  editTags.forEach((tag, i) => {
    const chip = document.createElement('span');
    chip.className = 'tag-chip';
    chip.innerHTML = escapeHtml(tag) + '<span class="tag-remove">&times;</span>';
    chip.querySelector('.tag-remove').onclick = () => { editTags.splice(i, 1); renderEditTags(); };
    wrap.insertBefore(chip, field);
  });
}

document.getElementById('editTagField').addEventListener('keydown', function(e) {
  if ((e.key === 'Enter' || e.key === ',') && this.value.trim()) {
    e.preventDefault();
    const tag = this.value.trim().replace(/,/g, '').substring(0, 30);
    if (tag && editTags.length < 10 && !editTags.includes(tag)) {
      editTags.push(tag);
      renderEditTags();
    }
    this.value = '';
  }
  if (e.key === 'Backspace' && !this.value && editTags.length > 0) {
    editTags.pop();
    renderEditTags();
  }
});

async function saveEdit() {
  const clipId = document.getElementById('editClipId').value;
  const title = document.getElementById('editTitleInput').value.trim();
  const tagsStr = editTags.length > 0 ? editTags.join(',') : null;

  try {
    const resp = await authFetch('/api/library/' + clipId, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title, tags: tagsStr }),
    });
    const data = await resp.json();
    if (data.success) {
      // Update local cache
      const clip = allClips.find(c => c.id === clipId);
      if (clip) {
        clip.title = title;
        clip.tags = tagsStr;
      }
      closeEditModal();
      applyLibraryView();
      showToast('Clip updated!', 'success');
    } else {
      showToast(data.error || 'Update failed', 'error');
    }
  } catch (e) {
    showToast('Update failed — network error', 'error');
  }
}

// ── Auth Helpers ────────────────────────────
function getAuthState() {
  try {
    const s = localStorage.getItem('clipforge_auth');
    return s ? JSON.parse(s) : null;
  } catch { return null; }
}

function setAuthState(state) {
  if (state) {
    localStorage.setItem('clipforge_auth', JSON.stringify(state));
  } else {
    localStorage.removeItem('clipforge_auth');
  }
}

function isLoggedIn() {
  return !!getAuthState()?.accessToken;
}

function authHeaders() {
  const state = getAuthState();
  if (state?.accessToken) {
    return { 'Authorization': 'Bearer ' + state.accessToken };
  }
  return {};
}

async function authFetch(url, options = {}) {
  options.headers = { ...authHeaders(), ...(options.headers || {}) };
  let resp = await fetchWithRetry(url, options);

  // Auto-refresh on 401
  if (resp.status === 401 && isLoggedIn()) {
    const refreshed = await refreshToken();
    if (refreshed) {
      options.headers = { ...authHeaders(), ...(options.headers || {}) };
      resp = await fetchWithRetry(url, options);
    }
  }
  return resp;
}

async function fetchWithRetry(url, options, maxRetries = 2) {
  let lastError;
  for (let i = 0; i <= maxRetries; i++) {
    try {
      const resp = await fetch(url, options);
      if (resp.status >= 500 && i < maxRetries) {
        await new Promise(r => setTimeout(r, 500 * (i + 1)));
        continue;
      }
      return resp;
    } catch (e) {
      lastError = e;
      if (i < maxRetries) await new Promise(r => setTimeout(r, 500 * (i + 1)));
    }
  }
  throw lastError;
}

async function refreshToken() {
  const state = getAuthState();
  if (!state?.refreshToken) return false;
  try {
    const resp = await fetch('/api/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: state.refreshToken }),
    });
    const data = await resp.json();
    if (data.success) {
      state.accessToken = data.access_token;
      state.refreshToken = data.refresh_token;
      setAuthState(state);
      return true;
    }
  } catch {}
  // Refresh failed, log out
  logout();
  return false;
}

// ── Auth UI ─────────────────────────────────
function showAuthModal(mode) {
  authMode = mode || 'login';
  document.getElementById('authModalTitle').textContent = authMode === 'login' ? 'Log In' : 'Sign Up';
  document.getElementById('authSubmit').textContent = authMode === 'login' ? 'Log In' : 'Sign Up';
  document.getElementById('authToggleText').textContent = authMode === 'login' ? "Don't have an account?" : 'Already have an account?';
  document.getElementById('authToggleLink').textContent = authMode === 'login' ? 'Sign up' : 'Log in';
  document.getElementById('authError').classList.remove('visible');
  document.getElementById('authEmail').value = '';
  document.getElementById('authPassword').value = '';
  document.getElementById('authModalOverlay').classList.add('visible');
  document.getElementById('authEmail').focus();
}

function closeAuthModal() {
  document.getElementById('authModalOverlay').classList.remove('visible');
}

function toggleAuthMode() {
  showAuthModal(authMode === 'login' ? 'signup' : 'login');
}

async function submitAuth() {
  const email = document.getElementById('authEmail').value.trim();
  const password = document.getElementById('authPassword').value;
  const errEl = document.getElementById('authError');
  const btn = document.getElementById('authSubmit');
  errEl.classList.remove('visible');

  if (!email || !password) {
    errEl.textContent = 'Email and password required.';
    errEl.classList.add('visible');
    return;
  }

  btn.disabled = true;
  btn.textContent = authMode === 'login' ? 'Logging in...' : 'Signing up...';

  const endpoint = authMode === 'login' ? '/api/auth/login' : '/api/auth/signup';
  try {
    const resp = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    const data = await resp.json();

    if (!resp.ok) {
      errEl.textContent = data.error || 'Authentication failed.';
      errEl.classList.add('visible');
      return;
    }

    if (authMode === 'signup') {
      showToast('Account created! Check your email to confirm.', 'success', 5000);
      showAuthModal('login');
      return;
    }

    // Login success
    setAuthState({
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      user: data.user,
    });
    closeAuthModal();
    updateUserUI();
    showToast('Welcome back, ' + data.user.email + '!', 'success');
    loadLibrary();
  } catch (e) {
    errEl.textContent = 'Network error.';
    errEl.classList.add('visible');
  } finally {
    btn.disabled = false;
    btn.textContent = authMode === 'login' ? 'Log In' : 'Sign Up';
  }
}

function logout() {
  setAuthState(null);
  localStorage.removeItem('clipforge_library');
  allClips = [];
  applyLibraryView();
  updateUserUI();
  showToast('Logged out', 'info');
}

function updateUserUI() {
  const area = document.getElementById('userArea');
  const state = getAuthState();
  if (state?.user) {
    area.innerHTML = '<div class="user-bar"><span class="user-email">' + escapeHtml(state.user.email) + '</span><button type="button" class="btn-logout" onclick="logout()">Log out</button></div>';
  } else {
    area.innerHTML = '<button type="button" class="btn-login-header" onclick="showAuthModal(\'login\')">Log in</button>';
  }
}

// Handle Enter key in auth inputs
document.getElementById('authPassword').addEventListener('keydown', e => {
  if (e.key === 'Enter') submitAuth();
});

// ── Init ────────────────────────────────────
updateUserUI();
loadLibrary();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    print("\n  ClipForge — Video Downloader & Trimmer")
    print("  Running at http://localhost:5000\n")
    app.run(debug=False, port=5000)
