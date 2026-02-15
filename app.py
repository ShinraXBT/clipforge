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

import yt_dlp
from supabase import create_client

app = Flask(__name__)

# ── Supabase ─────────────────────────────────────────────────────────────────
SUPABASE_URL = os.environ.get("SUPABASE_URL", "https://yopxattfhvxackbnrblw.supabase.co")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InlvcHhhdHRmaHZ4YWNrYm5yYmx3Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzExNTMwMjMsImV4cCI6MjA4NjcyOTAyM30.JMroS3lPPk5uLhA_N3qzpVMoQSHNhuYfDYqRnCy925Y")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InlvcHhhdHRmaHZ4YWNrYm5yYmx3Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3MTE1MzAyMywiZXhwIjoyMDg2NzI5MDIzfQ.M7kKleJL-zz9nmt6pXZjZg_LKBRLakoeydXbx498IOc")
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
    "youtube":   re.compile(r'^(www\.)?(youtube\.com|youtu\.be|m\.youtube\.com)$', re.I),
    "twitter":   re.compile(r'^(www\.)?(twitter\.com|x\.com|mobile\.twitter\.com|mobile\.x\.com)$', re.I),
    "instagram": re.compile(r'^(www\.)?(instagram\.com|m\.instagram\.com)$', re.I),
    "tiktok":    re.compile(r'^(www\.)?(tiktok\.com|vm\.tiktok\.com|m\.tiktok\.com)$', re.I),
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
        return None, "Unsupported URL. Paste a YouTube, Twitter/X, Instagram, or TikTok link."

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
    platform, err = validate_url(url)
    if err:
        return jsonify({"error": err}), 400

    job_id = uuid.uuid4().hex[:12]
    job_dir = TEMP_DIR / job_id
    job_dir.mkdir(exist_ok=True)

    try:
        output_template = str(job_dir / "video.%(ext)s")

        opts = safe_ydl_opts({
            "format": "best[ext=mp4]/best",
            "outtmpl": output_template,
        })

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

        opts = safe_ydl_opts({
            "format": "best[ext=mp4][height<=720]/best[height<=720]/best",
            "outtmpl": output_template,
            "download_ranges": yt_dlp.utils.download_range_func(
                None, [(start_sec, end_sec)]
            ),
            "force_keyframes_at_cuts": True,
        })

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
            opts = safe_ydl_opts({
                "format": "best[ext=mp4][height<=720]/best[height<=720]/best",
                "outtmpl": output_template,
                "download_ranges": yt_dlp.utils.download_range_func(None, [(start_sec, end_sec)]),
                "force_keyframes_at_cuts": True,
            })

            with yt_dlp.YoutubeDL(opts) as ydl:
                ydl.download([url])

            dl_file = find_downloaded_file(job_dir, "clip")
        else:
            output_template = str(job_dir / "video.%(ext)s")
            opts = safe_ydl_opts({
                "format": "best[ext=mp4]/best",
                "outtmpl": output_template,
            })

            with yt_dlp.YoutubeDL(opts) as ydl:
                ydl.download([url])

            dl_file = find_downloaded_file(job_dir, "video")

        if not dl_file:
            return jsonify({"error": "Downloaded file not found."}), 500

        if dl_file.stat().st_size > MAX_FILE_SIZE:
            cleanup_job_dir(job_dir)
            return jsonify({"error": "File too large (>100MB)."}), 413

        # Upload to Supabase
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
        return jsonify({"error": "An unexpected error occurred."}), 500


# ── API: Library (list / delete) ──────────────────────────────────────────────

@app.route("/api/library", methods=["GET"])
def get_library():
    """Return all saved clips, newest first."""
    try:
        result = sb.table("clips").select("*").order("created_at", desc=True).limit(100).execute()
        clips = result.data or []
        # Add public URL to each clip
        for clip in clips:
            clip["download_url"] = sb.storage.from_("clips").get_public_url(clip["file_path"])
        return jsonify({"clips": clips})
    except Exception:
        return jsonify({"clips": [], "error": "Could not load library."}), 500


@app.route("/api/library/<clip_id>", methods=["DELETE"])
def delete_clip(clip_id):
    """Delete a clip from storage and database."""
    # Validate UUID format
    if not re.match(r'^[a-f0-9-]{36}$', clip_id):
        return jsonify({"error": "Invalid clip ID."}), 400

    try:
        # Get the clip to find the file path
        result = sb.table("clips").select("file_path").eq("id", clip_id).execute()
        if not result.data:
            return jsonify({"error": "Clip not found."}), 404

        file_path = result.data[0]["file_path"]

        # Delete from storage
        try:
            sb.storage.from_("clips").remove([file_path])
        except Exception:
            pass  # Storage file may already be gone

        # Delete from database
        sb.table("clips").delete().eq("id", clip_id).execute()

        return jsonify({"success": True})
    except Exception:
        return jsonify({"error": "Could not delete clip."}), 500


# ── API: Toggle favorite ──────────────────────────────────────────────────────

@app.route("/api/library/<clip_id>/favorite", methods=["PATCH"])
def toggle_favorite(clip_id):
    """Toggle the is_favorite flag on a clip."""
    if not re.match(r'^[a-f0-9-]{36}$', clip_id):
        return jsonify({"error": "Invalid clip ID."}), 400

    try:
        result = sb.table("clips").select("is_favorite").eq("id", clip_id).execute()
        if not result.data:
            return jsonify({"error": "Clip not found."}), 404

        current = result.data[0].get("is_favorite", False)
        sb.table("clips").update({"is_favorite": not current}).eq("id", clip_id).execute()
        return jsonify({"success": True, "is_favorite": not current})
    except Exception:
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

    deleted = 0
    try:
        # Get file paths for storage cleanup
        result = sb.table("clips").select("id, file_path").in_("id", ids).execute()
        if result.data:
            file_paths = [r["file_path"] for r in result.data if r.get("file_path")]
            # Delete from storage
            if file_paths:
                try:
                    sb.storage.from_("clips").remove(file_paths)
                except Exception:
                    pass  # Some files may already be gone

            # Delete from database
            sb.table("clips").delete().in_("id", ids).execute()
            deleted = len(result.data)

        return jsonify({"success": True, "deleted": deleted})
    except Exception:
        return jsonify({"error": "Could not delete clips."}), 500


# ── Frontend HTML ────────────────────────────────────────────────────────────

INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ClipForge — Video Downloader & Trimmer</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>✂</text></svg>">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,300;0,9..40,400;0,9..40,500;0,9..40,600;0,9..40,700;1,9..40,400&family=Instrument+Serif:ital@0;1&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}

:root {
  --bg-deep: #000000;
  --bg-panel: rgba(18, 18, 20, 0.8);
  --bg-surface: #161618;
  --bg-elevated: #1c1c1e;
  --bg-hover: #222224;
  --border: rgba(255, 255, 255, 0.06);
  --border-light: rgba(255, 255, 255, 0.1);
  --border-focus: rgba(0, 229, 160, 0.4);
  --text-primary: #f5f5f7;
  --text-secondary: #a1a1a6;
  --text-muted: #6e6e73;
  --accent: #00e5a0;
  --accent-dim: rgba(0, 229, 160, 0.08);
  --accent-glow: rgba(0, 229, 160, 0.2);
  --accent-secondary: #34d399;
  --danger: #ff453a;
  --danger-dim: rgba(255, 69, 58, 0.1);
  --timeline-bg: #1c1c1e;
  --timeline-region: rgba(0, 229, 160, 0.1);
  --glass: rgba(30, 30, 32, 0.7);
  --glass-border: rgba(255, 255, 255, 0.08);
  --yt: #ff0033;
  --tw: #1d9bf0;
  --ig: #e1306c;
  --tk: #00f2ea;
  --radius-sm: 8px;
  --radius-md: 14px;
  --radius-lg: 20px;
  --radius-xl: 24px;
}

html { font-size: 16px; scroll-behavior: smooth; }

body {
  font-family: 'DM Sans', -apple-system, BlinkMacSystemFont, sans-serif;
  background: var(--bg-deep);
  color: var(--text-primary);
  min-height: 100vh;
  overflow-x: hidden;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  line-height: 1.5;
  letter-spacing: -0.01em;
}

body::before {
  content: '';
  position: fixed;
  top: -40%;
  left: -20%;
  width: 80%;
  height: 80%;
  background: radial-gradient(ellipse, rgba(0, 229, 160, 0.03) 0%, transparent 70%);
  pointer-events: none;
  z-index: 0;
}

body::after {
  content: '';
  position: fixed;
  bottom: -30%;
  right: -20%;
  width: 70%;
  height: 70%;
  background: radial-gradient(ellipse, rgba(0, 229, 160, 0.02) 0%, transparent 70%);
  pointer-events: none;
  z-index: 0;
}

.app-container {
  position: relative;
  z-index: 1;
  max-width: 1480px;
  margin: 0 auto;
  padding: 2.5rem 2rem 5rem;
}

.app-columns {
  display: grid;
  grid-template-columns: 1fr 420px;
  gap: 2rem;
  align-items: start;
}

.col-editor {
  min-width: 0;
  max-width: 780px;
}

.col-library {
  position: sticky;
  top: 2rem;
  max-height: calc(100vh - 4rem);
  overflow-y: auto;
  scrollbar-width: thin;
  scrollbar-color: rgba(255,255,255,0.08) transparent;
  padding-right: 4px;
}
.col-library::-webkit-scrollbar { width: 5px; }
.col-library::-webkit-scrollbar-track { background: transparent; }
.col-library::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.08); border-radius: 10px; }
.col-library::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.15); }

/* ── Header ─────────────────────────────────────── */
.header {
  text-align: center;
  margin-bottom: 3rem;
  padding-bottom: 2.5rem;
  border-bottom: 1px solid var(--border);
  animation: fadeIn 1s ease-out;
}

.logo {
  font-family: 'DM Mono', monospace;
  font-size: 0.75rem;
  letter-spacing: 4px;
  text-transform: uppercase;
  color: var(--accent);
  margin-bottom: 1rem;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.75rem;
  font-weight: 500;
}

.logo::before, .logo::after {
  content: '';
  width: 24px;
  height: 1px;
  background: var(--accent);
  opacity: 0.4;
}

.header h1 {
  font-family: 'Instrument Serif', Georgia, serif;
  font-size: 3.2rem;
  font-weight: 400;
  font-style: italic;
  letter-spacing: -1px;
  line-height: 1.1;
  color: var(--text-primary);
}

.header p {
  color: var(--text-muted);
  font-size: 1rem;
  margin-top: 0.75rem;
  font-weight: 400;
  letter-spacing: 0;
}

/* ── Platform pills ─────────────────────────────── */
.platforms {
  display: flex;
  justify-content: center;
  gap: 0.5rem;
  margin-top: 1.25rem;
  flex-wrap: wrap;
}

.platform-pill {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.4rem 0.85rem;
  border-radius: 100px;
  font-family: 'DM Sans', sans-serif;
  font-size: 0.8rem;
  font-weight: 500;
  border: 1px solid var(--border);
  background: transparent;
  color: var(--text-muted);
  transition: all 0.35s cubic-bezier(0.4, 0, 0.2, 1);
  cursor: default;
}

.platform-pill svg { width: 14px; height: 14px; opacity: 0.6; transition: opacity 0.3s; }
.platform-pill.yt svg { color: var(--yt); }
.platform-pill.tw svg { color: var(--tw); }
.platform-pill.ig svg { color: var(--ig); }
.platform-pill.tk svg { color: var(--tk); }

.platform-pill.active {
  border-color: var(--accent);
  background: var(--accent-dim);
  color: var(--text-primary);
}
.platform-pill.active svg { opacity: 1; }

/* ── Panels ─────────────────────────────────────── */
.panel {
  background: var(--bg-panel);
  backdrop-filter: blur(40px);
  -webkit-backdrop-filter: blur(40px);
  border: 1px solid var(--glass-border);
  border-radius: var(--radius-xl);
  padding: 2rem;
  margin-bottom: 1.25rem;
  animation: fadeIn 0.6s ease-out backwards;
  transition: border-color 0.4s, box-shadow 0.4s;
}
.panel:hover {
  border-color: var(--border-light);
  box-shadow: 0 0 0 1px rgba(255,255,255,0.02);
}

.panel-label {
  font-family: 'DM Mono', monospace;
  font-size: 0.7rem;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--text-muted);
  margin-bottom: 1.25rem;
  display: flex;
  align-items: center;
  gap: 0.6rem;
}

.panel-label .dot {
  width: 6px; height: 6px;
  border-radius: 50%;
  background: var(--accent);
}

/* ── Platform badge (shown on detected platform) ── */
.platform-badge {
  display: none;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 1.25rem;
  padding: 0.45rem 0.85rem;
  border-radius: 100px;
  font-family: 'DM Sans', sans-serif;
  font-size: 0.8rem;
  font-weight: 500;
  animation: fadeIn 0.4s ease-out;
}
.platform-badge.visible { display: inline-flex; }
.platform-badge svg { width: 16px; height: 16px; }
.platform-badge.youtube   { background: rgba(255,0,51,0.08); color: var(--yt); border: 1px solid rgba(255,0,51,0.15); }
.platform-badge.twitter   { background: rgba(29,155,240,0.08); color: var(--tw); border: 1px solid rgba(29,155,240,0.15); }
.platform-badge.instagram { background: rgba(225,48,108,0.08); color: var(--ig); border: 1px solid rgba(225,48,108,0.15); }
.platform-badge.tiktok    { background: rgba(0,242,234,0.08); color: var(--tk); border: 1px solid rgba(0,242,234,0.15); }

/* ── URL Input ──────────────────────────────────── */
.url-group {
  display: flex;
  gap: 0.75rem;
}

.url-input {
  flex: 1;
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 0.95rem 1.25rem;
  color: var(--text-primary);
  font-family: 'DM Sans', sans-serif;
  font-size: 0.95rem;
  outline: none;
  transition: all 0.35s cubic-bezier(0.4, 0, 0.2, 1);
}
.url-input::placeholder { color: var(--text-muted); font-weight: 400; }
.url-input:focus {
  border-color: var(--border-focus);
  box-shadow: 0 0 0 4px var(--accent-dim);
  background: var(--bg-elevated);
}

.btn-load {
  background: var(--text-primary);
  color: var(--bg-deep);
  border: none;
  border-radius: var(--radius-md);
  padding: 0.95rem 1.8rem;
  font-family: 'DM Sans', sans-serif;
  font-weight: 600;
  font-size: 0.95rem;
  cursor: pointer;
  letter-spacing: 0;
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  white-space: nowrap;
}
.btn-load:hover {
  background: var(--accent);
  transform: translateY(-1px);
  box-shadow: 0 8px 30px var(--accent-glow);
}
.btn-load:active { transform: translateY(0); }
.btn-load:disabled {
  opacity: 0.3;
  cursor: not-allowed;
  transform: none;
  box-shadow: none;
}

/* ── Video Preview ──────────────────────────────── */
.preview-section { display: none; }
.preview-section.visible { display: block; animation: fadeIn 0.5s ease-out; }

.video-meta {
  display: flex;
  align-items: start;
  gap: 1.25rem;
  margin-bottom: 1.5rem;
}

.video-thumb {
  width: 180px;
  min-width: 180px;
  aspect-ratio: 16/9;
  border-radius: var(--radius-md);
  object-fit: cover;
  border: 1px solid var(--border);
}

.video-info h3 {
  font-size: 1.05rem;
  font-weight: 600;
  line-height: 1.4;
  margin-bottom: 0.3rem;
  word-break: break-word;
  color: var(--text-primary);
}

.video-info .channel {
  color: var(--text-secondary);
  font-size: 0.9rem;
  font-weight: 400;
}

.video-info .duration-badge {
  display: inline-block;
  margin-top: 0.6rem;
  font-family: 'DM Mono', monospace;
  font-size: 0.75rem;
  background: var(--accent-dim);
  color: var(--accent);
  padding: 0.3rem 0.75rem;
  border-radius: 100px;
  border: 1px solid rgba(0, 229, 160, 0.15);
  font-weight: 500;
}

.player-wrap {
  position: relative;
  width: 100%;
  aspect-ratio: 16/9;
  border-radius: var(--radius-lg);
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
  font-size: 0.9rem;
  text-align: center;
  padding: 2rem;
  background: var(--bg-surface);
}

/* ── Mode Toggle (Trim vs Download) ─────────────── */
.mode-toggle {
  display: none;
  gap: 4px;
  margin-bottom: 1.25rem;
  background: var(--bg-surface);
  border-radius: var(--radius-md);
  padding: 4px;
  border: 1px solid var(--border);
}
.mode-toggle.visible { display: flex; }

.mode-btn {
  flex: 1;
  padding: 0.7rem;
  border: none;
  border-radius: 10px;
  background: transparent;
  color: var(--text-muted);
  font-family: 'DM Sans', sans-serif;
  font-size: 0.9rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  text-align: center;
}

.mode-btn:hover { color: var(--text-secondary); }

.mode-btn.active {
  background: var(--bg-elevated);
  color: var(--text-primary);
  box-shadow: 0 2px 8px rgba(0,0,0,0.3);
}

/* ── Timeline ───────────────────────────────────── */
.timeline-section { display: none; }
.timeline-section.visible { display: block; animation: fadeIn 0.5s ease-out; }

.time-controls {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
  margin-bottom: 1.5rem;
}

.time-field label {
  display: block;
  font-family: 'DM Mono', monospace;
  font-size: 0.7rem;
  letter-spacing: 1px;
  text-transform: uppercase;
  color: var(--text-muted);
  margin-bottom: 0.5rem;
}

.time-field input {
  width: 100%;
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 0.75rem 1rem;
  color: var(--text-primary);
  font-family: 'DM Mono', monospace;
  font-size: 1.15rem;
  font-weight: 500;
  text-align: center;
  outline: none;
  transition: all 0.35s;
}
.time-field input:focus {
  border-color: var(--border-focus);
  box-shadow: 0 0 0 4px var(--accent-dim);
}

.timeline-track {
  position: relative;
  height: 60px;
  background: var(--timeline-bg);
  border-radius: var(--radius-md);
  margin: 1rem 0 0.75rem;
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
  font-family: 'DM Mono', monospace;
  font-size: 0.7rem;
  color: var(--text-muted);
}

.clip-duration {
  text-align: center;
  margin-top: 1rem;
  font-family: 'DM Mono', monospace;
  font-size: 0.85rem;
  color: var(--text-secondary);
}
.clip-duration span { color: var(--accent); font-weight: 500; }

/* ── Action Buttons ─────────────────────────────── */
.action-section { display: none; }
.action-section.visible { display: block; animation: fadeIn 0.5s ease-out; }

.btn-action {
  width: 100%;
  padding: 1.1rem;
  background: var(--accent);
  color: var(--bg-deep);
  border: none;
  border-radius: var(--radius-md);
  font-family: 'DM Sans', sans-serif;
  font-size: 1rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  position: relative;
  overflow: hidden;
}
.btn-action:hover {
  transform: translateY(-1px);
  box-shadow: 0 8px 30px var(--accent-glow);
  filter: brightness(1.05);
}
.btn-action:active { transform: translateY(0); }
.btn-action:disabled {
  opacity: 0.35;
  cursor: not-allowed;
  transform: none;
  box-shadow: none;
}

/* ── Progress ───────────────────────────────────── */
.progress-section { display: none; }
.progress-section.visible { display: block; animation: fadeIn 0.5s ease-out; }

.progress-bar-track {
  height: 4px;
  background: var(--bg-elevated);
  border-radius: 100px;
  overflow: hidden;
  margin: 1.25rem 0;
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
  font-family: 'DM Sans', sans-serif;
  font-size: 0.85rem;
  color: var(--text-secondary);
  text-align: center;
}

.progress-status .spinner {
  display: inline-block;
  width: 14px;
  height: 14px;
  border: 2px solid rgba(255,255,255,0.1);
  border-top-color: var(--accent);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
  vertical-align: middle;
  margin-right: 0.5rem;
}

/* ── Download Ready ─────────────────────────────── */
.download-section { display: none; text-align: center; }
.download-section.visible { display: block; animation: scalePop 0.6s cubic-bezier(0.175, 0.885, 0.32, 1.1); }

.download-icon {
  width: 72px;
  height: 72px;
  margin: 0 auto 1.25rem;
  border-radius: 50%;
  background: var(--accent-dim);
  border: 1px solid rgba(0, 229, 160, 0.2);
  display: flex;
  align-items: center;
  justify-content: center;
}

.download-icon svg { width: 28px; height: 28px; stroke: var(--accent); }

.btn-download {
  display: inline-block;
  padding: 0.9rem 2.5rem;
  background: var(--text-primary);
  color: var(--bg-deep);
  border: none;
  border-radius: var(--radius-md);
  font-family: 'DM Sans', sans-serif;
  font-size: 0.95rem;
  font-weight: 600;
  cursor: pointer;
  text-decoration: none;
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  margin-top: 0.5rem;
}
.btn-download:hover {
  background: var(--accent);
  transform: translateY(-1px);
  box-shadow: 0 8px 30px var(--accent-glow);
}

.success-text {
  font-family: 'Instrument Serif', Georgia, serif;
  font-style: italic;
  color: var(--accent);
  font-size: 1.3rem;
  font-weight: 400;
  margin-bottom: 0.25rem;
}

.reset-link {
  display: inline-block;
  margin-top: 1.25rem;
  color: var(--text-muted);
  font-size: 0.85rem;
  cursor: pointer;
  transition: color 0.25s;
  background: none;
  border: none;
  font-family: 'DM Sans', sans-serif;
  text-decoration: none;
  border-bottom: 1px solid var(--border);
  padding-bottom: 2px;
}
.reset-link:hover { color: var(--text-secondary); border-color: var(--text-secondary); }

/* ── Error ──────────────────────────────────────── */
.error-msg {
  display: none;
  background: var(--danger-dim);
  border: 1px solid rgba(255, 69, 58, 0.15);
  border-radius: var(--radius-sm);
  padding: 0.85rem 1.1rem;
  color: var(--danger);
  font-size: 0.85rem;
  margin-top: 1rem;
  font-family: 'DM Sans', sans-serif;
}
.error-msg.visible { display: block; animation: fadeIn 0.3s ease-out; }

.limit-note {
  text-align: center;
  font-size: 0.8rem;
  color: var(--text-muted);
  font-family: 'DM Sans', sans-serif;
  margin-top: 0.75rem;
}

/* ── Save to Library Button ────────────────────── */
.btn-save-library {
  display: inline-block;
  padding: 0.7rem 1.8rem;
  background: transparent;
  color: var(--text-secondary);
  border: 1px solid var(--border-light);
  border-radius: var(--radius-md);
  font-family: 'DM Sans', sans-serif;
  font-size: 0.9rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  margin-top: 0.75rem;
}
.btn-save-library:hover {
  border-color: var(--accent);
  color: var(--accent);
  background: var(--accent-dim);
}
.btn-save-library:disabled {
  opacity: 0.4;
  cursor: not-allowed;
  transform: none;
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
  border-radius: var(--radius-md);
  padding: 1.5rem;
  margin-top: 1.25rem;
  text-align: left;
  animation: fadeIn 0.3s ease-out;
}
.save-dialog.visible { display: block; }

.save-dialog label {
  display: block;
  font-family: 'DM Sans', sans-serif;
  font-size: 0.8rem;
  font-weight: 500;
  color: var(--text-secondary);
  margin-bottom: 0.5rem;
}

.save-dialog input[type="text"] {
  width: 100%;
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 0.75rem 1rem;
  color: var(--text-primary);
  font-family: 'DM Sans', sans-serif;
  font-size: 0.9rem;
  outline: none;
  transition: all 0.35s;
  margin-bottom: 1.25rem;
}
.save-dialog input[type="text"]:focus {
  border-color: var(--border-focus);
  box-shadow: 0 0 0 4px var(--accent-dim);
}

.tag-input-wrap {
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem;
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 0.6rem 0.8rem;
  margin-bottom: 1.25rem;
  min-height: 44px;
  cursor: text;
  transition: all 0.35s;
  align-items: center;
}
.tag-input-wrap:focus-within {
  border-color: var(--border-focus);
  box-shadow: 0 0 0 4px var(--accent-dim);
}

.tag-chip {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  background: var(--accent-dim);
  color: var(--accent);
  border: 1px solid rgba(0, 229, 160, 0.2);
  border-radius: 100px;
  padding: 0.25rem 0.65rem;
  font-family: 'DM Sans', sans-serif;
  font-size: 0.75rem;
  font-weight: 500;
  white-space: nowrap;
}
.tag-chip .tag-remove {
  cursor: pointer;
  opacity: 0.5;
  font-size: 0.9rem;
  line-height: 1;
  transition: opacity 0.2s;
}
.tag-chip .tag-remove:hover { opacity: 1; }

.tag-input-field {
  flex: 1;
  min-width: 80px;
  background: transparent;
  border: none;
  color: var(--text-primary);
  font-family: 'DM Sans', sans-serif;
  font-size: 0.85rem;
  outline: none;
}
.tag-input-field::placeholder { color: var(--text-muted); }

.save-dialog-actions {
  display: flex;
  gap: 0.5rem;
}

.btn-confirm-save {
  flex: 1;
  padding: 0.75rem;
  background: var(--accent);
  color: var(--bg-deep);
  border: none;
  border-radius: var(--radius-sm);
  font-family: 'DM Sans', sans-serif;
  font-size: 0.9rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}
.btn-confirm-save:hover { box-shadow: 0 4px 20px var(--accent-glow); filter: brightness(1.05); }
.btn-confirm-save:disabled { opacity: 0.35; cursor: not-allowed; }

.btn-cancel-save {
  padding: 0.75rem 1.2rem;
  background: transparent;
  color: var(--text-muted);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  font-family: 'DM Sans', sans-serif;
  font-size: 0.9rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.25s;
}
.btn-cancel-save:hover { border-color: var(--border-light); color: var(--text-secondary); }

/* ── Library ───────────────────────────────────── */
.library-section {
  animation: fadeIn 0.8s ease-out backwards;
  animation-delay: 0.15s;
}

/* ── Library Toolbar ──────────────────────────── */
.library-toolbar {
  margin-bottom: 1.25rem;
}

.library-search {
  width: 100%;
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 0.7rem 1rem;
  color: var(--text-primary);
  font-family: 'DM Sans', sans-serif;
  font-size: 0.85rem;
  outline: none;
  transition: all 0.35s;
  margin-bottom: 0.75rem;
}
.library-search::placeholder { color: var(--text-muted); }
.library-search:focus { border-color: var(--border-focus); box-shadow: 0 0 0 4px var(--accent-dim); }

.library-filters {
  display: flex;
  gap: 0.35rem;
  flex-wrap: wrap;
  margin-bottom: 0.75rem;
}

.filter-pill {
  padding: 0.35rem 0.75rem;
  border-radius: 100px;
  font-family: 'DM Sans', sans-serif;
  font-size: 0.75rem;
  font-weight: 500;
  border: 1px solid var(--border);
  background: transparent;
  color: var(--text-muted);
  cursor: pointer;
  transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
}
.filter-pill:hover { border-color: var(--border-light); color: var(--text-secondary); }
.filter-pill.active { border-color: var(--accent); background: var(--accent-dim); color: var(--accent); }

.library-sort-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 0.75rem;
}

.library-sort {
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 0.4rem 0.7rem;
  color: var(--text-secondary);
  font-family: 'DM Sans', sans-serif;
  font-size: 0.75rem;
  outline: none;
  cursor: pointer;
}
.library-sort option { background: var(--bg-surface); color: var(--text-primary); }

.btn-select-all {
  background: transparent;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 0.4rem 0.75rem;
  color: var(--text-muted);
  font-family: 'DM Sans', sans-serif;
  font-size: 0.75rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.25s;
}
.btn-select-all:hover { border-color: var(--border-light); color: var(--text-secondary); }

.library-stats {
  font-family: 'DM Sans', sans-serif;
  font-size: 0.8rem;
  color: var(--text-muted);
  margin-bottom: 1rem;
  font-weight: 400;
}

.library-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(170px, 1fr));
  gap: 0.75rem;
}

.library-empty {
  grid-column: 1 / -1;
  text-align: center;
  padding: 3rem 1rem;
  color: var(--text-muted);
  font-size: 0.9rem;
}

/* ── Clip Card ─────────────────────────────────── */
.clip-card {
  position: relative;
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  overflow: hidden;
  transition: all 0.35s cubic-bezier(0.4, 0, 0.2, 1);
  animation: fadeIn 0.4s ease-out backwards;
}
.clip-card:hover {
  border-color: var(--border-light);
  transform: translateY(-3px);
  box-shadow: 0 12px 40px rgba(0,0,0,0.4);
}
.clip-card.selected { border-color: var(--accent); box-shadow: 0 0 0 2px var(--accent-dim); }

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
  transition: transform 0.5s cubic-bezier(0.4, 0, 0.2, 1);
}
.clip-card:hover .clip-card-thumb img {
  transform: scale(1.04);
}
.clip-card-thumb .clip-platform-tag {
  position: absolute;
  bottom: 8px;
  left: 8px;
  font-family: 'DM Sans', sans-serif;
  font-size: 0.65rem;
  font-weight: 600;
  padding: 0.2rem 0.5rem;
  border-radius: 6px;
  text-transform: uppercase;
  letter-spacing: 0.3px;
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
}
.clip-platform-tag.youtube { background: rgba(255,0,51,0.85); color: #fff; }
.clip-platform-tag.twitter { background: rgba(29,155,240,0.85); color: #fff; }
.clip-platform-tag.instagram { background: rgba(225,48,108,0.85); color: #fff; }
.clip-platform-tag.tiktok { background: rgba(0,242,234,0.85); color: #000; }

.clip-card-thumb .clip-mode-tag {
  position: absolute;
  bottom: 8px;
  right: 8px;
  font-family: 'DM Mono', monospace;
  font-size: 0.6rem;
  font-weight: 500;
  padding: 0.2rem 0.5rem;
  border-radius: 6px;
  background: rgba(0,0,0,0.65);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  color: var(--text-secondary);
}

/* Checkbox overlay */
.clip-checkbox {
  position: absolute;
  top: 8px;
  left: 8px;
  width: 22px;
  height: 22px;
  border-radius: 6px;
  border: 1.5px solid rgba(255,255,255,0.4);
  background: rgba(0,0,0,0.4);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  cursor: pointer;
  z-index: 3;
  opacity: 0;
  transition: opacity 0.25s;
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
  width: 6px;
  height: 10px;
  border: solid var(--bg-deep);
  border-width: 0 2px 2px 0;
  transform: rotate(45deg) translate(-1px, -1px);
}

/* Favorite star */
.clip-favorite {
  position: absolute;
  top: 8px;
  right: 8px;
  width: 30px;
  height: 30px;
  border-radius: 50%;
  background: rgba(0,0,0,0.4);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  border: none;
  cursor: pointer;
  z-index: 3;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 0.9rem;
  transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
  opacity: 0;
  color: rgba(255,255,255,0.5);
}
.clip-card:hover .clip-favorite { opacity: 1; }
.clip-favorite.active { opacity: 1; color: #ffd700; }
.clip-favorite:hover { transform: scale(1.15); background: rgba(0,0,0,0.6); }

.clip-card-body {
  padding: 0.85rem;
}
.clip-card-body h4 {
  font-size: 0.82rem;
  font-weight: 600;
  line-height: 1.35;
  margin-bottom: 0.3rem;
  overflow: hidden;
  text-overflow: ellipsis;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  color: var(--text-primary);
}

.clip-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 0.25rem;
  margin-bottom: 0.4rem;
}
.clip-tags .clip-tag {
  font-family: 'DM Sans', sans-serif;
  font-size: 0.6rem;
  font-weight: 500;
  padding: 0.12rem 0.45rem;
  border-radius: 100px;
  background: var(--bg-elevated);
  color: var(--text-secondary);
  border: 1px solid var(--border);
}

.clip-card-body .clip-meta {
  font-family: 'DM Sans', sans-serif;
  font-size: 0.7rem;
  color: var(--text-muted);
  margin-bottom: 0.6rem;
}

.clip-card-actions {
  display: flex;
  gap: 0.4rem;
}
.clip-card-actions a, .clip-card-actions button {
  flex: 1;
  padding: 0.45rem;
  border-radius: var(--radius-sm);
  font-family: 'DM Sans', sans-serif;
  font-size: 0.7rem;
  font-weight: 500;
  text-align: center;
  cursor: pointer;
  transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
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
  background: var(--glass);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border: 1px solid var(--glass-border);
  border-radius: var(--radius-md);
  padding: 0.85rem 1.1rem;
  margin-top: 0.75rem;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
  animation: fadeIn 0.3s ease-out;
  z-index: 10;
}
.bulk-bar.visible { display: flex; }

.bulk-bar-info {
  font-family: 'DM Sans', sans-serif;
  font-size: 0.8rem;
  color: var(--text-secondary);
  font-weight: 500;
}

.bulk-bar-actions { display: flex; gap: 0.5rem; }

.bulk-btn {
  padding: 0.45rem 0.9rem;
  border-radius: var(--radius-sm);
  font-family: 'DM Sans', sans-serif;
  font-size: 0.75rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
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
  border-color: rgba(255, 69, 58, 0.3);
}
.bulk-btn-delete:hover { background: var(--danger-dim); border-color: var(--danger); }

/* ── Animations ─────────────────────────────────── */
@keyframes fadeIn {
  from { opacity: 0; transform: translateY(8px); }
  to { opacity: 1; transform: translateY(0); }
}

@keyframes scalePop {
  from { opacity: 0; transform: scale(0.95); }
  to { opacity: 1; transform: scale(1); }
}

@keyframes spin { to { transform: rotate(360deg); } }

/* ── Responsive ─────────────────────────────────── */
@media (max-width: 1024px) {
  .app-columns { grid-template-columns: 1fr; }
  .col-editor { max-width: 100%; }
  .col-library { position: static; max-height: none; }
}
</style>
</head>
<body>

<div class="app-container">

  <!-- Header -->
  <header class="header">
    <div class="logo">ClipForge</div>
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
                 placeholder="Paste a YouTube, Twitter, Instagram, or TikTok URL..."
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

<script>
let videoDuration = 0;
let videoId = '';
let currentPlatform = '';
let currentMode = 'download';
let dragging = null;

// Library state
let allClips = [];
let currentFilter = 'all';
let selectedClipIds = new Set();
let saveTags = [];

const PLATFORM_LABELS = {
  youtube:   'YouTube',
  twitter:   'Twitter / X',
  instagram: 'Instagram',
  tiktok:    'TikTok',
};

const PLATFORM_ICONS = {
  youtube:   '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M23.5 6.2a3 3 0 0 0-2.1-2.1C19.5 3.5 12 3.5 12 3.5s-7.5 0-9.4.6A3 3 0 0 0 .5 6.2 31.4 31.4 0 0 0 0 12a31.4 31.4 0 0 0 .5 5.8 3 3 0 0 0 2.1 2.1c1.9.5 9.4.5 9.4.5s7.5 0 9.4-.6a3 3 0 0 0 2.1-2.1A31.4 31.4 0 0 0 24 12a31.4 31.4 0 0 0-.5-5.8zM9.6 15.5V8.5l6.3 3.5-6.3 3.5z"/></svg>',
  twitter:   '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>',
  instagram: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2.16c3.2 0 3.58.01 4.85.07 3.25.15 4.77 1.69 4.92 4.92.06 1.27.07 1.65.07 4.85s-.01 3.58-.07 4.85c-.15 3.23-1.66 4.77-4.92 4.92-1.27.06-1.65.07-4.85.07s-3.58-.01-4.85-.07c-3.26-.15-4.77-1.7-4.92-4.92-.06-1.27-.07-1.65-.07-4.85s.01-3.58.07-4.85C2.38 3.86 3.9 2.31 7.15 2.23 8.42 2.17 8.8 2.16 12 2.16zM12 0C8.74 0 8.33.01 7.05.07 2.7.27.27 2.7.07 7.05.01 8.33 0 8.74 0 12s.01 3.67.07 4.95c.2 4.36 2.62 6.78 6.98 6.98C8.33 23.99 8.74 24 12 24s3.67-.01 4.95-.07c4.35-.2 6.78-2.62 6.98-6.98.06-1.28.07-1.69.07-4.95s-.01-3.67-.07-4.95c-.2-4.35-2.63-6.78-6.98-6.98C15.67.01 15.26 0 12 0zm0 5.84A6.16 6.16 0 1 0 18.16 12 6.16 6.16 0 0 0 12 5.84zM12 16a4 4 0 1 1 4-4 4 4 0 0 1-4 4zm6.4-11.85a1.44 1.44 0 1 0 1.44 1.44 1.44 1.44 0 0 0-1.44-1.44z"/></svg>',
  tiktok:    '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M19.59 6.69a4.83 4.83 0 0 1-3.77-4.25V2h-3.45v13.67a2.89 2.89 0 0 1-2.88 2.5 2.89 2.89 0 0 1-2.89-2.89 2.89 2.89 0 0 1 2.89-2.89c.28 0 .54.04.79.1v-3.5a6.37 6.37 0 0 0-.79-.05A6.34 6.34 0 0 0 3.15 15a6.34 6.34 0 0 0 6.34 6.34 6.34 6.34 0 0 0 6.34-6.34V8.1a8.16 8.16 0 0 0 4.76 1.52v-3.4a4.85 4.85 0 0 1-1-.07z"/></svg>',
};

// ── Detect platform from URL ────────────────
function detectPlatform(url) {
  url = url.toLowerCase();
  if (/youtube\.com|youtu\.be/.test(url)) return 'youtube';
  if (/twitter\.com|x\.com/.test(url)) return 'twitter';
  if (/instagram\.com/.test(url)) return 'instagram';
  if (/tiktok\.com|vm\.tiktok/.test(url)) return 'tiktok';
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
});

// ── Load Video ──────────────────────────────
async function loadVideo() {
  const url = document.getElementById('urlInput').value.trim();
  const btn = document.getElementById('btnLoad');
  document.getElementById('urlError').classList.remove('visible');

  if (!url) { showError('urlError', 'Please paste a video URL.'); return; }

  const platform = detectPlatform(url);
  if (!platform) {
    showError('urlError', 'Unsupported URL. Paste a YouTube, Twitter/X, Instagram, or TikTok link.');
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
    body = { url, start, end };
    infoText = `Trimmed from ${start} to ${end}`;
    document.getElementById('progressStatus').innerHTML =
      '<span class="spinner"></span> Downloading & trimming your clip...';
  } else {
    endpoint = '/api/download-full';
    body = { url };
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
  document.getElementById('urlInput').value = '';
  document.getElementById('btnAction').disabled = false;
  document.querySelectorAll('.platform-pill').forEach(el => el.classList.remove('active'));
  videoDuration = 0;
  videoId = '';
  currentPlatform = '';
  currentMode = 'download';
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
  };

  if (currentMode === 'trim') {
    body.start = document.getElementById('startInput').value.trim();
    body.end = document.getElementById('endInput').value.trim();
  }

  try {
    const resp = await fetch('/api/save-to-library', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await resp.json();

    if (!resp.ok) {
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
    loadLibrary();
  } catch (e) {
    btn.textContent = 'Save Failed';
    btn.disabled = false;
    setTimeout(() => { btn.textContent = 'Confirm & Save'; }, 2000);
  }
}

async function loadLibrary() {
  try {
    const resp = await fetch('/api/library');
    const data = await resp.json();
    allClips = data.clips || [];
    applyLibraryView();
  } catch (e) {
    // silently fail
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
  const labels = ['all', 'youtube', 'twitter', 'instagram', 'tiktok'];
  pills.forEach((el, i) => el.classList.toggle('active', labels[i] === platform));
  applyLibraryView();
}

async function toggleFavorite(clipId) {
  try {
    const resp = await fetch('/api/library/' + clipId + '/favorite', { method: 'PATCH' });
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
    const resp = await fetch('/api/library/bulk-delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: Array.from(selectedClipIds) }),
    });
    if (resp.ok) {
      selectedClipIds.clear();
      updateBulkBar();
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

  grid.querySelectorAll('.clip-card').forEach(el => el.remove());

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
        '<h4>' + escapeHtml(clip.title) + '</h4>' +
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
    const resp = await fetch('/api/library/' + id, { method: 'DELETE' });
    if (resp.ok) {
      const card = btnEl.closest('.clip-card');
      card.style.opacity = '0';
      card.style.transform = 'scale(0.9)';
      selectedClipIds.delete(id);
      updateBulkBar();
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

// Load library on page load
loadLibrary();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    print("\n  ClipForge — Video Downloader & Trimmer")
    print("  Running at http://localhost:5000\n")
    app.run(debug=False, port=5000)
