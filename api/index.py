"""
ClipForge — Multi-Platform Video Downloader & Trimmer (Vercel Serverless)
Supports: YouTube, Twitter/X, Instagram, TikTok
Uses yt-dlp as a Python library (not CLI) for Vercel compatibility.
"""

import os
import re
import uuid
import time
import json
import subprocess
import mimetypes
import shutil
from pathlib import Path
from urllib.parse import urlparse, quote
from flask import Flask, request, jsonify, send_file

import logging
import urllib.request

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


def youtube_video_info_fallback(url, video_id):
    """Fetch YouTube video info via oEmbed API + innertube API. Bypasses bot detection."""
    info = {}

    # 1) oEmbed API — title, channel, thumbnail (never blocked, official API)
    try:
        oembed_url = f"https://www.youtube.com/oembed?url={quote(url, safe='')}&format=json"
        req = urllib.request.Request(oembed_url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            info["title"] = data.get("title", "Untitled")
            info["channel"] = data.get("author_name", "Unknown")
            info["thumbnail"] = data.get("thumbnail_url", "")
    except Exception as e:
        logger.warning("oEmbed fallback failed: %s", str(e)[:200])
        return None

    # 2) Innertube WEB API — duration (works from datacenter IPs, returns videoDetails)
    if video_id:
        try:
            payload = json.dumps({
                "videoId": video_id,
                "context": {"client": {"clientName": "WEB", "clientVersion": "2.20240101.00.00"}}
            }).encode("utf-8")
            api_req = urllib.request.Request(
                "https://www.youtube.com/youtubei/v1/player?prettyPrint=false",
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
            )
            with urllib.request.urlopen(api_req, timeout=10) as resp:
                result = json.loads(resp.read().decode("utf-8"))
            details = result.get("videoDetails", {})
            info["duration"] = int(details.get("lengthSeconds", 0))
        except Exception as e:
            logger.warning("Innertube duration fallback failed: %s", str(e)[:200])
            info["duration"] = 0
    else:
        info["duration"] = 0

    # Use high-res thumbnail if we have the video ID
    if video_id:
        info["thumbnail"] = f"https://i.ytimg.com/vi/{video_id}/hqdefault.jpg"

    info["id"] = video_id or "unknown"
    info["platform"] = "youtube"
    return info


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


def _init_js_runtimes():
    """Enable Node.js for yt-dlp YouTube signature decoding (yt-dlp 2025+)."""
    try:
        # Check if yt-dlp supports js_runtimes
        test = yt_dlp.YoutubeDL({"quiet": True, "no_warnings": True, "js_runtimes": {"node": {}}})
        test.close()
        return {"node": {}}
    except Exception:
        return None

_YDL_JS_RUNTIMES = _init_js_runtimes()


# ── PO Token: rustypipe-botguard binary (YouTube bot detection bypass) ────────
_RUSTYPIPE_BIN_PATH = "/tmp/rustypipe-botguard"
_RUSTYPIPE_VERSION = "v0.1.2"
_RUSTYPIPE_URL = (
    f"https://codeberg.org/ThetaDev/rustypipe-botguard/releases/download/{_RUSTYPIPE_VERSION}/"
    f"rustypipe-botguard-{_RUSTYPIPE_VERSION}-x86_64-unknown-linux-gnu.tar.xz"
)
_rustypipe_ready = False


def _ensure_rustypipe_binary():
    """Download rustypipe-botguard binary to /tmp on first call (cold start).
    Required by yt-dlp-get-pot-rustypipe plugin to generate PO tokens.
    Graceful fallback: if download fails, yt-dlp works without it."""
    global _rustypipe_ready
    if _rustypipe_ready:
        return True
    if os.path.isfile(_RUSTYPIPE_BIN_PATH) and os.access(_RUSTYPIPE_BIN_PATH, os.X_OK):
        _rustypipe_ready = True
        return True
    try:
        import lzma
        import tarfile
        import io
        logger.info("Downloading rustypipe-botguard binary (%s)...", _RUSTYPIPE_VERSION)
        req = urllib.request.Request(_RUSTYPIPE_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            xz_data = resp.read()
        with lzma.open(io.BytesIO(xz_data)) as xz:
            with tarfile.open(fileobj=xz) as tar:
                for member in tar.getmembers():
                    if member.name.endswith("rustypipe-botguard") and member.isfile():
                        f = tar.extractfile(member)
                        if f:
                            with open(_RUSTYPIPE_BIN_PATH, "wb") as out:
                                out.write(f.read())
                            os.chmod(_RUSTYPIPE_BIN_PATH, 0o755)
                            _rustypipe_ready = True
                            logger.info("rustypipe-botguard binary ready at %s", _RUSTYPIPE_BIN_PATH)
                            return True
        logger.warning("rustypipe-botguard binary not found in archive")
        return False
    except Exception as e:
        logger.warning("Failed to download rustypipe-botguard: %s", str(e)[:200])
        return False


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
    if _YDL_JS_RUNTIMES:
        opts["js_runtimes"] = _YDL_JS_RUNTIMES
    opts["enable_remote_components"] = ["ejs:github"]
    # PO Token: tell yt-dlp to use rustypipe-botguard for YouTube bot detection bypass
    _ensure_rustypipe_binary()
    if _rustypipe_ready:
        opts["extractor_args"] = {
            "youtube": {
                "rustypipe_bg_bin": [_RUSTYPIPE_BIN_PATH],
                "rustypipe_bg_pot_cache": ["1"],
            }
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

    # GIF: download as mp4 first, conversion happens in post_process
    if fmt == "gif":
        fmt_str = "best[ext=mp4][height<=480]/best[height<=480]/best"
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


# ── Post-processing helpers (GIF, Resize, Subtitles) ─────────────────────────

RESIZE_PRESETS = {
    "tiktok": {
        "label": "TikTok 9:16",
        "vf": "scale=1080:1920:force_original_aspect_ratio=increase,crop=1080:1920",
    },
    "square": {
        "label": "Square 1:1",
        "vf": "scale=1080:1080:force_original_aspect_ratio=increase,crop=1080:1080",
    },
    "twitter": {
        "label": "Twitter 16:9",
        "vf": "scale=1280:720:force_original_aspect_ratio=decrease,pad=1280:720:(ow-iw)/2:(oh-ih)/2",
    },
    "discord": {
        "label": "Discord (<25MB)",
        "max_size_mb": 25,
    },
    "whatsapp": {
        "label": "WhatsApp (<16MB)",
        "max_size_mb": 16,
    },
}

VALID_RESIZE_PRESETS = set(RESIZE_PRESETS.keys())

# ── Video Editor: Constants & Helpers ─────────────────────────────────────────

EFFECT_RANGES = {
    "speed":       (0.25, 3.0),
    "volume":      (0.0, 1.5),
    "brightness":  (-1.0, 1.0),
    "contrast":    (0.0, 2.0),
    "saturation":  (0.0, 3.0),
    "hue":         (0, 360),
    "temperature": (-1.0, 1.0),
    "fade_in":     (0.0, 3.0),
    "fade_out":    (0.0, 3.0),
}

VALID_ROTATIONS = {"none", "cw", "ccw", "180"}
VALID_FLIPS = {"none", "h", "v", "hv"}

FILTER_PRESETS = {
    "none":    {"brightness": 0, "contrast": 1.0, "saturation": 1.0, "hue": 0, "temperature": 0},
    "warm":    {"brightness": 0.05, "contrast": 1.1, "saturation": 1.2, "hue": 0, "temperature": 0.4},
    "cool":    {"brightness": 0, "contrast": 1.05, "saturation": 1.1, "hue": 0, "temperature": -0.4},
    "vintage": {"brightness": 0.1, "contrast": 0.9, "saturation": 0.7, "hue": 30, "temperature": 0.3},
    "bw":      {"brightness": 0, "contrast": 1.2, "saturation": 0, "hue": 0, "temperature": 0},
    "vivid":   {"brightness": 0.05, "contrast": 1.3, "saturation": 1.8, "hue": 0, "temperature": 0},
    "cinema":  {"brightness": -0.05, "contrast": 1.2, "saturation": 0.85, "hue": 10, "temperature": 0.15},
}


def sanitize_ffmpeg_text(text):
    """Escape special characters for FFmpeg drawtext filter (injection prevention)."""
    if not text or not isinstance(text, str):
        return ""
    text = text[:200]  # cap length
    for ch in ("\\", "'", ":", "[", "]", "%", ";", "{", "}"):
        text = text.replace(ch, "\\" + ch)
    return text


def validate_effects(data):
    """Extract and validate effects dict from request body. Returns clean dict or None."""
    raw = data.get("effects")
    if not raw or not isinstance(raw, dict):
        return None

    effects = {}

    # Numeric params — clamp to safe ranges
    for key, (lo, hi) in EFFECT_RANGES.items():
        if key in raw:
            try:
                val = float(raw[key])
                effects[key] = max(lo, min(hi, val))
            except (ValueError, TypeError):
                pass

    # Rotation
    rot = raw.get("rotate", "none")
    if rot in VALID_ROTATIONS:
        effects["rotate"] = rot

    # Flip
    flip = raw.get("flip", "none")
    if flip in VALID_FLIPS:
        effects["flip"] = flip

    # Filter preset (informational, values already baked into individual params)
    preset = raw.get("filter_preset", "none")
    if preset in FILTER_PRESETS:
        effects["filter_preset"] = preset

    # Text overlay
    text_overlays = raw.get("text_overlays")
    if isinstance(text_overlays, list):
        clean_overlays = []
        for overlay in text_overlays[:5]:
            if not isinstance(overlay, dict):
                continue
            text = sanitize_ffmpeg_text(overlay.get("text", ""))
            if not text:
                continue
            # Validate color
            color = overlay.get("color", "#FFFFFF")
            if not isinstance(color, str) or not re.match(r'^#[0-9a-fA-F]{6}$', color):
                color = "#FFFFFF"
            # Font size
            try:
                fontsize = int(overlay.get("fontsize", 48))
                fontsize = max(12, min(120, fontsize))
            except (ValueError, TypeError):
                fontsize = 48
            # Position
            position = overlay.get("position", "center")
            valid_positions = {"top-left", "top-center", "top-right",
                               "center-left", "center", "center-right",
                               "bottom-left", "bottom-center", "bottom-right"}
            if position not in valid_positions:
                position = "center"
            clean_overlays.append({
                "text": text,
                "color": color,
                "fontsize": fontsize,
                "position": position,
            })
        if clean_overlays:
            effects["text_overlays"] = clean_overlays

    # Check if any non-default values exist
    defaults = {"speed": 1.0, "volume": 1.0, "brightness": 0, "contrast": 1.0,
                "saturation": 1.0, "hue": 0, "temperature": 0, "fade_in": 0, "fade_out": 0,
                "rotate": "none", "flip": "none", "filter_preset": "none"}
    has_changes = False
    for k, v in effects.items():
        if k == "text_overlays":
            has_changes = True
            break
        if k in defaults and v != defaults[k]:
            has_changes = True
            break

    return effects if has_changes else None


def get_video_duration(file_path):
    """Get video duration in seconds via ffprobe."""
    try:
        probe = subprocess.run(
            ["ffprobe", "-v", "error", "-show_entries", "format=duration",
             "-of", "default=noprint_wrappers=1:nokey=1", str(file_path)],
            capture_output=True, text=True, timeout=30,
        )
        return float(probe.stdout.strip() or "0")
    except Exception:
        return 0


def apply_effects(input_path, output_path, effects):
    """Apply video/audio effects via a single FFmpeg command."""
    vf_filters = []
    af_filters = []

    speed = effects.get("speed", 1.0)
    volume = effects.get("volume", 1.0)
    rotate = effects.get("rotate", "none")
    flip = effects.get("flip", "none")
    brightness = effects.get("brightness", 0)
    contrast = effects.get("contrast", 1.0)
    saturation = effects.get("saturation", 1.0)
    hue = effects.get("hue", 0)
    temperature = effects.get("temperature", 0)
    fade_in = effects.get("fade_in", 0)
    fade_out = effects.get("fade_out", 0)
    text_overlays = effects.get("text_overlays", [])

    # ── Video filters (order matters) ──

    # Rotate
    if rotate == "cw":
        vf_filters.append("transpose=1")
    elif rotate == "ccw":
        vf_filters.append("transpose=2")
    elif rotate == "180":
        vf_filters.append("transpose=1,transpose=1")

    # Flip
    if flip == "h":
        vf_filters.append("hflip")
    elif flip == "v":
        vf_filters.append("vflip")
    elif flip == "hv":
        vf_filters.append("hflip,vflip")

    # Speed (video)
    if speed != 1.0:
        vf_filters.append(f"setpts=PTS/{speed}")

    # Brightness / Contrast / Saturation (single eq filter)
    if brightness != 0 or contrast != 1.0 or saturation != 1.0:
        vf_filters.append(f"eq=brightness={brightness}:contrast={contrast}:saturation={saturation}")

    # Hue
    if hue != 0:
        vf_filters.append(f"hue=h={hue}")

    # Temperature (warm = red boost / blue cut, cool = opposite)
    if temperature != 0:
        rs = round(temperature * 0.3, 3)
        gs = 0
        bs = round(-temperature * 0.3, 3)
        vf_filters.append(f"colorbalance=rs={rs}:gs={gs}:bs={bs}")

    # Get duration for fade-out calculation
    duration = get_video_duration(input_path)
    effective_duration = duration / speed if speed != 1.0 else duration

    # Fade in
    if fade_in > 0:
        vf_filters.append(f"fade=t=in:st=0:d={fade_in}")

    # Fade out
    if fade_out > 0 and effective_duration > fade_out:
        fade_out_start = round(effective_duration - fade_out, 3)
        vf_filters.append(f"fade=t=out:st={fade_out_start}:d={fade_out}")

    # Text overlays
    position_map = {
        "top-left":      ("x=20", "y=20"),
        "top-center":    ("x=(w-text_w)/2", "y=20"),
        "top-right":     ("x=w-text_w-20", "y=20"),
        "center-left":   ("x=20", "y=(h-text_h)/2"),
        "center":        ("x=(w-text_w)/2", "y=(h-text_h)/2"),
        "center-right":  ("x=w-text_w-20", "y=(h-text_h)/2"),
        "bottom-left":   ("x=20", "y=h-text_h-20"),
        "bottom-center": ("x=(w-text_w)/2", "y=h-text_h-20"),
        "bottom-right":  ("x=w-text_w-20", "y=h-text_h-20"),
    }
    for overlay in text_overlays:
        pos = position_map.get(overlay["position"], ("x=(w-text_w)/2", "y=(h-text_h)/2"))
        # Convert hex color to FFmpeg format (FFmpeg uses hex without #)
        color = overlay["color"]
        vf_filters.append(
            f"drawtext=text='{overlay['text']}':fontsize={overlay['fontsize']}"
            f":fontcolor={color}:{pos[0]}:{pos[1]}"
        )

    # ── Audio filters ──

    # Speed (audio) — atempo only accepts 0.5–2.0, chain for wider range
    if speed != 1.0:
        remaining = speed
        while remaining > 2.0:
            af_filters.append("atempo=2.0")
            remaining /= 2.0
        while remaining < 0.5:
            af_filters.append("atempo=0.5")
            remaining /= 0.5
        af_filters.append(f"atempo={round(remaining, 4)}")

    # Volume
    if volume != 1.0:
        af_filters.append(f"volume={volume}")

    # Audio fade in/out
    if fade_in > 0:
        af_filters.append(f"afade=t=in:st=0:d={fade_in}")
    if fade_out > 0 and effective_duration > fade_out:
        fade_out_start = round(effective_duration - fade_out, 3)
        af_filters.append(f"afade=t=out:st={fade_out_start}:d={fade_out}")

    # ── Build FFmpeg command ──
    cmd = ["ffmpeg", "-y", "-i", str(input_path)]

    if vf_filters:
        cmd += ["-vf", ",".join(vf_filters)]

    if af_filters:
        cmd += ["-af", ",".join(af_filters)]
        cmd += ["-c:a", "aac", "-b:a", "128k"]
    else:
        cmd += ["-c:a", "copy"]

    cmd += ["-c:v", "libx264", "-preset", "fast", "-crf", "23"]
    cmd += [str(output_path)]

    result = subprocess.run(cmd, capture_output=True, timeout=300)
    if result.returncode != 0:
        raise RuntimeError(f"Effects processing failed: {result.stderr.decode()[:200]}")


def convert_to_gif(input_path, output_path):
    """Convert a video to optimized GIF (max 30s, 12fps, 480px wide)."""
    cmd = [
        "ffmpeg", "-y", "-i", str(input_path),
        "-t", "30",
        "-vf", "fps=12,scale=480:-1:flags=lanczos,split[s0][s1];[s0]palettegen=max_colors=128[p];[s1][p]paletteuse=dither=bayer",
        "-loop", "0",
        str(output_path),
    ]
    result = subprocess.run(cmd, capture_output=True, timeout=120)
    if result.returncode != 0:
        raise RuntimeError(f"GIF conversion failed: {result.stderr.decode()[:200]}")


def resize_video(input_path, output_path, preset):
    """Resize/compress video for a target platform."""
    preset_cfg = RESIZE_PRESETS.get(preset)
    if not preset_cfg:
        raise ValueError(f"Unknown resize preset: {preset}")

    if "vf" in preset_cfg:
        # Scale/crop preset
        cmd = [
            "ffmpeg", "-y", "-i", str(input_path),
            "-vf", preset_cfg["vf"],
            "-c:v", "libx264", "-preset", "fast", "-crf", "23",
            "-c:a", "aac", "-b:a", "128k",
            str(output_path),
        ]
    else:
        # Size-limited preset (discord/whatsapp): calculate bitrate from duration
        max_bytes = preset_cfg["max_size_mb"] * 1024 * 1024
        # Get duration via ffprobe
        probe = subprocess.run(
            ["ffprobe", "-v", "error", "-show_entries", "format=duration",
             "-of", "default=noprint_wrappers=1:nokey=1", str(input_path)],
            capture_output=True, text=True, timeout=30,
        )
        duration = float(probe.stdout.strip() or "60")
        # Target bitrate: total bits / duration, leaving 128kbps for audio
        audio_bitrate = 128_000
        target_total_bitrate = int((max_bytes * 8) / duration * 0.9)  # 90% safety margin
        video_bitrate = max(100_000, target_total_bitrate - audio_bitrate)

        cmd = [
            "ffmpeg", "-y", "-i", str(input_path),
            "-c:v", "libx264", "-preset", "fast",
            "-b:v", str(video_bitrate),
            "-maxrate", str(video_bitrate),
            "-bufsize", str(video_bitrate * 2),
            "-c:a", "aac", "-b:a", "128k",
            str(output_path),
        ]

    result = subprocess.run(cmd, capture_output=True, timeout=300)
    if result.returncode != 0:
        raise RuntimeError(f"Resize failed: {result.stderr.decode()[:200]}")


def download_subtitles(url, job_dir):
    """Download auto-generated subtitles via yt-dlp. Returns SRT path or None."""
    sub_opts = safe_ydl_opts({
        "skip_download": True,
        "writeautomaticsub": True,
        "subtitleslangs": ["en", "fr"],
        "subtitlesformat": "srt",
        "outtmpl": str(job_dir / "subs.%(ext)s"),
    })
    try:
        with yt_dlp.YoutubeDL(sub_opts) as ydl:
            info = ydl.extract_info(url, download=True)
            # Check for downloaded subtitle files
            for lang in ["en", "fr"]:
                srt_path = job_dir / f"subs.{lang}.srt"
                if srt_path.exists() and srt_path.stat().st_size > 0:
                    return srt_path
                # Also check vtt that may have been auto-converted
                vtt_path = job_dir / f"subs.{lang}.vtt"
                if vtt_path.exists() and vtt_path.stat().st_size > 0:
                    # Convert VTT to SRT using ffmpeg
                    srt_out = job_dir / f"subs.{lang}.srt"
                    conv = subprocess.run(
                        ["ffmpeg", "-y", "-i", str(vtt_path), str(srt_out)],
                        capture_output=True, timeout=30,
                    )
                    if conv.returncode == 0 and srt_out.exists():
                        return srt_out
    except Exception:
        logger.debug("Subtitle download failed", exc_info=True)

    # Whisper fallback: if OPENAI_API_KEY is set, try transcription
    openai_key = os.environ.get("OPENAI_API_KEY", "")
    if openai_key:
        try:
            return _whisper_transcribe(url, job_dir, openai_key)
        except Exception:
            logger.debug("Whisper fallback failed", exc_info=True)

    return None


def _whisper_transcribe(url, job_dir, api_key):
    """Fallback: extract audio and call OpenAI Whisper API for subtitles."""
    import json
    from urllib.request import Request, urlopen

    # Extract audio from existing downloaded video
    audio_path = None
    for f in job_dir.iterdir():
        if f.suffix in (".mp4", ".webm", ".mkv") and f.is_file():
            audio_path = job_dir / "audio_for_whisper.mp3"
            subprocess.run(
                ["ffmpeg", "-y", "-i", str(f), "-vn", "-acodec", "mp3", "-ar", "16000", str(audio_path)],
                capture_output=True, timeout=60,
            )
            break
    if not audio_path or not audio_path.exists():
        return None

    # Call Whisper API
    import io
    boundary = uuid.uuid4().hex
    body = io.BytesIO()
    # model field
    body.write(f"--{boundary}\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nwhisper-1\r\n".encode())
    # response_format field
    body.write(f"--{boundary}\r\nContent-Disposition: form-data; name=\"response_format\"\r\n\r\nsrt\r\n".encode())
    # file field
    body.write(f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"audio.mp3\"\r\nContent-Type: audio/mpeg\r\n\r\n".encode())
    body.write(audio_path.read_bytes())
    body.write(f"\r\n--{boundary}--\r\n".encode())

    req = Request(
        "https://api.openai.com/v1/audio/transcriptions",
        data=body.getvalue(),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
    )
    with urlopen(req, timeout=120) as resp:
        srt_content = resp.read().decode()

    srt_path = job_dir / "whisper_subs.srt"
    srt_path.write_text(srt_content, encoding="utf-8")
    return srt_path


def burn_subtitles(input_path, srt_path, output_path):
    """Burn SRT subtitles into video with modern white-on-dark style."""
    # FFmpeg subtitles filter needs forward slashes and escaped colons/backslashes
    srt_str = str(srt_path).replace("\\", "/").replace(":", "\\:")
    style = "FontSize=22,Bold=1,PrimaryColour=&H00FFFFFF,OutlineColour=&H40000000,BorderStyle=3,Outline=2,MarginV=35"
    cmd = [
        "ffmpeg", "-y", "-i", str(input_path),
        "-vf", f"subtitles={srt_str}:force_style='{style}'",
        "-c:a", "copy",
        str(output_path),
    ]
    result = subprocess.run(cmd, capture_output=True, timeout=300)
    if result.returncode != 0:
        raise RuntimeError(f"Subtitle burn failed: {result.stderr.decode()[:200]}")


def post_process(file_path, job_dir, fmt="mp4", resize=None, subtitles_path=None, effects=None):
    """Run post-processing pipeline: effects → subtitles → resize → GIF conversion."""
    current = Path(file_path)

    # 1. Apply editor effects (only for video formats)
    if effects and fmt not in ("mp3",):
        output = job_dir / f"effects{current.suffix}"
        apply_effects(current, output, effects)
        current = output

    # 2. Burn subtitles (only for video formats)
    if subtitles_path and fmt not in ("mp3", "gif"):
        output = job_dir / f"subbed{current.suffix}"
        burn_subtitles(current, subtitles_path, output)
        current = output

    # 3. Resize for platform (only for video formats)
    if resize and resize in VALID_RESIZE_PRESETS and fmt not in ("mp3", "gif"):
        output = job_dir / f"resized{current.suffix}"
        resize_video(current, output, resize)
        current = output

    # 4. GIF conversion (changes format entirely)
    if fmt == "gif":
        output = job_dir / "output.gif"
        convert_to_gif(current, output)
        current = output

    return current


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

    # YouTube: try oEmbed + innertube first (bypasses bot detection on datacenter IPs)
    if platform == "youtube":
        yt_id = extract_video_id(url)
        fallback = youtube_video_info_fallback(url, yt_id)
        if fallback:
            return jsonify(fallback)

    # Non-YouTube platforms (or YouTube fallback failed): use yt-dlp
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
    except yt_dlp.utils.DownloadError as e:
        logger.warning("video-info DownloadError: %s", str(e)[:500])
        return jsonify({"error": "Could not fetch video info. The URL may be invalid or the video may be unavailable."}), 400
    except Exception as e:
        logger.exception("video-info error: %s", str(e)[:500])
        return jsonify({"error": f"An unexpected error occurred: {str(e)[:150]}"}), 500


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
    resize = data.get("resize", "")
    subtitles = data.get("subtitles", False)
    effects = validate_effects(data) if data.get("effects") else None
    platform, err = validate_url(url)
    if err:
        return jsonify({"error": err}), 400

    # Validate resize preset
    if resize and resize not in VALID_RESIZE_PRESETS:
        return jsonify({"error": "Invalid resize preset."}), 400

    job_id = uuid.uuid4().hex[:12]
    job_dir = TEMP_DIR / job_id
    job_dir.mkdir(exist_ok=True)

    try:
        # Download subtitles if requested
        srt_path = None
        if subtitles and fmt not in ("mp3", "gif"):
            srt_path = download_subtitles(url, job_dir)

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

        # Post-process (effects, subtitles, resize, GIF)
        final_file = post_process(dl_file, job_dir, fmt=fmt, resize=resize or None, subtitles_path=srt_path, effects=effects)

        # Check file size
        if final_file.stat().st_size > MAX_FILE_SIZE:
            cleanup_job_dir(job_dir)
            return jsonify({"error": "File too large (>100MB)."}), 413

        ext = final_file.suffix or ".mp4"
        mime = mimetypes.guess_type(final_file.name)[0] or "application/octet-stream"
        return send_file(
            str(final_file),
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
    resize = data.get("resize", "")
    subtitles = data.get("subtitles", False)
    effects = validate_effects(data) if data.get("effects") else None

    platform, err = validate_url(url)
    if err:
        return jsonify({"error": err}), 400

    # Validate resize preset
    if resize and resize not in VALID_RESIZE_PRESETS:
        return jsonify({"error": "Invalid resize preset."}), 400

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
        # Download subtitles if requested
        srt_path = None
        if subtitles and fmt not in ("mp3", "gif"):
            srt_path = download_subtitles(url, job_dir)

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

        # Post-process (effects, subtitles, resize, GIF)
        final_file = post_process(clip_file, job_dir, fmt=fmt, resize=resize or None, subtitles_path=srt_path, effects=effects)

        if final_file.stat().st_size > MAX_FILE_SIZE:
            cleanup_job_dir(job_dir)
            return jsonify({"error": "File too large (>100MB)."}), 413

        ext = final_file.suffix or ".mp4"
        mime = mimetypes.guess_type(final_file.name)[0] or "application/octet-stream"
        return send_file(
            str(final_file),
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
    resize = data.get("resize", "")
    subtitles = data.get("subtitles", False)
    effects = validate_effects(data) if data.get("effects") else None

    platform, err = validate_url(url)
    if err:
        return jsonify({"error": err}), 400

    # Validate resize preset
    if resize and resize not in VALID_RESIZE_PRESETS:
        return jsonify({"error": "Invalid resize preset."}), 400

    job_id = uuid.uuid4().hex[:12]
    job_dir = TEMP_DIR / job_id
    job_dir.mkdir(exist_ok=True)

    try:
        # Download subtitles if requested
        srt_path = None
        if subtitles and fmt not in ("mp3", "gif"):
            srt_path = download_subtitles(url, job_dir)

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

        # Post-process (effects, subtitles, resize, GIF)
        final_file = post_process(dl_file, job_dir, fmt=fmt, resize=resize or None, subtitles_path=srt_path, effects=effects)

        if final_file.stat().st_size > MAX_FILE_SIZE:
            cleanup_job_dir(job_dir)
            return jsonify({"error": "File too large (>100MB)."}), 413

        # Upload to Supabase
        user_id = require_auth()
        result = upload_to_library(final_file, {
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
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}

:root {
  --bg-deep: #06060a;
  --bg-glass: rgba(255,255,255,0.04);
  --bg-glass-hover: rgba(255,255,255,0.07);
  --bg-glass-active: rgba(255,255,255,0.10);
  --border: rgba(255,255,255,0.08);
  --border-light: rgba(255,255,255,0.12);
  --border-focus: rgba(59,130,246,0.5);
  --text-primary: #e2e8f0;
  --text-secondary: #94a3b8;
  --text-muted: #475569;
  --accent: #3b82f6;
  --accent-cyan: #06b6d4;
  --accent-dim: rgba(59,130,246,0.1);
  --accent-glow: rgba(59,130,246,0.15);
  --danger: #ef4444;
  --danger-dim: rgba(239,68,68,0.1);
  --success: #10b981;
  --success-dim: rgba(16,185,129,0.1);
  --yt: #ff0033;
  --tw: #1d9bf0;
  --ig: #e1306c;
  --tk: #00f2ea;
  --twitch: #9146ff;
  --sc: #ff5500;
  --radius-sm: 8px;
  --radius-md: 12px;
  --radius-lg: 20px;
  --blur: 12px;
  --transition: 200ms ease;
}

html { font-size: 15px; scroll-behavior: smooth; }

body {
  font-family: 'DM Sans', -apple-system, BlinkMacSystemFont, sans-serif;
  background: var(--bg-deep);
  color: var(--text-primary);
  min-height: 100vh;
  overflow-x: hidden;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  line-height: 1.55;
  letter-spacing: -0.01em;
  font-weight: 500;
}

/* ── Ambient background blobs ─────────────── */
body::before, body::after {
  content: '';
  position: fixed;
  border-radius: 50%;
  filter: blur(120px);
  opacity: 0.07;
  pointer-events: none;
  z-index: 0;
}
body::before {
  width: 600px; height: 600px;
  top: -200px; left: -100px;
  background: radial-gradient(circle, #3b82f6, transparent 70%);
}
body::after {
  width: 500px; height: 500px;
  bottom: -150px; right: -100px;
  background: radial-gradient(circle, #7c3aed, transparent 70%);
}

/* ── Glass mixin ──────────────────────────── */
.glass {
  background: var(--bg-glass);
  backdrop-filter: blur(var(--blur));
  -webkit-backdrop-filter: blur(var(--blur));
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  box-shadow: 0 8px 32px rgba(0,0,0,0.3), inset 0 1px 1px rgba(255,255,255,0.04);
  position: relative;
}

/* Grain texture overlay */
.glass::before {
  content: '';
  position: absolute;
  inset: 0;
  border-radius: inherit;
  opacity: 0.03;
  pointer-events: none;
  z-index: 0;
  background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.65' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");
  background-size: 128px 128px;
}

.glass > * { position: relative; z-index: 1; }

/* ── App layout ───────────────────────────── */
.app {
  position: relative;
  z-index: 1;
  max-width: 720px;
  margin: 0 auto;
  padding: 24px 16px 80px;
}

/* ── Navbar ────────────────────────────────── */
.navbar {
  position: fixed;
  top: 16px;
  left: 50%;
  transform: translateX(-50%);
  width: calc(100% - 32px);
  max-width: 720px;
  z-index: 100;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 20px;
  background: rgba(6,6,10,0.8);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border: 1px solid var(--border);
  border-radius: 16px;
}

.navbar-brand {
  display: flex;
  align-items: center;
  gap: 10px;
  font-family: 'JetBrains Mono', monospace;
  font-weight: 600;
  font-size: 0.95rem;
  letter-spacing: -0.02em;
  color: var(--text-primary);
  text-decoration: none;
}

.navbar-logo {
  width: 28px; height: 28px;
  background: linear-gradient(135deg, var(--accent), var(--accent-cyan));
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.navbar-logo svg { width: 16px; height: 16px; color: #fff; }

.navbar-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

.btn-nav {
  background: var(--bg-glass);
  border: 1px solid var(--border);
  color: var(--text-secondary);
  padding: 8px 14px;
  border-radius: var(--radius-sm);
  font-size: 0.8rem;
  font-weight: 600;
  cursor: pointer;
  transition: all var(--transition);
  font-family: inherit;
  display: flex;
  align-items: center;
  gap: 6px;
}

.btn-nav:hover {
  background: var(--bg-glass-hover);
  color: var(--text-primary);
  border-color: var(--border-light);
}

.btn-nav svg { width: 14px; height: 14px; }

.btn-nav.active {
  background: var(--accent-dim);
  color: var(--accent);
  border-color: rgba(59,130,246,0.3);
}

/* ── Spacer for fixed navbar ──────────────── */
.nav-spacer { height: 72px; }

/* ── Hero / URL input ─────────────────────── */
.hero {
  text-align: center;
  margin-bottom: 32px;
  animation: fadeUp 0.6s ease-out;
}

.hero h1 {
  font-size: 2rem;
  font-weight: 700;
  letter-spacing: -0.03em;
  line-height: 1.2;
  margin-bottom: 8px;
  background: linear-gradient(135deg, var(--text-primary) 0%, var(--text-secondary) 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

.hero p {
  color: var(--text-secondary);
  font-size: 0.95rem;
}

.url-card {
  padding: 20px;
  margin-bottom: 24px;
  animation: fadeUp 0.6s ease-out 0.1s both;
}

.url-input-row {
  display: flex;
  gap: 10px;
}

.url-input {
  flex: 1;
  background: rgba(0,0,0,0.3);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 14px 16px;
  color: var(--text-primary);
  font-size: 0.95rem;
  font-family: inherit;
  font-weight: 500;
  outline: none;
  transition: border-color var(--transition), box-shadow var(--transition);
}

.url-input::placeholder { color: var(--text-muted); }

.url-input:focus {
  border-color: var(--border-focus);
  box-shadow: 0 0 0 3px rgba(59,130,246,0.1);
}

.btn-load {
  background: linear-gradient(135deg, var(--accent), var(--accent-cyan));
  border: none;
  color: #fff;
  padding: 14px 24px;
  border-radius: var(--radius-md);
  font-size: 0.9rem;
  font-weight: 600;
  font-family: inherit;
  cursor: pointer;
  transition: all var(--transition);
  white-space: nowrap;
  position: relative;
  overflow: hidden;
}

.btn-load:hover { opacity: 0.9; transform: translateY(-1px); }
.btn-load:active { transform: translateY(0); }
.btn-load:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }

/* Glow border animation on CTA */
.btn-load::before {
  content: '';
  position: absolute;
  inset: -1px;
  border-radius: inherit;
  background: conic-gradient(from var(--glow-angle, 0deg), transparent 60%, rgba(59,130,246,0.4) 80%, transparent 100%);
  z-index: -1;
  animation: glowRotate 4s linear infinite;
}

@property --glow-angle {
  syntax: '<angle>';
  initial-value: 0deg;
  inherits: false;
}

@keyframes glowRotate { to { --glow-angle: 360deg; } }

.platform-pills {
  display: flex;
  gap: 6px;
  margin-top: 12px;
  justify-content: center;
  flex-wrap: wrap;
}

.platform-pill {
  display: flex;
  align-items: center;
  gap: 5px;
  padding: 5px 10px;
  border-radius: 20px;
  border: 1px solid transparent;
  background: transparent;
  color: var(--text-muted);
  font-size: 0.7rem;
  font-weight: 600;
  font-family: inherit;
  cursor: default;
  transition: all var(--transition);
}

.platform-pill svg { width: 12px; height: 12px; }
.platform-pill.active.youtube { color: var(--yt); border-color: rgba(255,0,51,0.3); background: rgba(255,0,51,0.08); }
.platform-pill.active.twitter { color: var(--tw); border-color: rgba(29,155,240,0.3); background: rgba(29,155,240,0.08); }
.platform-pill.active.instagram { color: var(--ig); border-color: rgba(225,48,108,0.3); background: rgba(225,48,108,0.08); }
.platform-pill.active.tiktok { color: var(--tk); border-color: rgba(0,242,234,0.3); background: rgba(0,242,234,0.08); }
.platform-pill.active.twitch { color: var(--twitch); border-color: rgba(145,70,255,0.3); background: rgba(145,70,255,0.08); }
.platform-pill.active.soundcloud { color: var(--sc); border-color: rgba(255,85,0,0.3); background: rgba(255,85,0,0.08); }

.error-msg {
  color: var(--danger);
  font-size: 0.8rem;
  margin-top: 8px;
  display: none;
}
.error-msg.visible { display: block; }

/* ── Sections (hidden by default) ─────────── */
.section { display: none; margin-bottom: 20px; animation: fadeUp 0.4s ease-out; }
.section.visible { display: block; }

/* ── Preview card ─────────────────────────── */
.preview-card { padding: 20px; }

.video-meta {
  display: flex;
  gap: 16px;
  margin-bottom: 16px;
}

.video-thumb {
  width: 160px;
  height: 90px;
  object-fit: cover;
  border-radius: var(--radius-sm);
  background: rgba(0,0,0,0.3);
  flex-shrink: 0;
}

.video-info { flex: 1; min-width: 0; }

.video-info h3 {
  font-size: 1rem;
  font-weight: 600;
  letter-spacing: -0.01em;
  margin-bottom: 4px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.video-channel {
  color: var(--text-secondary);
  font-size: 0.8rem;
  margin-bottom: 6px;
}

.platform-badge {
  display: none;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  border-radius: 20px;
  font-size: 0.7rem;
  font-weight: 600;
  width: fit-content;
}

.platform-badge.visible { display: inline-flex; }
.platform-badge svg { width: 12px; height: 12px; }
.platform-badge.youtube { background: rgba(255,0,51,0.1); color: var(--yt); }
.platform-badge.twitter { background: rgba(29,155,240,0.1); color: var(--tw); }
.platform-badge.instagram { background: rgba(225,48,108,0.1); color: var(--ig); }
.platform-badge.tiktok { background: rgba(0,242,234,0.1); color: var(--tk); }
.platform-badge.twitch { background: rgba(145,70,255,0.1); color: var(--twitch); }
.platform-badge.soundcloud { background: rgba(255,85,0,0.1); color: var(--sc); }

.duration-badge {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.75rem;
  color: var(--text-secondary);
  background: rgba(0,0,0,0.3);
  padding: 2px 8px;
  border-radius: 4px;
  width: fit-content;
}

.player-wrap {
  position: relative;
  width: 100%;
  padding-top: 56.25%;
  background: rgba(0,0,0,0.4);
  border-radius: var(--radius-md);
  overflow: hidden;
  margin-top: 4px;
}

.player-wrap iframe {
  position: absolute;
  top: 0; left: 0;
  width: 100%; height: 100%;
  border: none;
}

.no-embed {
  position: absolute;
  top: 0; left: 0;
  width: 100%; height: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--text-muted);
  font-size: 0.85rem;
  text-align: center;
  padding: 20px;
}

/* ── Mode toggle ──────────────────────────── */
.mode-toggle {
  display: none;
  gap: 4px;
  padding: 4px;
  background: var(--bg-glass);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  margin-bottom: 20px;
}
.mode-toggle.visible { display: flex; }

.mode-btn {
  flex: 1;
  padding: 10px 16px;
  border: none;
  border-radius: var(--radius-sm);
  background: transparent;
  color: var(--text-secondary);
  font-size: 0.85rem;
  font-weight: 600;
  font-family: inherit;
  cursor: pointer;
  transition: all var(--transition);
}

.mode-btn:hover { color: var(--text-primary); }

.mode-btn.active {
  background: var(--accent-dim);
  color: var(--accent);
  box-shadow: 0 0 20px rgba(59,130,246,0.08);
}

/* ── Options card (quality/format/export) ─── */
.options-card {
  padding: 20px;
  display: none;
}
.options-card.visible { display: block; }

.option-row {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 12px;
}

.option-row:last-child { margin-bottom: 0; }

.option-label {
  font-size: 0.75rem;
  font-weight: 600;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  width: 56px;
  flex-shrink: 0;
}

.pill-group {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
  flex: 1;
}

.pill {
  padding: 7px 14px;
  border: 1px solid var(--border);
  border-radius: 20px;
  background: transparent;
  color: var(--text-secondary);
  font-size: 0.8rem;
  font-weight: 600;
  font-family: inherit;
  cursor: pointer;
  transition: all var(--transition);
}

.pill:hover {
  background: var(--bg-glass-hover);
  color: var(--text-primary);
  border-color: var(--border-light);
}

.pill.active {
  background: var(--accent-dim);
  color: var(--accent);
  border-color: rgba(59,130,246,0.3);
}

.gif-note {
  font-size: 0.7rem;
  color: var(--text-muted);
  display: none;
}
.gif-note.visible { display: inline; }

.subtitle-check {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--text-secondary);
  font-size: 0.85rem;
  cursor: pointer;
}

.subtitle-check input[type="checkbox"] {
  width: 16px; height: 16px;
  accent-color: var(--accent);
  cursor: pointer;
}

.subtitle-note {
  font-size: 0.7rem;
  color: var(--text-muted);
  margin-left: 4px;
}

/* ── Timeline ─────────────────────────────── */
.timeline-card {
  padding: 20px;
}

.time-controls {
  display: flex;
  gap: 12px;
  margin-bottom: 16px;
}

.time-field { flex: 1; }

.time-field label {
  display: block;
  font-size: 0.7rem;
  font-weight: 600;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: 6px;
}

.time-field input {
  width: 100%;
  background: rgba(0,0,0,0.3);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 10px 12px;
  color: var(--text-primary);
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.9rem;
  font-weight: 500;
  outline: none;
  transition: border-color var(--transition);
}

.time-field input:focus {
  border-color: var(--border-focus);
}

.timeline-track {
  position: relative;
  height: 48px;
  background: rgba(0,0,0,0.3);
  border-radius: var(--radius-sm);
  overflow: hidden;
  cursor: pointer;
}

.timeline-waveform {
  display: flex;
  align-items: flex-end;
  gap: 2px;
  height: 100%;
  padding: 6px 4px;
  position: absolute;
  inset: 0;
  z-index: 1;
}

.timeline-waveform .bar {
  flex: 1;
  min-width: 2px;
  background: rgba(255,255,255,0.08);
  border-radius: 1px;
  transition: background var(--transition);
}

.timeline-region {
  position: absolute;
  top: 0; bottom: 0;
  background: rgba(59,130,246,0.12);
  z-index: 2;
  pointer-events: none;
}

.timeline-handle {
  position: absolute;
  top: 50%;
  transform: translateY(-50%);
  width: 14px;
  height: 32px;
  background: var(--accent);
  border-radius: 4px;
  z-index: 3;
  cursor: grab;
  transition: box-shadow var(--transition);
  box-shadow: 0 0 12px rgba(59,130,246,0.3);
}

.timeline-handle:hover, .timeline-handle:focus {
  box-shadow: 0 0 20px rgba(59,130,246,0.5);
  outline: none;
}

.timeline-handle::after {
  content: '';
  position: absolute;
  top: 50%; left: 50%;
  transform: translate(-50%,-50%);
  width: 2px;
  height: 14px;
  background: rgba(255,255,255,0.6);
  border-radius: 1px;
}

.timeline-labels {
  display: flex;
  justify-content: space-between;
  margin-top: 6px;
  font-size: 0.7rem;
  font-family: 'JetBrains Mono', monospace;
  color: var(--text-muted);
}

.clip-duration {
  text-align: center;
  margin-top: 8px;
  font-size: 0.8rem;
  color: var(--text-secondary);
}

.clip-duration span {
  font-family: 'JetBrains Mono', monospace;
  color: var(--accent);
  font-weight: 600;
}

/* ── Action section ───────────────────────── */
.action-section {
  display: none;
  text-align: center;
  margin-bottom: 20px;
}
.action-section.visible { display: block; }

.action-buttons {
  display: flex;
  gap: 10px;
}

.btn-action {
  flex: 1;
  padding: 14px 24px;
  border: none;
  border-radius: var(--radius-md);
  font-size: 0.9rem;
  font-weight: 600;
  font-family: inherit;
  cursor: pointer;
  transition: all var(--transition);
  background: linear-gradient(135deg, var(--accent), var(--accent-cyan));
  color: #fff;
}

.btn-action:hover { opacity: 0.9; transform: translateY(-1px); }
.btn-action:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }

.btn-save-trigger {
  flex: 1;
  padding: 14px 24px;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  font-size: 0.9rem;
  font-weight: 600;
  font-family: inherit;
  cursor: pointer;
  transition: all var(--transition);
  background: var(--bg-glass);
  color: var(--text-secondary);
}

.btn-save-trigger:hover {
  background: var(--bg-glass-hover);
  color: var(--text-primary);
  border-color: var(--border-light);
}

.btn-save-trigger.saved {
  color: var(--success);
  border-color: rgba(16,185,129,0.3);
  background: var(--success-dim);
}

.limit-note {
  font-size: 0.75rem;
  color: var(--text-muted);
  margin-top: 8px;
}

/* ── Progress ─────────────────────────────── */
.progress-card {
  padding: 24px;
  text-align: center;
}

.progress-bar-track {
  width: 100%;
  height: 4px;
  background: rgba(255,255,255,0.06);
  border-radius: 2px;
  overflow: hidden;
  margin-bottom: 16px;
}

.progress-bar-fill {
  height: 100%;
  width: 30%;
  background: linear-gradient(90deg, var(--accent), var(--accent-cyan));
  border-radius: 2px;
  animation: progressPulse 2s ease-in-out infinite;
}

@keyframes progressPulse {
  0%, 100% { width: 30%; opacity: 1; }
  50% { width: 70%; opacity: 0.7; }
}

.progress-status {
  color: var(--text-secondary);
  font-size: 0.85rem;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
}

.spinner {
  width: 16px; height: 16px;
  border: 2px solid rgba(255,255,255,0.1);
  border-top-color: var(--accent);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
  display: inline-block;
}

@keyframes spin { to { transform: rotate(360deg); } }

/* ── Download section ─────────────────────── */
.download-card {
  padding: 32px 24px;
  text-align: center;
}

.download-icon {
  width: 48px; height: 48px;
  margin: 0 auto 12px;
  background: var(--success-dim);
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
}

.download-icon svg { width: 22px; height: 22px; stroke: var(--success); }

.download-card h3 {
  font-size: 1.1rem;
  font-weight: 600;
  margin-bottom: 4px;
}

.download-info {
  color: var(--text-muted);
  font-size: 0.85rem;
  margin-bottom: 16px;
}

.btn-download {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 12px 28px;
  background: linear-gradient(135deg, var(--accent), var(--accent-cyan));
  color: #fff;
  text-decoration: none;
  border-radius: var(--radius-md);
  font-weight: 600;
  font-size: 0.9rem;
  transition: all var(--transition);
}

.btn-download:hover { opacity: 0.9; transform: translateY(-1px); }

.download-secondary {
  display: flex;
  gap: 12px;
  justify-content: center;
  margin-top: 16px;
}

.btn-secondary {
  padding: 8px 16px;
  background: var(--bg-glass);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  color: var(--text-secondary);
  font-size: 0.8rem;
  font-weight: 600;
  font-family: inherit;
  cursor: pointer;
  transition: all var(--transition);
}

.btn-secondary:hover {
  background: var(--bg-glass-hover);
  color: var(--text-primary);
}

/* ── Save dialog ──────────────────────────── */
.save-dialog {
  display: none;
  margin-top: 16px;
  text-align: left;
}
.save-dialog.visible { display: block; }

.save-dialog label {
  display: block;
  font-size: 0.75rem;
  font-weight: 600;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: 6px;
}

.save-dialog input[type="text"] {
  width: 100%;
  background: rgba(0,0,0,0.3);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 10px 12px;
  color: var(--text-primary);
  font-family: inherit;
  font-size: 0.9rem;
  font-weight: 500;
  outline: none;
  margin-bottom: 12px;
  transition: border-color var(--transition);
}

.save-dialog input[type="text"]:focus { border-color: var(--border-focus); }

.tag-input-wrap {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  padding: 8px 10px;
  background: rgba(0,0,0,0.3);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  cursor: text;
  margin-bottom: 12px;
}

.tag-chip {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 3px 8px;
  background: var(--accent-dim);
  color: var(--accent);
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
}

.tag-remove {
  cursor: pointer;
  opacity: 0.6;
  font-size: 0.85rem;
}

.tag-remove:hover { opacity: 1; }

.tag-input-field {
  border: none;
  background: transparent;
  color: var(--text-primary);
  font-family: inherit;
  font-size: 0.85rem;
  outline: none;
  min-width: 80px;
  flex: 1;
}

.tag-input-field::placeholder { color: var(--text-muted); }

.save-actions {
  display: flex;
  gap: 8px;
}

.btn-confirm {
  flex: 1;
  padding: 10px 16px;
  background: linear-gradient(135deg, var(--accent), var(--accent-cyan));
  border: none;
  color: #fff;
  border-radius: var(--radius-sm);
  font-size: 0.85rem;
  font-weight: 600;
  font-family: inherit;
  cursor: pointer;
  transition: all var(--transition);
}

.btn-confirm:hover { opacity: 0.9; }
.btn-confirm:disabled { opacity: 0.5; cursor: not-allowed; }

.btn-cancel {
  padding: 10px 16px;
  background: var(--bg-glass);
  border: 1px solid var(--border);
  color: var(--text-secondary);
  border-radius: var(--radius-sm);
  font-size: 0.85rem;
  font-weight: 600;
  font-family: inherit;
  cursor: pointer;
  transition: all var(--transition);
}

.btn-cancel:hover { background: var(--bg-glass-hover); color: var(--text-primary); }

/* ── Library slide-out panel ──────────────── */
.library-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.5);
  z-index: 200;
  opacity: 0;
  visibility: hidden;
  transition: opacity 0.3s ease, visibility 0.3s ease;
}

.library-overlay.visible {
  opacity: 1;
  visibility: visible;
}

.library-panel {
  position: fixed;
  top: 0; right: 0;
  width: 420px;
  max-width: 100%;
  height: 100vh;
  background: rgba(10,10,16,0.95);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border-left: 1px solid var(--border);
  z-index: 201;
  transform: translateX(100%);
  transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.library-overlay.visible .library-panel {
  transform: translateX(0);
}

.library-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 20px 20px 16px;
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}

.library-header h2 {
  font-size: 1.1rem;
  font-weight: 700;
  letter-spacing: -0.02em;
}

.btn-close-library {
  background: var(--bg-glass);
  border: 1px solid var(--border);
  color: var(--text-secondary);
  width: 32px; height: 32px;
  border-radius: var(--radius-sm);
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all var(--transition);
  font-size: 1rem;
}

.btn-close-library:hover { background: var(--bg-glass-hover); color: var(--text-primary); }

.library-toolbar {
  padding: 12px 20px;
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}

.library-search {
  width: 100%;
  background: rgba(0,0,0,0.3);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 10px 12px;
  color: var(--text-primary);
  font-family: inherit;
  font-size: 0.85rem;
  font-weight: 500;
  outline: none;
  margin-bottom: 10px;
  transition: border-color var(--transition);
}

.library-search::placeholder { color: var(--text-muted); }
.library-search:focus { border-color: var(--border-focus); }

.library-filters {
  display: flex;
  gap: 4px;
  flex-wrap: wrap;
  margin-bottom: 10px;
}

.filter-pill {
  padding: 4px 10px;
  border: 1px solid transparent;
  border-radius: 20px;
  background: transparent;
  color: var(--text-muted);
  font-size: 0.7rem;
  font-weight: 600;
  font-family: inherit;
  cursor: pointer;
  transition: all var(--transition);
}

.filter-pill:hover { color: var(--text-secondary); }

.filter-pill.active {
  background: var(--accent-dim);
  color: var(--accent);
  border-color: rgba(59,130,246,0.2);
}

.library-sort-row {
  display: flex;
  align-items: center;
  gap: 8px;
}

.library-sort {
  flex: 1;
  background: rgba(0,0,0,0.3);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 6px 10px;
  color: var(--text-secondary);
  font-family: inherit;
  font-size: 0.8rem;
  font-weight: 500;
  outline: none;
  cursor: pointer;
}

.library-sort option { background: #111; }

.btn-select-all {
  padding: 6px 12px;
  background: var(--bg-glass);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  color: var(--text-muted);
  font-size: 0.75rem;
  font-weight: 600;
  font-family: inherit;
  cursor: pointer;
  transition: all var(--transition);
  white-space: nowrap;
}

.btn-select-all:hover { color: var(--text-secondary); background: var(--bg-glass-hover); }

.library-stats {
  padding: 8px 20px;
  font-size: 0.75rem;
  color: var(--text-muted);
  flex-shrink: 0;
}

.library-grid {
  flex: 1;
  overflow-y: auto;
  padding: 8px 20px 20px;
  scrollbar-width: thin;
  scrollbar-color: rgba(255,255,255,0.06) transparent;
}

.library-grid::-webkit-scrollbar { width: 4px; }
.library-grid::-webkit-scrollbar-track { background: transparent; }
.library-grid::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.08); border-radius: 10px; }

.library-empty {
  text-align: center;
  padding: 48px 20px;
  color: var(--text-muted);
}

.library-empty svg { margin-bottom: 8px; }
.library-empty p { font-size: 0.85rem; }
.library-empty .sub { font-size: 0.75rem; margin-top: 4px; }

/* ── Clip cards ───────────────────────────── */
.clip-card {
  display: flex;
  gap: 12px;
  padding: 12px;
  background: var(--bg-glass);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  margin-bottom: 8px;
  transition: all var(--transition);
  cursor: default;
}

.clip-card:hover {
  background: var(--bg-glass-hover);
  border-color: var(--border-light);
}

.clip-card.selected {
  border-color: rgba(59,130,246,0.3);
  background: var(--accent-dim);
}

.clip-card-thumb {
  position: relative;
  width: 80px;
  height: 50px;
  flex-shrink: 0;
  border-radius: 6px;
  overflow: hidden;
  background: rgba(0,0,0,0.3);
}

.clip-card-thumb img {
  width: 100%; height: 100%;
  object-fit: cover;
}

.clip-checkbox {
  position: absolute;
  top: 4px; left: 4px;
  width: 16px; height: 16px;
  border: 2px solid rgba(255,255,255,0.3);
  border-radius: 3px;
  cursor: pointer;
  z-index: 2;
  transition: all var(--transition);
  background: rgba(0,0,0,0.4);
}

.clip-checkbox:hover { border-color: var(--accent); }

.clip-checkbox.checked {
  background: var(--accent);
  border-color: var(--accent);
}

.clip-checkbox.checked::after {
  content: '';
  position: absolute;
  top: 1px; left: 4px;
  width: 4px; height: 8px;
  border: solid #fff;
  border-width: 0 2px 2px 0;
  transform: rotate(45deg);
}

.clip-favorite {
  position: absolute;
  top: 4px; right: 4px;
  background: rgba(0,0,0,0.4);
  border: none;
  color: rgba(255,255,255,0.4);
  font-size: 0.75rem;
  cursor: pointer;
  padding: 2px;
  border-radius: 3px;
  z-index: 2;
  line-height: 1;
  transition: color var(--transition);
}

.clip-favorite:hover { color: #fbbf24; }
.clip-favorite.active { color: #fbbf24; }

.clip-platform-tag {
  position: absolute;
  bottom: 4px; left: 4px;
  padding: 1px 5px;
  border-radius: 3px;
  font-size: 0.55rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.03em;
  z-index: 2;
}

.clip-platform-tag.youtube { background: rgba(255,0,51,0.8); color: #fff; }
.clip-platform-tag.twitter { background: rgba(29,155,240,0.8); color: #fff; }
.clip-platform-tag.instagram { background: rgba(225,48,108,0.8); color: #fff; }
.clip-platform-tag.tiktok { background: rgba(0,242,234,0.8); color: #000; }
.clip-platform-tag.twitch { background: rgba(145,70,255,0.8); color: #fff; }
.clip-platform-tag.soundcloud { background: rgba(255,85,0,0.8); color: #fff; }

.clip-card-body {
  flex: 1;
  min-width: 0;
}

.clip-title-edit {
  font-size: 0.85rem;
  font-weight: 600;
  margin-bottom: 2px;
  cursor: pointer;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  transition: color var(--transition);
}

.clip-title-edit:hover { color: var(--accent); }

.clip-tags {
  display: flex;
  gap: 4px;
  flex-wrap: wrap;
  margin-bottom: 4px;
}

.clip-tag {
  font-size: 0.65rem;
  padding: 1px 6px;
  background: var(--accent-dim);
  color: var(--accent);
  border-radius: 3px;
  font-weight: 600;
}

.clip-meta {
  font-size: 0.7rem;
  color: var(--text-muted);
  margin-bottom: 6px;
}

.clip-card-actions {
  display: flex;
  gap: 6px;
}

.clip-btn-dl, .clip-btn-del {
  padding: 3px 8px;
  border-radius: 4px;
  font-size: 0.7rem;
  font-weight: 600;
  font-family: inherit;
  cursor: pointer;
  transition: all var(--transition);
  text-decoration: none;
}

.clip-btn-dl {
  background: var(--accent-dim);
  color: var(--accent);
  border: none;
}

.clip-btn-dl:hover { background: rgba(59,130,246,0.2); }

.clip-btn-del {
  background: transparent;
  color: var(--text-muted);
  border: 1px solid var(--border);
}

.clip-btn-del:hover {
  background: var(--danger-dim);
  color: var(--danger);
  border-color: rgba(239,68,68,0.3);
}

/* Skeleton cards */
.skeleton-card {
  padding: 12px;
  background: var(--bg-glass);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  margin-bottom: 8px;
}

.skeleton-thumb {
  width: 80px;
  height: 50px;
  background: rgba(255,255,255,0.04);
  border-radius: 6px;
  animation: shimmer 1.5s ease-in-out infinite;
}

.skeleton-line {
  height: 12px;
  background: rgba(255,255,255,0.04);
  border-radius: 3px;
  margin-top: 8px;
  animation: shimmer 1.5s ease-in-out infinite;
}

.skeleton-line.short { width: 60%; }

@keyframes shimmer {
  0%, 100% { opacity: 0.4; }
  50% { opacity: 0.8; }
}

.btn-load-more {
  display: none;
  width: 100%;
  padding: 10px;
  background: var(--bg-glass);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  color: var(--text-secondary);
  font-size: 0.8rem;
  font-weight: 600;
  font-family: inherit;
  cursor: pointer;
  transition: all var(--transition);
  margin-top: 8px;
}

.btn-load-more.visible { display: block; }
.btn-load-more:hover { background: var(--bg-glass-hover); color: var(--text-primary); }

/* ── Bulk action bar ──────────────────────── */
.bulk-bar {
  display: none;
  align-items: center;
  justify-content: space-between;
  padding: 12px 20px;
  background: rgba(59,130,246,0.1);
  border-top: 1px solid rgba(59,130,246,0.2);
  flex-shrink: 0;
}

.bulk-bar.visible { display: flex; }

.bulk-bar-info {
  font-size: 0.8rem;
  font-weight: 600;
  color: var(--accent);
}

.bulk-bar-actions { display: flex; gap: 8px; }

.bulk-btn {
  padding: 6px 14px;
  border-radius: var(--radius-sm);
  font-size: 0.75rem;
  font-weight: 600;
  font-family: inherit;
  cursor: pointer;
  transition: all var(--transition);
  border: none;
}

.bulk-btn-download { background: var(--accent-dim); color: var(--accent); }
.bulk-btn-download:hover { background: rgba(59,130,246,0.2); }
.bulk-btn-delete { background: var(--danger-dim); color: var(--danger); }
.bulk-btn-delete:hover { background: rgba(239,68,68,0.2); }

/* ── Modal (edit + auth) ──────────────────── */
.modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.6);
  backdrop-filter: blur(4px);
  z-index: 300;
  display: none;
  align-items: center;
  justify-content: center;
  padding: 20px;
}

.modal-overlay.visible { display: flex; }

.modal {
  background: rgba(16,16,24,0.95);
  backdrop-filter: blur(20px);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 28px;
  width: 100%;
  max-width: 400px;
  box-shadow: 0 24px 64px rgba(0,0,0,0.5);
}

.modal h3 {
  font-size: 1.1rem;
  font-weight: 700;
  letter-spacing: -0.02em;
  margin-bottom: 20px;
}

.modal label {
  display: block;
  font-size: 0.75rem;
  font-weight: 600;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: 6px;
}

.modal input[type="text"],
.modal input[type="email"],
.modal input[type="password"] {
  width: 100%;
  background: rgba(0,0,0,0.3);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 11px 14px;
  color: var(--text-primary);
  font-family: inherit;
  font-size: 0.9rem;
  font-weight: 500;
  outline: none;
  margin-bottom: 14px;
  transition: border-color var(--transition);
}

.modal input:focus { border-color: var(--border-focus); }

.modal-actions {
  display: flex;
  gap: 8px;
  margin-top: 4px;
}

.auth-error {
  color: var(--danger);
  font-size: 0.8rem;
  margin-bottom: 12px;
  display: none;
}
.auth-error.visible { display: block; }

.auth-submit {
  width: 100%;
  padding: 12px;
  background: linear-gradient(135deg, var(--accent), var(--accent-cyan));
  border: none;
  color: #fff;
  border-radius: var(--radius-sm);
  font-size: 0.9rem;
  font-weight: 600;
  font-family: inherit;
  cursor: pointer;
  transition: all var(--transition);
}

.auth-submit:hover { opacity: 0.9; }
.auth-submit:disabled { opacity: 0.5; cursor: not-allowed; }

.auth-toggle {
  text-align: center;
  margin-top: 16px;
  font-size: 0.8rem;
  color: var(--text-muted);
}

.auth-toggle a {
  color: var(--accent);
  cursor: pointer;
  font-weight: 600;
  text-decoration: none;
}

.auth-toggle a:hover { text-decoration: underline; }

/* ── Toasts ───────────────────────────────── */
.toast-container {
  position: fixed;
  bottom: 24px;
  left: 50%;
  transform: translateX(-50%);
  z-index: 400;
  display: flex;
  flex-direction: column;
  gap: 8px;
  align-items: center;
}

.toast {
  padding: 10px 20px;
  border-radius: var(--radius-sm);
  font-size: 0.8rem;
  font-weight: 600;
  animation: toastIn 0.3s ease-out;
  backdrop-filter: blur(12px);
  border: 1px solid var(--border);
}

.toast-success { background: rgba(16,185,129,0.15); color: var(--success); border-color: rgba(16,185,129,0.2); }
.toast-error { background: rgba(239,68,68,0.15); color: var(--danger); border-color: rgba(239,68,68,0.2); }
.toast-info { background: rgba(59,130,246,0.15); color: var(--accent); border-color: rgba(59,130,246,0.2); }

.toast-out { animation: toastOut 0.3s ease-in forwards; }

@keyframes toastIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
@keyframes toastOut { from { opacity: 1; } to { opacity: 0; transform: translateY(-10px); } }

/* ── Animations ───────────────────────────── */
@keyframes fadeUp {
  from { opacity: 0; transform: translateY(16px); }
  to { opacity: 1; transform: translateY(0); }
}

/* ── Responsive ───────────────────────────── */
@media (max-width: 640px) {
  .app { padding: 16px 12px 80px; }
  .navbar { top: 8px; width: calc(100% - 16px); padding: 10px 14px; }
  .nav-spacer { height: 64px; }
  .hero h1 { font-size: 1.5rem; }
  .url-input-row { flex-direction: column; }
  .btn-load { width: 100%; }
  .video-meta { flex-direction: column; }
  .video-thumb { width: 100%; height: auto; aspect-ratio: 16/9; }
  .option-row { flex-direction: column; align-items: flex-start; gap: 6px; }
  .option-label { width: auto; }
  .action-buttons { flex-direction: column; }
  .library-panel { width: 100%; }
  .time-controls { flex-direction: column; }
}

/* ── Reduced motion ───────────────────────── */
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    transition-duration: 0.01ms !important;
  }
}

/* ── User area in navbar ──────────────────── */
.user-bar {
  display: flex;
  align-items: center;
  gap: 8px;
}

.user-email {
  font-size: 0.75rem;
  color: var(--text-muted);
  max-width: 120px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.btn-logout {
  padding: 5px 10px;
  background: var(--bg-glass);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  color: var(--text-muted);
  font-size: 0.7rem;
  font-weight: 600;
  font-family: inherit;
  cursor: pointer;
  transition: all var(--transition);
}

.btn-logout:hover { color: var(--danger); border-color: rgba(239,68,68,0.3); }
</style>
</head>
<body>

<!-- ═══ NAVBAR ═══ -->
<nav class="navbar">
  <a class="navbar-brand" href="/" onclick="event.preventDefault();resetAll()">
    <div class="navbar-logo">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/><line x1="9" y1="15" x2="15" y2="15"/></svg>
    </div>
    ClipForge
  </a>
  <div class="navbar-actions">
    <div id="userArea"></div>
    <button type="button" class="btn-nav" id="btnLibrary" onclick="toggleLibrary()">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
      Library
    </button>
  </div>
</nav>

<div class="app">
  <div class="nav-spacer"></div>

  <!-- ═══ HERO ═══ -->
  <div class="hero">
    <h1>Clip any video, instantly</h1>
    <p>Paste a URL from YouTube, Twitter, Instagram, TikTok, Twitch or SoundCloud</p>
  </div>

  <!-- ═══ URL INPUT ═══ -->
  <div class="url-card glass">
    <div class="url-input-row">
      <input type="text" class="url-input" id="urlInput" placeholder="Paste a video URL..." autocomplete="off" spellcheck="false">
      <button type="button" class="btn-load" id="btnLoad" onclick="loadVideo()">Load</button>
    </div>
    <div class="platform-pills">
      <span class="platform-pill youtube" id="pillYt"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M23.5 6.2a3 3 0 0 0-2.1-2.1C19.5 3.5 12 3.5 12 3.5s-7.5 0-9.4.6A3 3 0 0 0 .5 6.2 31.4 31.4 0 0 0 0 12a31.4 31.4 0 0 0 .5 5.8 3 3 0 0 0 2.1 2.1c1.9.5 9.4.5 9.4.5s7.5 0 9.4-.6a3 3 0 0 0 2.1-2.1A31.4 31.4 0 0 0 24 12a31.4 31.4 0 0 0-.5-5.8zM9.6 15.5V8.5l6.3 3.5-6.3 3.5z"/></svg> YouTube</span>
      <span class="platform-pill twitter" id="pillTw"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg> X</span>
      <span class="platform-pill instagram" id="pillIg"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2.16c3.2 0 3.58.01 4.85.07 3.25.15 4.77 1.69 4.92 4.92.06 1.27.07 1.65.07 4.85s-.01 3.58-.07 4.85c-.15 3.23-1.66 4.77-4.92 4.92-1.27.06-1.65.07-4.85.07s-3.58-.01-4.85-.07c-3.26-.15-4.77-1.7-4.92-4.92C2.17 15.58 2.16 15.2 2.16 12s.01-3.58.07-4.85C2.38 3.86 3.9 2.31 7.15 2.23 8.42 2.17 8.8 2.16 12 2.16z"/></svg> IG</span>
      <span class="platform-pill tiktok" id="pillTk"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M19.59 6.69a4.83 4.83 0 0 1-3.77-4.25V2h-3.45v13.67a2.89 2.89 0 0 1-2.88 2.5 2.89 2.89 0 0 1-2.89-2.89 2.89 2.89 0 0 1 2.89-2.89c.28 0 .54.04.79.1v-3.5a6.37 6.37 0 0 0-.79-.05A6.34 6.34 0 0 0 3.15 15a6.34 6.34 0 0 0 6.34 6.34 6.34 6.34 0 0 0 6.34-6.34V8.1a8.16 8.16 0 0 0 4.76 1.52v-3.4a4.85 4.85 0 0 1-1-.07z"/></svg> TikTok</span>
      <span class="platform-pill twitch" id="pillTwitch"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M11.571 4.714h1.715v5.143H11.57zm4.715 0H18v5.143h-1.714zM6 0L1.714 4.286v15.428h5.143V24l4.286-4.286h3.428L22.286 12V0zm14.571 11.143l-3.428 3.428h-3.429l-3 3v-3H6.857V1.714h13.714z"/></svg> Twitch</span>
      <span class="platform-pill soundcloud" id="pillSc"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M1.175 12.225c-.051 0-.094.046-.101.1l-.233 2.154.233 2.105c.007.058.05.098.101.098.05 0 .09-.04.099-.098l.255-2.105-.27-2.154c-.009-.06-.05-.1-.1-.1m-.899.828c-.06 0-.091.037-.104.094L0 14.479l.172 1.308c.013.06.045.094.104.094.057 0 .09-.037.104-.093l.2-1.31-.2-1.326c-.014-.057-.047-.094-.104-.094m1.81-1.153c-.074 0-.12.06-.12.135l-.217 2.443.217 2.36c0 .074.046.135.12.135.073 0 .119-.06.119-.135l.241-2.36-.241-2.443c0-.075-.046-.135-.12-.135m.943-.424c-.074 0-.135.065-.143.14l-.2 2.866.2 2.775c.008.074.07.14.143.14.074 0 .135-.066.143-.14l.227-2.775-.227-2.866c-.008-.075-.07-.14-.143-.14m.975-.263c-.09 0-.158.074-.158.166l-.176 3.13.176 2.992c0 .09.067.165.158.165.09 0 .157-.074.165-.165l.2-2.993-.2-3.13c-.008-.09-.074-.165-.165-.165m1.02-.296c-.1 0-.18.082-.18.182l-.156 3.427.156 3.083c0 .1.08.182.18.182.098 0 .178-.082.186-.182l.176-3.083-.176-3.427c-.008-.1-.088-.182-.186-.182m1.057-.191c-.112 0-.2.09-.2.2l-.143 3.618.143 3.14c0 .112.088.2.2.2.111 0 .2-.088.2-.2l.159-3.14-.16-3.618c0-.111-.088-.2-.2-.2m1.099.018c-.12 0-.217.098-.217.218l-.118 3.4.118 3.167c0 .12.097.217.217.217s.217-.097.217-.217l.131-3.167-.131-3.4c0-.12-.097-.218-.217-.218m1.123-.473c-.133 0-.24.108-.24.24l-.1 3.855.1 3.208c0 .134.107.241.24.241s.24-.107.24-.24l.114-3.21-.114-3.854c0-.133-.107-.241-.24-.241m1.14-.12c-.146 0-.26.116-.26.262l-.085 3.975.085 3.233c0 .146.114.262.26.262.144 0 .26-.116.26-.262l.096-3.233-.096-3.975c0-.146-.116-.262-.26-.262m1.175-.213c-.158 0-.283.126-.283.283l-.07 4.188.07 3.246c0 .158.126.283.283.283.158 0 .283-.126.283-.283l.078-3.246-.078-4.188c0-.157-.125-.283-.283-.283m1.21-.362c-.17 0-.307.137-.307.307l-.053 4.55.053 3.253c0 .17.138.307.308.307.17 0 .307-.137.307-.307l.06-3.253-.06-4.55c0-.17-.137-.307-.307-.307m1.251.065c-.183 0-.33.148-.33.33l-.04 4.154.04 3.265c0 .183.147.33.33.33.182 0 .33-.147.33-.33l.044-3.265-.044-4.154c0-.182-.148-.33-.33-.33m1.281-.29c-.197 0-.354.158-.354.354l-.025 4.444.025 3.27c0 .196.157.353.354.353.195 0 .353-.157.353-.353l.028-3.27-.028-4.443c0-.197-.158-.355-.353-.355m1.318-.133c-.208 0-.375.168-.375.375l-.01 4.577.01 3.273c0 .208.167.375.375.375.209 0 .375-.167.375-.375l.012-3.273-.012-4.577c0-.207-.166-.375-.375-.375m3.472 2.168c-.26 0-.5.057-.727.156a3.055 3.055 0 0 0-3.057-2.884c-.21 0-.415.025-.612.074-.132.03-.165.073-.165.145v5.784c0 .076.06.14.135.148h4.426a2.17 2.17 0 0 0 2.17-2.172 2.17 2.17 0 0 0-2.17-2.251z"/></svg> SC</span>
    </div>
    <div class="error-msg" id="urlError"></div>
  </div>

  <!-- ═══ PREVIEW ═══ -->
  <div class="section" id="previewSection">
    <div class="preview-card glass">
      <div class="video-meta">
        <img class="video-thumb" id="videoThumb" src="" alt="">
        <div class="video-info">
          <div class="platform-badge" id="platformBadge"></div>
          <h3 id="videoTitle"></h3>
          <div class="video-channel" id="videoChannel"></div>
          <div class="duration-badge" id="videoDuration"></div>
        </div>
      </div>
      <div class="player-wrap" id="playerWrap">
        <iframe id="ytPlayer" src="" allow="autoplay; encrypted-media" allowfullscreen sandbox="allow-scripts allow-same-origin allow-popups"></iframe>
      </div>
    </div>
  </div>

  <!-- ═══ MODE TOGGLE ═══ -->
  <div class="mode-toggle" id="modeToggle">
    <button type="button" class="mode-btn active" id="modeDownload" onclick="setMode('download')">Download Full</button>
    <button type="button" class="mode-btn" id="modeTrim" onclick="setMode('trim')">Trim & Download</button>
  </div>

  <!-- ═══ TIMELINE ═══ -->
  <div class="section" id="timelineSection">
    <div class="timeline-card glass">
      <div class="time-controls">
        <div class="time-field">
          <label for="startInput">Start</label>
          <input type="text" id="startInput" value="0:00" placeholder="0:00">
        </div>
        <div class="time-field">
          <label for="endInput">End</label>
          <input type="text" id="endInput" value="0:00" placeholder="0:00">
        </div>
      </div>
      <div class="timeline-track" id="timelineTrack">
        <div class="timeline-waveform" id="waveform"></div>
        <div class="timeline-region" id="timelineRegion"></div>
        <div class="timeline-handle" id="handleStart" style="left:0%" tabindex="0" role="slider" aria-label="Trim start"></div>
        <div class="timeline-handle" id="handleEnd" style="left:100%" tabindex="0" role="slider" aria-label="Trim end"></div>
      </div>
      <div class="timeline-labels">
        <span>0:00</span>
        <span id="totalDurationLabel">0:00</span>
      </div>
      <div class="clip-duration">Clip length: <span id="clipDuration">0:00</span></div>
    </div>
  </div>

  <!-- ═══ OPTIONS ═══ -->
  <div class="options-card glass" id="qualitySection">
    <div class="option-row">
      <span class="option-label">Quality</span>
      <div class="pill-group" id="qualityGroup">
        <button type="button" class="pill" data-q="360p">360p</button>
        <button type="button" class="pill" data-q="480p">480p</button>
        <button type="button" class="pill active" data-q="720p">720p</button>
        <button type="button" class="pill" data-q="1080p">1080p</button>
        <button type="button" class="pill" data-q="best">Best</button>
      </div>
    </div>
    <div class="option-row">
      <span class="option-label">Format</span>
      <div class="pill-group" id="formatGroup">
        <button type="button" class="pill active" data-f="mp4">MP4</button>
        <button type="button" class="pill" data-f="webm">WebM</button>
        <button type="button" class="pill" data-f="mp3">MP3</button>
        <button type="button" class="pill" data-f="gif">GIF</button>
      </div>
      <span class="gif-note" id="gifNote">Max 30s</span>
    </div>
    <div class="option-row" id="exportRow">
      <span class="option-label">Export</span>
      <div class="pill-group" id="exportGroup">
        <button type="button" class="pill active" data-r="">Original</button>
        <button type="button" class="pill" data-r="tiktok">TikTok</button>
        <button type="button" class="pill" data-r="square">Square</button>
        <button type="button" class="pill" data-r="twitter">Twitter</button>
        <button type="button" class="pill" data-r="discord">Discord</button>
        <button type="button" class="pill" data-r="whatsapp">WhatsApp</button>
      </div>
    </div>
    <div class="option-row" id="subtitleRow">
      <span class="option-label">Subs</span>
      <label class="subtitle-check">
        <input type="checkbox" id="subtitleCheck">
        Auto-subtitles
      </label>
      <span class="subtitle-note" id="subtitleNote"></span>
    </div>
  </div>

  <!-- ═══ ACTION BUTTONS ═══ -->
  <div class="action-section" id="actionSection">
    <div class="action-buttons">
      <button type="button" class="btn-action" id="btnAction" onclick="startAction()">Download Video</button>
      <button type="button" class="btn-save-trigger" id="btnSaveLibrary" onclick="openSaveDialog()">Save to Library</button>
    </div>
    <div class="limit-note" id="limitNote"></div>
    <div class="error-msg" id="trimError"></div>
  </div>

  <!-- ═══ PROGRESS ═══ -->
  <div class="section" id="progressSection">
    <div class="progress-card glass">
      <div class="progress-bar-track">
        <div class="progress-bar-fill" id="progressFill"></div>
      </div>
      <div class="progress-status" id="progressStatus">
        <span class="spinner"></span> Downloading video...
      </div>
    </div>
  </div>

  <!-- ═══ DOWNLOAD RESULT ═══ -->
  <div class="section" id="downloadSection">
    <div class="download-card glass">
      <div class="download-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="20 6 9 17 4 12"/>
        </svg>
      </div>
      <h3>Your video is ready!</h3>
      <p class="download-info" id="downloadInfo"></p>
      <a class="btn-download" id="btnDownload" href="#">Download MP4</a>
      <div class="download-secondary">
        <button type="button" class="btn-secondary" id="btnSaveFromDl" onclick="openSaveDialog()">Save to Library</button>
        <button type="button" class="btn-secondary" onclick="resetAll()">New clip</button>
      </div>

      <!-- Save Dialog -->
      <div class="save-dialog" id="saveDialog">
        <label for="saveTitleInput">Title</label>
        <input type="text" id="saveTitleInput" placeholder="Clip title..." maxlength="200">
        <label>Tags <span style="font-size:0.65rem;font-weight:400;color:var(--text-muted)">(Enter to add, max 10)</span></label>
        <div class="tag-input-wrap" id="tagInputWrap" onclick="document.getElementById('tagField').focus()">
          <input type="text" class="tag-input-field" id="tagField" placeholder="Add a tag...">
        </div>
        <div class="save-actions">
          <button type="button" class="btn-confirm" id="btnConfirmSave" onclick="saveToLibrary()">Confirm & Save</button>
          <button type="button" class="btn-cancel" onclick="closeSaveDialog()">Cancel</button>
        </div>
      </div>
    </div>
  </div>

</div><!-- /app -->

<!-- ═══ LIBRARY SLIDE-OUT ═══ -->
<div class="library-overlay" id="libraryOverlay" onclick="if(event.target===this)closeLibrary()">
  <div class="library-panel">
    <div class="library-header">
      <h2>My Library</h2>
      <button type="button" class="btn-close-library" onclick="closeLibrary()">&times;</button>
    </div>
    <div class="library-toolbar">
      <input type="text" class="library-search" id="librarySearch" placeholder="Search clips...">
      <div class="library-filters" id="libraryFilters">
        <button type="button" class="filter-pill active" onclick="setFilter('all')">All</button>
        <button type="button" class="filter-pill" onclick="setFilter('youtube')">YouTube</button>
        <button type="button" class="filter-pill" onclick="setFilter('twitter')">X</button>
        <button type="button" class="filter-pill" onclick="setFilter('instagram')">IG</button>
        <button type="button" class="filter-pill" onclick="setFilter('tiktok')">TikTok</button>
        <button type="button" class="filter-pill" onclick="setFilter('twitch')">Twitch</button>
        <button type="button" class="filter-pill" onclick="setFilter('soundcloud')">SC</button>
      </div>
      <div class="library-sort-row">
        <select class="library-sort" id="librarySort" onchange="applyLibraryView()">
          <option value="newest">Newest</option>
          <option value="oldest">Oldest</option>
          <option value="largest">Largest</option>
          <option value="smallest">Smallest</option>
        </select>
        <button type="button" class="btn-select-all" onclick="toggleSelectAll()">Select All</button>
      </div>
    </div>
    <div class="library-stats" id="libraryStats"></div>
    <div class="library-grid" id="libraryGrid">
      <div class="library-empty" id="libraryEmpty">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="width:36px;height:36px;color:var(--text-muted)">
          <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
        </svg>
        <p>No saved clips yet</p>
        <p class="sub">Download a video and save it to your library</p>
      </div>
    </div>
    <button type="button" class="btn-load-more" id="btnLoadMore" onclick="loadMoreClips()">Load more</button>
    <div class="bulk-bar" id="bulkBar">
      <span class="bulk-bar-info" id="bulkBarInfo">0 selected</span>
      <div class="bulk-bar-actions">
        <button type="button" class="bulk-btn bulk-btn-download" onclick="bulkDownload()">Download</button>
        <button type="button" class="bulk-btn bulk-btn-delete" onclick="bulkDelete()">Delete</button>
      </div>
    </div>
  </div>
</div>

<!-- ═══ EDIT MODAL ═══ -->
<div class="modal-overlay" id="editModalOverlay" onclick="if(event.target===this)closeEditModal()">
  <div class="modal">
    <h3>Edit Clip</h3>
    <input type="hidden" id="editClipId">
    <label for="editTitleInput">Title</label>
    <input type="text" id="editTitleInput" placeholder="Clip title..." maxlength="200">
    <label>Tags <span style="font-size:0.65rem;font-weight:400;color:var(--text-muted)">(Enter to add)</span></label>
    <div class="tag-input-wrap" id="editTagInputWrap" onclick="document.getElementById('editTagField').focus()">
      <input type="text" class="tag-input-field" id="editTagField" placeholder="Add a tag...">
    </div>
    <div class="modal-actions">
      <button type="button" class="btn-confirm" onclick="saveEdit()" style="flex:1">Save Changes</button>
      <button type="button" class="btn-cancel" onclick="closeEditModal()">Cancel</button>
    </div>
  </div>
</div>

<!-- ═══ AUTH MODAL ═══ -->
<div class="modal-overlay" id="authModalOverlay" onclick="if(event.target===this)closeAuthModal()">
  <div class="modal">
    <h3 id="authModalTitle">Log In</h3>
    <input type="email" id="authEmail" placeholder="Email address">
    <input type="password" id="authPassword" placeholder="Password">
    <div class="auth-error" id="authError"></div>
    <button type="button" class="auth-submit" id="authSubmit" onclick="submitAuth()">Log In</button>
    <div class="auth-toggle">
      <span id="authToggleText">Don't have an account?</span>
      <a id="authToggleLink" onclick="toggleAuthMode()">Sign up</a>
    </div>
  </div>
</div>

<!-- ═══ TOASTS ═══ -->
<div class="toast-container" id="toastContainer"></div>

<script>
// ── State ────────────────────────────────────
let videoDuration = 0;
let videoId = '';
let currentPlatform = '';
let currentMode = 'download';
let dragging = null;
let currentQuality = '720p';
let currentFormat = 'mp4';
let currentResize = '';
let currentSubtitles = false;

// Library state
let allClips = [];
let currentFilter = 'all';
let selectedClipIds = new Set();
let saveTags = [];
let editTags = [];
let libraryPage = 1;
let libraryHasMore = false;

// Auth state
let authMode = 'login';

const PLATFORM_LABELS = {
  youtube: 'YouTube', twitter: 'Twitter / X', instagram: 'Instagram',
  tiktok: 'TikTok', twitch: 'Twitch', soundcloud: 'SoundCloud',
};

const PLATFORM_ICONS = {
  youtube:   '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M23.5 6.2a3 3 0 0 0-2.1-2.1C19.5 3.5 12 3.5 12 3.5s-7.5 0-9.4.6A3 3 0 0 0 .5 6.2 31.4 31.4 0 0 0 0 12a31.4 31.4 0 0 0 .5 5.8 3 3 0 0 0 2.1 2.1c1.9.5 9.4.5 9.4.5s7.5 0 9.4-.6a3 3 0 0 0 2.1-2.1A31.4 31.4 0 0 0 24 12a31.4 31.4 0 0 0-.5-5.8zM9.6 15.5V8.5l6.3 3.5-6.3 3.5z"/></svg>',
  twitter:   '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>',
  instagram: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2.16c3.2 0 3.58.01 4.85.07 3.25.15 4.77 1.69 4.92 4.92.06 1.27.07 1.65.07 4.85s-.01 3.58-.07 4.85c-.15 3.23-1.66 4.77-4.92 4.92-1.27.06-1.65.07-4.85.07s-3.58-.01-4.85-.07c-3.26-.15-4.77-1.7-4.92-4.92C2.17 15.58 2.16 15.2 2.16 12s.01-3.58.07-4.85C2.38 3.86 3.9 2.31 7.15 2.23 8.42 2.17 8.8 2.16 12 2.16z"/></svg>',
  tiktok:    '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M19.59 6.69a4.83 4.83 0 0 1-3.77-4.25V2h-3.45v13.67a2.89 2.89 0 0 1-2.88 2.5 2.89 2.89 0 0 1-2.89-2.89 2.89 2.89 0 0 1 2.89-2.89c.28 0 .54.04.79.1v-3.5a6.37 6.37 0 0 0-.79-.05A6.34 6.34 0 0 0 3.15 15a6.34 6.34 0 0 0 6.34 6.34 6.34 6.34 0 0 0 6.34-6.34V8.1a8.16 8.16 0 0 0 4.76 1.52v-3.4a4.85 4.85 0 0 1-1-.07z"/></svg>',
  twitch:    '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M11.571 4.714h1.715v5.143H11.57zm4.715 0H18v5.143h-1.714zM6 0L1.714 4.286v15.428h5.143V24l4.286-4.286h3.428L22.286 12V0zm14.571 11.143l-3.428 3.428h-3.429l-3 3v-3H6.857V1.714h13.714z"/></svg>',
  soundcloud:'<svg viewBox="0 0 24 24" fill="currentColor"><path d="M1.175 12.225c-.051 0-.094.046-.101.1l-.233 2.154.233 2.105c.007.058.05.098.101.098.05 0 .09-.04.099-.098l.255-2.105-.27-2.154c-.009-.06-.05-.1-.1-.1m-.899.828c-.06 0-.091.037-.104.094L0 14.479l.172 1.308c.013.06.045.094.104.094.057 0 .09-.037.104-.093l.2-1.31-.2-1.326c-.014-.057-.047-.094-.104-.094m1.81-1.153c-.074 0-.12.06-.12.135l-.217 2.443.217 2.36c0 .074.046.135.12.135.073 0 .119-.06.119-.135l.241-2.36-.241-2.443c0-.075-.046-.135-.12-.135m.943-.424c-.074 0-.135.065-.143.14l-.2 2.866.2 2.775c.008.074.07.14.143.14.074 0 .135-.066.143-.14l.227-2.775-.227-2.866c-.008-.075-.07-.14-.143-.14m.975-.263c-.09 0-.158.074-.158.166l-.176 3.13.176 2.992c0 .09.067.165.158.165.09 0 .157-.074.165-.165l.2-2.993-.2-3.13c-.008-.09-.074-.165-.165-.165m1.02-.296c-.1 0-.18.082-.18.182l-.156 3.427.156 3.083c0 .1.08.182.18.182.098 0 .178-.082.186-.182l.176-3.083-.176-3.427c-.008-.1-.088-.182-.186-.182m1.057-.191c-.112 0-.2.09-.2.2l-.143 3.618.143 3.14c0 .112.088.2.2.2.111 0 .2-.088.2-.2l.159-3.14-.16-3.618c0-.111-.088-.2-.2-.2m1.099.018c-.12 0-.217.098-.217.218l-.118 3.4.118 3.167c0 .12.097.217.217.217s.217-.097.217-.217l.131-3.167-.131-3.4c0-.12-.097-.218-.217-.218m1.123-.473c-.133 0-.24.108-.24.24l-.1 3.855.1 3.208c0 .134.107.241.24.241s.24-.107.24-.24l.114-3.21-.114-3.854c0-.133-.107-.241-.24-.241m1.14-.12c-.146 0-.26.116-.26.262l-.085 3.975.085 3.233c0 .146.114.262.26.262.144 0 .26-.116.26-.262l.096-3.233-.096-3.975c0-.146-.116-.262-.26-.262m1.175-.213c-.158 0-.283.126-.283.283l-.07 4.188.07 3.246c0 .158.126.283.283.283.158 0 .283-.126.283-.283l.078-3.246-.078-4.188c0-.157-.125-.283-.283-.283m1.21-.362c-.17 0-.307.137-.307.307l-.053 4.55.053 3.253c0 .17.138.307.308.307.17 0 .307-.137.307-.307l.06-3.253-.06-4.55c0-.17-.137-.307-.307-.307m1.251.065c-.183 0-.33.148-.33.33l-.04 4.154.04 3.265c0 .183.147.33.33.33.182 0 .33-.147.33-.33l.044-3.265-.044-4.154c0-.182-.148-.33-.33-.33m1.281-.29c-.197 0-.354.158-.354.354l-.025 4.444.025 3.27c0 .196.157.353.354.353.195 0 .353-.157.353-.353l.028-3.27-.028-4.443c0-.197-.158-.355-.353-.355m1.318-.133c-.208 0-.375.168-.375.375l-.01 4.577.01 3.273c0 .208.167.375.375.375.209 0 .375-.167.375-.375l.012-3.273-.012-4.577c0-.207-.166-.375-.375-.375m3.472 2.168c-.26 0-.5.057-.727.156a3.055 3.055 0 0 0-3.057-2.884c-.21 0-.415.025-.612.074-.132.03-.165.073-.165.145v5.784c0 .076.06.14.135.148h4.426a2.17 2.17 0 0 0 2.17-2.172 2.17 2.17 0 0 0-2.17-2.251z"/></svg>',
};

// ── Platform detection ─────────────────────
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

// Highlight platform pill on input
document.getElementById('urlInput').addEventListener('input', function() {
  const p = detectPlatform(this.value);
  document.querySelectorAll('.platform-pill').forEach(el => el.classList.remove('active'));
  if (p === 'youtube') document.getElementById('pillYt').classList.add('active');
  else if (p === 'twitter') document.getElementById('pillTw').classList.add('active');
  else if (p === 'instagram') document.getElementById('pillIg').classList.add('active');
  else if (p === 'tiktok') document.getElementById('pillTk').classList.add('active');
  else if (p === 'twitch') document.getElementById('pillTwitch').classList.add('active');
  else if (p === 'soundcloud') document.getElementById('pillSc').classList.add('active');
  if (p === 'soundcloud') { currentFormat = 'mp3'; updateFormatPills(); }
});

// ── Load Video ─────────────────────────────
async function loadVideo() {
  const url = document.getElementById('urlInput').value.trim();
  const btn = document.getElementById('btnLoad');
  document.getElementById('urlError').classList.remove('visible');
  if (!url) { showError('urlError', 'Please paste a video URL.'); return; }
  const platform = detectPlatform(url);
  if (!platform) { showError('urlError', 'Unsupported URL. Paste a YouTube, Twitter/X, Instagram, TikTok, Twitch, or SoundCloud link.'); return; }
  btn.disabled = true; btn.textContent = 'Loading...';
  try {
    const resp = await fetch('/api/video-info', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }) });
    const data = await resp.json();
    if (!resp.ok) { showError('urlError', data.error || 'Failed to load video.'); return; }
    currentPlatform = data.platform || platform;
    videoId = data.id;
    videoDuration = data.duration || 0;

    // Platform badge
    const badge = document.getElementById('platformBadge');
    badge.className = 'platform-badge visible ' + currentPlatform;
    badge.textContent = '';
    const iconHtml = PLATFORM_ICONS[currentPlatform];
    if (iconHtml) { const w = document.createElement('span'); w.innerHTML = iconHtml; badge.appendChild(w); }
    const lbl = document.createElement('span'); lbl.textContent = PLATFORM_LABELS[currentPlatform] || currentPlatform; badge.appendChild(lbl);

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
      ytPlayer.src = 'https://www.youtube.com/embed/' + safeVideoId + '?rel=0&modestbranding=1';
      ytPlayer.style.display = '';
      const noEmbed = playerWrap.querySelector('.no-embed');
      if (noEmbed) noEmbed.remove();
    } else {
      ytPlayer.style.display = 'none'; ytPlayer.src = '';
      let noEmbed = playerWrap.querySelector('.no-embed');
      if (!noEmbed) { noEmbed = document.createElement('div'); noEmbed.className = 'no-embed'; playerWrap.appendChild(noEmbed); }
      noEmbed.textContent = 'Preview not available for ' + (PLATFORM_LABELS[currentPlatform] || currentPlatform) + '. Use the original link to preview.';
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

    // Subtitle note
    const subNote = document.getElementById('subtitleNote');
    subNote.textContent = currentPlatform === 'youtube' ? '(YouTube auto-captions)' : '(auto-generated if available)';

    // Default mode
    if (currentPlatform === 'youtube' && videoDuration > 30) setMode('trim');
    else setMode('download');

    generateWaveform();
    updateTimeline();
  } catch (e) {
    showError('urlError', 'Network error — is the server running?');
  } finally {
    btn.disabled = false; btn.textContent = 'Load';
  }
}

// ── Mode toggle ────────────────────────────
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
    if (!videoDuration) { showError('trimError', 'Trim not available — video duration unknown.'); setMode('download'); return; }
  } else {
    document.getElementById('timelineSection').classList.remove('visible');
    btn.textContent = 'Download Video';
    note.textContent = '';
  }
}

// ── Timeline ───────────────────────────────
function generateWaveform() {
  const c = document.getElementById('waveform'); c.innerHTML = '';
  const frag = document.createDocumentFragment();
  for (let i = 0; i < 120; i++) {
    const bar = document.createElement('div'); bar.className = 'bar';
    bar.style.height = (8 + Math.random() * 30) + 'px'; frag.appendChild(bar);
  }
  c.appendChild(frag);
}

function updateTimeline() {
  if (!videoDuration) return;
  const startSec = parseTime(document.getElementById('startInput').value);
  const endSec = parseTime(document.getElementById('endInput').value);
  const startPct = (startSec / videoDuration) * 100;
  const endPct = (endSec / videoDuration) * 100;
  document.getElementById('timelineRegion').style.left = startPct + '%';
  document.getElementById('timelineRegion').style.width = (endPct - startPct) + '%';
  document.getElementById('handleStart').style.left = 'calc(' + startPct + '% - 7px)';
  document.getElementById('handleEnd').style.left = 'calc(' + endPct + '% - 7px)';
  document.getElementById('clipDuration').textContent = formatTime(Math.max(0, endSec - startSec));
}

['handleStart', 'handleEnd'].forEach(id => {
  const el = document.getElementById(id);
  el.addEventListener('mousedown', e => { e.preventDefault(); dragging = id; });
  el.addEventListener('touchstart', e => { dragging = id; }, { passive: true });
});

let _rafPending = false;
function handleMove(clientX) {
  if (!dragging || _rafPending) return;
  _rafPending = true;
  requestAnimationFrame(() => {
    _rafPending = false;
    if (!dragging) return;
    const track = document.getElementById('timelineTrack');
    const rect = track.getBoundingClientRect();
    let pct = Math.max(0, Math.min(100, ((clientX - rect.left) / rect.width) * 100));
    const sec = (pct / 100) * videoDuration;
    if (dragging === 'handleStart') document.getElementById('startInput').value = formatTime(Math.floor(sec));
    else document.getElementById('endInput').value = formatTime(Math.floor(sec));
    updateTimeline();
  });
}

document.addEventListener('mousemove', e => handleMove(e.clientX));
document.addEventListener('touchmove', e => handleMove(e.touches[0].clientX), { passive: true });
document.addEventListener('mouseup', () => { dragging = null; });
document.addEventListener('touchend', () => { dragging = null; });

// Keyboard support for handles
['handleStart', 'handleEnd'].forEach(id => {
  document.getElementById(id).addEventListener('keydown', e => {
    if (!videoDuration) return;
    const step = e.shiftKey ? 10 : 1;
    const inputId = id === 'handleStart' ? 'startInput' : 'endInput';
    let sec = parseTime(document.getElementById(inputId).value);
    if (e.key === 'ArrowRight' || e.key === 'ArrowUp') { e.preventDefault(); sec = Math.min(sec + step, videoDuration); document.getElementById(inputId).value = formatTime(sec); updateTimeline(); }
    else if (e.key === 'ArrowLeft' || e.key === 'ArrowDown') { e.preventDefault(); sec = Math.max(sec - step, 0); document.getElementById(inputId).value = formatTime(sec); updateTimeline(); }
  });
});

document.getElementById('startInput').addEventListener('input', updateTimeline);
document.getElementById('endInput').addEventListener('input', updateTimeline);

// ── Action (Download or Trim) ──────────────
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
    if (parseTime(end) <= parseTime(start)) { showError('trimError', 'End time must be after start time.'); restoreAction(); return; }
    if (parseTime(end) - parseTime(start) > 600) { showError('trimError', 'Clips are limited to 10 minutes max.'); restoreAction(); return; }
    endpoint = '/api/trim';
    body = { url, start, end, quality: currentQuality, format: currentFormat, resize: currentResize, subtitles: currentSubtitles };
    infoText = 'Trimmed from ' + start + ' to ' + end;
    document.getElementById('progressStatus').innerHTML = '<span class="spinner"></span> Downloading & trimming your clip...';
  } else {
    endpoint = '/api/download-full';
    body = { url, quality: currentQuality, format: currentFormat, resize: currentResize, subtitles: currentSubtitles };
    infoText = 'Full video from ' + (PLATFORM_LABELS[currentPlatform] || 'source');
    document.getElementById('progressStatus').innerHTML = '<span class="spinner"></span> Downloading video...';
  }

  try {
    const resp = await fetch(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (!resp.ok) { let errMsg = 'Download failed.'; try { const d = await resp.json(); errMsg = d.error || errMsg; } catch {} throw new Error(errMsg); }
    const blob = await resp.blob();
    const dlBtn = document.getElementById('btnDownload');
    if (dlBtn.href && dlBtn.href.startsWith('blob:')) URL.revokeObjectURL(dlBtn.href);
    const downloadUrl = URL.createObjectURL(blob);
    let fileExt = '.mp4';
    const disposition = resp.headers.get('Content-Disposition');
    if (disposition) { const match = disposition.match(/filename="?[^"]*(\.\w+)"?/); if (match) fileExt = match[1]; }
    document.getElementById('progressSection').classList.remove('visible');
    document.getElementById('downloadInfo').textContent = infoText;
    dlBtn.href = downloadUrl;
    dlBtn.setAttribute('download', currentPlatform + '_' + (videoId || 'video') + fileExt);
    dlBtn.textContent = 'Download ' + fileExt.replace('.', '').toUpperCase();
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
  const dlBtn = document.getElementById('btnDownload');
  if (dlBtn.href && dlBtn.href.startsWith('blob:')) URL.revokeObjectURL(dlBtn.href);
  dlBtn.href = '#'; dlBtn.textContent = 'Download MP4';

  const saveBtn = document.getElementById('btnSaveLibrary');
  saveBtn.disabled = false; saveBtn.textContent = 'Save to Library';
  saveBtn.classList.remove('saved');
  closeSaveDialog();
  const confirmBtn = document.getElementById('btnConfirmSave');
  confirmBtn.disabled = false; confirmBtn.textContent = 'Confirm & Save';
  saveTags = [];

  ['previewSection','timelineSection','progressSection','downloadSection'].forEach(id => document.getElementById(id).classList.remove('visible'));
  document.getElementById('modeToggle').classList.remove('visible');
  document.getElementById('qualitySection').classList.remove('visible');
  document.getElementById('actionSection').classList.remove('visible');
  document.getElementById('urlInput').value = '';
  document.getElementById('urlInput').focus();
  document.getElementById('btnAction').disabled = false;
  document.querySelectorAll('.platform-pill').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.error-msg').forEach(el => el.classList.remove('visible'));
  videoDuration = 0; videoId = ''; currentPlatform = ''; currentMode = 'download';
  currentQuality = '720p'; currentFormat = 'mp4'; currentResize = ''; currentSubtitles = false;
  document.getElementById('subtitleCheck').checked = false;
  updateQualityPills(); updateFormatPills(); updateExportPills();
}

// ── Utilities ──────────────────────────────
function formatTime(sec) {
  sec = Math.max(0, Math.round(sec));
  const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
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

function showError(id, msg) { const el = document.getElementById(id); el.textContent = msg; el.classList.add('visible'); }
function escapeHtml(str) { return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }
function escapeAttr(str) { return String(str).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/'/g,'&#39;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function isValidUUID(str) { return /^[a-f0-9-]{36}$/.test(str); }
function formatFileSize(bytes) { if (bytes < 1024) return bytes + ' B'; if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB'; return (bytes / 1048576).toFixed(1) + ' MB'; }
function debounce(fn, ms) { let timer; return function(...args) { clearTimeout(timer); timer = setTimeout(() => fn.apply(this, args), ms); }; }

document.getElementById('urlInput').addEventListener('keydown', e => { if (e.key === 'Enter') loadVideo(); });

// ── Quality/Format/Export pills ────────────
document.querySelectorAll('#qualityGroup .pill').forEach(btn => { btn.addEventListener('click', () => { currentQuality = btn.dataset.q; updateQualityPills(); }); });
document.querySelectorAll('#formatGroup .pill').forEach(btn => { btn.addEventListener('click', () => { currentFormat = btn.dataset.f; updateFormatPills(); }); });
document.querySelectorAll('#exportGroup .pill').forEach(btn => { btn.addEventListener('click', () => { currentResize = btn.dataset.r; updateExportPills(); }); });

function updateQualityPills() { document.querySelectorAll('#qualityGroup .pill').forEach(p => p.classList.toggle('active', p.dataset.q === currentQuality)); }

function updateFormatPills() {
  document.querySelectorAll('#formatGroup .pill').forEach(p => p.classList.toggle('active', p.dataset.f === currentFormat));
  const qRow = document.querySelector('#qualityGroup').parentElement;
  const exportRow = document.getElementById('exportRow');
  const subtitleRow = document.getElementById('subtitleRow');
  const gifNote = document.getElementById('gifNote');
  const hideExtras = currentFormat === 'mp3' || currentFormat === 'gif';
  if (currentFormat === 'mp3' || currentFormat === 'gif') {
    qRow.style.display = 'none';
    if (currentMode === 'trim' && currentFormat === 'mp3') setMode('download');
    document.getElementById('modeTrim').style.display = currentFormat === 'mp3' ? 'none' : '';
  } else { qRow.style.display = ''; document.getElementById('modeTrim').style.display = ''; }
  exportRow.style.display = hideExtras ? 'none' : '';
  subtitleRow.style.display = hideExtras ? 'none' : '';
  gifNote.classList.toggle('visible', currentFormat === 'gif');
  if (hideExtras) { currentResize = ''; currentSubtitles = false; document.getElementById('subtitleCheck').checked = false; updateExportPills(); }
}

function updateExportPills() { document.querySelectorAll('#exportGroup .pill').forEach(p => p.classList.toggle('active', p.dataset.r === currentResize)); }

document.getElementById('subtitleCheck').addEventListener('change', function() { currentSubtitles = this.checked; });

// ── Save Dialog ────────────────────────────
function openSaveDialog() {
  const dialog = document.getElementById('saveDialog');
  document.getElementById('saveTitleInput').value = document.getElementById('videoTitle').textContent || '';
  saveTags = []; renderSaveTags();
  dialog.classList.add('visible');
  document.getElementById('saveTitleInput').focus();
}

function closeSaveDialog() { document.getElementById('saveDialog').classList.remove('visible'); }

function renderSaveTags() {
  const wrap = document.getElementById('tagInputWrap');
  wrap.querySelectorAll('.tag-chip').forEach(el => el.remove());
  const field = document.getElementById('tagField');
  saveTags.forEach((tag, i) => {
    const chip = document.createElement('span'); chip.className = 'tag-chip';
    chip.innerHTML = escapeHtml(tag) + '<span class="tag-remove">&times;</span>';
    chip.querySelector('.tag-remove').onclick = () => { saveTags.splice(i, 1); renderSaveTags(); };
    wrap.insertBefore(chip, field);
  });
}

document.getElementById('tagField').addEventListener('keydown', function(e) {
  if ((e.key === 'Enter' || e.key === ',') && this.value.trim()) {
    e.preventDefault();
    const tag = this.value.trim().replace(/,/g, '').substring(0, 30);
    if (tag && saveTags.length < 10 && !saveTags.includes(tag)) { saveTags.push(tag); renderSaveTags(); }
    this.value = '';
  }
  if (e.key === 'Backspace' && !this.value && saveTags.length > 0) { saveTags.pop(); renderSaveTags(); }
});

// ── Library ────────────────────────────────
async function saveToLibrary() {
  const btn = document.getElementById('btnConfirmSave');
  btn.disabled = true; btn.textContent = 'Saving...';
  const url = document.getElementById('urlInput').value.trim();
  const customTitle = document.getElementById('saveTitleInput').value.trim() || 'Untitled';
  const tagsStr = saveTags.length > 0 ? saveTags.join(',') : null;
  const body = { url, mode: currentMode, title: customTitle, platform: currentPlatform, thumbnail: document.getElementById('videoThumb').src, channel: document.getElementById('videoChannel').textContent, duration: videoDuration, tags: tagsStr, quality: currentQuality, format: currentFormat, resize: currentResize, subtitles: currentSubtitles };
  if (currentMode === 'trim') { body.start = document.getElementById('startInput').value.trim(); body.end = document.getElementById('endInput').value.trim(); }
  try {
    const resp = await authFetch('/api/save-to-library', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const data = await resp.json();
    if (!resp.ok) { showToast(data.error || 'Save failed', 'error'); btn.textContent = 'Save Failed'; btn.disabled = false; setTimeout(() => { btn.textContent = 'Confirm & Save'; }, 2000); return; }
    closeSaveDialog();
    const saveBtn = document.getElementById('btnSaveLibrary');
    if (saveBtn) { saveBtn.textContent = 'Saved!'; saveBtn.classList.add('saved'); }
    const saveBtn2 = document.getElementById('btnSaveFromDl');
    if (saveBtn2) { saveBtn2.textContent = 'Saved!'; saveBtn2.disabled = true; }
    showToast('Clip saved to library!', 'success');
    loadLibrary();
  } catch (e) {
    showToast('Save failed — network error', 'error');
    btn.textContent = 'Save Failed'; btn.disabled = false;
    setTimeout(() => { btn.textContent = 'Confirm & Save'; }, 2000);
  }
}

async function loadLibrary(append) {
  if (!append) {
    libraryPage = 1;
    const cached = localStorage.getItem('clipforge_library');
    if (cached) { try { allClips = JSON.parse(cached); applyLibraryView(); } catch(e) {} }
    else showLibrarySkeleton();
  }
  try {
    const resp = await authFetch('/api/library?page=' + libraryPage + '&per_page=20');
    const data = await resp.json();
    allClips = append ? allClips.concat(data.clips || []) : (data.clips || []);
    libraryHasMore = data.has_more || false;
    localStorage.setItem('clipforge_library', JSON.stringify(allClips));
    applyLibraryView();
    document.getElementById('btnLoadMore').classList.toggle('visible', libraryHasMore);
  } catch (e) {}
}

function loadMoreClips() { libraryPage++; loadLibrary(true); }

function showLibrarySkeleton() {
  const grid = document.getElementById('libraryGrid');
  const empty = document.getElementById('libraryEmpty');
  empty.style.display = 'none';
  grid.querySelectorAll('.clip-card, .skeleton-card').forEach(el => el.remove());
  for (let i = 0; i < 4; i++) {
    const sk = document.createElement('div'); sk.className = 'skeleton-card';
    sk.innerHTML = '<div class="skeleton-thumb"></div><div class="skeleton-line"></div><div class="skeleton-line short"></div>';
    grid.appendChild(sk);
  }
}

function applyLibraryView() {
  const search = (document.getElementById('librarySearch').value || '').toLowerCase();
  const sort = document.getElementById('librarySort').value;
  let filtered = allClips.filter(c => {
    if (currentFilter !== 'all' && c.platform !== currentFilter) return false;
    if (search) { const t = (c.title || '').toLowerCase(); const tg = (c.tags || '').toLowerCase(); if (!t.includes(search) && !tg.includes(search)) return false; }
    return true;
  });
  if (sort === 'newest' || sort === 'oldest') { for (let i = 0; i < filtered.length; i++) { if (filtered[i]._ts === undefined) filtered[i]._ts = new Date(filtered[i].created_at).getTime(); } }
  filtered.sort((a, b) => { if (sort === 'newest') return b._ts - a._ts; if (sort === 'oldest') return a._ts - b._ts; if (sort === 'largest') return (b.file_size || 0) - (a.file_size || 0); if (sort === 'smallest') return (a.file_size || 0) - (b.file_size || 0); return 0; });
  const favs = [], rest = [];
  for (let i = 0; i < filtered.length; i++) (filtered[i].is_favorite ? favs : rest).push(filtered[i]);
  if (favs.length > 0) filtered = favs.concat(rest);
  renderLibrary(filtered);
}

document.getElementById('librarySearch').addEventListener('input', debounce(applyLibraryView, 200));

function setFilter(platform) {
  currentFilter = platform;
  const pills = document.querySelectorAll('#libraryFilters .filter-pill');
  const labels = ['all', 'youtube', 'twitter', 'instagram', 'tiktok', 'twitch', 'soundcloud'];
  pills.forEach((el, i) => el.classList.toggle('active', labels[i] === platform));
  applyLibraryView();
}

async function toggleFavorite(clipId) {
  try {
    const resp = await authFetch('/api/library/' + clipId + '/favorite', { method: 'PATCH' });
    const data = await resp.json();
    if (data.success) { const clip = allClips.find(c => c.id === clipId); if (clip) clip.is_favorite = data.is_favorite; applyLibraryView(); }
  } catch (e) {}
}

function onClipSelectChange(clipId) {
  const isSelected = selectedClipIds.has(clipId);
  if (isSelected) selectedClipIds.delete(clipId); else selectedClipIds.add(clipId);
  updateBulkBar();
  const card = document.querySelector('.clip-card[data-clip-id="' + clipId + '"]');
  if (card) {
    const nowSelected = !isSelected;
    card.classList.toggle('selected', nowSelected);
    const cb = card.querySelector('.clip-checkbox'); if (cb) cb.classList.toggle('checked', nowSelected);
  }
}

function toggleSelectAll() {
  const grid = document.getElementById('libraryGrid');
  const visibleIds = [];
  grid.querySelectorAll('.clip-checkbox').forEach(cb => visibleIds.push(cb.dataset.clipId));
  const allSelected = visibleIds.length > 0 && visibleIds.every(id => selectedClipIds.has(id));
  if (allSelected) visibleIds.forEach(id => selectedClipIds.delete(id));
  else visibleIds.forEach(id => selectedClipIds.add(id));
  updateBulkBar();
  grid.querySelectorAll('.clip-card').forEach(card => {
    const cb = card.querySelector('.clip-checkbox'); if (!cb) return;
    card.classList.toggle('selected', selectedClipIds.has(cb.dataset.clipId));
    cb.classList.toggle('checked', selectedClipIds.has(cb.dataset.clipId));
  });
}

function updateBulkBar() {
  const bar = document.getElementById('bulkBar');
  const info = document.getElementById('bulkBarInfo');
  if (selectedClipIds.size > 0) { bar.classList.add('visible'); info.textContent = selectedClipIds.size + ' selected'; }
  else bar.classList.remove('visible');
}

async function bulkDelete() {
  if (!confirm('Delete ' + selectedClipIds.size + ' clip(s) permanently?')) return;
  try {
    const resp = await authFetch('/api/library/bulk-delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ids: Array.from(selectedClipIds) }) });
    if (resp.ok) { selectedClipIds.clear(); updateBulkBar(); showToast('Clips deleted', 'success'); loadLibrary(); }
  } catch (e) {}
}

function bulkDownload() {
  const clips = allClips.filter(c => selectedClipIds.has(c.id));
  clips.forEach((clip, i) => { setTimeout(() => { const a = document.createElement('a'); a.href = clip.download_url; a.download = (clip.title || 'clip') + (clip.file_ext || '.mp4'); document.body.appendChild(a); a.click(); document.body.removeChild(a); }, i * 500); });
}

const _dateFormatter = new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric' });

function renderLibrary(clips) {
  const grid = document.getElementById('libraryGrid');
  const empty = document.getElementById('libraryEmpty');
  const stats = document.getElementById('libraryStats');
  const oldCards = grid.querySelectorAll('.clip-card, .skeleton-card');
  for (let i = oldCards.length - 1; i >= 0; i--) oldCards[i].remove();
  if (clips.length === 0) {
    empty.style.display = '';
    stats.textContent = currentFilter !== 'all' || document.getElementById('librarySearch').value ? 'No clips match your filters' : '';
    return;
  }
  empty.style.display = 'none';
  let totalSize = 0;
  for (let i = 0; i < clips.length; i++) totalSize += (clips[i].file_size || 0);
  stats.textContent = clips.length + ' clip' + (clips.length !== 1 ? 's' : '') + ' \u00b7 ' + formatFileSize(totalSize);

  const frag = document.createDocumentFragment();
  for (let i = 0; i < clips.length; i++) {
    const clip = clips[i];
    const safeId = isValidUUID(clip.id) ? clip.id : '';
    if (!safeId) continue;
    const card = document.createElement('div');
    card.className = 'clip-card' + (selectedClipIds.has(safeId) ? ' selected' : '');
    card.dataset.clipId = safeId;
    const dateStr = _dateFormatter.format(new Date(clip.created_at));
    let tagsHtml = '';
    if (clip.tags) { const tagArr = clip.tags.split(','); let tagParts = ''; for (let j = 0; j < tagArr.length; j++) { const t = tagArr[j].trim(); if (t) tagParts += '<span class="clip-tag">' + escapeHtml(t) + '</span>'; } if (tagParts) tagsHtml = '<div class="clip-tags">' + tagParts + '</div>'; }
    const isChecked = selectedClipIds.has(safeId);
    const isFav = clip.is_favorite;
    const safePlatform = escapeAttr(clip.platform || 'unknown');
    card.innerHTML =
      '<div class="clip-card-thumb">' +
        '<div class="clip-checkbox' + (isChecked ? ' checked' : '') + '" data-clip-id="' + safeId + '"></div>' +
        '<button type="button" class="clip-favorite' + (isFav ? ' active' : '') + '" data-clip-id="' + safeId + '" title="Favorite">' + (isFav ? '\u2605' : '\u2606') + '</button>' +
        (clip.thumbnail ? '<img src="' + escapeAttr(clip.thumbnail) + '" alt="' + escapeAttr(clip.title) + '" loading="lazy">' : '') +
        '<span class="clip-platform-tag ' + safePlatform + '">' + escapeHtml(PLATFORM_LABELS[clip.platform] || clip.platform) + '</span>' +
      '</div>' +
      '<div class="clip-card-body">' +
        '<h4 class="clip-title-edit" data-clip-id="' + safeId + '" title="Click to edit">' + escapeHtml(clip.title) + '</h4>' +
        tagsHtml +
        '<div class="clip-meta">' + escapeHtml(clip.channel || '') + ' \u00b7 ' + dateStr + ' \u00b7 ' + formatFileSize(clip.file_size || 0) + '</div>' +
        '<div class="clip-card-actions">' +
          '<a class="clip-btn-dl" href="' + escapeAttr(clip.download_url || '') + '" download="' + escapeAttr((clip.title || 'clip') + (clip.file_ext || '.mp4')) + '">Download</a>' +
          '<button type="button" class="clip-btn-del" data-clip-id="' + safeId + '">Delete</button>' +
        '</div>' +
      '</div>';
    frag.appendChild(card);
  }
  grid.appendChild(frag);
}

async function deleteClip(id, btnEl) {
  if (!confirm('Delete this clip permanently?')) return;
  btnEl.textContent = '...'; btnEl.disabled = true;
  try {
    const resp = await authFetch('/api/library/' + id, { method: 'DELETE' });
    if (resp.ok) {
      const card = btnEl.closest('.clip-card'); card.style.opacity = '0'; card.style.transform = 'scale(0.9)';
      selectedClipIds.delete(id); updateBulkBar();
      showToast('Clip deleted', 'success');
      setTimeout(() => { card.remove(); loadLibrary(); }, 300);
    }
  } catch (e) { btnEl.textContent = 'Error'; }
}

// ── Library panel toggle ───────────────────
function toggleLibrary() {
  const overlay = document.getElementById('libraryOverlay');
  if (overlay.classList.contains('visible')) closeLibrary();
  else { overlay.classList.add('visible'); document.getElementById('btnLibrary').classList.add('active'); loadLibrary(); }
}

function closeLibrary() {
  document.getElementById('libraryOverlay').classList.remove('visible');
  document.getElementById('btnLibrary').classList.remove('active');
}

// ── Event Delegation: Library Grid ─────────
document.getElementById('libraryGrid').addEventListener('click', function(e) {
  const target = e.target;
  const checkbox = target.closest('.clip-checkbox');
  if (checkbox) { e.stopPropagation(); const clipId = checkbox.dataset.clipId; if (clipId && isValidUUID(clipId)) onClipSelectChange(clipId); return; }
  const favBtn = target.closest('.clip-favorite');
  if (favBtn) { e.stopPropagation(); const clipId = favBtn.dataset.clipId; if (clipId && isValidUUID(clipId)) toggleFavorite(clipId); return; }
  const titleEl = target.closest('.clip-title-edit');
  if (titleEl) { const clipId = titleEl.dataset.clipId; if (clipId && isValidUUID(clipId)) openEditModal(clipId); return; }
  const delBtn = target.closest('.clip-btn-del');
  if (delBtn) { const clipId = delBtn.dataset.clipId; if (clipId && isValidUUID(clipId)) deleteClip(clipId, delBtn); return; }
});

// ── Toast Notifications ────────────────────
function showToast(message, type, duration) {
  duration = duration || 3500;
  type = type || 'info';
  const container = document.getElementById('toastContainer');
  const toast = document.createElement('div');
  toast.className = 'toast toast-' + type;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => { toast.classList.add('toast-out'); setTimeout(() => toast.remove(), 300); }, duration);
}

// ── Edit Modal ─────────────────────────────
function openEditModal(clipId) {
  const clip = allClips.find(c => c.id === clipId); if (!clip) return;
  document.getElementById('editClipId').value = clipId;
  document.getElementById('editTitleInput').value = clip.title || '';
  editTags = clip.tags ? clip.tags.split(',').map(t => t.trim()).filter(Boolean) : [];
  renderEditTags();
  document.getElementById('editModalOverlay').classList.add('visible');
  document.getElementById('editTitleInput').focus();
}

function closeEditModal() { document.getElementById('editModalOverlay').classList.remove('visible'); }

function renderEditTags() {
  const wrap = document.getElementById('editTagInputWrap');
  wrap.querySelectorAll('.tag-chip').forEach(el => el.remove());
  const field = document.getElementById('editTagField');
  editTags.forEach((tag, i) => {
    const chip = document.createElement('span'); chip.className = 'tag-chip';
    chip.innerHTML = escapeHtml(tag) + '<span class="tag-remove">&times;</span>';
    chip.querySelector('.tag-remove').onclick = () => { editTags.splice(i, 1); renderEditTags(); };
    wrap.insertBefore(chip, field);
  });
}

document.getElementById('editTagField').addEventListener('keydown', function(e) {
  if ((e.key === 'Enter' || e.key === ',') && this.value.trim()) {
    e.preventDefault();
    const tag = this.value.trim().replace(/,/g, '').substring(0, 30);
    if (tag && editTags.length < 10 && !editTags.includes(tag)) { editTags.push(tag); renderEditTags(); }
    this.value = '';
  }
  if (e.key === 'Backspace' && !this.value && editTags.length > 0) { editTags.pop(); renderEditTags(); }
});

async function saveEdit() {
  const clipId = document.getElementById('editClipId').value;
  const title = document.getElementById('editTitleInput').value.trim();
  const tagsStr = editTags.length > 0 ? editTags.join(',') : null;
  try {
    const resp = await authFetch('/api/library/' + clipId, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ title, tags: tagsStr }) });
    const data = await resp.json();
    if (data.success) {
      const clip = allClips.find(c => c.id === clipId);
      if (clip) { clip.title = title; clip.tags = tagsStr; }
      closeEditModal(); applyLibraryView(); showToast('Clip updated!', 'success');
    } else showToast(data.error || 'Update failed', 'error');
  } catch (e) { showToast('Update failed — network error', 'error'); }
}

// ── Auth ────────────────────────────────────
function getAuthState() { try { const s = localStorage.getItem('clipforge_auth'); return s ? JSON.parse(s) : null; } catch { return null; } }
function setAuthState(state) { if (state) localStorage.setItem('clipforge_auth', JSON.stringify(state)); else localStorage.removeItem('clipforge_auth'); }
function isLoggedIn() { return !!getAuthState()?.accessToken; }
function authHeaders() { const state = getAuthState(); if (state?.accessToken) return { 'Authorization': 'Bearer ' + state.accessToken }; return {}; }

async function authFetch(url, options) {
  options = options || {};
  options.headers = { ...authHeaders(), ...(options.headers || {}) };
  let resp = await fetchWithRetry(url, options);
  if (resp.status === 401 && isLoggedIn()) { const refreshed = await refreshToken(); if (refreshed) { options.headers = { ...authHeaders(), ...(options.headers || {}) }; resp = await fetchWithRetry(url, options); } }
  return resp;
}

async function fetchWithRetry(url, options, maxRetries) {
  maxRetries = maxRetries || 2; let lastError;
  for (let i = 0; i <= maxRetries; i++) {
    try { const resp = await fetch(url, options); if (resp.status >= 500 && i < maxRetries) { await new Promise(r => setTimeout(r, 500 * (i + 1))); continue; } return resp; }
    catch (e) { lastError = e; if (i < maxRetries) await new Promise(r => setTimeout(r, 500 * (i + 1))); }
  }
  throw lastError;
}

async function refreshToken() {
  const state = getAuthState();
  if (!state?.refreshToken) return false;
  try {
    const resp = await fetch('/api/auth/refresh', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ refresh_token: state.refreshToken }) });
    const data = await resp.json();
    if (data.success) { state.accessToken = data.access_token; state.refreshToken = data.refresh_token; setAuthState(state); return true; }
  } catch {}
  logout(); return false;
}

function showAuthModal(mode) {
  authMode = mode || 'login';
  document.getElementById('authModalTitle').textContent = authMode === 'login' ? 'Log In' : 'Sign Up';
  document.getElementById('authSubmit').textContent = authMode === 'login' ? 'Log In' : 'Sign Up';
  document.getElementById('authToggleText').textContent = authMode === 'login' ? "Don't have an account?" : 'Already have an account?';
  document.getElementById('authToggleLink').textContent = authMode === 'login' ? 'Sign up' : 'Log in';
  document.getElementById('authError').classList.remove('visible');
  document.getElementById('authEmail').value = ''; document.getElementById('authPassword').value = '';
  document.getElementById('authModalOverlay').classList.add('visible');
  document.getElementById('authEmail').focus();
}

function closeAuthModal() { document.getElementById('authModalOverlay').classList.remove('visible'); }
function toggleAuthMode() { showAuthModal(authMode === 'login' ? 'signup' : 'login'); }

async function submitAuth() {
  const email = document.getElementById('authEmail').value.trim();
  const password = document.getElementById('authPassword').value;
  const errEl = document.getElementById('authError');
  const btn = document.getElementById('authSubmit');
  errEl.classList.remove('visible');
  if (!email || !password) { errEl.textContent = 'Email and password required.'; errEl.classList.add('visible'); return; }
  btn.disabled = true; btn.textContent = authMode === 'login' ? 'Logging in...' : 'Signing up...';
  try {
    const resp = await fetch(authMode === 'login' ? '/api/auth/login' : '/api/auth/signup', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }) });
    const data = await resp.json();
    if (!resp.ok) { errEl.textContent = data.error || 'Authentication failed.'; errEl.classList.add('visible'); return; }
    if (authMode === 'signup') { showToast('Account created! Check your email to confirm.', 'success', 5000); showAuthModal('login'); return; }
    setAuthState({ accessToken: data.access_token, refreshToken: data.refresh_token, user: data.user });
    closeAuthModal(); updateUserUI(); showToast('Welcome back, ' + data.user.email + '!', 'success'); loadLibrary();
  } catch (e) { errEl.textContent = 'Network error.'; errEl.classList.add('visible'); }
  finally { btn.disabled = false; btn.textContent = authMode === 'login' ? 'Log In' : 'Sign Up'; }
}

function logout() { setAuthState(null); localStorage.removeItem('clipforge_library'); allClips = []; applyLibraryView(); updateUserUI(); showToast('Logged out', 'info'); }

function updateUserUI() {
  const area = document.getElementById('userArea'); area.textContent = '';
  const state = getAuthState();
  if (state?.user) {
    const bar = document.createElement('div'); bar.className = 'user-bar';
    const emailSpan = document.createElement('span'); emailSpan.className = 'user-email'; emailSpan.textContent = state.user.email;
    const logoutBtn = document.createElement('button'); logoutBtn.type = 'button'; logoutBtn.className = 'btn-logout'; logoutBtn.textContent = 'Log out';
    logoutBtn.addEventListener('click', logout);
    bar.appendChild(emailSpan); bar.appendChild(logoutBtn); area.appendChild(bar);
  } else {
    const loginBtn = document.createElement('button'); loginBtn.type = 'button'; loginBtn.className = 'btn-nav'; loginBtn.textContent = 'Log in';
    loginBtn.addEventListener('click', () => showAuthModal('login'));
    area.appendChild(loginBtn);
  }
}

document.getElementById('authPassword').addEventListener('keydown', e => { if (e.key === 'Enter') submitAuth(); });

// ── Init ───────────────────────────────────
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
