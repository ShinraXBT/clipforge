"""
ClipForge — Multi-Platform Video Downloader & Trimmer (Vercel Serverless)
Supports: YouTube, Twitter/X, Instagram, TikTok
Uses yt-dlp as a Python library (not CLI) for Vercel compatibility.
"""

import os
import re
import uuid
import time
import shutil
from pathlib import Path
from flask import Flask, request, jsonify, send_file

import yt_dlp

app = Flask(__name__)

TEMP_DIR = Path("/tmp/clipforge")
TEMP_DIR.mkdir(exist_ok=True)


def cleanup_old_files(max_age_seconds=300):
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
    parts = time_str.strip().split(":")
    parts = [int(p) for p in parts]
    if len(parts) == 2:
        return parts[0] * 60 + parts[1]
    elif len(parts) == 3:
        return parts[0] * 3600 + parts[1] * 60 + parts[2]
    return 0


def find_downloaded_file(directory, prefix):
    """Find the first file in directory starting with prefix."""
    for f in directory.iterdir():
        if f.name.startswith(prefix) and f.is_file():
            return f
    return None


# ── Serve frontend ───────────────────────────────────────────────────────────

@app.route("/")
def index():
    return INDEX_HTML


# ── API: Video Info (all platforms) ──────────────────────────────────────────

@app.route("/api/video-info", methods=["POST"])
def video_info():
    data = request.json
    url = data.get("url", "")

    platform = detect_platform(url)
    if not platform:
        return jsonify({"error": "Unsupported URL. Paste a YouTube, Twitter/X, Instagram, or TikTok link."}), 400

    try:
        ydl_opts = {
            "quiet": True,
            "no_warnings": True,
            "noplaylist": True,
            "skip_download": True,
        }

        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
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
        return jsonify({"error": f"Could not fetch video: {str(e)[:200]}"}), 400
    except Exception as e:
        return jsonify({"error": str(e)[:300]}), 500


# ── API: Download (full video, no trim) ──────────────────────────────────────

@app.route("/api/download-full", methods=["POST"])
def download_full():
    cleanup_old_files()

    data = request.json
    url = data.get("url", "")
    platform = detect_platform(url)
    if not platform:
        return jsonify({"error": "Unsupported URL"}), 400

    job_id = str(uuid.uuid4())[:12]
    job_dir = TEMP_DIR / job_id
    job_dir.mkdir(exist_ok=True)

    try:
        output_template = str(job_dir / "video.%(ext)s")

        ydl_opts = {
            "format": "best[ext=mp4]/best",
            "outtmpl": output_template,
            "noplaylist": True,
            "quiet": True,
            "no_warnings": True,
            "socket_timeout": 30,
        }

        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            ydl.download([url])

        dl_file = find_downloaded_file(job_dir, "video")
        if not dl_file:
            return jsonify({"error": "Downloaded file not found."}), 500

        ext = dl_file.suffix or ".mp4"
        return send_file(
            str(dl_file),
            as_attachment=True,
            download_name=f"{platform}_{job_id}{ext}",
            mimetype="video/mp4",
        )

    except yt_dlp.utils.DownloadError as e:
        return jsonify({"error": f"Download failed: {str(e)[:300]}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)[:300]}), 500


# ── API: Trim (works for any platform with duration) ─────────────────────────

@app.route("/api/trim", methods=["POST"])
def trim_video():
    cleanup_old_files()

    data = request.json
    url = data.get("url", "")
    start_time = data.get("start", "0:00")
    end_time = data.get("end", "0:00")

    platform = detect_platform(url)
    if not platform:
        return jsonify({"error": "Unsupported URL"}), 400

    start_sec = time_to_seconds(start_time)
    end_sec = time_to_seconds(end_time)
    duration = end_sec - start_sec

    if duration <= 0:
        return jsonify({"error": "End time must be after start time."}), 400

    if duration > 600:
        return jsonify({"error": "Clips are limited to 10 minutes max."}), 400

    job_id = str(uuid.uuid4())[:12]
    job_dir = TEMP_DIR / job_id
    job_dir.mkdir(exist_ok=True)

    try:
        output_template = str(job_dir / "clip.%(ext)s")

        ydl_opts = {
            "format": "best[ext=mp4][height<=720]/best[height<=720]/best",
            "outtmpl": output_template,
            "noplaylist": True,
            "quiet": True,
            "no_warnings": True,
            "socket_timeout": 30,
            "download_ranges": yt_dlp.utils.download_range_func(
                None, [(start_sec, end_sec)]
            ),
            "force_keyframes_at_cuts": True,
        }

        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            ydl.download([url])

        clip_file = find_downloaded_file(job_dir, "clip")
        if not clip_file:
            return jsonify({"error": "Downloaded file not found."}), 500

        ext = clip_file.suffix or ".mp4"
        return send_file(
            str(clip_file),
            as_attachment=True,
            download_name=f"clip_{job_id}{ext}",
            mimetype="video/mp4",
        )

    except yt_dlp.utils.DownloadError as e:
        return jsonify({"error": f"Trim failed: {str(e)[:300]}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)[:300]}), 500


# ── Frontend HTML ────────────────────────────────────────────────────────────

INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ClipForge — Video Downloader & Trimmer</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Outfit:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}

:root {
  --bg-deep: #07080a;
  --bg-panel: #0d0f13;
  --bg-surface: #13161c;
  --bg-elevated: #1a1e27;
  --border: #1e2230;
  --border-light: #2a2f40;
  --text-primary: #e8eaf0;
  --text-secondary: #7a8199;
  --text-muted: #4a5068;
  --accent: #00e5a0;
  --accent-dim: #00e5a020;
  --accent-glow: #00e5a040;
  --accent-secondary: #00b8ff;
  --danger: #ff4060;
  --timeline-bg: #161a24;
  --timeline-region: #00e5a018;
  --yt: #ff0033;
  --tw: #1d9bf0;
  --ig: #e1306c;
  --tk: #00f2ea;
}

html { font-size: 16px; }

body {
  font-family: 'Outfit', sans-serif;
  background: var(--bg-deep);
  color: var(--text-primary);
  min-height: 100vh;
  overflow-x: hidden;
  -webkit-font-smoothing: antialiased;
}

body::before {
  content: '';
  position: fixed;
  inset: 0;
  background:
    radial-gradient(ellipse 80% 60% at 20% 10%, #00e5a008 0%, transparent 60%),
    radial-gradient(ellipse 60% 50% at 80% 80%, #00b8ff06 0%, transparent 60%);
  pointer-events: none;
  z-index: 0;
}

body::after {
  content: '';
  position: fixed;
  inset: 0;
  background: repeating-linear-gradient(0deg, transparent, transparent 2px, #00000008 2px, #00000008 4px);
  pointer-events: none;
  z-index: 9999;
}

.app-container {
  position: relative;
  z-index: 1;
  max-width: 900px;
  margin: 0 auto;
  padding: 2rem 1.5rem 4rem;
}

/* ── Header ─────────────────────────────────────── */
.header {
  text-align: center;
  margin-bottom: 2.5rem;
  animation: fadeSlideIn 0.8s ease-out;
}

.logo {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.7rem;
  letter-spacing: 6px;
  text-transform: uppercase;
  color: var(--accent);
  margin-bottom: 0.75rem;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.75rem;
}

.logo::before, .logo::after {
  content: '';
  width: 30px;
  height: 1px;
  background: linear-gradient(90deg, transparent, var(--accent));
}
.logo::after {
  background: linear-gradient(90deg, var(--accent), transparent);
}

.header h1 {
  font-size: 2.4rem;
  font-weight: 800;
  letter-spacing: -1.5px;
  line-height: 1.1;
  background: linear-gradient(135deg, var(--text-primary) 0%, var(--text-secondary) 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}

.header p {
  color: var(--text-secondary);
  font-size: 0.95rem;
  margin-top: 0.5rem;
  font-weight: 300;
}

/* ── Platform pills ─────────────────────────────── */
.platforms {
  display: flex;
  justify-content: center;
  gap: 0.5rem;
  margin-top: 1rem;
  flex-wrap: wrap;
}

.platform-pill {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.35rem 0.75rem;
  border-radius: 20px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.65rem;
  font-weight: 600;
  letter-spacing: 0.5px;
  border: 1px solid var(--border);
  background: var(--bg-surface);
  color: var(--text-secondary);
  transition: all 0.3s;
}

.platform-pill svg { width: 14px; height: 14px; }
.platform-pill.yt svg { color: var(--yt); }
.platform-pill.tw svg { color: var(--tw); }
.platform-pill.ig svg { color: var(--ig); }
.platform-pill.tk svg { color: var(--tk); }

.platform-pill.active {
  border-color: var(--accent);
  background: var(--accent-dim);
  color: var(--text-primary);
}

/* ── Panels ─────────────────────────────────────── */
.panel {
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: 16px;
  padding: 1.75rem;
  margin-bottom: 1.25rem;
  animation: fadeSlideIn 0.8s ease-out backwards;
  transition: border-color 0.3s;
}
.panel:hover { border-color: var(--border-light); }

.panel-label {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.6rem;
  letter-spacing: 3px;
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
  box-shadow: 0 0 8px var(--accent-glow);
}

/* ── Platform badge (shown on detected platform) ── */
.platform-badge {
  display: none;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 1rem;
  padding: 0.5rem 0.85rem;
  border-radius: 8px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.7rem;
  font-weight: 600;
  letter-spacing: 1px;
  animation: fadeSlideIn 0.4s ease-out;
}
.platform-badge.visible { display: inline-flex; }
.platform-badge svg { width: 16px; height: 16px; }
.platform-badge.youtube   { background: #ff003315; color: var(--yt); border: 1px solid #ff003330; }
.platform-badge.twitter   { background: #1d9bf015; color: var(--tw); border: 1px solid #1d9bf030; }
.platform-badge.instagram { background: #e1306c15; color: var(--ig); border: 1px solid #e1306c30; }
.platform-badge.tiktok    { background: #00f2ea15; color: var(--tk); border: 1px solid #00f2ea30; }

/* ── URL Input ──────────────────────────────────── */
.url-group {
  display: flex;
  gap: 0.75rem;
}

.url-input {
  flex: 1;
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 0.85rem 1.1rem;
  color: var(--text-primary);
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.85rem;
  outline: none;
  transition: all 0.3s;
}
.url-input::placeholder { color: var(--text-muted); }
.url-input:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-dim), inset 0 0 20px var(--accent-dim);
}

.btn-load {
  background: var(--accent);
  color: var(--bg-deep);
  border: none;
  border-radius: 10px;
  padding: 0.85rem 1.6rem;
  font-family: 'Outfit', sans-serif;
  font-weight: 700;
  font-size: 0.85rem;
  cursor: pointer;
  letter-spacing: 0.5px;
  transition: all 0.25s;
  white-space: nowrap;
}
.btn-load:hover {
  transform: translateY(-1px);
  box-shadow: 0 6px 24px var(--accent-glow);
}
.btn-load:active { transform: translateY(0); }
.btn-load:disabled {
  opacity: 0.4;
  cursor: not-allowed;
  transform: none;
  box-shadow: none;
}

/* ── Video Preview ──────────────────────────────── */
.preview-section { display: none; }
.preview-section.visible { display: block; animation: fadeSlideIn 0.5s ease-out; }

.video-meta {
  display: flex;
  align-items: start;
  gap: 1.25rem;
  margin-bottom: 1.25rem;
}

.video-thumb {
  width: 160px;
  min-width: 160px;
  aspect-ratio: 16/9;
  border-radius: 8px;
  object-fit: cover;
  border: 1px solid var(--border);
}

.video-info h3 {
  font-size: 1rem;
  font-weight: 600;
  line-height: 1.4;
  margin-bottom: 0.25rem;
  word-break: break-word;
}

.video-info .channel {
  color: var(--text-secondary);
  font-size: 0.8rem;
  font-weight: 400;
}

.video-info .duration-badge {
  display: inline-block;
  margin-top: 0.5rem;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.7rem;
  background: var(--bg-elevated);
  color: var(--accent);
  padding: 0.3rem 0.7rem;
  border-radius: 6px;
  border: 1px solid var(--border);
}

.player-wrap {
  position: relative;
  width: 100%;
  aspect-ratio: 16/9;
  border-radius: 12px;
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
  padding: 2rem;
  background: var(--bg-surface);
}

/* ── Mode Toggle (Trim vs Download) ─────────────── */
.mode-toggle {
  display: none;
  gap: 0.5rem;
  margin-bottom: 1.25rem;
}
.mode-toggle.visible { display: flex; }

.mode-btn {
  flex: 1;
  padding: 0.75rem;
  border: 1px solid var(--border);
  border-radius: 10px;
  background: var(--bg-surface);
  color: var(--text-secondary);
  font-family: 'Outfit', sans-serif;
  font-size: 0.85rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.25s;
  text-align: center;
}

.mode-btn:hover { border-color: var(--border-light); color: var(--text-primary); }

.mode-btn.active {
  border-color: var(--accent);
  background: var(--accent-dim);
  color: var(--accent);
}

/* ── Timeline ───────────────────────────────────── */
.timeline-section { display: none; }
.timeline-section.visible { display: block; animation: fadeSlideIn 0.5s ease-out; }

.time-controls {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
  margin-bottom: 1.5rem;
}

.time-field label {
  display: block;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.6rem;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--text-muted);
  margin-bottom: 0.5rem;
}

.time-field input {
  width: 100%;
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.7rem 1rem;
  color: var(--text-primary);
  font-family: 'JetBrains Mono', monospace;
  font-size: 1.1rem;
  font-weight: 600;
  text-align: center;
  outline: none;
  transition: all 0.3s;
}
.time-field input:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-dim);
}

.timeline-track {
  position: relative;
  height: 56px;
  background: var(--timeline-bg);
  border-radius: 10px;
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
  padding: 0 8px;
  opacity: 0.25;
}

.timeline-waveform .bar {
  width: 3px;
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
  background: linear-gradient(180deg, var(--accent-dim) 0%, transparent 100%);
}

.timeline-handle {
  position: absolute;
  top: 0;
  bottom: 0;
  width: 14px;
  cursor: ew-resize;
  z-index: 5;
  display: flex;
  align-items: center;
  justify-content: center;
}

.timeline-handle::after {
  content: '';
  width: 4px;
  height: 20px;
  border-radius: 2px;
  background: var(--accent);
  box-shadow: 0 0 10px var(--accent-glow);
}

.timeline-handle:hover::after {
  height: 28px;
  box-shadow: 0 0 16px var(--accent);
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
  margin-top: 1rem;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.8rem;
  color: var(--text-secondary);
}
.clip-duration span { color: var(--accent); font-weight: 700; }

/* ── Action Buttons ─────────────────────────────── */
.action-section { display: none; }
.action-section.visible { display: block; animation: fadeSlideIn 0.5s ease-out; }

.btn-action {
  width: 100%;
  padding: 1.1rem;
  background: linear-gradient(135deg, var(--accent) 0%, #00c98a 100%);
  color: var(--bg-deep);
  border: none;
  border-radius: 12px;
  font-family: 'Outfit', sans-serif;
  font-size: 1rem;
  font-weight: 700;
  letter-spacing: 0.5px;
  cursor: pointer;
  transition: all 0.3s;
  position: relative;
  overflow: hidden;
}
.btn-action::before {
  content: '';
  position: absolute;
  inset: 0;
  background: linear-gradient(135deg, transparent 0%, #ffffff20 100%);
  opacity: 0;
  transition: opacity 0.3s;
}
.btn-action:hover::before { opacity: 1; }
.btn-action:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 32px var(--accent-glow);
}
.btn-action:active { transform: translateY(0); }
.btn-action:disabled {
  opacity: 0.5;
  cursor: not-allowed;
  transform: none;
  box-shadow: none;
}

/* ── Progress ───────────────────────────────────── */
.progress-section { display: none; }
.progress-section.visible { display: block; animation: fadeSlideIn 0.5s ease-out; }

.progress-bar-track {
  height: 6px;
  background: var(--bg-elevated);
  border-radius: 3px;
  overflow: hidden;
  margin: 1rem 0;
}

.progress-bar-fill {
  height: 100%;
  background: linear-gradient(90deg, var(--accent), var(--accent-secondary));
  border-radius: 3px;
  width: 0%;
  animation: indeterminate 1.8s ease-in-out infinite;
}

@keyframes indeterminate {
  0% { width: 5%; margin-left: 0; }
  50% { width: 40%; margin-left: 30%; }
  100% { width: 5%; margin-left: 95%; }
}

.progress-status {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.75rem;
  color: var(--text-secondary);
  text-align: center;
}

.progress-status .spinner {
  display: inline-block;
  width: 12px;
  height: 12px;
  border: 2px solid var(--border-light);
  border-top-color: var(--accent);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
  vertical-align: middle;
  margin-right: 0.5rem;
}

/* ── Download Ready ─────────────────────────────── */
.download-section { display: none; text-align: center; }
.download-section.visible { display: block; animation: scalePop 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275); }

.download-icon {
  width: 64px;
  height: 64px;
  margin: 0 auto 1rem;
  border-radius: 50%;
  background: var(--accent-dim);
  border: 2px solid var(--accent);
  display: flex;
  align-items: center;
  justify-content: center;
  box-shadow: 0 0 40px var(--accent-glow);
}

.download-icon svg { width: 28px; height: 28px; stroke: var(--accent); }

.btn-download {
  display: inline-block;
  padding: 0.9rem 2.5rem;
  background: var(--accent);
  color: var(--bg-deep);
  border: none;
  border-radius: 10px;
  font-family: 'Outfit', sans-serif;
  font-size: 0.95rem;
  font-weight: 700;
  cursor: pointer;
  text-decoration: none;
  transition: all 0.25s;
  margin-top: 0.5rem;
}
.btn-download:hover {
  transform: translateY(-1px);
  box-shadow: 0 6px 24px var(--accent-glow);
}

.success-text { color: var(--accent); font-weight: 600; margin-bottom: 0.25rem; }

.reset-link {
  display: inline-block;
  margin-top: 1rem;
  color: var(--text-muted);
  font-size: 0.8rem;
  cursor: pointer;
  transition: color 0.2s;
  background: none;
  border: none;
  font-family: 'Outfit', sans-serif;
  text-decoration: underline;
  text-underline-offset: 3px;
}
.reset-link:hover { color: var(--text-secondary); }

/* ── Error ──────────────────────────────────────── */
.error-msg {
  display: none;
  background: #ff406010;
  border: 1px solid #ff406030;
  border-radius: 10px;
  padding: 0.9rem 1.1rem;
  color: var(--danger);
  font-size: 0.85rem;
  margin-top: 1rem;
  font-family: 'JetBrains Mono', monospace;
}
.error-msg.visible { display: block; animation: fadeSlideIn 0.3s ease-out; }

.limit-note {
  text-align: center;
  font-size: 0.7rem;
  color: var(--text-muted);
  font-family: 'JetBrains Mono', monospace;
  margin-top: 0.75rem;
}

/* ── Animations ─────────────────────────────────── */
@keyframes fadeSlideIn {
  from { opacity: 0; transform: translateY(12px); }
  to { opacity: 1; transform: translateY(0); }
}

@keyframes scalePop {
  from { opacity: 0; transform: scale(0.9); }
  to { opacity: 1; transform: scale(1); }
}

@keyframes spin { to { transform: rotate(360deg); } }

/* ── Responsive ─────────────────────────────────── */
@media (max-width: 600px) {
  .app-container { padding: 1.25rem 1rem 3rem; }
  .header h1 { font-size: 1.8rem; }
  .url-group { flex-direction: column; }
  .video-meta { flex-direction: column; }
  .video-thumb { width: 100%; }
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

  <!-- URL Input -->
  <div class="panel">
    <div class="panel-label"><span class="dot"></span> Source</div>
    <div class="url-group">
      <input type="text" class="url-input" id="urlInput"
             placeholder="Paste a YouTube, Twitter, Instagram, or TikTok URL..."
             spellcheck="false" autocomplete="off">
      <button class="btn-load" id="btnLoad" onclick="loadVideo()">Load</button>
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
      <iframe id="ytPlayer" src="" allow="autoplay; encrypted-media" allowfullscreen></iframe>
    </div>
  </div>

  <!-- Mode Toggle -->
  <div class="mode-toggle" id="modeToggle">
    <button class="mode-btn active" id="modeDownload" onclick="setMode('download')">Download Full</button>
    <button class="mode-btn" id="modeTrim" onclick="setMode('trim')">Trim & Download</button>
  </div>

  <!-- Timeline (trim mode) -->
  <div class="panel timeline-section" id="timelineSection">
    <div class="panel-label"><span class="dot"></span> Trim Range</div>
    <div class="time-controls">
      <div class="time-field">
        <label>Start Time</label>
        <input type="text" id="startInput" value="0:00" placeholder="0:00">
      </div>
      <div class="time-field">
        <label>End Time</label>
        <input type="text" id="endInput" value="0:00" placeholder="0:00">
      </div>
    </div>
    <div class="timeline-track" id="timelineTrack">
      <div class="timeline-waveform" id="waveform"></div>
      <div class="timeline-region" id="timelineRegion"></div>
      <div class="timeline-handle" id="handleStart" style="left: 0%"></div>
      <div class="timeline-handle" id="handleEnd" style="left: 100%"></div>
    </div>
    <div class="timeline-labels">
      <span>0:00</span>
      <span id="totalDurationLabel">0:00</span>
    </div>
    <div class="clip-duration">Clip length: <span id="clipDuration">0:00</span></div>
  </div>

  <!-- Action Button -->
  <div class="action-section" id="actionSection">
    <button class="btn-action" id="btnAction" onclick="startAction()">
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

  <!-- Download -->
  <div class="panel download-section" id="downloadSection">
    <div class="download-icon">
      <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
        <polyline points="7 10 12 15 17 10"/>
        <line x1="12" y1="15" x2="12" y2="3"/>
      </svg>
    </div>
    <div class="success-text">Your video is ready!</div>
    <p style="color:var(--text-secondary);font-size:0.85rem;margin-bottom:0.5rem" id="downloadInfo"></p>
    <a class="btn-download" id="btnDownload" href="#">Download MP4</a>
    <br>
    <button class="reset-link" onclick="resetAll()">Download another video</button>
  </div>

</div>

<script>
let videoDuration = 0;
let videoId = '';
let currentPlatform = '';
let currentMode = 'download';
let dragging = null;

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
    badge.innerHTML = `${PLATFORM_ICONS[currentPlatform] || ''} ${PLATFORM_LABELS[currentPlatform] || currentPlatform}`;

    // Video meta
    document.getElementById('videoThumb').src = data.thumbnail || '';
    document.getElementById('videoTitle').textContent = data.title || 'Untitled';
    document.getElementById('videoChannel').textContent = data.channel || '';
    document.getElementById('videoDuration').textContent = videoDuration ? formatTime(videoDuration) : 'N/A';

    // Player — only YouTube gets embed
    const playerWrap = document.getElementById('playerWrap');
    const ytPlayer = document.getElementById('ytPlayer');
    if (currentPlatform === 'youtube' && videoId) {
      ytPlayer.src = `https://www.youtube.com/embed/${videoId}?rel=0&modestbranding=1`;
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
document.addEventListener('touchmove', e => handleMove(e.touches[0].clientX));
document.addEventListener('mouseup', () => { dragging = null; });
document.addEventListener('touchend', () => { dragging = null; });
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
    const downloadUrl = URL.createObjectURL(blob);

    document.getElementById('progressSection').classList.remove('visible');
    document.getElementById('downloadInfo').textContent = infoText;
    document.getElementById('btnDownload').href = downloadUrl;
    document.getElementById('btnDownload').setAttribute('download',
      `${currentPlatform}_${videoId || 'video'}.mp4`);
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
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  return m + ':' + String(s).padStart(2, '0');
}

function parseTime(str) {
  const parts = str.split(':').map(Number);
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
</script>
</body>
</html>
"""

if __name__ == "__main__":
    print("\n  ClipForge — Video Downloader & Trimmer")
    print("  Running at http://localhost:5000\n")
    app.run(debug=True, port=5000)
