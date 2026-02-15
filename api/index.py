"""
ClipForge — YouTube Video Trimmer (Vercel Serverless)
All routes served from a single Flask app.
"""

import os
import re
import json
import uuid
import subprocess
import time
import shutil
from pathlib import Path
from flask import Flask, request, jsonify, send_file, Response

# Locate ffmpeg — use static-ffmpeg package (provides Linux binaries on Lambda)
try:
    import static_ffmpeg
    static_ffmpeg.add_paths()
except ImportError:
    pass

app = Flask(__name__)

TEMP_DIR = Path("/tmp/clipforge")
TEMP_DIR.mkdir(exist_ok=True)


def cleanup_old_files(max_age_seconds=300):
    """Remove temp files older than 5 minutes."""
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


# ── Serve frontend ───────────────────────────────────────────────────────────

@app.route("/")
def index():
    return INDEX_HTML


# ── API: Video Info ──────────────────────────────────────────────────────────

@app.route("/api/video-info", methods=["POST"])
def video_info():
    data = request.json
    url = data.get("url", "")
    video_id = extract_video_id(url)
    if not video_id:
        return jsonify({"error": "Invalid YouTube URL"}), 400

    try:
        cmd = ["yt-dlp", "--dump-json", "--no-playlist", url]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
        if result.returncode != 0:
            return jsonify({"error": "Could not fetch video info"}), 400

        info = json.loads(result.stdout)
        return jsonify({
            "id": video_id,
            "title": info.get("title", "Unknown"),
            "duration": info.get("duration", 0),
            "thumbnail": info.get("thumbnail", ""),
            "channel": info.get("uploader", "Unknown"),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── API: Trim (synchronous — downloads, trims, returns file) ─────────────────

@app.route("/api/trim", methods=["POST"])
def trim_video():
    cleanup_old_files()

    data = request.json
    url = data.get("url", "")
    start_time = data.get("start", "0:00")
    end_time = data.get("end", "0:00")

    video_id = extract_video_id(url)
    if not video_id:
        return jsonify({"error": "Invalid YouTube URL"}), 400

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
        # Step 1: Download
        raw_output = job_dir / "raw.%(ext)s"
        dl_cmd = [
            "yt-dlp",
            "-f", "bestvideo[ext=mp4][height<=720]+bestaudio[ext=m4a]/best[ext=mp4][height<=720]/best[height<=720]",
            "--merge-output-format", "mp4",
            "-o", str(raw_output),
            "--no-playlist",
            "--download-sections", f"*{start_sec}-{end_sec}",
            url,
        ]
        result = subprocess.run(dl_cmd, capture_output=True, text=True, timeout=55)
        if result.returncode != 0:
            return jsonify({"error": f"Download failed: {result.stderr[:300]}"}), 500

        # Find downloaded file
        raw_file = None
        for f in job_dir.iterdir():
            if f.name.startswith("raw"):
                raw_file = f
                break

        if not raw_file:
            return jsonify({"error": "Downloaded file not found."}), 500

        # Step 2: Re-encode with ffmpeg for clean cuts
        output_file = job_dir / "trimmed.mp4"
        trim_cmd = [
            "ffmpeg", "-y",
            "-i", str(raw_file),
            "-c:v", "libx264",
            "-c:a", "aac",
            "-movflags", "+faststart",
            "-preset", "ultrafast",
            str(output_file),
        ]
        result = subprocess.run(trim_cmd, capture_output=True, text=True, timeout=55)

        # If re-encode fails, serve the raw download (already trimmed by yt-dlp)
        if result.returncode != 0 or not output_file.exists():
            output_file = raw_file

        return send_file(
            str(output_file),
            as_attachment=True,
            download_name=f"clip_{job_id}.mp4",
            mimetype="video/mp4",
        )

    except subprocess.TimeoutExpired:
        return jsonify({"error": "Processing timed out. Try a shorter clip."}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        # Schedule cleanup (files stay briefly for the send_file to complete)
        pass


# ── Frontend HTML ────────────────────────────────────────────────────────────

INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ClipForge — YouTube Trimmer</title>
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

.header {
  text-align: center;
  margin-bottom: 3rem;
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
  font-size: 2.6rem;
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

.action-section { display: none; }
.action-section.visible { display: block; animation: fadeSlideIn 0.5s ease-out; }

.btn-trim {
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
.btn-trim::before {
  content: '';
  position: absolute;
  inset: 0;
  background: linear-gradient(135deg, transparent 0%, #ffffff20 100%);
  opacity: 0;
  transition: opacity 0.3s;
}
.btn-trim:hover::before { opacity: 1; }
.btn-trim:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 32px var(--accent-glow);
}
.btn-trim:active { transform: translateY(0); }
.btn-trim:disabled {
  opacity: 0.5;
  cursor: not-allowed;
  transform: none;
  box-shadow: none;
}

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

@keyframes fadeSlideIn {
  from { opacity: 0; transform: translateY(12px); }
  to { opacity: 1; transform: translateY(0); }
}

@keyframes scalePop {
  from { opacity: 0; transform: scale(0.9); }
  to { opacity: 1; transform: scale(1); }
}

@keyframes spin { to { transform: rotate(360deg); } }

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

  <header class="header">
    <div class="logo">ClipForge</div>
    <h1>Trim Any YouTube Video</h1>
    <p>Paste a link, set your cut points, download the clip.</p>
  </header>

  <div class="panel">
    <div class="panel-label"><span class="dot"></span> Source</div>
    <div class="url-group">
      <input type="text" class="url-input" id="urlInput"
             placeholder="https://youtube.com/watch?v=..."
             spellcheck="false" autocomplete="off">
      <button class="btn-load" id="btnLoad" onclick="loadVideo()">Load</button>
    </div>
    <div class="error-msg" id="urlError"></div>
  </div>

  <div class="panel preview-section" id="previewSection">
    <div class="panel-label"><span class="dot"></span> Preview</div>
    <div class="video-meta">
      <img class="video-thumb" id="videoThumb" src="" alt="">
      <div class="video-info">
        <h3 id="videoTitle"></h3>
        <div class="channel" id="videoChannel"></div>
        <div class="duration-badge" id="videoDuration"></div>
      </div>
    </div>
    <div class="player-wrap">
      <iframe id="ytPlayer" src="" allow="autoplay; encrypted-media" allowfullscreen></iframe>
    </div>
  </div>

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

  <div class="action-section" id="actionSection">
    <button class="btn-trim" id="btnTrim" onclick="startTrim()">
      Trim & Download
    </button>
    <div class="limit-note">Max clip length: 10 minutes</div>
    <div class="error-msg" id="trimError"></div>
  </div>

  <div class="panel progress-section" id="progressSection">
    <div class="panel-label"><span class="dot"></span> Processing</div>
    <div class="progress-bar-track">
      <div class="progress-bar-fill" id="progressFill"></div>
    </div>
    <div class="progress-status" id="progressStatus">
      <span class="spinner"></span> Downloading & trimming your clip...
    </div>
  </div>

  <div class="panel download-section" id="downloadSection">
    <div class="download-icon">
      <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
        <polyline points="7 10 12 15 17 10"/>
        <line x1="12" y1="15" x2="12" y2="3"/>
      </svg>
    </div>
    <div class="success-text">Your clip is ready!</div>
    <p style="color:var(--text-secondary);font-size:0.85rem;margin-bottom:0.5rem" id="downloadInfo"></p>
    <a class="btn-download" id="btnDownload" href="#">Download MP4</a>
    <br>
    <button class="reset-link" onclick="resetAll()">Trim another video</button>
  </div>

</div>

<script>
let videoDuration = 0;
let videoId = '';
let dragging = null;

async function loadVideo() {
  const url = document.getElementById('urlInput').value.trim();
  const btn = document.getElementById('btnLoad');
  const err = document.getElementById('urlError');
  err.classList.remove('visible');

  if (!url) { showError('urlError', 'Please paste a YouTube URL.'); return; }

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

    videoId = data.id;
    videoDuration = data.duration;

    document.getElementById('videoThumb').src = data.thumbnail;
    document.getElementById('videoTitle').textContent = data.title;
    document.getElementById('videoChannel').textContent = data.channel;
    document.getElementById('videoDuration').textContent = formatTime(data.duration);
    document.getElementById('ytPlayer').src =
      `https://www.youtube.com/embed/${data.id}?rel=0&modestbranding=1`;

    document.getElementById('endInput').value = formatTime(data.duration);
    document.getElementById('totalDurationLabel').textContent = formatTime(data.duration);
    document.getElementById('clipDuration').textContent = formatTime(data.duration);

    document.getElementById('previewSection').classList.add('visible');
    document.getElementById('timelineSection').classList.add('visible');
    document.getElementById('actionSection').classList.add('visible');

    generateWaveform();
    updateTimeline();
  } catch (e) {
    showError('urlError', 'Network error — is the server running?');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Load';
  }
}

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

async function startTrim() {
  const url = document.getElementById('urlInput').value.trim();
  const start = document.getElementById('startInput').value.trim();
  const end = document.getElementById('endInput').value.trim();
  const errEl = document.getElementById('trimError');
  errEl.classList.remove('visible');

  if (parseTime(end) <= parseTime(start)) {
    showError('trimError', 'End time must be after start time.');
    return;
  }

  if (parseTime(end) - parseTime(start) > 600) {
    showError('trimError', 'Clips are limited to 10 minutes max.');
    return;
  }

  document.getElementById('btnTrim').disabled = true;
  document.getElementById('progressSection').classList.add('visible');
  document.getElementById('actionSection').classList.remove('visible');

  try {
    const resp = await fetch('/api/trim', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, start, end }),
    });

    if (!resp.ok) {
      let errMsg = 'Trimming failed.';
      try { const d = await resp.json(); errMsg = d.error || errMsg; } catch {}
      throw new Error(errMsg);
    }

    // Response is the file itself — create a download
    const blob = await resp.blob();
    const downloadUrl = URL.createObjectURL(blob);

    document.getElementById('progressSection').classList.remove('visible');
    document.getElementById('downloadInfo').textContent = `Trimmed from ${start} to ${end}`;
    document.getElementById('btnDownload').href = downloadUrl;
    document.getElementById('btnDownload').setAttribute('download', `clip_${videoId}.mp4`);
    document.getElementById('downloadSection').classList.add('visible');

  } catch (e) {
    document.getElementById('progressSection').classList.remove('visible');
    showError('trimError', e.message);
    document.getElementById('actionSection').classList.add('visible');
    document.getElementById('btnTrim').disabled = false;
  }
}

function resetAll() {
  ['previewSection','timelineSection','actionSection','progressSection','downloadSection'].forEach(id =>
    document.getElementById(id).classList.remove('visible'));
  document.getElementById('urlInput').value = '';
  document.getElementById('btnTrim').disabled = false;
  videoDuration = 0;
  videoId = '';
}

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
    print("\n  ClipForge — YouTube Video Trimmer")
    print("  Running at http://localhost:5000\n")
    app.run(debug=True, port=5000)
