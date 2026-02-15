# ClipForge — Multi-Platform Video Downloader & Trimmer

## Architecture
- **Single-file app**: `api/index.py` contains Flask backend + full HTML/CSS/JS frontend
- `app.py` is a mirror of `api/index.py` for local development
- Deployed on Vercel (serverless)
- Supabase for storage (video files) + PostgreSQL (clip metadata)

## Tech Stack
- Python / Flask
- yt-dlp (video downloading)
- Supabase (storage + DB)
- Vanilla HTML/CSS/JS frontend (no framework)
- Vercel serverless deployment

## UI Layout
- Two-column layout: editor (left 57%) + library (right 43%)
- Library is sticky-scrollable, always visible
- Save dialog with custom title + tag chips
- Library toolbar: search, platform filter pills, sort dropdown
- Clip cards: checkbox (bulk mode), favorite star, tags
- Bulk action bar: multi-select download/delete

## DB Schema (Supabase `clips` table)
- id, title, platform, source_url, thumbnail, channel, duration
- trim_start, trim_end, mode, file_path, file_size, file_ext
- tags (TEXT, comma-separated), is_favorite (BOOLEAN)
- created_at

## APIs
- `POST /api/video-info` — fetch video metadata
- `POST /api/download-full` — download full video
- `POST /api/trim` — trim + download
- `POST /api/save-to-library` — download + save to Supabase (with tags)
- `GET /api/library` — list all clips
- `DELETE /api/library/<id>` — delete single clip
- `PATCH /api/library/<id>/favorite` — toggle favorite
- `POST /api/library/bulk-delete` — delete multiple clips

## How to Run
```bash
pip install flask yt-dlp supabase
python app.py
# Runs at http://localhost:5000
```

## Key Decisions
- Single-file architecture for Vercel serverless simplicity
- yt-dlp as Python library (not CLI) for serverless compat
- Tags stored as comma-separated TEXT (simple, no join table needed)
- Client-side search/filter/sort (no server round-trips for library UX)
- Favorites pinned to top of library view
