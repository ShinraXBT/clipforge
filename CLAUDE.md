# ClipForge — Multi-Platform Video Downloader & Trimmer

## Architecture
- **Single-file app**: `api/index.py` contains Flask backend + full HTML/CSS/JS frontend
- `app.py` is a mirror of `api/index.py` for local development
- Deployed on Vercel (serverless)
- Supabase for storage (video files) + PostgreSQL (clip metadata) + Auth

## Tech Stack
- Python / Flask
- yt-dlp (video downloading)
- Supabase (storage + DB + Auth)
- PyJWT (JWT token verification for auth)
- Vanilla HTML/CSS/JS frontend (no framework)
- Vercel serverless deployment

## UI Layout
- Two-column layout: editor (left 57%) + library (right 43%)
- Library is sticky-scrollable, always visible
- Quality/format picker: resolution pills (360p–Best) + format pills (MP4/WebM/MP3)
- Save dialog with custom title + tag chips
- Edit modal: click clip title to edit title/tags
- Library toolbar: search, platform filter pills (6 platforms), sort dropdown
- Clip cards: checkbox (bulk mode), favorite star, tags
- Bulk action bar: multi-select download/delete
- Auth modal: login/signup with email/password
- Toast notifications (success/error/info)
- Skeleton loading cards + localStorage cache for instant perceived load
- Pagination with "Load more" button

## Supported Platforms
YouTube, Twitter/X, Instagram, TikTok, Twitch, SoundCloud

## DB Schema (Supabase `clips` table)
- id, title, platform, source_url, thumbnail, channel, duration
- trim_start, trim_end, mode, file_path, file_size, file_ext
- tags (TEXT, comma-separated), is_favorite (BOOLEAN)
- user_id (UUID, references auth.users, RLS-protected)
- created_at

## APIs
- `POST /api/video-info` — fetch video metadata
- `POST /api/download-full` — download full video (accepts quality/format)
- `POST /api/trim` — trim + download (accepts quality/format)
- `POST /api/save-to-library` — download + save to Supabase (with tags, quality/format)
- `GET /api/library` — list clips (paginated, user-scoped if authenticated)
- `DELETE /api/library/<id>` — delete single clip
- `PATCH /api/library/<id>` — edit clip title/tags
- `PATCH /api/library/<id>/favorite` — toggle favorite
- `POST /api/library/bulk-delete` — delete multiple clips
- `POST /api/auth/signup` — create account
- `POST /api/auth/login` — login, returns JWT tokens
- `POST /api/auth/refresh` — refresh expired JWT token

## Environment Variables
- `SUPABASE_URL` — Supabase project URL
- `SUPABASE_KEY` — Supabase anon key (for auth operations)
- `SUPABASE_SERVICE_KEY` — Supabase service key (for storage/DB)
- `SUPABASE_JWT_SECRET` — JWT secret for token verification

## How to Run
```bash
pip install flask yt-dlp supabase PyJWT
python app.py
# Runs at http://localhost:5000
```

## SQL Migration (for auth/RLS)
```sql
ALTER TABLE clips ADD COLUMN user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE;
CREATE INDEX idx_clips_user_id ON clips(user_id);
ALTER TABLE clips ENABLE ROW LEVEL SECURITY;
CREATE POLICY "select_own" ON clips FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "insert_own" ON clips FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "update_own" ON clips FOR UPDATE USING (auth.uid() = user_id);
CREATE POLICY "delete_own" ON clips FOR DELETE USING (auth.uid() = user_id);
```

## Key Decisions
- Single-file architecture for Vercel serverless simplicity
- yt-dlp as Python library (not CLI) for serverless compat
- Tags stored as comma-separated TEXT (simple, no join table needed)
- Client-side search/filter/sort (no server round-trips for library UX)
- Favorites pinned to top of library view
- Auth is optional/graceful: app works without auth, library becomes user-scoped when logged in
- Quality/format picker with build_format_string() helper for DRY format string generation
- MP3 extraction via FFmpeg postprocessor (falls back to raw audio if FFmpeg unavailable)
- localStorage cache for instant library load on repeat visits
- Retry logic with exponential backoff for resilient API calls
- Toast notifications replace alerts for non-blocking UX
