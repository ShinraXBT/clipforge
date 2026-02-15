-- ClipForge — Supabase Auth Migration
-- Run this in Supabase SQL Editor (Dashboard > SQL Editor > New Query)
-- This adds user accounts support with Row Level Security (RLS)

-- 1. Add user_id column to clips table
ALTER TABLE clips ADD COLUMN user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE;
CREATE INDEX idx_clips_user_id ON clips(user_id);

-- 2. (Optional) Clean existing orphan data that has no owner
-- Uncomment the next 2 lines if you want to require user_id on all rows
-- DELETE FROM clips WHERE user_id IS NULL;
-- ALTER TABLE clips ALTER COLUMN user_id SET NOT NULL;

-- 3. Enable Row Level Security
ALTER TABLE clips ENABLE ROW LEVEL SECURITY;

-- 4. RLS policies — each user can only access their own clips
CREATE POLICY "select_own" ON clips FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "insert_own" ON clips FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "update_own" ON clips FOR UPDATE USING (auth.uid() = user_id);
CREATE POLICY "delete_own" ON clips FOR DELETE USING (auth.uid() = user_id);
