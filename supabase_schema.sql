-- ============================================================================
-- SiteCheck — Supabase Database Schema Migration
-- Team: Obsidian
-- Table: scan_reports
-- Description: Stores security audit reports, scores, findings, and AI insights.
-- ============================================================================

-- 1. Create the scan_reports table
create table if not exists public.scan_reports (
  id uuid primary key default gen_random_uuid(),
  url text not null,
  final_url text not null,
  hostname text not null,
  score_overall integer not null check (score_overall >= 0 and score_overall <= 100),
  score_by_category jsonb not null default '{}'::jsonb,
  summary_counts jsonb not null default '{"high": 0, "medium": 0, "low": 0}'::jsonb,
  findings jsonb not null default '[]'::jsonb,
  ai_explanation jsonb default null,
  metadata jsonb default '{}'::jsonb,
  scanned_at timestamptz not null default now()
);

-- 2. Add high-performance indexes for search, history, and analytics
create index if not exists idx_scan_reports_hostname 
  on public.scan_reports (hostname);

create index if not exists idx_scan_reports_scanned_at 
  on public.scan_reports (scanned_at desc);

create index if not exists idx_scan_reports_score 
  on public.scan_reports (score_overall);

create index if not exists idx_scan_reports_host_date 
  on public.scan_reports (hostname, scanned_at desc);

-- 3. Enable Row Level Security (RLS)
alter table public.scan_reports enable row level security;

-- 4. RLS Policy: Anyone can view scan reports (public permalinks & recent scans)
drop policy if exists "Public read access for scan reports" on public.scan_reports;
create policy "Public read access for scan reports"
  on public.scan_reports
  for select
  using (true);

-- 5. RLS Policy: Allow backend or public anon client to insert scan reports
drop policy if exists "Allow inserts for scan reports" on public.scan_reports;
create policy "Allow inserts for scan reports"
  on public.scan_reports
  for insert
  with check (
    score_overall >= 0 and score_overall <= 100 and
    length(hostname) > 0
  );

-- 6. Convenient view for latest scan per domain (deduplicated posture overview)
create or replace view public.latest_site_scans as
select distinct on (hostname)
  id,
  hostname,
  url,
  final_url,
  score_overall,
  summary_counts,
  scanned_at
from public.scan_reports
order by hostname, scanned_at desc;

-- 7. Comments for documentation inside Supabase Studio
comment on table public.scan_reports is 'Stores SiteCheck cybersecurity audit reports and posture scores.';
comment on column public.scan_reports.score_overall is 'Overall security posture score from 0 to 100.';
comment on column public.scan_reports.findings is 'Sanitized evaluation findings from security rules (without check functions).';
comment on column public.scan_reports.ai_explanation is 'Plain-English AI generated summary, explanation, and remediation advice.';
