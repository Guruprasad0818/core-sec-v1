-- CBAD PostgreSQL Schema
-- Production-ready tables for behavior profiling, commit features, baselines, and anomaly events.

CREATE SCHEMA IF NOT EXISTS cbad;

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS btree_gin;

CREATE TABLE IF NOT EXISTS cbad.behavior_profiles (
  profile_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  developer_id text NOT NULL,
  repository_id text,
  profile_window_days integer NOT NULL DEFAULT 90,
  feature_summary jsonb NOT NULL,
  drift_metrics jsonb NOT NULL,
  baseline_hash text NOT NULL,
  feature_count integer NOT NULL DEFAULT 0,
  window_start timestamptz NOT NULL,
  window_end timestamptz NOT NULL,
  last_updated_at timestamptz NOT NULL DEFAULT now(),
  model_version text NOT NULL,
  tags text[] NOT NULL DEFAULT ARRAY[]::text[],
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_behavior_profiles_developer_id ON cbad.behavior_profiles (developer_id);
CREATE INDEX IF NOT EXISTS idx_behavior_profiles_repository_id ON cbad.behavior_profiles (repository_id);
CREATE INDEX IF NOT EXISTS idx_behavior_profiles_last_updated_at ON cbad.behavior_profiles (last_updated_at);
CREATE INDEX IF NOT EXISTS idx_behavior_profiles_profile_window ON cbad.behavior_profiles (profile_window_days);
CREATE INDEX IF NOT EXISTS idx_behavior_profiles_baseline_hash ON cbad.behavior_profiles USING hash (baseline_hash);

CREATE TABLE IF NOT EXISTS cbad.commit_features (
  commit_id text PRIMARY KEY,
  repository_id text NOT NULL,
  branch_name text NOT NULL,
  parent_commit_ids text[] NOT NULL,
  developer_id text NOT NULL,
  author_name text NOT NULL,
  author_email text NOT NULL,
  author_date timestamptz NOT NULL,
  committer_date timestamptz NOT NULL,
  commit_message text NOT NULL,
  commit_message_features jsonb NOT NULL,
  diff_features jsonb NOT NULL,
  code_metrics jsonb NOT NULL,
  time_features jsonb NOT NULL,
  repository_features jsonb NOT NULL,
  developer_features jsonb NOT NULL,
  language_features jsonb NOT NULL,
  tooling_features jsonb NOT NULL,
  feature_vector jsonb NOT NULL,
  raw_diff text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  model_version text NOT NULL,
  anomaly_score numeric,
  anomaly_label text,
  feature_source text
);

CREATE INDEX IF NOT EXISTS idx_commit_features_repository ON cbad.commit_features (repository_id);
CREATE INDEX IF NOT EXISTS idx_commit_features_developer ON cbad.commit_features (developer_id);
CREATE INDEX IF NOT EXISTS idx_commit_features_author_date ON cbad.commit_features (author_date);
CREATE INDEX IF NOT EXISTS idx_commit_features_branch_name ON cbad.commit_features (branch_name);
CREATE INDEX IF NOT EXISTS idx_commit_features_anomaly_score ON cbad.commit_features (anomaly_score);
CREATE INDEX IF NOT EXISTS idx_commit_features_parent_commit_ids ON cbad.commit_features USING gin (parent_commit_ids);
CREATE INDEX IF NOT EXISTS idx_commit_features_feature_vector ON cbad.commit_features USING gin (feature_vector jsonb_path_ops);

CREATE TABLE IF NOT EXISTS cbad.developer_baselines (
  baseline_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  developer_id text NOT NULL,
  repository_id text,
  baseline_window_days integer NOT NULL DEFAULT 90,
  feature_statistics jsonb NOT NULL,
  thresholds jsonb NOT NULL,
  policy_flags jsonb NOT NULL DEFAULT '{}'::jsonb,
  evaluation_state jsonb NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_developer_baselines_developer_id ON cbad.developer_baselines (developer_id);
CREATE INDEX IF NOT EXISTS idx_developer_baselines_repository_id ON cbad.developer_baselines (repository_id);
CREATE INDEX IF NOT EXISTS idx_developer_baselines_updated_at ON cbad.developer_baselines (updated_at);

CREATE TABLE IF NOT EXISTS cbad.anomaly_events (
  event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  commit_id text NOT NULL,
  repository_id text NOT NULL,
  developer_id text NOT NULL,
  detected_at timestamptz NOT NULL DEFAULT now(),
  stage text NOT NULL,
  anomaly_score numeric NOT NULL,
  anomaly_label text NOT NULL,
  severity text NOT NULL,
  detection_reason text NOT NULL,
  feature_contributions jsonb NOT NULL,
  actions text[] NOT NULL DEFAULT ARRAY[]::text[],
  policy_snapshot jsonb NOT NULL,
  model_version text NOT NULL,
  review_ticket_id text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_anomaly_events_commit_id ON cbad.anomaly_events (commit_id);
CREATE INDEX IF NOT EXISTS idx_anomaly_events_repository_id ON cbad.anomaly_events (repository_id);
CREATE INDEX IF NOT EXISTS idx_anomaly_events_developer_id ON cbad.anomaly_events (developer_id);
CREATE INDEX IF NOT EXISTS idx_anomaly_events_detected_at ON cbad.anomaly_events (detected_at);
CREATE INDEX IF NOT EXISTS idx_anomaly_events_severity ON cbad.anomaly_events (severity);
CREATE INDEX IF NOT EXISTS idx_anomaly_events_anomaly_score ON cbad.anomaly_events (anomaly_score);
