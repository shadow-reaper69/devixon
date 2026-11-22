# DEVIXON — DATABASE SCHEMA SPECIFICATION

Database Engine: SQLite (with SQLAlchemy 2.0 ORM + Foreign Keys enabled)

## Tables
1. `assessments`
   - `id` (VARCHAR(36), PK)
   - `target` (VARCHAR(255))
   - `scope_profile_json` (TEXT)
   - `scan_profile` (VARCHAR(50)) -- PASSIVE, QUICK, FULL, CUSTOM
   - `status` (VARCHAR(50)) -- PENDING, RUNNING, COMPLETED, CANCELLED, FAILED
   - `start_time` (DATETIME)
   - `end_time` (DATETIME, NULLABLE)
   - `summary_json` (TEXT, NULLABLE)
   - `created_at` (DATETIME)

2. `assets`
   - `id` (VARCHAR(36), PK)
   - `assessment_id` (VARCHAR(36), FK -> assessments.id)
   - `hostname` (VARCHAR(255))
   - `ip_address` (VARCHAR(45), NULLABLE)
   - `asset_type` (VARCHAR(50))
   - `scope_status` (VARCHAR(50))
   - `discovery_source` (VARCHAR(100))
   - `tags` (TEXT, NULLABLE)
   - `first_seen` (DATETIME)
   - `last_seen` (DATETIME)

3. `services`
   - `id` (VARCHAR(36), PK)
   - `asset_id` (VARCHAR(36), FK -> assets.id)
   - `port` (INTEGER)
   - `protocol` (VARCHAR(20))
   - `service_name` (VARCHAR(100))
   - `version` (VARCHAR(100), NULLABLE)
   - `banner` (TEXT, NULLABLE)
   - `confidence` (VARCHAR(50))

4. `endpoints`
   - `id` (VARCHAR(36), PK)
   - `asset_id` (VARCHAR(36), FK -> assets.id)
   - `url` (TEXT)
   - `path` (TEXT)
   - `method` (VARCHAR(10))
   - `params` (TEXT, NULLABLE)
   - `content_type` (VARCHAR(100), NULLABLE)
   - `status_code` (INTEGER, NULLABLE)
   - `discovery_source` (VARCHAR(100))

5. `findings`
   - `id` (VARCHAR(36), PK)
   - `assessment_id` (VARCHAR(36), FK -> assessments.id)
   - `asset_id` (VARCHAR(36), FK -> assets.id, NULLABLE)
   - `endpoint_id` (VARCHAR(36), FK -> endpoints.id, NULLABLE)
   - `title` (VARCHAR(255))
   - `category` (VARCHAR(100))
   - `severity` (VARCHAR(50))
   - `cvss_score` (FLOAT, NULLABLE)
   - `cvss_vector` (VARCHAR(100), NULLABLE)
   - `confidence` (VARCHAR(50))
   - `verification_status` (VARCHAR(50))
   - `description` (TEXT)
   - `impact` (TEXT)
   - `reproduction_steps` (TEXT)
   - `remediation` (TEXT)
   - `references` (TEXT, NULLABLE)
   - `false_positive_reason` (TEXT, NULLABLE)
   - `created_at` (DATETIME)
   - `updated_at` (DATETIME)

6. `evidence`
   - `id` (VARCHAR(36), PK)
   - `finding_id` (VARCHAR(36), FK -> findings.id)
   - `evidence_type` (VARCHAR(100))
   - `description` (TEXT)
   - `sanitized_data` (TEXT)
   - `source` (VARCHAR(100))
   - `data_hash` (VARCHAR(64))
   - `created_at` (DATETIME)

7. `scan_stages`
   - `id` (VARCHAR(36), PK)
   - `assessment_id` (VARCHAR(36), FK -> assessments.id)
   - `stage_id` (VARCHAR(50))
   - `name` (VARCHAR(100))
   - `status` (VARCHAR(50))
   - `progress` (FLOAT)
   - `start_time` (DATETIME)
   - `end_time` (DATETIME, NULLABLE)
   - `duration` (FLOAT, NULLABLE)
   - `error_message` (TEXT, NULLABLE)
   - `retry_count` (INTEGER)
