# DEVIXON — API & DATA CONTRACTS

## Core Pydantic Schemas & Data Models

### 1. Scope Profile
- `assessment_id`: UUID4 string
- `primary_target`: str (domain or IP)
- `allowed_domains`: List[str] (e.g. `*.example.com`, `api.example.com`)
- `allowed_ips`: List[str] (e.g. `192.168.1.0/24`)
- `excluded_targets`: List[str]
- `excluded_paths`: List[str]
- `rate_limit`: int (requests per second, default: 10)
- `max_concurrency`: int (default: 5)
- `timeout`: int (seconds, default: 15)
- `authorized_by_user`: bool (mandatory `True` for active scans)

### 2. Discovered Asset
- `hostname`: str
- `ip_address`: Optional[str]
- `asset_type`: `DOMAIN`, `SUBDOMAIN`, `IP`
- `scope_status`: `IN_SCOPE`, `OUT_OF_SCOPE`, `EXCLUDED`
- `discovery_source`: str
- `tags`: List[str]

### 3. Finding
- `title`: str
- `category`: str
- `severity`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`
- `confidence`: `CONFIRMED`, `LIKELY`, `SUSPECTED`, `INFORMATIONAL`
- `verification_status`: `CONFIRMED`, `LIKELY`, `NEEDS_REVIEW`, `INFORMATIONAL`, `FALSE_POSITIVE`, `FIXED`
- `cvss_score`: Optional[float]
- `cvss_vector`: Optional[str]
- `evidence`: List[EvidenceContract]
- `reproduction_steps`: List[str]
- `remediation`: str
