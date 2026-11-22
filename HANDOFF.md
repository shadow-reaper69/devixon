# DEVIXON — HANDOFF STATUS & ROADMAP

## Current State: Reconnaissance Engine Upgrade Complete & Verified

### 1. Architectural Upgrades & Database Models
- **Database Models Added**:
  - `Subdomain`: Explicit `NOT_APPLICABLE` support for localhost / IP targets, DNS records JSON, resolved IP, resolution status, discovery source.
  - `DNSRecord`: Host, record type (`A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`), resolved values, TTL.
  - `LiveHost`: Discovered HTTP/HTTPS hosts, status code, title, web server, detected technologies, content type, response time (ms), redirect destination.
  - `DiscoveredPath`: Wordlist fuzzing and discovery files, status codes, content lengths, redirect locations, response times, discovery tool (`FFUF` / native).
  - `InternalLink`: Crawler links, source and destination URLs, method, link type (`a_href`, `form_action`, `script_src`), internal/external classification, crawl depth.
  - `Endpoint`: URLs, paths, methods, historical vs live distinction (`is_historical`), discovery source.
  - `Parameter`: Discovered query and body parameters, endpoint mapping, example values.
  - `JavaScriptAsset`: JavaScript file URLs, discovered routes/endpoints, source map links, and strictly masked/sanitized secret patterns.
  - `Technology`: Fingerprinted software, servers, frameworks, CMS, and libraries with confidence ratings.
- **SQLite Migrations**: Automatic schema migration in `init_db()` ensures columns (`assessment_id`, `is_historical`, etc.) are seamlessly added without data loss.

### 2. Reconnaissance Pipeline Enhancements
- **Subdomain Enumeration**: Integrated `subfinder`, `amass`, `dnsx` adapters + native crt.sh and dnspython fallback. Localhost/IP targets are explicitly tagged `NOT_APPLICABLE`.
- **Live Host Discovery**: Integrated ProjectDiscovery `httpx` + native async httpx client prober collecting response times, redirects, titles, servers, and technologies.
- **Directory and File Discovery**: Integrated `ffuf` + native safe wordlist path discoverer recording status codes, content lengths, redirects, and execution metrics.
- **Internal Link Crawling**: Integrated `katana` + native async HTML/JS crawler recording real links, methods, link types, depths, and internal/external flags.
- **URL & Endpoint Intelligence**: Integrated `gau`, `waybackurls`, and `katana` with clear separation of historical archive URLs from live endpoints.
- **JavaScript Intelligence**: Extracts client-side routes, API paths, source maps, and applies strict masking to discovered secrets.
- **API Discovery**: Automatically identifies OpenAPI/Swagger documentation, GraphQL endpoints, and REST schema routes.

### 3. Expanded CLI Suite
- `devixon recon subdomains` — Subdomain enumeration and DNS resolution only.
- `devixon recon hosts` — Live HTTP/HTTPS host and service discovery only.
- `devixon recon crawl` — Scope-governed internal link crawler.
- `devixon recon paths` — Directory and file path discovery.
- `devixon recon urls` — Historical URL intelligence from archives.
- `devixon recon endpoints` — Endpoint, API, and parameter extraction.
- `devixon recon full` — Complete 18-stage assessment pipeline.
- `devixon paths list` — List discovered directories and files with status codes and lengths.
- `devixon assets list` — Real subdomain, IP, and live service inventory.
- `devixon assets inspect` — Deep inspection of host intelligence, open ports, and technologies.
- `devixon endpoints list` — Complete endpoint and query parameter inventory.

### 4. 15-Section Comprehensive Reporting
Generated HTML (dark theme) and Markdown reports now comprehensively present all 15 intelligence sections:
1. Executive Summary
2. Scope Information
3. Subdomain Inventory
4. DNS Intelligence
5. Live Hosts
6. Technology Fingerprinting
7. Discovered Directories and Files
8. Internal Links Crawled
9. URL Inventory (Historical vs Live)
10. Endpoint Inventory
11. Parameter Inventory
12. JavaScript Intelligence
13. API Discoveries
14. Security Posture Findings
15. Scan Coverage and Errors

### 5. Test Suite Verification
- **21 / 21 Tests Passing** in `pytest -v` (including real end-to-end HTTP server crawl and discovery test).
- **9 / 9 Tests Passing** in `devixon self-test`.
