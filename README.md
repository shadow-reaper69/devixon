# DEVIXON
> AI-Assisted Reconnaissance & Vulnerability Intelligence Framework

DEVIXON is a terminal-first security assessment platform for authorized penetration testing, bug bounty research, and security audits.

## Key Features
- **Strict Scope Guard**: Prevents out-of-scope probes or unauthorized network activity.
- **18-Stage Recon Pipeline**: Subdomain discovery, DNS enumeration, live host probing, service discovery, URL intelligence, crawling, endpoint extraction, JS intelligence, API reconnaissance, safe security checks.
- **Native Fallbacks**: Built-in Python implementations ensure full functionality even when external CLI tools (Subfinder, Katana, Nmap, ffuf) are not installed.
- **Multi-State Finding Verification**: Differentiates confirmed findings, suspected vulnerabilities, and informational observations.
- **AI Advisory Subsystem**: Structured analysis with prompt injection quarantine and AI-disabled offline mode.
- **Professional Reports**: HTML (interactive dark theme), Markdown (Bugcrowd/HackerOne), JSON, and CSV.

## Quick Start
```bash
# Setup
devixon setup
devixon doctor

# Run self-tests
devixon self-test

# Define scope & run reconnaissance
devixon scope create --domain example.com --authorized
devixon recon full --target example.com
```
