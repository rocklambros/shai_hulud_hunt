# Usage Examples

## Quick Start Examples

### Example 1: Scan a Public Organization
```bash
export GITHUB_TOKEN="github_pat_your_token_here"
export GITHUB_ORG="microsoft"
python3 shai_hulud_github_hunt.py
```

**Expected Output:**
```
🔍 Fetching repositories for organization: microsoft
📊 Found 3420 repositories to scan
🔍 Searching for repositories with suspicious names...
🔍 Searching for malicious workflow files...
🔍 Searching for webhook.site references...
🔍 Scanning for compromised packages across all ecosystems...
   📦 Scanning packages in microsoft/vscode
   📦 Scanning packages in microsoft/TypeScript
...
🎯 SHAI HULUD THREAT HUNT RESULTS
============================================================
📊 Repositories scanned: 3420
📊 Suspicious repositories: 0
📊 Malicious workflows: 0
📊 Webhook.site references: 0
📊 Compromised packages: 0
📊 Suspicious branches: 0
📊 Audit log events: 0
```

### Example 2: Scan a User's Repositories
```bash
export GITHUB_TOKEN="github_pat_your_token_here"
export GITHUB_USER="octocat"
python3 shai_hulud_github_hunt.py
```

### Example 3: Scan a Single Repository
```bash
export GITHUB_TOKEN="github_pat_your_token_here"
export GITHUB_TARGET="facebook/react"
python3 shai_hulud_github_hunt.py
```

## Interactive Mode Examples

### Organization Scanning
```bash
python3 shai_hulud_github_hunt.py
```

**Interactive Prompts:**
```
🎯 Select scan target:
1. Organization repositories
2. User repositories
3. Single repository
Choose option (1-3): 1

Enter organization name to scan:
Organization name: acme-corp

GitHub Personal Access Token not found in environment.
Enter your GitHub token: github_pat_xxxxxxxxxxxxx

🔍 Fetching repositories for organization: acme-corp
📊 Found 45 repositories to scan
...
```

### User Repository Scanning
```bash
python3 shai_hulud_github_hunt.py
```

**Interactive Session:**
```
🎯 Select scan target:
1. Organization repositories
2. User repositories
3. Single repository
Choose option (1-3): 2

Enter username to scan personal repositories:
Username: johndoe

🔍 Fetching repositories for user: johndoe
📊 Found 12 repositories to scan
```

## Advanced Scanning Examples

### Large Organization with Findings
```bash
export GITHUB_TOKEN="github_pat_your_token_here"
export GITHUB_ORG="vulnerable-org"
python3 shai_hulud_github_hunt.py
```

**Output with Threats Detected:**
```
🎯 SHAI HULUD THREAT HUNT RESULTS
============================================================
📊 Repositories scanned: 156
📊 Suspicious repositories: 1
📊 Malicious workflows: 2
📊 Webhook.site references: 3
📊 Compromised packages: 8
📊 Suspicious branches: 1
📊 Audit log events: 15

🔍 Package findings by ecosystem:
   JavaScript/Node.js: 5 compromised packages
   Python: 2 compromised packages
   Go: 1 compromised packages

================================================================================
🔍 DETAILED THREAT ANALYSIS - PER REPOSITORY BREAKDOWN
================================================================================
📊 SUMMARY: 5/156 repositories have security issues
🚨 HIGH RISK: 2 repositories require immediate attention

============================================================
📁 REPOSITORY: vulnerable-org/legacy-app
🎯 RISK LEVEL: 🚨 CRITICAL (Score: 380)
🔢 ISSUES FOUND: 5
📝 Description: Legacy application with multiple vulnerabilities
🔒 Visibility: Private

🔍 DETAILED ISSUES:

   1. 🚨 [MALICIOUS_WORKFLOW] Shai Hulud malicious workflow detected
      📋 Malicious workflow file found at .github/workflows/shai-hulud-workflow.yml
      📁 Path: .github/workflows/shai-hulud-workflow.yml

   2. 🚨 [WEBHOOK_EXFILTRATION] Webhook.site data exfiltration reference
      📋 Code references webhook.site - potential data exfiltration
      🌐 Reference URL: https://github.com/vulnerable-org/legacy-app/blob/main/src/config.js

   3. 🚨 [COMPROMISED_PACKAGE] Compromised JavaScript/Node.js package: @ahmedhfarag/ngx-perfect-scrollbar
      📋 Package @ahmedhfarag/ngx-perfect-scrollbar@20.0.20 is compromised (Shai Hulud campaign)
      📦 File: package.json
      🔗 Ecosystem: JavaScript/Node.js
      📌 Dependency Type: dependencies
      🌐 View File: https://github.com/vulnerable-org/legacy-app/blob/main/package.json

   4. 🚨 [COMPROMISED_PACKAGE] Compromised Python package: encounter-playground
      📋 Package encounter-playground@1.0.0 is compromised (Shai Hulud campaign)
      📦 File: requirements.txt
      🔗 Ecosystem: Python
      📌 Dependency Type: requirements

   5. ⚠️  [SUSPICIOUS_BRANCH] Suspicious branch name: shai-hulud
      📋 Branch name matches Shai Hulud indicators
      🌿 Branch Name: shai-hulud
```

## Output Analysis Examples

### JSON Output Processing
```bash
# Save JSON output for SIEM integration
python3 shai_hulud_github_hunt.py > scan_results.json 2>&1

# Extract only the JSON portion
python3 shai_hulud_github_hunt.py 2>/dev/null | tail -n +$(python3 shai_hulud_github_hunt.py 2>/dev/null | grep -n "RAW JSON FINDINGS" | cut -d: -f1) | tail -n +2
```

### Filtering High-Risk Repositories
```bash
# Run scan and filter for critical/high risk repos
python3 shai_hulud_github_hunt.py | grep -A 10 "🚨 CRITICAL\|⚠️  HIGH"
```

### Package-Specific Scanning
```bash
# Focus on specific ecosystems by watching output
python3 shai_hulud_github_hunt.py | grep -E "(JavaScript|Python|Go)"
```

## Integration Examples

### CI/CD Pipeline Integration
```yaml
# GitHub Actions example
name: Shai Hulud Security Scan
on:
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 6 AM
  workflow_dispatch:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'

      - name: Install dependencies
        run: pip install requests

      - name: Run Shai Hulud scan
        env:
          GITHUB_TOKEN: ${{ secrets.SECURITY_SCAN_TOKEN }}
          GITHUB_ORG: ${{ github.repository_owner }}
        run: python3 shai_hulud_github_hunt.py > scan_results.json

      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: security-scan-results
          path: scan_results.json
```

### SIEM Integration (Splunk)
```bash
# Schedule regular scans and send to Splunk
#!/bin/bash
export GITHUB_TOKEN="github_pat_your_token_here"
export GITHUB_ORG="your-org"

# Run scan and extract JSON
python3 shai_hulud_github_hunt.py > /tmp/scan_output.txt 2>&1
grep -A 999999 "RAW JSON FINDINGS:" /tmp/scan_output.txt | tail -n +2 > /tmp/scan_results.json

# Send to Splunk via HTTP Event Collector
curl -k -X POST https://splunk.company.com:8088/services/collector \
  -H "Authorization: Splunk your-hec-token" \
  -H "Content-Type: application/json" \
  -d @/tmp/scan_results.json
```

### Automated Alerting
```bash
#!/bin/bash
# automated_scan.sh - Run daily and alert on findings

export GITHUB_TOKEN="github_pat_your_token_here"
export GITHUB_ORG="your-org"

# Run scan
python3 shai_hulud_github_hunt.py > scan_results.txt 2>&1

# Check for threats
THREAT_COUNT=$(grep "📊 HIGH RISK:" scan_results.txt | awk '{print $4}')

if [ "$THREAT_COUNT" -gt 0 ]; then
    # Send alert email
    mail -s "🚨 Shai Hulud Threats Detected: $THREAT_COUNT repositories" \
         security-team@company.com < scan_results.txt

    # Send Slack notification
    curl -X POST -H 'Content-type: application/json' \
         --data "{\"text\":\"🚨 Shai Hulud scan found $THREAT_COUNT high-risk repositories\"}" \
         YOUR_SLACK_WEBHOOK_URL
fi
```

## Error Handling Examples

### Network Connectivity Issues
```bash
# Test connectivity before scanning
if ! curl -s --head https://api.github.com >/dev/null; then
    echo "❌ Cannot reach GitHub API"
    exit 1
fi

python3 shai_hulud_github_hunt.py
```

### Token Permission Validation
```bash
# Validate token before running full scan
python3 -c "
import os, requests
token = os.environ.get('GITHUB_TOKEN')
headers = {'Authorization': f'Bearer {token}'}
r = requests.get('https://api.github.com/user', headers=headers)
if r.status_code != 200:
    print(f'❌ Token validation failed: {r.status_code}')
    exit(1)
print('✅ Token validated successfully')
"

python3 shai_hulud_github_hunt.py
```

### Rate Limit Handling
```bash
# Monitor rate limits during scan
python3 shai_hulud_github_hunt.py 2>&1 | tee scan.log

# Check for rate limit warnings
if grep -q "rate limit" scan.log; then
    echo "⚠️ Rate limits encountered, scan may be incomplete"
fi
```

## Performance Examples

### Large Organization Scanning
```bash
# For organizations with 1000+ repositories
export GITHUB_TOKEN="github_pat_your_token_here"
export GITHUB_ORG="large-org"

# Run in background with progress monitoring
nohup python3 shai_hulud_github_hunt.py > large_scan.log 2>&1 &
SCAN_PID=$!

# Monitor progress
echo "Scan running with PID: $SCAN_PID"
tail -f large_scan.log &
TAIL_PID=$!

# Wait for completion
wait $SCAN_PID
kill $TAIL_PID

echo "Scan completed. Results in large_scan.log"
```

### Parallel Scanning (Multiple Targets)
```bash
#!/bin/bash
# scan_multiple_orgs.sh

ORGS=("org1" "org2" "org3")
export GITHUB_TOKEN="github_pat_your_token_here"

for org in "${ORGS[@]}"; do
    echo "Starting scan for $org"
    (
        export GITHUB_ORG="$org"
        python3 shai_hulud_github_hunt.py > "scan_${org}.log" 2>&1
        echo "Completed scan for $org"
    ) &
done

# Wait for all scans to complete
wait
echo "All organization scans completed"
```

## Troubleshooting Examples

### Debug Mode Simulation
```bash
# Add verbose output by monitoring specific patterns
python3 shai_hulud_github_hunt.py 2>&1 | \
  grep -E "(🔍|📊|⚠️|❌|✅)" | \
  tee debug_output.txt
```

### Partial Scan Recovery
```bash
# If scan fails partway through, check progress
python3 shai_hulud_github_hunt.py 2>&1 | \
  grep "📦 Scanning packages" | \
  wc -l

# Resume from specific repository (manual modification needed)
# Edit script to start from last successful repository
```

### Memory Usage Monitoring
```bash
# Monitor memory usage during large scans
python3 shai_hulud_github_hunt.py &
SCAN_PID=$!

while kill -0 $SCAN_PID 2>/dev/null; do
    ps -p $SCAN_PID -o pid,vsz,rss,pcpu,comm
    sleep 30
done
```

## Best Practices Examples

### Production Deployment
```bash
#!/bin/bash
# production_scan.sh - Production-ready scanning script

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Configuration
SCAN_DIR="/opt/shai_hulud_hunt"
LOG_DIR="/var/log/shai_hulud"
RESULTS_DIR="/var/lib/shai_hulud/results"

# Setup
mkdir -p "$LOG_DIR" "$RESULTS_DIR"
cd "$SCAN_DIR"

# Logging
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$LOG_DIR/scan_$TIMESTAMP.log"

# Environment validation
if [[ -z "${GITHUB_TOKEN:-}" ]]; then
    echo "❌ GITHUB_TOKEN not set" | tee -a "$LOG_FILE"
    exit 1
fi

# Run scan with comprehensive logging
{
    echo "🚀 Starting Shai Hulud scan at $(date)"
    python3 shai_hulud_github_hunt.py
    echo "✅ Scan completed at $(date)"
} 2>&1 | tee "$LOG_FILE"

# Save results
cp "$LOG_FILE" "$RESULTS_DIR/latest_scan.log"
echo "Results saved to $RESULTS_DIR/latest_scan.log"
```

---

**Usage Examples Guide Version**: 1.0 | **Last Updated**: 2025-09-17