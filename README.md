# Shai Hulud GitHub Threat Hunt Tool

A comprehensive cybersecurity tool for detecting Shai Hulud campaign indicators across GitHub organizations, users, and repositories. This tool provides detailed threat analysis with per-repository, per-issue reporting and risk scoring.

## 🎯 Overview

The Shai Hulud threat hunting tool scans GitHub environments for indicators of compromise (IOCs) related to the Shai Hulud supply chain attack campaign. It provides immediate detection capabilities for organizations to assess their exposure and respond to threats.

### Key Features

- ✅ **Multi-Target Scanning**: Organizations, users, or individual repositories
- ✅ **Comprehensive Package Detection**: 555 known compromised packages across 8+ ecosystems
- ✅ **Detailed Threat Reporting**: Per-repository, per-issue analysis with risk scoring
- ✅ **Multiple Threat Vectors**: Malicious workflows, package vulnerabilities, suspicious branches, webhook exfiltration
- ✅ **Enterprise Security**: Secure token storage, input sanitization, DoS protection
- ✅ **SIEM Integration**: Structured JSON output for security orchestration
- ✅ **Security Hardened**: Protection against credential exposure, injection attacks, and resource exhaustion

## 🚨 Threat Detection Capabilities

### Package Vulnerability Detection
Scans for compromised packages across multiple ecosystems:
- **JavaScript/Node.js**: package.json, yarn.lock, package-lock.json
- **Python**: requirements.txt, pyproject.toml, Pipfile, setup.py
- **Go**: go.mod, go.sum
- **Rust**: Cargo.toml, Cargo.lock
- **Java**: pom.xml, build.gradle
- **Ruby**: Gemfile
- **PHP**: composer.json

### Malicious Infrastructure Detection
- **Workflow Files**: `.github/workflows/shai-hulud-workflow.yml`
- **Data Exfiltration**: webhook.site references in code
- **Suspicious Branches**: "shai-hulud" or "shai hulud" branch names
- **Audit Events**: Repository creation, visibility changes, push events

### Risk Scoring System
- **🚨 CRITICAL (150+)**: Multiple high-severity threats
- **⚠️ HIGH (80-149)**: Single high-severity or multiple medium threats
- **🟡 MEDIUM (1-79)**: Single medium-severity threat
- **✅ CLEAN (0)**: No threats detected

---

## 🚀 Quick Start

### Requirements
- Python 3.7+
- `requests` library
- GitHub Personal Access Token
- Internet connectivity for GitHub API access

### Installation
```bash
# 1. Download and setup
git clone https://github.com/rocklambros/shai_hulud_hunt.git
cd shai_hulud_hunt
pip install requests

# 2. Configure GitHub token
export GITHUB_TOKEN="github_pat_your_token_here"
export GITHUB_ORG="your-organization"

# 3. Run scan
python3 shai_hulud_github_hunt.py
```

### Alternative Installation Methods

#### Virtual Environment (Recommended)
```bash
# Create virtual environment
python3 -m venv shai_hulud_env
source shai_hulud_env/bin/activate  # Linux/macOS
# OR
shai_hulud_env\Scripts\activate.bat  # Windows

# Install and run
git clone https://github.com/rocklambros/shai_hulud_hunt.git
cd shai_hulud_hunt
pip install requests
python3 shai_hulud_github_hunt.py
```

#### Docker
```bash
# Build and run with Docker
docker build -t shai-hulud-hunt .
docker run -e GITHUB_TOKEN=$GITHUB_TOKEN -e GITHUB_ORG=$GITHUB_ORG shai-hulud-hunt
```

---

## 🔑 GitHub Token Setup

### Creating a Personal Access Token

1. **Navigate to GitHub Settings**
   - Go to https://github.com/settings/tokens
   - Click "Generate new token" → "Fine-grained tokens" (recommended)

2. **Configure Token Permissions**

   **For Public Repository Scanning:**
   - ✅ `Contents: Read`
   - ✅ `Metadata: Read`

   **For Private Repository & Organization Scanning:**
   - ✅ `Contents: Read`
   - ✅ `Metadata: Read`
   - ✅ `Actions: Read` (for workflow detection)

   **For Enterprise Audit Log Access (Optional):**
   - ✅ `Administration: Read` (for audit logs)

3. **Generate and Secure Token**
   - Click "Generate token"
   - **Copy token immediately** (cannot be viewed again)
   - Store securely in password manager

### Environment Variables

#### Linux/macOS
```bash
# Add to ~/.bashrc or ~/.zshrc for persistence
export GITHUB_TOKEN="github_pat_your_token_here"
export GITHUB_ORG="your-organization-name"

# Apply changes
source ~/.bashrc
```

#### Windows PowerShell
```powershell
# Set for current session
$env:GITHUB_TOKEN="github_pat_your_token_here"
$env:GITHUB_ORG="your-organization-name"

# Set permanently (requires restart)
[Environment]::SetEnvironmentVariable("GITHUB_TOKEN", "github_pat_your_token_here", "User")
```

### Environment Variables Reference
| Variable | Description | Required |
|----------|-------------|----------|
| `GITHUB_TOKEN` | GitHub Personal Access Token | Yes |
| `GITHUB_ORG` | Target organization name | Optional* |
| `GITHUB_USER` | Target username | Optional* |
| `GITHUB_TARGET` | Target repository (owner/repo) | Optional* |

*At least one target must be specified via environment variable or interactive prompt

---

## 📖 Usage Examples

### Interactive Mode
Run without environment variables for guided setup:
```bash
python3 shai_hulud_github_hunt.py
```

The tool will prompt for:
1. **Scan Target Type**: Organization, User, or Single Repository
2. **Target Name**: Specific organization, username, or repository
3. **GitHub Token**: If not set in environment variables

### Environment Variable Mode

#### Scan an Organization
```bash
export GITHUB_TOKEN="github_pat_your_token_here"
export GITHUB_ORG="microsoft"
python3 shai_hulud_github_hunt.py
```

#### Scan a User's Repositories
```bash
export GITHUB_TOKEN="github_pat_your_token_here"
export GITHUB_USER="octocat"
python3 shai_hulud_github_hunt.py
```

#### Scan a Single Repository
```bash
export GITHUB_TOKEN="github_pat_your_token_here"
export GITHUB_TARGET="microsoft/vscode"
python3 shai_hulud_github_hunt.py
```

### Sample Output

#### Executive Summary
```
🎯 SHAI HULUD THREAT HUNT RESULTS
============================================================
📊 Repositories scanned: 150
📊 Suspicious repositories: 2
📊 Malicious workflows: 1
📊 Webhook.site references: 3
📊 Compromised packages: 5
📊 Suspicious branches: 1
📊 Audit log events: 12
```

#### Detailed Repository Analysis
```
============================================================
📁 REPOSITORY: orgname/vulnerable-app
🎯 RISK LEVEL: 🚨 CRITICAL (Score: 310)
🔢 ISSUES FOUND: 4

🔍 DETAILED ISSUES:
   1. 🚨 [COMPROMISED_PACKAGE] Compromised JavaScript package: @ahmedhfarag/ngx-perfect-scrollbar
      📋 Package @ahmedhfarag/ngx-perfect-scrollbar@20.0.20 is compromised (Shai Hulud campaign)
      📦 File: package.json
      🔗 Ecosystem: JavaScript/Node.js
      🌐 View File: https://github.com/orgname/vulnerable-app/blob/main/package.json
```

#### JSON Output
Complete findings in SIEM-ready JSON format at the end of output for integration with security tools.

---

## 🚨 Security Features

### Security Hardening (v1.1)
The tool includes enterprise-grade security protections:

- ✅ **Secure Token Storage**: XOR obfuscation prevents credential exposure in memory dumps
- ✅ **Input Sanitization**: Comprehensive validation protects against injection attacks
- ✅ **Token Scope Validation**: Automatic checking for least privilege compliance
- ✅ **DoS Protection**: Resource limits prevent attacks on large organizations
- ✅ **Security Logging**: Comprehensive audit trail for compliance and incident response
- ✅ **Defensive Programming**: API timeouts, rate limiting, error sanitization

### Token Security
- **Secure Storage**: Tokens stored with XOR obfuscation in memory
- **Automatic Validation**: Pre-scan token scope and permission checking
- **Least Privilege**: Warns about excessive permissions (admin:org, etc.)
- **Never commit tokens to version control**
- Use environment variables or secure credential management
- Rotate tokens regularly

### Resource Protection
- **Repository Limits**: Maximum 1000 repositories per scan
- **Branch Limits**: Maximum 100 branches per repository
- **API Rate Limiting**: 60 calls per minute with automatic backoff
- **Timeout Protection**: 15-second timeout on all API requests

### Network Security
- Tool makes HTTPS requests to api.github.com only
- No data is transmitted to third parties
- All scanning is read-only (no modifications made)
- Input sanitization prevents malicious repository data processing

### Data Privacy & Compliance
- **Local Processing**: All analysis performed locally, no external data transmission
- **Audit Trail**: Comprehensive security event logging for compliance
- **Data Sanitization**: Sensitive information removed from error messages
- **Secure Defaults**: Security-first configuration throughout

---

## 🔧 Configuration

### Corporate Environment Setup

#### Proxy Configuration
```bash
# Set proxy environment variables
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080

# For authenticated proxies
export HTTP_PROXY=http://username:password@proxy.company.com:8080
export HTTPS_PROXY=http://username:password@proxy.company.com:8080
```

#### SSL Certificate Issues
```bash
# Add CA certificate to Python requests
export REQUESTS_CA_BUNDLE=/path/to/company-ca-bundle.crt

# Or disable SSL verification (NOT recommended for production)
export PYTHONHTTPSVERIFY=0
```

### Customizing Package Detection
The tool uses `compromised_packages.txt` containing 555 known compromised packages. To update:

1. Add new package identifiers in `package@version` format
2. One package per line
3. Comments supported with `#` prefix

### Rate Limiting
The tool implements intelligent rate limiting:
- Automatic retry with exponential backoff
- 60 API calls per minute maximum
- 15-second timeout on all requests
- Polite delays between different API endpoint calls

---

## 🔄 Troubleshooting

### Common Issues

#### Token Permission Errors
**Problem**: 401 Unauthorized or insufficient permissions
**Solution**: Verify token has required scopes:
```bash
# The tool now includes automatic token validation
export GITHUB_TOKEN="github_pat_your_token_here"
python3 shai_hulud_github_hunt.py

# Output includes security validation:
# 🔍 Validating GitHub token...
# ✅ Token validation successful
# ⚠️ Warning: Token has excessive scope 'admin:org' - not required for scanning
```

#### Rate Limiting
**Problem**: HTTP 429 errors or rate limit warnings
**Solution**: Tool implements automatic rate limiting and retry logic

#### 403 Forbidden Errors
**Problem**: API returns 403 Forbidden during package scanning
**Solution**: Tool automatically uses Repository Contents API instead of Search API

#### Network Connectivity Issues
```bash
# Test GitHub API connectivity
curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user
```

#### No Packages Found
**Problem**: Package scanning reports 0 packages but repositories contain package files
**Solution**: Check that `compromised_packages.txt` exists and contains package data

### Installation Issues

#### "ModuleNotFoundError: No module named 'requests'"
```bash
pip install requests

# If using system Python on Linux
sudo apt-get install python3-pip  # Ubuntu/Debian
pip3 install requests
```

#### "Permission denied" on Linux/macOS
```bash
chmod +x shai_hulud_github_hunt.py
# Or run with python3 explicitly
python3 shai_hulud_github_hunt.py
```

#### Corporate Network Issues
1. **Proxy Configuration**: Set HTTP_PROXY/HTTPS_PROXY environment variables
2. **Firewall Rules**: Ensure outbound HTTPS access to api.github.com
3. **SSL Certificates**: Configure REQUESTS_CA_BUNDLE if needed

---

## 📈 Performance

### Scanning Speed
- **Small organizations** (<10 repos): 1-2 minutes
- **Medium organizations** (10-100 repos): 5-15 minutes
- **Large organizations** (100+ repos): 15+ minutes

### Resource Usage
- **Memory**: <50MB typical usage (512MB limit enforced)
- **Network**: ~1KB per API call, depends on repository count
- **CPU**: Minimal, I/O bound workload

### For Large Organizations (100+ repositories)
```bash
# Consider running in background
nohup python3 shai_hulud_github_hunt.py > scan_results.log 2>&1 &

# Monitor progress
tail -f scan_results.log
```

---

## 🔗 Integration

### SIEM Integration
The tool outputs structured JSON at the end of each scan for easy integration with security tools:

#### Splunk Integration
```bash
# Extract JSON findings and send to Splunk
python3 shai_hulud_github_hunt.py > /tmp/scan_output.txt 2>&1
grep -A 999999 "RAW JSON FINDINGS:" /tmp/scan_output.txt | tail -n +2 > /tmp/scan_results.json

# Send to Splunk via HTTP Event Collector
curl -k -X POST https://splunk.company.com:8088/services/collector \
  -H "Authorization: Splunk your-hec-token" \
  -H "Content-Type: application/json" \
  -d @/tmp/scan_results.json
```

### Automated Scanning
```bash
#!/bin/bash
# automated_scan.sh - Daily scanning with alerting

export GITHUB_TOKEN="github_pat_your_token_here"
export GITHUB_ORG="your-org"

# Run scan
python3 shai_hulud_github_hunt.py > scan_results.txt 2>&1

# Check for threats and alert
CRITICAL_COUNT=$(grep -c "🚨 CRITICAL" scan_results.txt || echo "0")

if [ "$CRITICAL_COUNT" -gt 0 ]; then
    # Send alert notification
    echo "🚨 $CRITICAL_COUNT critical threats detected in $GITHUB_ORG" | \
    mail -s "Shai Hulud Critical Alert" security-team@company.com
fi
```

### CI/CD Integration
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
      - uses: actions/checkout@v4
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      - name: Install dependencies
        run: pip install requests
      - name: Run secure scan
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

---

## 🤝 Contributing

### Development Setup
```bash
git clone https://github.com/rocklambros/shai_hulud_hunt.git
cd shai_hulud_hunt

# Install development dependencies
pip install requests

# Run syntax check
python3 -m py_compile shai_hulud_github_hunt.py

# Test with small repository
export GITHUB_TARGET="octocat/Hello-World"
python3 shai_hulud_github_hunt.py
```

### Adding New Package Ecosystems
1. Update `package_files` dictionary in `scan_repository_packages()`
2. Add parsing logic in `parse_package_file_content()`
3. Test with sample package files
4. Update documentation

### Code Style
- Follow PEP 8 Python style guidelines
- Use descriptive variable names
- Add docstrings for functions
- Maintain existing error handling patterns

---

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is provided for legitimate cybersecurity purposes only. Users are responsible for:
- Ensuring proper authorization before scanning GitHub resources
- Complying with applicable laws and regulations
- Respecting GitHub's Terms of Service and API rate limits
- Protecting any sensitive information discovered during scanning

## 📞 Support

For issues, questions, or contributions:
- **Issues**: Open a GitHub issue with detailed reproduction steps
- **Documentation**: Check this README and inline code documentation
- **Security Issues**: Report privately to maintainers

## 🏆 Acknowledgments

- GitHub API documentation and best practices
- Cybersecurity research community for IOC identification
- Open source security tools for inspiration and patterns

---

**Generated with Claude Code** | **Last Updated**: 2025-09-17