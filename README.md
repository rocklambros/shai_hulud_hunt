# Shai Hulud GitHub Threat Hunt Tool

A comprehensive cybersecurity tool for detecting Shai Hulud campaign indicators across GitHub organizations, users, and repositories. This tool provides detailed threat analysis with per-repository, per-issue reporting and risk scoring.

## 🎯 Overview

The Shai Hulud threat hunting tool scans GitHub environments for indicators of compromise (IOCs) related to the Shai Hulud supply chain attack campaign. It provides immediate detection capabilities for organizations to assess their exposure and respond to threats.

### Key Features

- ✅ **Multi-Target Scanning**: Organizations, users, or individual repositories
- ✅ **Comprehensive Package Detection**: 555 known compromised packages across 8+ ecosystems
- ✅ **Detailed Threat Reporting**: Per-repository, per-issue analysis with risk scoring
- ✅ **Multiple Threat Vectors**: Malicious workflows, package vulnerabilities, suspicious branches, webhook exfiltration
- ✅ **Enterprise Ready**: Rate limiting, error recovery, audit trail integration
- ✅ **SIEM Integration**: Structured JSON output for security orchestration

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

## 📋 Requirements

### System Requirements
- Python 3.7+
- `requests` library (`pip install requests`)
- Internet connectivity for GitHub API access

### GitHub Token Requirements
The tool requires a GitHub Personal Access Token with appropriate scopes:

**For Public Repositories:**
- `public_repo` scope

**For Private Repositories & Organizations:**
- `repo` scope (full repository access)
- `read:org` scope (organization member access)

**For Enterprise Audit Logs (Optional):**
- `read:audit_log` scope (Enterprise Cloud only)

### Token Setup
1. Navigate to GitHub Settings → Developer settings → Personal access tokens
2. Generate a new token with required scopes
3. Set as environment variable:
   ```bash
   export GITHUB_TOKEN="your_token_here"
   ```

## 🚀 Installation

### Quick Start
```bash
# Clone the repository
git clone https://github.com/your-username/shai_hulud_hunt.git
cd shai_hulud_hunt

# Install dependencies
pip install requests

# Set up environment
export GITHUB_TOKEN="your_github_token"
export GITHUB_ORG="your_organization"  # Optional

# Run the tool
python3 shai_hulud_github_hunt.py
```

### Environment Variables
| Variable | Description | Required |
|----------|-------------|----------|
| `GITHUB_TOKEN` | GitHub Personal Access Token | Yes |
| `GITHUB_ORG` | Target organization name | Optional* |
| `GITHUB_USER` | Target username | Optional* |
| `GITHUB_TARGET` | Target repository (owner/repo) | Optional* |

*At least one target must be specified via environment variable or interactive prompt

## 📖 Usage

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
```bash
# Scan an organization
export GITHUB_TOKEN="your_token"
export GITHUB_ORG="microsoft"
python3 shai_hulud_github_hunt.py

# Scan a user's repositories
export GITHUB_TOKEN="your_token"
export GITHUB_USER="octocat"
python3 shai_hulud_github_hunt.py

# Scan a single repository
export GITHUB_TOKEN="your_token"
export GITHUB_TARGET="microsoft/vscode"
python3 shai_hulud_github_hunt.py
```

## 📊 Output Analysis

### Executive Summary
The tool provides a high-level overview of findings:
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

### Detailed Repository Analysis
Per-repository breakdown with risk scoring:
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

### JSON Output
Complete findings in SIEM-ready JSON format:
```json
{
  "target": "your-org",
  "target_type": "organization",
  "repos_scanned": [...],
  "packages": [...],
  "workflows": [...],
  "webhook_hits": [...],
  "branches": [...],
  "audit": [...]
}
```

## 🔧 Advanced Configuration

### Customizing Package Detection
The tool uses `compromised_packages.txt` containing 555 known compromised packages. To update:

1. Add new package identifiers in `package@version` format
2. One package per line
3. Comments supported with `#` prefix

### Rate Limiting
The tool implements intelligent rate limiting:
- 0.05 seconds between Repository Contents API calls
- 0.2 seconds between branch enumeration requests
- 0.5 seconds between Search API calls (fallback)
- Automatic retry with exponential backoff

## 🚨 Security Considerations

### Token Security
- **Never commit tokens to version control**
- Use environment variables or secure credential management
- Rotate tokens regularly
- Apply principle of least privilege for token scopes

### Network Security
- Tool makes HTTPS requests to api.github.com only
- No data is transmitted to third parties
- All scanning is read-only (no modifications made)

### Data Privacy
- Scanned repository metadata is processed locally
- No persistent storage of sensitive information
- JSON output may contain repository paths and filenames

## 🔄 Troubleshooting

### Common Issues

#### 403 Forbidden Errors
**Problem**: API returns 403 Forbidden during package scanning
**Solution**: Tool automatically uses Repository Contents API instead of Search API

#### Rate Limiting
**Problem**: HTTP 429 errors or rate limit warnings
**Solution**: Tool implements automatic rate limiting and retry logic

#### Token Permission Errors
**Problem**: 401 Unauthorized or insufficient permissions
**Solution**: Verify token has required scopes:
```bash
curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user
```

#### No Packages Found
**Problem**: Package scanning reports 0 packages but repositories contain package files
**Solution**: Check that `compromised_packages.txt` exists and contains package data

### Debug Information
Run with increased verbosity by examining the script output for:
- API endpoint URLs being called
- Response status codes
- Error messages with context
- Repository and file paths being scanned

## 📈 Performance

### Scanning Speed
- **Small organizations** (<10 repos): 1-2 minutes
- **Medium organizations** (10-100 repos): 5-15 minutes
- **Large organizations** (100+ repos): 15+ minutes

### Resource Usage
- **Memory**: <50MB typical usage
- **Network**: ~1KB per API call, depends on repository count
- **CPU**: Minimal, I/O bound workload

## 🤝 Contributing

### Development Setup
```bash
git clone https://github.com/your-username/shai_hulud_hunt.git
cd shai_hulud_hunt

# Install development dependencies
pip install requests

# Run tests
python3 -m py_compile shai_hulud_github_hunt.py
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