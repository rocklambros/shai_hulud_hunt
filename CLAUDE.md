# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a cybersecurity threat hunting tool designed to detect "Shai Hulud" indicators across GitHub organizations. The project provides two equivalent implementations for hunting malicious activities:

- **`shai_hulud_github_hunt.py`**: Python implementation using GitHub REST API
- **`shai_hulud_quick.sh`**: Shell script using GitHub CLI

Both tools search for suspicious repositories, malicious workflow files, webhook.site references, suspicious branches, and audit log events. They output structured data suitable for SIEM integration.

## Setup and Dependencies

### Environment Variables (Optional)
```bash
export GITHUB_ORG="your-org"
export GITHUB_TOKEN="your-github-token"
```

**Note**: The Python script now prompts for credentials if environment variables are not set.

### Dependencies
```bash
# For Python script
pip install requests

# For shell script
gh auth login
```

### GitHub Token Requirements

For **fine-grained tokens**, you need:
- **Contents: Read** - For code search and file access
- **Metadata: Read** - For repository information
- **Audit Log: Read** - For Enterprise Cloud audit logs (optional)

For **classic tokens**, you need:
- `repo` scope for repository access
- `read:audit_log` scope for Enterprise Cloud audit logs

## Running the Tools

```bash
# Python implementation (interactive prompts if env vars not set)
python3 shai_hulud_github_hunt.py

# Shell implementation (requires pre-set environment or gh CLI auth)
./shai_hulud_quick.sh

# Pass environment variables directly (most secure)
GITHUB_ORG="your-org" GITHUB_TOKEN="your-token" python3 shai_hulud_github_hunt.py
```

## Architecture

### Core Design Patterns
- **Single-purpose scripts**: Each file is self-contained
- **API pagination**: Built-in handling of GitHub API pagination with rate limiting
- **Environment-driven configuration**: No config files, uses environment variables
- **SIEM-ready output**: JSON (Python) and structured text (shell) for machine processing

### Threat Hunting Phases
1. **Repository scanning**: Names/descriptions matching "Shai Hulud" or "migration" patterns
2. **Workflow detection**: Malicious `.github/workflows/shai-hulud-workflow.yml` files
3. **Code scanning**: webhook.site references (exfiltration indicators)
4. **Branch enumeration**: Branches named "shai-hulud" or "shai hulud"
5. **Audit analysis**: Enterprise Cloud audit logs for suspicious activities

### Key Functions
- `gh_paged()`: Handles GitHub API pagination with rate limiting
- `hunt()`: Main orchestration function for all threat hunting phases

## Development Workflow

### Before Making Changes
```bash
# Verify current functionality
python3 shai_hulud_github_hunt.py
./shai_hulud_quick.sh

# Check environment setup
echo $GITHUB_ORG && echo $GITHUB_TOKEN
gh auth status
```

### Validation After Changes
```bash
# Python syntax check
python3 -m py_compile shai_hulud_github_hunt.py

# Shell script validation
bash -n shai_hulud_quick.sh

# Dependencies check
python3 -c "import requests"
```

### Code Style Guidelines
- **Python**: Compact style, minimal comments, dictionary/list comprehensions
- **Shell**: UPPERCASE variables, `jq` for JSON processing
- **Error handling**: Simple `sys.exit()` for critical errors, `raise_for_status()` for HTTP
- **Rate limiting**: Use `time.sleep()` to respect GitHub API limits

## Important Notes

- **Read-only tools**: These scripts make no changes to repositories
- **Rate limiting**: Built-in delays prevent API rate limit violations  
- **Enterprise features**: Audit log access requires GitHub Enterprise Cloud
- **Output format**: Designed for SIEM integration - maintain structured output
- **Security focus**: Environment variables prevent token exposure in code