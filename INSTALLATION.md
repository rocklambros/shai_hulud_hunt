# Installation Guide

## System Requirements

### Operating System Support
- **Linux**: Ubuntu 18.04+, CentOS 7+, RHEL 7+
- **macOS**: 10.14+ (Mojave or later)
- **Windows**: Windows 10+, Windows Server 2019+

### Python Requirements
- **Python Version**: 3.7 or higher
- **Package Manager**: pip (included with Python 3.4+)

### Network Requirements
- Internet connectivity for GitHub API access
- HTTPS outbound access to `api.github.com` (port 443)
- Optional: Corporate proxy configuration support

## Installation Methods

### Method 1: Direct Download (Recommended)

```bash
# Download the latest release
curl -L https://github.com/your-username/shai_hulud_hunt/archive/main.zip -o shai_hulud_hunt.zip

# Extract and setup
unzip shai_hulud_hunt.zip
cd shai_hulud_hunt-main

# Install dependencies
pip install requests

# Verify installation
python3 shai_hulud_github_hunt.py --help
```

### Method 2: Git Clone

```bash
# Clone repository
git clone https://github.com/your-username/shai_hulud_hunt.git
cd shai_hulud_hunt

# Install dependencies
pip install requests

# Make executable (Linux/macOS)
chmod +x shai_hulud_github_hunt.py
```

### Method 3: Virtual Environment (Recommended for Development)

```bash
# Create virtual environment
python3 -m venv shai_hulud_env
source shai_hulud_env/bin/activate  # Linux/macOS
# OR
shai_hulud_env\Scripts\activate.bat  # Windows

# Clone and install
git clone https://github.com/your-username/shai_hulud_hunt.git
cd shai_hulud_hunt
pip install requests

# Verify installation
python shai_hulud_github_hunt.py
```

## GitHub Token Setup

### Creating a Personal Access Token

1. **Navigate to GitHub Settings**
   - Go to https://github.com/settings/tokens
   - Click "Generate new token" → "Generate new token (classic)"

2. **Configure Token Permissions**

   **For Public Repository Scanning:**
   - ✅ `public_repo` - Access public repositories

   **For Private Repository & Organization Scanning:**
   - ✅ `repo` - Full control of private repositories
   - ✅ `read:org` - Read organization membership

   **For Enterprise Audit Log Access (Optional):**
   - ✅ `read:audit_log` - Read audit log events

3. **Generate and Secure Token**
   - Click "Generate token"
   - **Copy token immediately** (cannot be viewed again)
   - Store securely in password manager

### Setting Environment Variables

#### Linux/macOS (Bash/Zsh)
```bash
# Add to ~/.bashrc or ~/.zshrc for persistence
export GITHUB_TOKEN="github_pat_your_token_here"
export GITHUB_ORG="your-organization-name"

# Apply changes
source ~/.bashrc  # or ~/.zshrc
```

#### Windows (PowerShell)
```powershell
# Set for current session
$env:GITHUB_TOKEN="github_pat_your_token_here"
$env:GITHUB_ORG="your-organization-name"

# Set permanently (requires restart)
[Environment]::SetEnvironmentVariable("GITHUB_TOKEN", "github_pat_your_token_here", "User")
[Environment]::SetEnvironmentVariable("GITHUB_ORG", "your-organization-name", "User")
```

#### Windows (Command Prompt)
```cmd
# Set for current session
set GITHUB_TOKEN=github_pat_your_token_here
set GITHUB_ORG=your-organization-name

# Set permanently
setx GITHUB_TOKEN "github_pat_your_token_here"
setx GITHUB_ORG "your-organization-name"
```

## Corporate Environment Setup

### Proxy Configuration

If your organization uses a corporate proxy:

```bash
# Set proxy environment variables
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080

# For authenticated proxies
export HTTP_PROXY=http://username:password@proxy.company.com:8080
export HTTPS_PROXY=http://username:password@proxy.company.com:8080
```

### SSL Certificate Issues

For organizations with custom CA certificates:

```bash
# Add CA certificate to Python requests
export REQUESTS_CA_BUNDLE=/path/to/company-ca-bundle.crt

# Or disable SSL verification (NOT recommended for production)
export PYTHONHTTPSVERIFY=0
```

## Verification and Testing

### Basic Installation Test
```bash
# Test Python and dependencies
python3 -c "import requests; print('Dependencies OK')"

# Test script syntax
python3 -m py_compile shai_hulud_github_hunt.py

# Test token authentication
python3 -c "
import os, requests
token = os.environ.get('GITHUB_TOKEN')
if not token:
    print('❌ GITHUB_TOKEN not set')
else:
    headers = {'Authorization': f'Bearer {token}'}
    r = requests.get('https://api.github.com/user', headers=headers)
    print(f'✅ Token valid: {r.status_code == 200}')
"
```

### Connectivity Test
```bash
# Test GitHub API access
curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user

# Expected response: JSON with user information
# Status: 200 OK
```

### Sample Run Test
```bash
# Run with a small public repository
export GITHUB_TARGET="octocat/Hello-World"
python3 shai_hulud_github_hunt.py

# Should complete without errors and show summary
```

## Troubleshooting Installation

### Common Issues

#### "ModuleNotFoundError: No module named 'requests'"
```bash
# Solution: Install requests library
pip install requests

# If using system Python on Linux
sudo apt-get install python3-pip  # Ubuntu/Debian
pip3 install requests
```

#### "Permission denied" on Linux/macOS
```bash
# Solution: Add execute permissions
chmod +x shai_hulud_github_hunt.py

# Or run with python3 explicitly
python3 shai_hulud_github_hunt.py
```

#### "python3: command not found" on Windows
```cmd
# Solution: Use 'python' instead of 'python3'
python shai_hulud_github_hunt.py

# Or add Python to PATH during installation
```

#### Token Authentication Failures
1. **Verify token format**: Should start with `github_pat_` or `ghp_`
2. **Check token scopes**: Ensure required permissions are granted
3. **Test token manually**:
   ```bash
   curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user
   ```

#### Corporate Network Issues
1. **Proxy Configuration**: Set HTTP_PROXY/HTTPS_PROXY environment variables
2. **Firewall Rules**: Ensure outbound HTTPS access to api.github.com
3. **SSL Certificates**: Configure REQUESTS_CA_BUNDLE if needed

### Performance Optimization

#### For Large Organizations (100+ repositories)
```bash
# Consider running in background
nohup python3 shai_hulud_github_hunt.py > scan_results.log 2>&1 &

# Monitor progress
tail -f scan_results.log
```

#### Memory Optimization
```bash
# For memory-constrained environments
export PYTHONUNBUFFERED=1  # Immediate output
ulimit -m 512000  # Limit memory to 512MB (Linux)
```

## Docker Installation (Alternative)

### Using Docker
```dockerfile
# Create Dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY . .
RUN pip install requests

ENTRYPOINT ["python", "shai_hulud_github_hunt.py"]
```

```bash
# Build and run
docker build -t shai-hulud-hunt .
docker run -e GITHUB_TOKEN=$GITHUB_TOKEN -e GITHUB_ORG=$GITHUB_ORG shai-hulud-hunt
```

## Next Steps

After successful installation:

1. **Review README.md** for usage instructions
2. **Test with a small target** (single repository)
3. **Configure monitoring** for large-scale scans
4. **Set up automated scheduling** if needed
5. **Review SECURITY.md** for operational security guidelines

## Support

If you encounter installation issues:

1. **Check system requirements** (Python 3.7+, internet connectivity)
2. **Verify GitHub token** permissions and validity
3. **Review firewall/proxy** configuration for corporate environments
4. **Open a GitHub issue** with detailed error messages and environment information

---

**Installation Guide Version**: 1.0 | **Last Updated**: 2025-09-17