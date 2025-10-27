# Security Guidelines

## Security Overview

The Shai Hulud GitHub Threat Hunt Tool is designed for legitimate cybersecurity purposes and follows security best practices for safe operation in enterprise environments.

## Threat Model

### Tool Security Posture
- **Read-Only Operations**: Tool performs no write operations to GitHub repositories
- **API-Only Access**: Uses official GitHub REST API with standard authentication
- **Local Processing**: All analysis performed locally, no data transmitted to third parties
- **Credential Security**: Implements secure token handling and validation

### Potential Risks
- **Token Exposure**: GitHub tokens could be exposed through environment variables or logs
- **Network Interception**: API communications could be intercepted without HTTPS
- **Data Leakage**: Scan results may contain sensitive repository information
- **Privilege Escalation**: Overprivileged tokens could access unintended resources

## Secure Configuration

### GitHub Token Management

#### Token Creation Best Practices
```bash
# Use fine-grained personal access tokens (recommended)
# Navigate to: Settings → Developer settings → Personal access tokens → Fine-grained tokens

# Minimum required permissions:
- Repository permissions:
  ✅ Contents: Read
  ✅ Metadata: Read
  ✅ Actions: Read (for workflow detection)

- Organization permissions (if scanning orgs):
  ✅ Members: Read
  ✅ Administration: Read (for audit logs)

# Token expiration: Set to minimum necessary duration (90 days max recommended)
# Token name: Use descriptive names like "shai-hulud-scan-prod-YYYY-MM"
```

#### Token Storage Security
```bash
# ✅ SECURE: Environment variables
export GITHUB_TOKEN="github_pat_xxxxxxxxxxxxx"

# ✅ SECURE: Credential management systems
# AWS Secrets Manager
aws secretsmanager get-secret-value --secret-id github-token --query SecretString --output text

# HashiCorp Vault
vault kv get -field=token secret/github/scanning

# ❌ INSECURE: Hardcoded in scripts
GITHUB_TOKEN="github_pat_xxxxxxxxxxxxx"  # Never do this

# ❌ INSECURE: Version control
git add .env  # Never commit tokens
```

### Network Security Configuration

#### Corporate Environment Setup
```bash
# HTTPS proxy configuration (if required)
export HTTPS_PROXY="https://proxy.company.com:8080"
export HTTP_PROXY="http://proxy.company.com:8080"

# Certificate authority configuration
export REQUESTS_CA_BUNDLE="/etc/ssl/certs/ca-certificates.crt"

# Network monitoring whitelist
# Allow outbound HTTPS to: api.github.com (140.82.112.0/20)
```

#### TLS/SSL Verification
```python
# Default behavior (recommended)
# Tool automatically verifies GitHub's SSL certificate

# Corporate environments with custom CAs
export SSL_CERT_FILE="/path/to/company-ca-bundle.pem"

# ⚠️ WARNING: Never disable SSL verification in production
# export PYTHONHTTPSVERIFY=0  # Only for testing
```

## Operational Security

### Access Control

#### Principle of Least Privilege
```yaml
# Token Scope Mapping:
scanning_target: required_scopes
public_repos: ["public_repo"]
private_repos: ["repo"]
organization: ["repo", "read:org"]
enterprise_audit: ["repo", "read:org", "read:audit_log"]

# User Access Control:
role: permissions
security_analyst: ["read_scan_results"]
incident_responder: ["run_targeted_scans"]
security_admin: ["full_org_scans", "audit_access"]
```

#### Token Rotation Policy
```bash
#!/bin/bash
# token_rotation.sh - Automated token rotation

# 1. Generate new token via GitHub API or manually
# 2. Test new token
NEW_TOKEN="github_pat_new_token"
curl -H "Authorization: Bearer $NEW_TOKEN" https://api.github.com/user

# 3. Update deployment
kubectl create secret generic github-token \
  --from-literal=token=$NEW_TOKEN \
  --dry-run=client -o yaml | kubectl apply -f -

# 4. Verify deployment
# 5. Revoke old token
```

### Data Protection

#### Sensitive Information Handling
```bash
# Configure logging to exclude sensitive data
export PYTHONHTTPSVERIFY=1  # Ensure HTTPS
export GITHUB_LOG_LEVEL="WARNING"  # Reduce verbose logging

# Secure temporary files
umask 077  # Create files with restrictive permissions
export TMPDIR="/secure/temp/path"

# Clean up after scanning
trap 'rm -f /tmp/scan_* 2>/dev/null' EXIT
```

#### Output Data Classification
```yaml
# Data Classification Matrix:
output_section: classification: handling
repository_names: "INTERNAL": "Standard corporate data handling"
file_paths: "INTERNAL": "Standard corporate data handling"
package_versions: "PUBLIC": "Can be shared with vendors"
vulnerability_details: "CONFIDENTIAL": "Restrict to security team"
audit_logs: "RESTRICTED": "Security team + compliance only"
```

### Monitoring and Audit

#### Security Event Monitoring
```bash
# Log all scan executions
logger "shai_hulud_scan: Started by $(whoami) at $(date) targeting $GITHUB_ORG"

# Monitor token usage
# GitHub provides audit logs for token usage at:
# Settings → Developer settings → Personal access tokens → View audit log

# Track file access
auditctl -w /opt/shai_hulud_hunt/ -p rwxa -k shai_hulud_access
```

#### Compliance Logging
```python
# Audit trail example
import logging
import json
from datetime import datetime

# Configure audit logging
audit_logger = logging.getLogger('shai_hulud_audit')
audit_handler = logging.FileHandler('/var/log/audit/shai_hulud.log')
audit_handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
audit_logger.addHandler(audit_handler)
audit_logger.setLevel(logging.INFO)

# Log scan initiation
audit_logger.info(json.dumps({
    'event': 'scan_initiated',
    'user': os.getenv('USER'),
    'target': os.getenv('GITHUB_ORG'),
    'timestamp': datetime.utcnow().isoformat(),
    'source_ip': '192.168.1.100'
}))
```

## Incident Response

### Security Incident Procedures

#### Token Compromise Response
```bash
# 1. IMMEDIATE: Revoke compromised token
# Go to GitHub → Settings → Developer settings → Personal access tokens
# Click "Delete" next to compromised token

# 2. ASSESS: Check token usage logs
# GitHub → Settings → Developer settings → View audit log
# Look for unexpected API calls or access patterns

# 3. ROTATE: Generate new token with minimum required permissions
# Follow token creation best practices above

# 4. UPDATE: Deploy new token to all systems
# Update environment variables, secret management systems

# 5. MONITOR: Watch for continued unauthorized access
# Review GitHub audit logs for 48 hours post-incident
```

#### Data Exposure Response
```bash
# 1. CONTAIN: Identify scope of exposure
grep -r "sensitive_pattern" /var/log/shai_hulud/
find /tmp -name "*scan*" -type f -exec rm {} \;

# 2. ASSESS: Determine data classification
# Review scan output for sensitive repository names, paths, or content

# 3. NOTIFY: Alert appropriate stakeholders
# Security team, compliance, data protection officer

# 4. REMEDIATE: Implement additional controls
# Enhanced logging, data encryption, access restrictions
```

### Vulnerability Disclosure

#### Responsible Disclosure Process
1. **Internal Discovery**: Security issues found in tool itself
   - Report to tool maintainers via private GitHub issue
   - Include proof of concept and suggested remediation
   - Allow 90 days for fix before public disclosure

2. **External Dependencies**: Vulnerabilities in Python packages
   - Report to package maintainers following standard disclosure
   - Update requirements.txt when fixes available

3. **GitHub API Issues**: Problems with GitHub's API
   - Report through GitHub's official bug bounty program
   - Follow GitHub's responsible disclosure guidelines

## Implemented Security Fixes

### v1.1 Security Hardening (2025-09-17)

The following critical security vulnerabilities have been addressed based on comprehensive security assessment:

#### HIGH-Severity Fixes Implemented

**H-01: Secure Token Storage**
- **Issue**: GitHub tokens exposed in process memory
- **Fix**: Implemented `SecureTokenManager` class with XOR obfuscation
- **Protection**: Prevents memory dumps from exposing credentials
- **Implementation**: Token stored in obfuscated form, cleared after use
```python
# Secure token management
SECURE_TOKEN_MANAGER = SecureTokenManager()
SECURE_TOKEN_MANAGER.store_token(token)
```

**H-02: Comprehensive Input Sanitization**
- **Issue**: Injection vulnerabilities from unsanitized external data
- **Fix**: Added sanitization functions for all user input and API responses
- **Protection**: Prevents code injection and malicious input processing
- **Coverage**: Repository names, branch names, file paths, descriptions
```python
# Input sanitization applied to all external data
sanitized_name = sanitize_string(repo_name, max_length=255, allow_chars=r'[a-zA-Z0-9\-_./]')
```

**H-03: Enhanced Token Scope Validation**
- **Issue**: Excessive token permissions (privilege escalation risk)
- **Fix**: Implemented scope checking and least privilege validation
- **Protection**: Warns about unnecessary permissions, validates required scopes
- **Implementation**: Pre-scan token validation with scope analysis
```python
# Token scope validation
validate_token_scopes(token, target, target_type)
# Warns about excessive scopes like 'admin:org' when not needed
```

**H-04: Resource Consumption Limits**
- **Issue**: DoS vulnerability against large organizations
- **Fix**: Implemented `ResourceLimits` class with configurable thresholds
- **Protection**: Prevents memory exhaustion and API abuse
- **Limits**: Max 1000 repos, 100 branches/repo, 60 API calls/min, 15s timeouts
```python
# Resource limits enforced
limits = ResourceLimits()
if len(repositories) > limits.MAX_REPOSITORIES:
    print(f"⚠️ Repository count ({len(repositories)}) exceeds limit ({limits.MAX_REPOSITORIES})")
```

#### Additional Security Enhancements

**Security Logging and Audit Trail**
- **Feature**: Comprehensive security event logging via `SecurityLogger` class
- **Coverage**: Scan initiation, security warnings, threat detection, API access
- **Compliance**: Structured JSON logs for SIEM integration and audit requirements
- **Implementation**: Real-time security event tracking with timestamp and context

**Defensive Programming Patterns**
- **API Timeouts**: All requests have 15-second timeout limits
- **Rate Limit Handling**: Automatic retry logic with exponential backoff
- **Error Sanitization**: Sensitive information removed from error messages
- **Safe Defaults**: Secure-by-default configuration throughout

### Security Validation Procedures

#### Pre-Deployment Validation
1. **Token Scope Validation**: Verify minimum required permissions
2. **Resource Limit Testing**: Confirm DoS protection effectiveness
3. **Input Sanitization Testing**: Validate injection attack prevention
4. **Memory Security Testing**: Confirm token obfuscation effectiveness

#### Runtime Security Monitoring
1. **Security Event Logging**: Monitor all security-relevant events
2. **Resource Consumption Tracking**: Track API usage and memory consumption
3. **Token Usage Auditing**: Log all GitHub API access attempts
4. **Threat Detection Alerting**: Real-time alerts on security findings

#### Security Compliance
- **Data Protection**: All sensitive data properly sanitized and protected
- **Audit Trail**: Comprehensive logging for compliance and incident response
- **Least Privilege**: Token permissions validated against actual requirements
- **Defense in Depth**: Multiple layers of security controls implemented

## Security Best Practices

### Deployment Security

#### Production Deployment Checklist
- [ ] **Token Security**: Fine-grained tokens with minimum required permissions
- [ ] **Network Security**: HTTPS proxy configured, SSL verification enabled
- [ ] **Access Control**: Role-based access to scanning capabilities
- [ ] **Audit Logging**: Comprehensive logging of all scan activities
- [ ] **Data Protection**: Secure handling of scan results and temporary files
- [ ] **Monitoring**: Real-time monitoring of token usage and scan activities
- [ ] **Incident Response**: Documented procedures for security incidents
- [ ] **Regular Updates**: Keep tool and dependencies updated

#### Secure Automation
```yaml
# GitHub Actions security example
name: Secure Shai Hulud Scan
on:
  schedule:
    - cron: '0 6 * * 1'  # Weekly scans

jobs:
  security-scan:
    runs-on: ubuntu-latest
    environment: production  # Require approval for production scans

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Configure security
        run: |
          # Set secure umask
          umask 077
          # Verify runner environment
          echo "Runner: $(whoami) on $(hostname)"

      - name: Validate token
        env:
          GITHUB_TOKEN: ${{ secrets.SECURITY_SCAN_TOKEN }}
        run: |
          # Test token without exposing it
          if ! curl -sf -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user > /dev/null; then
            echo "❌ Token validation failed"
            exit 1
          fi

      - name: Run secure scan
        env:
          GITHUB_TOKEN: ${{ secrets.SECURITY_SCAN_TOKEN }}
          GITHUB_ORG: ${{ github.repository_owner }}
        run: |
          python3 shai_hulud_github_hunt.py > scan_results.txt 2>&1

      - name: Sanitize results
        run: |
          # Remove potentially sensitive information
          sed -i 's/github_pat_[a-zA-Z0-9]*/[REDACTED]/g' scan_results.txt

      - name: Upload results securely
        uses: actions/upload-artifact@v4
        with:
          name: security-scan-results
          path: scan_results.txt
          retention-days: 30
```

### Continuous Security

#### Security Monitoring
```bash
# Weekly security review script
#!/bin/bash

echo "🔒 Shai Hulud Security Review - $(date)"

# 1. Check for tool updates
git fetch origin
if [ $(git rev-list HEAD...origin/main --count) -gt 0 ]; then
    echo "⚠️ Tool updates available"
fi

# 2. Review token usage
# Check GitHub audit logs for unexpected activity

# 3. Validate permissions
python3 -c "
import os, requests
token = os.environ.get('GITHUB_TOKEN')
headers = {'Authorization': f'Bearer {token}'}
r = requests.get('https://api.github.com/user', headers=headers)
scopes = r.headers.get('X-OAuth-Scopes', '')
print(f'Current token scopes: {scopes}')
"

# 4. Check scan logs for anomalies
grep -E "(ERROR|WARNING|CRITICAL)" /var/log/shai_hulud/*.log | tail -20
```

#### Threat Intelligence Integration
```bash
# Update compromised package database
#!/bin/bash

# Download latest IOCs from threat intelligence sources
# curl -s https://threat-intel-source.com/shai-hulud-iocs.txt > new_packages.txt

# Validate format and merge with existing database
# python3 validate_packages.py new_packages.txt
# if [ $? -eq 0 ]; then
#     cp new_packages.txt compromised_packages.txt
#     echo "✅ Package database updated"
# fi
```

## Compliance Considerations

### Regulatory Compliance

#### GDPR/Privacy Considerations
- **Data Collection**: Tool collects repository metadata, not personal data
- **Data Processing**: Processing occurs locally, no third-party data sharing
- **Data Retention**: Configure log retention policies per organizational requirements
- **Right to Erasure**: Ensure scan logs can be purged upon request

#### SOC 2 / ISO 27001 Alignment
- **Access Controls**: Implement role-based access to scanning capabilities
- **Audit Logging**: Comprehensive logging of all security-relevant events
- **Change Management**: Version control for tool updates and configuration changes
- **Incident Response**: Documented procedures for security incident handling

### Industry-Specific Requirements

#### Financial Services (PCI DSS)
- **Network Segmentation**: Deploy tool in secure network segments
- **Access Logging**: Log all access to scanning systems and results
- **Encryption**: Encrypt scan results at rest and in transit

#### Healthcare (HIPAA)
- **Administrative Safeguards**: Limit access to authorized security personnel
- **Physical Safeguards**: Secure deployment environments
- **Technical Safeguards**: Encryption, access controls, audit logging

## Contact Information

### Security Contact
- **Security Issues**: security@your-organization.com
- **Vulnerability Reports**: Use private GitHub security advisories
- **Emergency Contact**: Follow your organization's incident response procedures

---

**Security Guidelines Version**: 1.0 | **Last Updated**: 2025-09-17 | **Next Review**: 2025-12-17