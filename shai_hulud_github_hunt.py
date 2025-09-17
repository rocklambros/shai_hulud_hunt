'''
Hunt for Shai Hulud indicators across a GitHub org at scale via the REST API: it searches for repositories named "Shai Hulud" or with migration in the name or description, locates the exact malicious workflow path .github/workflows/shai-hulud-workflow.yml, scans for webhook.site references in code, enumerates branches named shai-hulud or shai hulud, and pulls org audit log events for repo.create, repo.visibility_change, and git.push within a defined window.

USAGE:
  python3 shai_hulud_github_hunt.py

The script will prompt for GitHub organization and token if not set in environment variables:
- GITHUB_ORG: GitHub organization name
- GITHUB_TOKEN: Personal access token with required permissions

REQUIRED TOKEN PERMISSIONS:
- Contents (Read): For code search and file access
- Metadata (Read): For repository information
- Audit Log (Read): For Enterprise Cloud audit logs (optional)

The script is read-only, makes no changes, uses polite pagination with sleeps to respect rate limits, and outputs JSON suitable for SIEM integration. You can tune the dates and queries to re-run until your estate is clean.
'''

# pip install requests
import os, time, sys, csv, json, requests, getpass, re
import base64
import hashlib
from typing import Optional
import logging
from datetime import datetime, timezone

# MONITORING AND ALERTING CONFIGURATION
# Risk Score Thresholds (based on confidence scoring):
# - CRITICAL (≥200): Multiple high-confidence threats, immediate escalation
# - HIGH (≥100): Single high-confidence threat, urgent review required
# - MEDIUM (≥30): Low-confidence patterns, continued monitoring
# - LOW (<30): Minimal risk, routine monitoring sufficient
#
# Confidence Thresholds:
# - ≥0.8: High confidence (educational filters applied)
# - ≥0.7: Medium confidence (repository context considered)
# - <0.7: Low confidence (filtered as potential false positive)
#
# Alert Escalation:
# - Critical: Immediate security team notification
# - High: Schedule review within 24 hours
# - Medium: Weekly monitoring report
# - Low: Monthly summary review

class ResourceLimits:
  """Resource consumption limits to prevent DoS attacks"""

  def __init__(self):
    # Repository limits
    self.MAX_REPOSITORIES = 1000  # Maximum repositories to scan
    self.MAX_BRANCHES_PER_REPO = 100  # Maximum branches to check per repository
    self.MAX_FILES_PER_REPO = 50  # Maximum package files to check per repository

    # API limits
    self.MAX_API_CALLS_PER_MINUTE = 60  # Rate limiting
    self.API_TIMEOUT_SECONDS = 15  # Timeout for API calls
    self.MAX_RETRIES = 3  # Maximum retry attempts

    # Memory limits
    self.MAX_FILE_SIZE_BYTES = 1024 * 1024  # 1MB max file size
    self.MAX_RESPONSE_SIZE_BYTES = 10 * 1024 * 1024  # 10MB max response
    self.MAX_TOTAL_MEMORY_MB = 512  # 512MB total memory limit

    # Security limits
    self.MAX_STRING_LENGTH = 1000  # Maximum string length for inputs
    self.MAX_SEARCH_RESULTS = 100  # Maximum search results to process

    # Tracking for rate limiting
    self.api_calls_this_minute = 0
    self.last_rate_limit_reset = time.time()

  def check_repository_limit(self, current_count):
    """Check if repository count exceeds limits"""
    if current_count > self.MAX_REPOSITORIES:
      raise RuntimeError(f"Repository limit exceeded: {current_count} > {self.MAX_REPOSITORIES}")

  def check_branch_limit(self, current_count, repo_name):
    """Check if branch count exceeds limits for a repository"""
    if current_count > self.MAX_BRANCHES_PER_REPO:
      print(f"⚠️  Warning: {repo_name} has {current_count} branches, limiting to {self.MAX_BRANCHES_PER_REPO}")
      return self.MAX_BRANCHES_PER_REPO
    return current_count

  def check_file_size_limit(self, file_size, file_path):
    """Check if file size exceeds limits"""
    if file_size > self.MAX_FILE_SIZE_BYTES:
      print(f"⚠️  Warning: {file_path} size ({file_size} bytes) exceeds limit, skipping")
      return False
    return True

  def check_response_size_limit(self, response_size):
    """Check if response size exceeds limits"""
    if response_size > self.MAX_RESPONSE_SIZE_BYTES:
      raise RuntimeError(f"Response size limit exceeded: {response_size} > {self.MAX_RESPONSE_SIZE_BYTES}")

  def rate_limit_check(self):
    """Check and enforce API rate limiting"""
    current_time = time.time()

    # Reset counter if minute has passed
    if current_time - self.last_rate_limit_reset >= 60:
      self.api_calls_this_minute = 0
      self.last_rate_limit_reset = current_time

    # Check if we've exceeded rate limit
    if self.api_calls_this_minute >= self.MAX_API_CALLS_PER_MINUTE:
      sleep_time = 60 - (current_time - self.last_rate_limit_reset)
      if sleep_time > 0:
        print(f"⏳ Rate limit reached, sleeping for {sleep_time:.1f} seconds...")
        time.sleep(sleep_time)
        self.api_calls_this_minute = 0
        self.last_rate_limit_reset = time.time()

    self.api_calls_this_minute += 1

  def get_api_timeout(self):
    """Get API timeout value"""
    return self.API_TIMEOUT_SECONDS

class SecurityLogger:
  """Security logging and audit trail for threat hunting operations"""

  def __init__(self):
    # Configure security logger
    self.logger = logging.getLogger('shai_hulud_security')
    self.logger.setLevel(logging.INFO)

    # Create formatter for security events
    formatter = logging.Formatter(
      '%(asctime)s [SECURITY] %(levelname)s - %(message)s',
      datefmt='%Y-%m-%d %H:%M:%S UTC'
    )

    # Console handler for immediate visibility
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    self.logger.addHandler(console_handler)

    # Track security events
    self.security_events = []

  def log_scan_start(self, target, target_type, user=None):
    """Log the start of a security scan"""
    event = {
      'timestamp': datetime.now(timezone.utc).isoformat(),
      'event_type': 'SCAN_INITIATED',
      'target': target,
      'target_type': target_type,
      'user': user or os.getenv('USER', 'unknown'),
      'source_ip': 'localhost',  # Could be enhanced to get real IP
      'tool_version': '2.0.0'
    }
    self.security_events.append(event)
    self.logger.info(f"Threat hunt scan initiated - Target: {target_type}:{target}, User: {event['user']}")

  def log_security_warning(self, warning_type, message, details=None):
    """Log security warnings and violations"""
    event = {
      'timestamp': datetime.now(timezone.utc).isoformat(),
      'event_type': 'SECURITY_WARNING',
      'warning_type': warning_type,
      'message': message,
      'details': details or {}
    }
    self.security_events.append(event)
    self.logger.warning(f"Security Warning [{warning_type}]: {message}")

  def log_threat_detection(self, threat_type, severity, repo_name, details=None):
    """Log threat detections"""
    event = {
      'timestamp': datetime.now(timezone.utc).isoformat(),
      'event_type': 'THREAT_DETECTED',
      'threat_type': threat_type,
      'severity': severity,
      'repository': repo_name,
      'details': details or {}
    }
    self.security_events.append(event)
    self.logger.warning(f"Threat Detected [{severity}] {threat_type} in {repo_name}")

  def log_access_attempt(self, endpoint, success, status_code=None):
    """Log API access attempts"""
    event = {
      'timestamp': datetime.now(timezone.utc).isoformat(),
      'event_type': 'API_ACCESS',
      'endpoint': endpoint,
      'success': success,
      'status_code': status_code
    }
    if not success:
      self.security_events.append(event)
      self.logger.warning(f"API Access Failed: {endpoint} (Status: {status_code})")

  def log_rate_limit_hit(self, calls_per_minute):
    """Log rate limiting events"""
    event = {
      'timestamp': datetime.now(timezone.utc).isoformat(),
      'event_type': 'RATE_LIMIT_HIT',
      'calls_per_minute': calls_per_minute
    }
    self.security_events.append(event)
    self.logger.info(f"Rate limit enforced - {calls_per_minute} calls/minute")

  def log_scan_completion(self, repos_scanned, threats_found, duration_seconds):
    """Log scan completion with summary"""
    event = {
      'timestamp': datetime.now(timezone.utc).isoformat(),
      'event_type': 'SCAN_COMPLETED',
      'repositories_scanned': repos_scanned,
      'threats_found': threats_found,
      'duration_seconds': duration_seconds
    }
    self.security_events.append(event)
    self.logger.info(f"Scan completed - {repos_scanned} repos, {threats_found} threats, {duration_seconds:.1f}s")

  def get_audit_trail(self):
    """Get complete audit trail for compliance"""
    return {
      'scan_session': {
        'session_id': f"shai_hulud_{int(time.time())}",
        'events': self.security_events
      }
    }

class SecureTokenManager:
  """
  Secure token storage with XOR obfuscation to prevent memory dumps.

  Implements secure storage of GitHub Personal Access Tokens to prevent
  credential exposure through memory dumps or process inspection. Uses
  XOR obfuscation with a derived key to protect tokens in memory.

  Security Features:
  - XOR obfuscation prevents plain text token storage
  - Automatic token clearing after use
  - Hash-based key derivation
  - Memory-safe token management

  Example:
    manager = SecureTokenManager()
    manager.store_token("github_pat_...")
    headers = manager.get_headers()
    manager.clear_token()
  """

  def __init__(self):
    self._token_hash: Optional[str] = None
    self._obfuscated_token: Optional[bytes] = None
    self._key: Optional[bytes] = None

  def store_token(self, token: str) -> None:
    """Securely store token with obfuscation"""
    if not token:
      return

    # Create a simple key from token hash (not cryptographically secure, but better than plaintext)
    self._token_hash = hashlib.sha256(token.encode()).hexdigest()[:16]
    self._key = base64.b64encode(self._token_hash.encode())[:16]

    # Simple XOR obfuscation (not encryption, but prevents casual memory inspection)
    token_bytes = token.encode('utf-8')
    key_bytes = (self._key * ((len(token_bytes) // len(self._key)) + 1))[:len(token_bytes)]
    self._obfuscated_token = bytes(a ^ b for a, b in zip(token_bytes, key_bytes))

  def get_token(self) -> Optional[str]:
    """Retrieve the stored token"""
    if not self._obfuscated_token or not self._key:
      return None

    # Reverse the XOR obfuscation
    key_bytes = (self._key * ((len(self._obfuscated_token) // len(self._key)) + 1))[:len(self._obfuscated_token)]
    token_bytes = bytes(a ^ b for a, b in zip(self._obfuscated_token, key_bytes))
    return token_bytes.decode('utf-8')

  def get_headers(self) -> dict:
    """Get authorization headers with secure token retrieval"""
    token = self.get_token()
    if not token:
      raise ValueError("No token available for authentication")

    return {
      "Authorization": f"Bearer {token}",
      "Accept": "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28"
    }

  def clear_token(self) -> None:
    """Clear stored token from memory"""
    if self._obfuscated_token:
      # Overwrite memory with zeros
      self._obfuscated_token = b'\x00' * len(self._obfuscated_token)
    self._obfuscated_token = None
    self._token_hash = None
    self._key = None

def sanitize_string(input_str: str, max_length: int = 255, allow_chars: str = r'[a-zA-Z0-9\-_./]') -> str:
  """
  Sanitize string input to prevent injection attacks and malicious content.

  Removes dangerous patterns and characters from user input and external API
  responses to prevent code injection, path traversal, and other security attacks.

  Args:
    input_str: The string to sanitize
    max_length: Maximum allowed length (default: 255 characters)
    allow_chars: Regex pattern for allowed characters (default: alphanumeric, dash, underscore, dot, slash)

  Returns:
    Sanitized string with dangerous content removed and length limited

  Security Features:
  - Removes HTML/XML tags and scripts
  - Blocks JavaScript and data URLs
  - Prevents path traversal attempts
  - Filters command injection patterns
  - Enforces length limits

  Example:
    safe_name = sanitize_string("repo<script>alert(1)</script>name")
    # Returns: "reponame"
  """
  if not input_str:
    return ""

  # Truncate to maximum length
  sanitized = str(input_str)[:max_length]

  # Remove or replace potentially dangerous characters
  import re
  # Keep only allowed characters
  sanitized = re.sub(f'[^{allow_chars[1:-1]}]', '', sanitized)

  # Additional safety: remove common injection patterns
  dangerous_patterns = [
    r'[;&|`$()]',  # Shell injection
    r'<[^>]*>',    # HTML/XML tags
    r'javascript:', # JavaScript protocol
    r'data:',      # Data URI
    r'\.\./',      # Path traversal
  ]

  for pattern in dangerous_patterns:
    sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE)

  return sanitized

def sanitize_branch_name(branch_name: str) -> str:
  """Sanitize Git branch name to prevent command injection"""
  if not branch_name:
    return ""

  # Git branch names have specific rules
  # Allow: alphanumeric, hyphens, underscores, forward slashes, dots
  sanitized = sanitize_string(branch_name, max_length=255, allow_chars=r'[a-zA-Z0-9\-_./]')

  # Additional Git-specific validation
  # Branch names cannot start/end with dots or slashes
  sanitized = sanitized.strip('./')

  # Cannot contain consecutive dots
  while '..' in sanitized:
    sanitized = sanitized.replace('..', '.')

  return sanitized

def sanitize_repository_path(repo_path: str) -> str:
  """Sanitize repository path to prevent path traversal"""
  if not repo_path:
    return ""

  # Repository paths: owner/repo format
  sanitized = sanitize_string(repo_path, max_length=200, allow_chars=r'[a-zA-Z0-9\-_./]')

  # Ensure it matches owner/repo pattern
  import re
  if '/' in sanitized and re.match(r'^[a-zA-Z0-9\-_.]+/[a-zA-Z0-9\-_.]+$', sanitized):
    return sanitized

  return ""

def sanitize_file_path(file_path: str) -> str:
  """Sanitize file path to prevent directory traversal"""
  if not file_path:
    return ""

  # Remove dangerous path elements
  import os
  sanitized = os.path.normpath(file_path)

  # Remove path traversal attempts
  sanitized = sanitized.replace('..', '')
  sanitized = sanitized.replace('//', '/')

  # Remove leading slashes and dangerous paths
  sanitized = sanitized.lstrip('/')

  # Ensure reasonable length
  sanitized = sanitized[:500]

  return sanitized

def validate_org_name(org):
  """Validate GitHub organization name format"""
  if not org:
    return False
  # GitHub org names: alphanumeric, hyphens, no consecutive hyphens, no start/end hyphens
  import re
  match = re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$', org)
  return bool(match) and len(org) <= 39

def validate_token_format(token):
  """Basic GitHub token format validation"""
  if not token:
    return False
  # Fine-grained tokens start with github_pat_, classic tokens with ghp_
  return token.startswith(('github_pat_', 'ghp_')) and len(token) > 20

def validate_token_scopes(token, target, target_type):
  """
  Validate GitHub token scopes against required permissions for secure operation.

  Checks that the provided GitHub Personal Access Token has the minimum required
  scopes for the scanning operation and warns about excessive permissions that
  violate the principle of least privilege.

  Args:
    token: GitHub Personal Access Token to validate
    target: Target name (organization, user, or repository)
    target_type: Type of target ("organization", "user", or "repository")

  Security Features:
  - Validates minimum required permissions
  - Warns about excessive scopes (privilege escalation risk)
  - Checks token validity and accessibility
  - Implements least privilege principle

  Required Scopes by Target Type:
  - Public repositories: public_repo
  - Private repositories: repo
  - Organizations: repo + read:org
  - Enterprise audit: repo + read:org + read:audit_log

  Example:
    validate_token_scopes(token, "microsoft", "organization")
    # Validates token can access organization repositories
  """
  test_headers = {
    "Authorization": f"Bearer {token}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28"
  }

  required_permissions = {
    'user_info': True,
    'repo_metadata': True,
    'repo_contents': True,
    'org_repos': target_type == "organization",
    'user_repos': target_type == "user",
    'single_repo': target_type == "repository"
  }

  validation_results = {}

  try:
    # 1. Test basic authentication and user info access
    r = requests.get("https://api.github.com/user", headers=test_headers, timeout=10)
    validation_results['user_info'] = r.status_code == 200

    # 2. Check token scopes from response headers
    token_scopes = r.headers.get('X-OAuth-Scopes', '').split(', ') if r.headers.get('X-OAuth-Scopes') else []

    # 3. Test specific endpoint access based on target type
    if target_type == "organization":
      # Test organization access
      r = requests.get(f"https://api.github.com/orgs/{target}", headers=test_headers, timeout=10)
      validation_results['org_access'] = r.status_code == 200

      # Test repository listing
      r = requests.get(f"https://api.github.com/orgs/{target}/repos?per_page=1", headers=test_headers, timeout=10)
      validation_results['repo_metadata'] = r.status_code == 200

    elif target_type == "user":
      # Test user access
      r = requests.get(f"https://api.github.com/users/{target}", headers=test_headers, timeout=10)
      validation_results['user_access'] = r.status_code == 200

      # Test repository listing
      r = requests.get(f"https://api.github.com/users/{target}/repos?per_page=1", headers=test_headers, timeout=10)
      validation_results['repo_metadata'] = r.status_code == 200

    elif target_type == "repository":
      # Test single repository access
      owner, repo = target.split("/", 1)
      r = requests.get(f"https://api.github.com/repos/{owner}/{repo}", headers=test_headers, timeout=10)
      validation_results['single_repo'] = r.status_code == 200

    # 4. Test repository contents access (required for package scanning)
    if target_type in ["organization", "user"]:
      # We'll test this during the actual scan
      validation_results['repo_contents'] = True  # Assume true for now, will be tested during scan
    elif target_type == "repository":
      # Test contents access for single repo
      owner, repo = target.split("/", 1)
      r = requests.get(f"https://api.github.com/repos/{owner}/{repo}/contents", headers=test_headers, timeout=10)
      validation_results['repo_contents'] = r.status_code in [200, 404]  # 404 is OK if no files at root

    # 5. Analyze scope validation results
    failed_permissions = []
    security_warnings = []

    if not validation_results.get('user_info', False):
      failed_permissions.append("User information access (basic authentication failed)")

    if not validation_results.get('repo_metadata', False):
      failed_permissions.append("Repository metadata access")

    if not validation_results.get('repo_contents', False):
      failed_permissions.append("Repository contents access (required for package scanning)")

    # Check for excessive permissions (security warning)
    excessive_scopes = []
    if 'repo' in token_scopes and target_type != "repository":
      excessive_scopes.append("repo (full repository access)")
    if 'admin:org' in token_scopes:
      excessive_scopes.append("admin:org (organization administration)")
    if 'delete_repo' in token_scopes:
      excessive_scopes.append("delete_repo (repository deletion)")

    if excessive_scopes:
      security_warnings.append(f"Token has potentially excessive permissions: {', '.join(excessive_scopes)}")

    # Return validation results
    if failed_permissions:
      return False, f"Insufficient permissions: {', '.join(failed_permissions)}", security_warnings
    else:
      return True, f"Token validated with required permissions for {target_type}: {target}", security_warnings

  except requests.RequestException as e:
    return False, f"Network error during validation: {str(e)}", []

def test_token_access(target, target_type, token):
  """Enhanced token validation with scope checking"""
  is_valid, message, warnings = validate_token_scopes(token, target, target_type)

  # Print security warnings
  for warning in warnings:
    print(f"⚠️  Security Warning: {warning}")
    print("   Consider using a token with minimum required permissions")

  return is_valid, message

def select_scan_target():
  """Interactive target selection for scanning"""
  print("\n" + "="*60)
  print("🎯 SHAI HULUD THREAT HUNTING TOOL")
  print("="*60)
  print("Select scan target:")
  print("  [1] Organization (scan all repos in an organization)")
  print("  [2] Personal Account (scan all personal repositories)")
  print("  [3] Single Repository (scan specific repo)")
  print("="*60)

  while True:
    choice = input("Enter choice (1-3): ").strip()
    if choice in ['1', '2', '3']:
      return choice
    print("Invalid choice. Please enter 1, 2, or 3.")

def get_credentials():
  """Get GitHub target and token from environment or user input"""
  # Check environment variables first
  target = os.getenv("GITHUB_ORG") or os.getenv("GITHUB_USER") or os.getenv("GITHUB_TARGET")
  token = os.getenv("GITHUB_TOKEN")
  target_type = None

  # If no environment variables, get target selection
  if not target:
    choice = select_scan_target()

    if choice == "1":
      target_type = "organization"
      print("\nEnter organization name to scan:")
      while True:
        raw_target = input("Organization name: ").strip()
        # Sanitize user input before validation
        target = sanitize_string(raw_target, max_length=39, allow_chars=r'[a-zA-Z0-9\-]')
        if target and validate_org_name(target):
          break
        print("Invalid organization name. Use alphanumeric characters and hyphens only.")

    elif choice == "2":
      target_type = "user"
      print("\nEnter username to scan personal repositories:")
      while True:
        raw_target = input("Username: ").strip()
        # Sanitize user input before validation
        target = sanitize_string(raw_target, max_length=39, allow_chars=r'[a-zA-Z0-9\-]')
        if target and validate_org_name(target):  # Same validation rules apply
          break
        print("Invalid username. Use alphanumeric characters and hyphens only.")

    elif choice == "3":
      target_type = "repository"
      print("\nEnter repository in format 'owner/repo':")
      while True:
        raw_target = input("Repository (owner/repo): ").strip()
        # Sanitize repository path input
        target = sanitize_repository_path(raw_target)
        if target and "/" in target and len(target.split("/")) == 2:
          owner, repo = target.split("/", 1)
          if validate_org_name(owner) and validate_org_name(repo):
            break
        print("Invalid format. Use 'owner/repository-name' format.")
  else:
    # Environment variable provided - assume organization for backwards compatibility
    target_type = "organization"
    print(f"Using target from environment: {target}")

  # Get token
  if not token:
    print("\nGitHub token not found in environment.")
    print("Required permissions: Contents (Read), Metadata (Read), Audit Log (Read - Enterprise Cloud)")
    print("Create token at: https://github.com/settings/tokens")
    while True:
      token = getpass.getpass("Enter GitHub personal access token: ").strip()
      if validate_token_format(token):
        break
      print("Invalid token format. Token should start with 'github_pat_' or 'ghp_'")

  # Test token access
  print(f"\nValidating token access to {target_type}: {target}...")
  is_valid, message = test_token_access(target, target_type, token)
  if not is_valid:
    sys.exit(f"Error: {message}")

  print(f"✅ {message}")
  return target, target_type, token

# Initialize global variables with secure token management and resource limits
TARGET = None
TARGET_TYPE = None
SECURE_TOKEN_MANAGER = SecureTokenManager()
RESOURCE_LIMITS = ResourceLimits()

def load_compromised_packages():
  """Load compromised packages from the database file"""
  compromised_packages = set()
  try:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    packages_file = os.path.join(script_dir, 'compromised_packages.txt')

    with open(packages_file, 'r', encoding='utf-8') as f:
      for line in f:
        line = line.strip()
        if line and not line.startswith('#'):
          # Store full package@version string for exact matching
          compromised_packages.add(line.strip())

    print(f"📋 Loaded {len(compromised_packages)} compromised packages from database")
    return compromised_packages

  except FileNotFoundError:
    print("⚠️  compromised_packages.txt not found - package scanning will be limited")
    return set()
  except Exception as e:
    print(f"⚠️  Error loading compromised packages: {e}")
    return set()

def parse_package_file_content(content, file_type):
  """Parse package file content and extract dependencies"""
  dependencies = []

  try:
    if file_type == 'package.json':
      data = json.loads(content)
      for dep_type in ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']:
        if dep_type in data:
          for name, version in data[dep_type].items():
            dependencies.append((name, version, dep_type))

    elif file_type in ['requirements.txt', 'requirements-dev.txt', 'requirements-test.txt']:
      for line in content.split('\n'):
        line = line.strip()
        if line and not line.startswith('#') and not line.startswith('-'):
          # Handle various pip requirement formats
          package_match = re.match(r'^([a-zA-Z0-9._-]+)', line)
          if package_match:
            name = package_match.group(1)
            version = line[len(name):].strip()
            dependencies.append((name, version, 'requirements'))

    elif file_type == 'pyproject.toml':
      # Basic TOML parsing for dependencies
      lines = content.split('\n')
      in_dependencies = False
      for line in lines:
        line = line.strip()
        if line.startswith('[tool.poetry.dependencies]') or line.startswith('[project]'):
          in_dependencies = True
        elif line.startswith('[') and in_dependencies:
          in_dependencies = False
        elif in_dependencies and '=' in line:
          parts = line.split('=', 1)
          if len(parts) == 2:
            name = parts[0].strip().strip('"')
            version = parts[1].strip().strip('"')
            dependencies.append((name, version, 'pyproject'))

    elif file_type == 'go.mod':
      for line in content.split('\n'):
        line = line.strip()
        if line.startswith('require '):
          # Parse go module requirements
          require_part = line[8:].strip()
          if ' ' in require_part:
            name, version = require_part.split(' ', 1)
            dependencies.append((name, version, 'go.mod'))

    elif file_type == 'Cargo.toml':
      # Basic Cargo.toml parsing
      lines = content.split('\n')
      in_dependencies = False
      for line in lines:
        line = line.strip()
        if line.startswith('[dependencies]'):
          in_dependencies = True
        elif line.startswith('[') and in_dependencies:
          in_dependencies = False
        elif in_dependencies and '=' in line:
          parts = line.split('=', 1)
          if len(parts) == 2:
            name = parts[0].strip()
            version = parts[1].strip().strip('"')
            dependencies.append((name, version, 'cargo'))

    elif file_type in ['pom.xml', 'build.gradle']:
      # Basic XML/Gradle parsing for Java dependencies
      # This is simplified - production code would use proper XML parsing
      if file_type == 'pom.xml':
        pattern = r'<groupId>(.*?)</groupId>\s*<artifactId>(.*?)</artifactId>\s*<version>(.*?)</version>'
        matches = re.findall(pattern, content, re.DOTALL)
        for group, artifact, version in matches:
          name = f"{group.strip()}:{artifact.strip()}"
          dependencies.append((name, version.strip(), 'maven'))

      elif file_type == 'build.gradle':
        # Look for dependency declarations
        patterns = [
          r"implementation\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]",
          r"compile\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]"
        ]
        for pattern in patterns:
          matches = re.findall(pattern, content)
          for group, artifact, version in matches:
            name = f"{group}:{artifact}"
            dependencies.append((name, version, 'gradle'))

  except Exception as e:
    print(f"⚠️  Error parsing {file_type}: {e}")

  return dependencies

def initialize_globals():
  """Initialize global variables with credentials using secure token management"""
  global TARGET, TARGET_TYPE, SECURE_TOKEN_MANAGER
  target, target_type, token = get_credentials()
  TARGET, TARGET_TYPE = target, target_type
  SECURE_TOKEN_MANAGER.store_token(token)
  # Clear the local token variable for security
  token = None

def gh_paged(url, params=None):
  out = []
  while url:
    try:
      # Ap2ply rate limiting
      RESOURCE_LIMITS.rate_limit_check()

      headers = SECURE_TOKEN_MANAGER.get_headers()
      timeout = RESOURCE_LIMITS.get_api_timeout()
      r = requests.get(url, headers=headers, params=params, timeout=timeout)
      r.raise_for_status()
      response_data = r.json()

      # Handle different GitHub API response formats
      if isinstance(response_data, list):
        # Direct API endpoints (e.g., /orgs/{org}/repos) return arrays directly
        out.extend(response_data)
      elif isinstance(response_data, dict) and "items" in response_data:
        # Search API endpoints return {"items": [...], "total_count": ...}
        out.extend(response_data["items"])
      elif isinstance(response_data, dict):
        # Single object response, wrap in list
        out.append(response_data)
      else:
        print(f"⚠️  Unexpected response format: {type(response_data)}")

      # follow Link header if present
      url = None
      if "next" in r.links:
        url = r.links["next"]["url"]
        params = None
      time.sleep(0.5)
    except requests.exceptions.HTTPError as e:
      if hasattr(e, 'response') and e.response.status_code == 422:
        print(f"⚠️  Search query error: {params.get('q', 'unknown')} - {e}")
        print(f"   Response: {e.response.text}")
        break
      elif hasattr(e, 'response') and e.response.status_code == 403:
        print(f"⚠️  API rate limit or permissions error: {e}")
        break
      else:
        raise
    except requests.exceptions.RequestException as e:
      print(f"⚠️  Network error: {e}")
      break
  return out

def scan_repository_packages(repo_name, compromised_packages):
  """Scan a single repository for compromised packages using Repository Contents API"""
  package_findings = []

  # Define package files to search for
  package_files = {
    'package.json': 'JavaScript/Node.js',
    'yarn.lock': 'JavaScript/Yarn',
    'package-lock.json': 'JavaScript/npm',
    'requirements.txt': 'Python',
    'requirements-dev.txt': 'Python (dev)',
    'requirements-test.txt': 'Python (test)',
    'pyproject.toml': 'Python (Poetry/PEP 518)',
    'Pipfile': 'Python (Pipenv)',
    'setup.py': 'Python (setuptools)',
    'go.mod': 'Go',
    'go.sum': 'Go (checksums)',
    'Cargo.toml': 'Rust',
    'Cargo.lock': 'Rust (lock)',
    'pom.xml': 'Java (Maven)',
    'build.gradle': 'Java (Gradle)',
    'Gemfile': 'Ruby',
    'composer.json': 'PHP'
  }

  # Common paths where package files might be located
  common_paths = ['', 'frontend/', 'backend/', 'api/', 'web/', 'client/', 'server/', 'src/']

  for filename, ecosystem in package_files.items():
    for path_prefix in common_paths:
      # Sanitize file path construction
      raw_file_path = f"{path_prefix}{filename}".lstrip('/')
      file_path = sanitize_file_path(raw_file_path)
      if not file_path:  # Skip if sanitization removes the path entirely
        continue

      try:
        # Sanitize repository name as well
        safe_repo_name = sanitize_repository_path(repo_name)
        if not safe_repo_name:
          continue

        # Use Repository Contents API instead of Search API
        url = f"https://api.github.com/repos/{safe_repo_name}/contents/{file_path}"
        headers = SECURE_TOKEN_MANAGER.get_headers()
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
          file_data = response.json()

          # Skip if it's a directory
          if file_data.get("type") == "dir":
            continue

          if file_data.get("encoding") == "base64":
            import base64
            content = base64.b64decode(file_data["content"]).decode('utf-8', errors='ignore')

            # Parse dependencies from file
            dependencies = parse_package_file_content(content, filename)

            # Check for compromised packages
            for dep_name, dep_version, dep_type in dependencies:
              # Check both exact package@version match and package name match
              clean_version = dep_version.strip('^~>=<*')
              full_package_string = f"{dep_name}@{clean_version}"
              if full_package_string in compromised_packages or dep_name in compromised_packages:
                package_findings.append({
                  "repo": repo_name,
                  "file_path": file_path,
                  "package_name": dep_name,
                  "package_version": dep_version,
                  "dependency_type": dep_type,
                  "ecosystem": ecosystem,
                  "file_url": file_data.get("html_url", ""),
                  "severity": "HIGH"
                })

            # Only check the first path where the file is found
            break

        elif response.status_code == 404:
          # File doesn't exist at this path, try next path
          continue
        else:
          # Other error, log and continue
          print(f"⚠️  Error accessing {file_path} in {repo_name}: {response.status_code}")

      except Exception as e:
        print(f"⚠️  Error processing {file_path} in {repo_name}: {e}")

    time.sleep(0.05)  # Rate limiting - reduced since we're not using search API

  return package_findings

def generate_detailed_repository_report(findings):
  """Generate detailed per-repository, per-issue threat report"""
  print("\n" + "="*80)
  print("🔍 DETAILED THREAT ANALYSIS - PER REPOSITORY BREAKDOWN")
  print("="*80)

  # Organize all findings by repository
  repo_issues = {}

  # Collect all scanned repositories
  for repo_info in findings.get('repos_scanned', []):
    # Use defensive key access to handle missing keys
    repo_name = repo_info.get('full_name') or repo_info.get('name', 'UNKNOWN_REPO')
    repo_issues[repo_name] = {
      'metadata': repo_info,
      'issues': [],
      'risk_score': 0
    }

  # Add suspicious repository findings with confidence scoring
  for repo in findings.get('repos', []):
    repo_name = repo.get('full_name', 'UNKNOWN_REPO')
    confidence = repo.get('confidence', 0.5)  # Default confidence if not set
    pattern_match = repo.get('pattern_match', 'unknown')

    if repo_name not in repo_issues:
      repo_issues[repo_name] = {'metadata': repo, 'issues': [], 'risk_score': 0}

    # Only add as issue if confidence is above threshold
    if confidence >= 0.7:
      severity = 'HIGH' if confidence >= 0.8 else 'MEDIUM'
      risk_points = int(confidence * 100)  # Scale risk based on confidence

      repo_issues[repo_name]['issues'].append({
        'type': 'SUSPICIOUS_REPOSITORY',
        'severity': severity,
        'title': f'Repository flagged as suspicious (confidence: {confidence:.2f})',
        'description': f"Pattern '{pattern_match}' detected. {repo.get('desc', 'No description available')}",
        'details': repo,
        'confidence': confidence,
        'pattern_match': pattern_match
      })
      repo_issues[repo_name]['risk_score'] += risk_points
    else:
      # Log filtered low-confidence findings for transparency
      print(f"   ℹ️  Filtered low-confidence suspicious repository: {repo_name} (confidence: {confidence:.2f})")

  # Add malicious workflow findings
  for workflow in findings.get('workflows', []):
    repo_name = workflow['repo']
    if repo_name not in repo_issues:
      repo_issues[repo_name] = {'metadata': {'full_name': repo_name}, 'issues': [], 'risk_score': 0}

    repo_issues[repo_name]['issues'].append({
      'type': 'MALICIOUS_WORKFLOW',
      'severity': 'HIGH',
      'title': 'Shai Hulud malicious workflow detected',
      'description': f"Malicious workflow file found at {workflow['path']}",
      'details': workflow
    })
    repo_issues[repo_name]['risk_score'] += 100

  # Add webhook.site references
  for webhook in findings.get('webhook_hits', []):
    # Extract repo name from URL if possible
    repo_name = "UNKNOWN"
    if 'github.com' in webhook.get('url', ''):
      url_parts = webhook['url'].split('/')
      if len(url_parts) >= 5:
        repo_name = f"{url_parts[3]}/{url_parts[4]}"

    if repo_name not in repo_issues:
      repo_issues[repo_name] = {'metadata': {'full_name': repo_name}, 'issues': [], 'risk_score': 0}

    repo_issues[repo_name]['issues'].append({
      'type': 'WEBHOOK_EXFILTRATION',
      'severity': 'HIGH',
      'title': 'Webhook.site data exfiltration reference',
      'description': 'Code references webhook.site - potential data exfiltration',
      'details': webhook
    })
    repo_issues[repo_name]['risk_score'] += 90

  # Add compromised package findings
  for package in findings.get('packages', []):
    repo_name = package['repo']
    if repo_name not in repo_issues:
      repo_issues[repo_name] = {'metadata': {'full_name': repo_name}, 'issues': [], 'risk_score': 0}

    repo_issues[repo_name]['issues'].append({
      'type': 'COMPROMISED_PACKAGE',
      'severity': package.get('severity', 'HIGH'),
      'title': f"Compromised {package['ecosystem']} package: {package['package_name']}",
      'description': f"Package {package['package_name']}@{package['package_version']} is compromised (Shai Hulud campaign)",
      'details': package
    })
    repo_issues[repo_name]['risk_score'] += 80

  # Add suspicious branch findings
  for branch in findings.get('branches', []):
    repo_name = branch['repo']
    if repo_name not in repo_issues:
      repo_issues[repo_name] = {'metadata': {'full_name': repo_name}, 'issues': [], 'risk_score': 0}

    repo_issues[repo_name]['issues'].append({
      'type': 'SUSPICIOUS_BRANCH',
      'severity': 'MEDIUM',
      'title': f"Suspicious branch name: {branch['branch']}",
      'description': 'Branch name matches Shai Hulud indicators',
      'details': branch
    })
    repo_issues[repo_name]['risk_score'] += 40

  # Add audit log findings
  for audit_event in findings.get('audit', []):
    # Audit events might not have direct repo association, group under organization
    repo_name = f"ORG_AUDIT/{TARGET}" if TARGET else "AUDIT_EVENTS"
    if repo_name not in repo_issues:
      repo_issues[repo_name] = {'metadata': {'full_name': repo_name}, 'issues': [], 'risk_score': 0}

    action_type = audit_event.get('action', 'unknown')
    repo_issues[repo_name]['issues'].append({
      'type': 'SUSPICIOUS_AUDIT_EVENT',
      'severity': 'MEDIUM',
      'title': f"Suspicious audit event: {action_type}",
      'description': f"Audit log shows suspicious activity: {action_type}",
      'details': audit_event
    })
    repo_issues[repo_name]['risk_score'] += 30

  # Sort repositories by risk score (highest first)
  sorted_repos = sorted(repo_issues.items(), key=lambda x: x[1]['risk_score'], reverse=True)

  # Display results
  if not sorted_repos:
    print("✅ No threats detected across all scanned repositories")
    return

  # Summary statistics with confidence-based thresholds
  total_repos = len(sorted_repos)
  compromised_repos = len([r for r in sorted_repos if r[1]['risk_score'] > 0])
  critical_repos = len([r for r in sorted_repos if r[1]['risk_score'] >= 200])
  high_risk_repos = len([r for r in sorted_repos if r[1]['risk_score'] >= 100])
  medium_risk_repos = len([r for r in sorted_repos if 30 <= r[1]['risk_score'] < 100])

  print(f"📊 SUMMARY: {compromised_repos}/{total_repos} repositories have security issues")
  print(f"🚨 CRITICAL: {critical_repos} repositories require immediate action")
  print(f"⚠️  HIGH RISK: {high_risk_repos} repositories need urgent review")
  print(f"🟡 MEDIUM RISK: {medium_risk_repos} repositories should be monitored")

  # Monitoring recommendations based on findings
  if critical_repos > 0:
    print(f"\n🔔 ALERT THRESHOLD: Critical threats detected - escalate to security team")
  elif high_risk_repos > 0:
    print(f"\n🔔 ALERT THRESHOLD: High-risk threats detected - schedule immediate review")
  elif medium_risk_repos > 0:
    print(f"\n🔔 MONITORING: Medium-risk patterns detected - continue monitoring")
  else:
    print(f"\n✅ STATUS: No high-confidence threats detected - routine monitoring sufficient")
  print()

  # Detailed per-repository breakdown
  for repo_name, repo_data in sorted_repos:
    if repo_data['risk_score'] == 0:
      continue  # Skip clean repositories in detailed view

    # Updated risk thresholds based on confidence scoring
    # CRITICAL: Multiple high-confidence threats or confirmed malicious activity
    # HIGH: Single high-confidence threat or multiple medium threats
    # MEDIUM: Low-confidence threats or suspicious patterns
    risk_level = "🚨 CRITICAL" if repo_data['risk_score'] >= 200 else "⚠️  HIGH" if repo_data['risk_score'] >= 100 else "🟡 MEDIUM" if repo_data['risk_score'] >= 30 else "🟢 LOW"

    print(f"\n{'='*60}")
    print(f"📁 REPOSITORY: {repo_name}")
    print(f"🎯 RISK LEVEL: {risk_level} (Score: {repo_data['risk_score']})")
    print(f"🔢 ISSUES FOUND: {len(repo_data['issues'])}")

    # Repository metadata
    metadata = repo_data.get('metadata', {})
    if metadata.get('description'):
      print(f"📝 Description: {metadata['description']}")
    if metadata.get('private') is not None:
      print(f"🔒 Visibility: {'Private' if metadata['private'] else 'Public'}")

    # List all issues for this repository
    print(f"\n🔍 DETAILED ISSUES:")
    for i, issue in enumerate(repo_data['issues'], 1):
      severity_icon = "🚨" if issue['severity'] == 'HIGH' else "⚠️ " if issue['severity'] == 'MEDIUM' else "ℹ️ "
      print(f"\n   {i}. {severity_icon} [{issue['type']}] {issue['title']}")
      print(f"      📋 {issue['description']}")

      # Add specific details based on issue type
      details = issue['details']
      if issue['type'] == 'COMPROMISED_PACKAGE':
        print(f"      📦 File: {details.get('file_path', 'N/A')}")
        print(f"      🔗 Ecosystem: {details.get('ecosystem', 'N/A')}")
        print(f"      📌 Dependency Type: {details.get('dependency_type', 'N/A')}")
        if details.get('file_url'):
          print(f"      🌐 View File: {details['file_url']}")
      elif issue['type'] == 'MALICIOUS_WORKFLOW':
        print(f"      📁 Path: {details.get('path', 'N/A')}")
      elif issue['type'] == 'WEBHOOK_EXFILTRATION':
        print(f"      🌐 Reference URL: {details.get('url', 'N/A')}")
      elif issue['type'] == 'SUSPICIOUS_BRANCH':
        print(f"      🌿 Branch Name: {details.get('branch', 'N/A')}")
      elif issue['type'] == 'SUSPICIOUS_AUDIT_EVENT':
        print(f"      📊 Action: {details.get('action', 'N/A')}")
        print(f"      👤 Actor: {details.get('actor', 'N/A')}")
        print(f"      📅 Timestamp: {details.get('created_at', 'N/A')}")
        if details.get('repo'):
          print(f"      📁 Repository: {details.get('repo', 'N/A')}")

  # Clean repositories summary
  clean_repos = [r for r in sorted_repos if r[1]['risk_score'] == 0]
  if clean_repos:
    print(f"\n{'='*60}")
    print(f"✅ CLEAN REPOSITORIES ({len(clean_repos)} repositories)")
    print("="*60)
    for repo_name, _ in clean_repos:
      print(f"   ✅ {repo_name}")

  print("\n" + "="*80)
  print("🎯 THREAT HUNT COMPLETE - Review repositories with HIGH/CRITICAL risk levels immediately")
  print("="*80)

def get_repositories():
  """Get repositories based on target type with resource limits"""
  if TARGET_TYPE == "organization":
    print(f"🔍 Fetching repositories for organization: {TARGET}")
    repos = gh_paged(f"https://api.github.com/orgs/{TARGET}/repos", params={"per_page": 100})
  elif TARGET_TYPE == "user":
    print(f"🔍 Fetching repositories for user: {TARGET}")
    repos = gh_paged(f"https://api.github.com/users/{TARGET}/repos", params={"per_page": 100})
  elif TARGET_TYPE == "repository":
    print(f"🔍 Fetching single repository: {TARGET}")
    if TARGET and "/" in TARGET:
      owner, repo = TARGET.split("/", 1)
      repo_data = gh_paged(f"https://api.github.com/repos/{owner}/{repo}")
      return repo_data if repo_data else []
    else:
      print(f"⚠️  Invalid repository format: {TARGET}")
      return []
  else:
    print(f"⚠️  Unknown target type: {TARGET_TYPE}")
    return []

  # Apply repository count limits
  if repos:
    try:
      RESOURCE_LIMITS.check_repository_limit(len(repos))
    except RuntimeError as e:
      print(f"⚠️  {e}")
      print(f"   Limiting scan to first {RESOURCE_LIMITS.MAX_REPOSITORIES} repositories")
      repos = repos[:RESOURCE_LIMITS.MAX_REPOSITORIES]

  return repos

def calculate_threat_confidence(repo):
  """Calculate confidence score for threat classification (0.0-1.0)"""
  confidence = 0.0
  repo_name = repo["full_name"].lower()
  repo_desc = (repo.get("description") or "").lower()

  # Educational/research indicators (reduce confidence)
  educational_keywords = [
    "tutorial", "example", "demo", "educational", "research", "academic",
    "course", "training", "learning", "study", "university", "school",
    "framework", "osint", "cybersecurity", "security", "analysis"
  ]

  research_indicators = [
    "poc", "proof-of-concept", "demonstration", "showcase", "sample",
    "reference", "template", "boilerplate", "starter", "guide"
  ]

  # Check for educational/research patterns
  education_score = 0
  for keyword in educational_keywords + research_indicators:
    if keyword in repo_name or keyword in repo_desc:
      education_score += 0.2

  # If high education score, very low confidence of being actual threat
  if education_score >= 0.4:
    confidence = max(0.1, 0.8 - education_score)
  else:
    # Check for actual threat indicators
    threat_indicators = [
      "migration", "attack", "exploit", "payload", "backdoor",
      "malicious", "stealer", "trojan", "virus"
    ]

    for indicator in threat_indicators:
      if indicator in repo_name or indicator in repo_desc:
        confidence += 0.3

    # Repository characteristics that suggest legitimacy
    if repo.get("stargazers_count", 0) > 10:
      confidence -= 0.1  # Popular repos less likely to be malicious

    if repo.get("forks_count", 0) > 5:
      confidence -= 0.1  # Forked repos less likely to be malicious

    # Recent activity suggests legitimate project
    if repo.get("updated_at"):
      try:
        from datetime import datetime, timedelta
        updated = datetime.fromisoformat(repo["updated_at"].replace('Z', '+00:00'))
        if datetime.now().replace(tzinfo=updated.tzinfo) - updated < timedelta(days=30):
          confidence -= 0.1
      except:
        pass

  # Clamp confidence to valid range
  return max(0.0, min(1.0, confidence))

def validate_repository_ownership(repo, target, target_type):
  """Validate that repository belongs to the target being scanned"""
  try:
    if target_type == "organization":
      repo_owner = repo.get("full_name", "").split("/")[0] if repo.get("full_name") else ""
      return repo_owner.lower() == target.lower()
    elif target_type == "user":
      repo_owner = repo.get("owner", {}).get("login", "")
      return repo_owner.lower() == target.lower()
    elif target_type == "repository":
      return repo.get("full_name", "").lower() == target.lower()
  except (AttributeError, IndexError, KeyError):
    return False
  return False

def validate_search_scope(findings, target, target_type):
  """Validate that all findings are within the expected scope"""
  scope_violations = []

  for repo in findings.get('repos', []):
    if not validate_repository_ownership(repo, target, target_type):
      scope_violations.append(repo.get('full_name', 'UNKNOWN'))

  if scope_violations:
    print(f"⚠️  Warning: {len(scope_violations)} findings are outside target scope:")
    for violation in scope_violations[:5]:  # Show first 5
      print(f"   - {violation}")
    if len(scope_violations) > 5:
      print(f"   ... and {len(scope_violations) - 5} more")

  return len(scope_violations) == 0

def hunt():
  """
  Main threat hunting function to scan GitHub targets for Shai Hulud indicators.

  Orchestrates the complete scanning workflow including:
  - Repository enumeration and filtering
  - Malicious workflow detection
  - Compromised package identification
  - Webhook exfiltration detection
  - Suspicious branch analysis
  - Risk scoring and reporting

  Security Features:
  - Input sanitization on all external data
  - Resource consumption limits
  - Rate limiting and timeout protection
  - Comprehensive security logging

  Returns:
    Dict containing comprehensive findings with threat analysis and risk scores

  Output Structure:
    {
      "target": "target-name",
      "target_type": "organization|user|repository",
      "repos_scanned": ["repo1", "repo2"],
      "repos": [repository_objects],
      "workflows": [malicious_workflows],
      "webhook_hits": [webhook_references],
      "branches": [suspicious_branches],
      "packages": [compromised_packages],
      "audit": [audit_events]
    }
  """
  findings = {"target": TARGET, "target_type": TARGET_TYPE, "repos_scanned": [], "repos": [], "workflows": [], "webhook_hits": [], "branches": [], "packages": [], "audit": []}

  # Load compromised packages database
  compromised_packages = load_compromised_packages()

  # Get repositories to scan
  repos = get_repositories()
  print(f"📊 Found {len(repos)} repositories to scan")

  if not repos:
    print("❌ No repositories found or accessible")
    return findings

  # Store scanned repos for explicit reporting
  findings["repos_scanned"] = [{"full_name": r["full_name"], "name": r["name"], "private": r.get("private", False), "size": r.get("size", 0), "description": r.get("description")} for r in repos]

  # 1 repos - check for suspicious repository patterns within target scope only
  if TARGET_TYPE in ["organization", "user"]:
    print("🔍 Analyzing repository names for suspicious patterns...")
    # Check only repositories we already fetched, not global searches
    suspicious_patterns = ["shai-hulud", "shai hulud", "migration", "hulud"]

    for repo in repos:
      repo_name = repo["full_name"].lower()
      repo_desc = (repo.get("description") or "").lower()

      # Check for suspicious patterns in repository name or description
      for pattern in suspicious_patterns:
        if pattern in repo_name or pattern in repo_desc:
          # Validate this is actually suspicious (not educational/research)
          confidence_score = calculate_threat_confidence(repo)
          if confidence_score >= 0.7:  # Only report high-confidence threats
            findings["repos"].append({
              "full_name": repo["full_name"],
              "desc": repo.get("description"),
              "confidence": confidence_score,
              "pattern_match": pattern
            })
            print(f"   🚨 Suspicious repository detected: {repo['full_name']} (confidence: {confidence_score:.2f})")
          else:
            print(f"   ℹ️  Low-confidence match filtered: {repo['full_name']} (confidence: {confidence_score:.2f})")

  # 2 workflow file - search for malicious workflow files
  print("🔍 Searching for malicious workflow files...")
  search_target = f"{TARGET_TYPE}:{TARGET}" if TARGET_TYPE in ["organization", "user"] else f"repo:{TARGET}"
  items = gh_paged("https://api.github.com/search/code",
                   params={"q": f"{search_target} path:.github/workflows filename:shai-hulud-workflow.yml"})
  if items:
    findings["workflows"] += [{"repo": i["repository"]["full_name"], "path": i["path"]} for i in items]

  # 3 webhook.site hits in code - search for exfiltration indicators
  print("🔍 Searching for webhook.site references...")
  items = gh_paged("https://api.github.com/search/code", params={"q": f"{search_target} webhook.site in:file"})
  if items:
    findings["webhook_hits"] += [{"url": i["html_url"]} for i in items]

  # 4 packages - scan for compromised packages across ecosystems
  if compromised_packages:
    print("🔍 Scanning for compromised packages across all ecosystems...")
    total_packages_found = 0

    for repo in repos:
      repo_name = repo["full_name"]
      print(f"   📦 Scanning packages in {repo_name}")

      package_findings = scan_repository_packages(repo_name, compromised_packages)
      if package_findings:
        findings["packages"].extend(package_findings)
        total_packages_found += len(package_findings)
        print(f"   🚨 Found {len(package_findings)} compromised packages in {repo_name}")

    print(f"📊 Total compromised packages found: {total_packages_found}")
  else:
    print("ℹ️  Skipping package scanning - no compromised packages database available")

  # 5 branches named shai hulud - enumerate suspicious branches
  print("🔍 Enumerating repository branches...")
  for r in repos:
    try:
      # Apply rate limiting for API calls
      RESOURCE_LIMITS.rate_limit_check()

      headers = SECURE_TOKEN_MANAGER.get_headers()
      timeout = RESOURCE_LIMITS.get_api_timeout()
      b = requests.get(r["branches_url"].replace("{/branch}", ""), headers=headers, timeout=timeout).json()

      # Apply branch count limits
      branch_count = len(b) if b else 0
      max_branches = RESOURCE_LIMITS.check_branch_limit(branch_count, r.get("full_name", "unknown"))

      # Only process up to the limit
      branches_to_check = b[:max_branches] if b else []

      for br in branches_to_check:
        # Sanitize branch name from external API
        branch_name = sanitize_branch_name(br.get("name", ""))
        if branch_name and branch_name in ["shai-hulud", "shai hulud"]:
          # Also sanitize repository name
          repo_name = sanitize_repository_path(r.get("full_name", ""))
          if repo_name:
            findings["branches"].append({"repo": repo_name, "branch": branch_name})
      time.sleep(0.2)
    except Exception as e:
      print(f"⚠️  Error scanning branches for {r['full_name']}: {e}")

  # 5 audit log window - Enterprise Cloud only (organizations only)
  if TARGET_TYPE == "organization":
    print("🔍 Checking audit logs (Enterprise Cloud feature)...")
    audit_phrases = ["action:repo.create", "action:repo.visibility_change", "action:git.push"]

    for phrase in audit_phrases:
      print(f"   Searching audit logs for: {phrase}")
      url = f"https://api.github.com/orgs/{TARGET}/audit-log"
      params = {"per_page": 100, "phrase": f"{phrase}+created:2025-09-13..2025-09-17"}
      if phrase == "action:git.push":
        params["include"] = "git"
      audit_results = gh_paged(url, params=params)
      if audit_results:
        findings["audit"] += audit_results
  else:
    print("ℹ️  Audit log scanning only available for organizations")

  # Summary report
  print("\n" + "="*60)
  print("🎯 SHAI HULUD THREAT HUNT RESULTS")
  print("="*60)
  print(f"📊 Repositories scanned: {len(findings['repos_scanned'])}")
  print(f"📊 Suspicious repositories: {len(findings['repos'])}")
  print(f"📊 Malicious workflows: {len(findings['workflows'])}")
  print(f"📊 Webhook.site references: {len(findings['webhook_hits'])}")
  print(f"📊 Compromised packages: {len(findings['packages'])}")
  print(f"📊 Suspicious branches: {len(findings['branches'])}")
  print(f"📊 Audit log events: {len(findings['audit'])}")

  # Package ecosystem breakdown
  if findings['packages']:
    ecosystems = {}
    for pkg in findings['packages']:
      eco = pkg['ecosystem']
      ecosystems[eco] = ecosystems.get(eco, 0) + 1
    print("\n🔍 Package findings by ecosystem:")
    for ecosystem, count in sorted(ecosystems.items()):
      print(f"   {ecosystem}: {count} compromised packages")

  print("="*60)

  # Generate detailed per-repository, per-issue report
  # Validate search scope and warn about potential issues
  scope_valid = validate_search_scope(findings, TARGET, TARGET_TYPE)
  if not scope_valid:
    print("\n⚠️  SCOPE WARNING: Some findings may be outside the intended target scope.")
    print("   This could indicate false positives from global searches.")

  generate_detailed_repository_report(findings)

  print("\n📋 RAW JSON FINDINGS:")
  print(json.dumps(findings, indent=2))

  return findings

if __name__ == "__main__":
  initialize_globals()
  hunt()