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

def test_token_access(target, target_type, token):
  """Test if token has basic access to the target (organization or user)"""
  test_headers = {
    "Authorization": f"Bearer {token}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28"
  }

  try:
    # Test basic auth
    r = requests.get("https://api.github.com/user", headers=test_headers, timeout=10)
    if r.status_code != 200:
      return False, f"Token authentication failed: {r.status_code}"

    # Test target access based on type
    if target_type == "organization":
      r = requests.get(f"https://api.github.com/orgs/{target}", headers=test_headers, timeout=10)
      if r.status_code == 404:
        return False, f"Organization '{target}' not found or no access"
      elif r.status_code != 200:
        return False, f"Organization access failed: {r.status_code}"
    elif target_type == "user":
      r = requests.get(f"https://api.github.com/users/{target}", headers=test_headers, timeout=10)
      if r.status_code == 404:
        return False, f"User '{target}' not found or no access"
      elif r.status_code != 200:
        return False, f"User access failed: {r.status_code}"

    return True, f"Token validated successfully for {target_type}: {target}"
  except requests.RequestException as e:
    return False, f"Network error: {str(e)}"

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
        target = input("Organization name: ").strip()
        if validate_org_name(target):
          break
        print("Invalid organization name. Use alphanumeric characters and hyphens only.")

    elif choice == "2":
      target_type = "user"
      print("\nEnter username to scan personal repositories:")
      while True:
        target = input("Username: ").strip()
        if validate_org_name(target):  # Same validation rules apply
          break
        print("Invalid username. Use alphanumeric characters and hyphens only.")

    elif choice == "3":
      target_type = "repository"
      print("\nEnter repository in format 'owner/repo':")
      while True:
        target = input("Repository (owner/repo): ").strip()
        if "/" in target and len(target.split("/")) == 2:
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

# Initialize global variables
TARGET = None
TARGET_TYPE = None
TOKEN = None
HEADERS = None

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
  """Initialize global variables with credentials"""
  global TARGET, TARGET_TYPE, TOKEN, HEADERS
  TARGET, TARGET_TYPE, TOKEN = get_credentials()
  HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28"
  }

def gh_paged(url, params=None):
  out = []
  while url:
    try:
      r = requests.get(url, headers=HEADERS, params=params, timeout=10)
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
      file_path = f"{path_prefix}{filename}".lstrip('/')
      try:
        # Use Repository Contents API instead of Search API
        url = f"https://api.github.com/repos/{repo_name}/contents/{file_path}"
        response = requests.get(url, headers=HEADERS, timeout=10)

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
  """Get repositories based on target type"""
  if TARGET_TYPE == "organization":
    print(f"🔍 Fetching repositories for organization: {TARGET}")
    return gh_paged(f"https://api.github.com/orgs/{TARGET}/repos", params={"per_page": 100})
  elif TARGET_TYPE == "user":
    print(f"🔍 Fetching repositories for user: {TARGET}")
    return gh_paged(f"https://api.github.com/users/{TARGET}/repos", params={"per_page": 100})
  elif TARGET_TYPE == "repository":
    print(f"🔍 Fetching single repository: {TARGET}")
    owner, repo = TARGET.split("/", 1)
    repo_data = gh_paged(f"https://api.github.com/repos/{owner}/{repo}")
    return repo_data if repo_data else []
  else:
    print(f"⚠️  Unknown target type: {TARGET_TYPE}")
    return []

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
      b = requests.get(r["branches_url"].replace("{/branch}", ""), headers=HEADERS, timeout=10).json()
      for br in b:
        if br["name"] in ["shai-hulud", "shai hulud"]:
          findings["branches"].append({"repo": r["full_name"], "branch": br["name"]})
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