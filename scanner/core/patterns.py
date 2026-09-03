import re

PATTERNS = {
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Firebase URL": r"https://[a-z0-9.-]+\.firebaseio\.com",
    "Amazon AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "Amazon AWS Secret Access Key": r"(?i)aws_secret|aws_key|aws_access.*['\"]([A-Za-z0-9/+=]{40})['\"]",
    "JSON Web Token (JWT)": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "GitHub Personal Access Token": r"ghp_[a-zA-Z0-9]{36}",
    "Stripe API Key": r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24}",
    "Private Key (PEM)": r"-----BEGIN [A-Z ]+ PRIVATE KEY-----",
    "Potential Password/Secret": r"""(?i)\b(password|passwd|pass|secret|secrets|auth[-_]?token|access[-_]?token|refresh[-_]?token|id[-_]?token|api[-_]?key|apikey|api[-_]?secret|client[-_]?secret|client[-_]?id|private[-_]?key|public[-_]?key|credential|credentials|jwt|bearer|authorization|encryption[-_]?key|signing[-_]?key|database[-_]?url|database[-_]?password|db[-_]?password|aws[-_]?access[-_]?key|aws[-_]?secret[-_]?key|github[-_]?token|gitlab[-_]?token|npm[-_]?token|stripe[-_]?key|stripe[-_]?secret|firebase[-_]?key)\b\s*[:=]\s*["'][^"'\r\n]+["']""",
}

VULNERABILITY_PATTERNS = {
    "SQL Query in Frontend": r"SELECT\s+.*\s+FROM\s+.*|INSERT\s+INTO\s+.*|UPDATE\s+.*\s+SET\s+.*|DELETE\s+FROM\s+.*",
    "Prisma/ORM usage in Front": r"prisma\.(?:user|account|post|profile|data)\.(?:findMany|findUnique|create|update|delete)",
}

LIB_PATTERNS = {
    "React": r"React\.version\s*=\s*[\"']([^\"']+)[\"']",
    "Next.js": r"\"next\"\s*:\s*[\"']([^\"']+)[\"']|/_next/static/",
    "Next.js (Build)": r"\"buildId\"\s*:\s*[\"']([^\"']+)[\"']",
    "jQuery": r"jQuery\.fn\.jquery\s*=\s*[\"']([^\"']+)[\"']",
    "Vue": r"Vue\.version\s*=\s*[\"']([^\"']+)[\"']",
    "Angular": r"ng-version=\"([^\"]+)\"",
    "WordPress": r"wp-content|wp-includes",
}

URL_PATTERN = r"https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[a-zA-Z0-9._%+-]*)*"
EMAIL_PATTERN = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
IPV4_PATTERN = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"

# Pattern to detect URL methods if they appear in code or as string literals
HTTP_METHOD_PATTERN = r"(?i)(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+(https?://[^\s\"']+)"
