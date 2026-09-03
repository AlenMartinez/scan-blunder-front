from scanner.core.patterns import LIB_PATTERNS, PATTERNS, VULNERABILITY_PATTERNS, URL_PATTERN, HTTP_METHOD_PATTERN
import re
from scanner.core.findings.writer import create_finding_file

class Detector:
    def __init__(self, domain):
        self.domain = domain
        self.found_libs = {}
        self.found_secrets = []
        self.found_vulnerabilities = []
        self.found_urls = set()
        self.found_methods = []

    def scan(self, url, content):
        # 1. Detect Libraries
        for lib, pattern in LIB_PATTERNS.items():
            match = re.search(pattern, content)
            if match:
                version = match.group(1) if match.groups() else "Detected"
                if lib not in self.found_libs:
                    self.found_libs[lib] = version

        # 2. Detect Secrets
        for name, pattern in PATTERNS.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                start = max(0, match.start() - 150)
                end = min(len(content), match.end() + 150)
                context = content[start:end]

                value = match.group(0)
                self.found_secrets.append({
                    "type": name,
                    "value": value,
                    "url": url,
                    "line": content.count("\n", 0, match.start()) + 1,
                    "context": context
                })

        # 3. Detect Vulnerabilities (SQL in front, etc)
        for name, pattern in VULNERABILITY_PATTERNS.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                start = max(0, match.start() - 150)
                end = min(len(content), match.end() + 150)
                context = content[start:end]
                self.found_vulnerabilities.append({
                    "type": name,
                    "value": match.group(0),
                    "url": url,
                    "line": content.count("\n", 0, match.start()) + 1,
                    "context": context
                })

        # 4. Extract URLs
        urls = re.findall(URL_PATTERN, content)
        for u in urls:
            self.found_urls.add(u)

        # 5. Extract HTTP Methods
        methods = re.finditer(HTTP_METHOD_PATTERN, content)
        for m in methods:
            self.found_methods.append({
                "method": m.group(1),
                "url": m.group(2),
                "source": url
            })


        

    def get_results(self):
        import json
        finding_file = create_finding_file(self.domain)
        with open(finding_file, "w", encoding="utf-8") as f:
            f.write(json.dumps({
                "libs": self.found_libs,
                "secrets": self.found_secrets,
                "vulnerabilities": self.found_vulnerabilities,
                "urls": list(self.found_urls),
                "methods": self.found_methods,
            }, indent=4))

        return {
            "libs": self.found_libs,
            "secrets": self.found_secrets,
            "vulnerabilities": self.found_vulnerabilities,
            "urls": list(self.found_urls),
            "methods": self.found_methods
        }
