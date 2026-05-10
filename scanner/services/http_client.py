import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class HttpClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        })

    def fetch(self, url: str, timeout: int = 10):
        try:
            response = self.session.get(url, timeout=timeout)
            if response.status_code != 200:
                return None, []
            
            content = response.text
            scripts = []
            
            if "text/html" in response.headers.get("Content-Type", ""):
                soup = BeautifulSoup(content, "html.parser")
                for script in soup.find_all("script", src=True):
                    scripts.append(urljoin(url, script["src"]))
                for link in soup.find_all("link", href=True):
                    if link["href"].endswith(".js"):
                        scripts.append(urljoin(url, link["href"]))
            
            return content, scripts
        except requests.RequestException:
            return None, []