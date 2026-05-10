from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse
from scanner.services.http_client import HttpClient
from scanner.core.detector.detector_services import Detector
from scanner.cli.output import success, info, error, show_results

class ScannerEngine:
    def __init__(self, url: str, max_threads: int = 10):
        self.url = url
        self.domain = urlparse(url).netloc
        self.max_threads = max_threads
        self.visited_urls = set()
        self.js_queue = set()
        self.detector = Detector()
        self.http_client = HttpClient()

    def process_url(self, url):
        if url in self.visited_urls:
            return
        self.visited_urls.add(url)
        
        info(f"Scanning: {url}")
        content, scripts = self.http_client.fetch(url)
        
        if content:
            self.detector.scan(url, content)
            
            # If it's the main page or we find scripts, add them to the queue
            for script in scripts:
                if script not in self.visited_urls:
                    self.js_queue.add(script)
            
            # Special handling for Next.js chunks if detected
            if "Next.js" in self.detector.found_libs:
                # Common Next.js paths
                next_paths = [
                    "/_next/static/runtime/main.js",
                    "/_next/static/chunks/main.js",
                    "/_next/static/chunks/pages/_app.js",
                ]
                for p in next_paths:
                    full_p = urljoin(self.url, p)
                    if full_p not in self.visited_urls:
                        self.js_queue.add(full_p)

    def run(self):
        info(f"Starting scan on {self.url}")
        
        # Initial scan of the target URL
        self.process_url(self.url)
        
        # Process JS files in parallel
        while self.js_queue:
            current_batch = list(self.js_queue)
            self.js_queue = set()
            
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                executor.map(self.process_url, current_batch)
        
        results = self.detector.get_results()
        show_results(results)