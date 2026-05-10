import argparse
from scanner.cli.validators import url_validator
from scanner.cli.output import show_banner
from scanner.core.engine import ScannerEngine


def run():
    show_banner()
    parser = argparse.ArgumentParser(description="Professional JS Secret Scanner")
    parser.add_argument("url", type=url_validator, help="Target URL to scan")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads (default: 10)")
    
    args = parser.parse_args()
    url = args.url
    engine = ScannerEngine(url, max_threads=args.threads)
    engine.run()