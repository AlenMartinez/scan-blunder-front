from pathlib import Path
from datetime import datetime


def create_finding_file(domain: str) -> Path:
    findings_dir = Path("findings")
    findings_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    finding_file = findings_dir / f"{domain}_{timestamp}.txt"

    return finding_file