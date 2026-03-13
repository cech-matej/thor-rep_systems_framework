from datetime import datetime
from pathlib import Path


def create_output_dir(use_mock: bool):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if use_mock:
        name = f"{timestamp}_mock"
    else:
        name = timestamp

    path = Path("output") / name
    path.mkdir(parents=True, exist_ok=True)

    return path