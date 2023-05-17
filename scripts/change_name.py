"""
This script is used to add a string to the name of each file in the specified directory.
"""

import sys
from pathlib import Path


def main(directory, name_addition):
    files = [f for f in directory.iterdir()]
    for f in files:
        rename_to = f"{f.parent}/{f.stem}_{name_addition}{f.suffix}"
        f.rename(rename_to)


if __name__ == "__main__":
    if len(sys.argv) != 3 or not Path(sys.argv[1]).is_dir():
        print(f"Usage: python {sys.argv[0]} <directory> <name_addition>")
        sys.exit(1)
    main(Path(sys.argv[1]), sys.argv[2])
