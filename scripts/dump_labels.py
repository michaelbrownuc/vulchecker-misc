"""
This script outputs the labels and labeled source line for each program in the specified directory.
"""

from pathlib import Path
import sys
from read_label import read_label


def main(cwe_path: Path):
    programs = sorted([p for p in cwe_path.iterdir() if p.is_dir() and not p.name.startswith(".")])
    for program in programs:
        label_file = program / "labels.json"
        print(f"-------------------- {program.name} --------------------")
        read_label(label_file, program)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} path_to_label_cwe_dir")
        sys.exit(1)
    cwe_path = Path(sys.argv[1])
    if not cwe_path.is_dir():
        print(f"Usage: python3 {sys.argv[0]} path_to_label_cwe_dir")
        sys.exit(1)
    main(cwe_path)
