import sys
import re
from pathlib import Path

from process_juliet import preprocess_directory


def main(juliet_cwe_path, output_path):
    s_regex = re.compile("s[0-9]+")

    subdirs = [
        subdir
        for subdir in juliet_cwe_path.iterdir()
        if subdir.is_dir() and s_regex.match(str(subdir.name))
    ]

    if len(subdirs) == 0:
        # No s## directories
        preprocess_directory(juliet_cwe_path, output_path)
    else:
        # s## directories present
        for input_sub in subdirs:
            preprocess_directory(input_sub, output_path)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python3 {__file__} <juliet-cwe-path> <output-path>")
        sys.exit(1)
    juliet_cwe_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    if not juliet_cwe_path.is_dir() or not output_path.is_dir():
        print(f"Usage: python3 {__file__} <juliet-cwe-path> <output-path>")
        sys.exit(1)
    main(juliet_cwe_path, output_path)
