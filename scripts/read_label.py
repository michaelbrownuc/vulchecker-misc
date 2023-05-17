"""
This script reads a label file for a program, prints each label and the corresponding source code
line.
"""

import sys
import json
from pathlib import Path


VALID_LABELS = {
    'declared_buffer',
    'stack_overflow',
    'heap_overflow',
    'overflowed_variable',
    'overflowed_call',
    'underflowed_variable',
    'underflowed_call',
    'first_free',
    'second_free',
    'freed_variable',
    'use_after_free',
}


def read_label(label_path: Path, source_path: Path):
    with label_path.open() as lf:
        labels = json.load(lf)
    for label in labels:
        assert label['label'] in VALID_LABELS
        print(f"{label['label']} {label['filename']}:{label['line_number']}")
        file_path = source_path / label['filename']
        with file_path.open() as f:
            lines = f.readlines()
            labeled_line = lines[label['line_number']-1].strip()
            print(f"{labeled_line}\n")


def main():
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} path_to_labels program_source_root")
        sys.exit(1)
    label_path = Path(sys.argv[1])
    source_path = Path(sys.argv[2])
    if not label_path.is_file() or not source_path.is_dir():
        print(f"Usage: python3 {sys.argv[0]} path_to_labels program_source_root")
        sys.exit(1)
    read_label(label_path, source_path)


if __name__ == "__main__":
    main()
