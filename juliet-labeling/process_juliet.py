#!/usr/bin/env python3

import re
import argparse
from pathlib import Path
import subprocess
from multiprocessing import Pool

from label import process_cwes, HANDLERS


def get_args() -> argparse.Namespace:
    """
    Get the provided arguments
    """
    parser = argparse.ArgumentParser(
        description="Generate labels for the Juliet test suite"
    )
    parser.add_argument(
        "-l",
        action="store_true",
        help="Run the labeler on files that have already been preprocessed",
    )
    parser.add_argument("juliet_path", type=str, help="Path of the Juliet directory")
    parser.add_argument("output_path", type=str, help="Path of the output directory")
    args = parser.parse_args()
    return args


def preprocess_directory(input_dir: Path, output_dir: Path):
    """
    Preprocess all .c and .cpp files in input_dir and write the resulting files in output_dir
    """
    for file in input_dir.iterdir():
        if file.suffix == ".c":
            output_file_good = output_dir / file.name.replace(".c", "_omitbad.c")
            output_file_bad = output_dir / file.name.replace(".c", "_omitgood.c")
        elif file.suffix == ".cpp":
            output_file_good = output_dir / file.name.replace(".cpp", "_omitbad.cpp")
            output_file_bad = output_dir / file.name.replace(".cpp", "_omitgood.cpp")
        else:
            continue

        subprocess.run(["cppp", "-DOMITGOOD", "-DINCLUDEMAIN", str(file), str(output_file_bad)])
        subprocess.run(["cppp", "-DOMITBAD", "-DINCLUDEMAIN", str(file), str(output_file_good)])


def preprocess_all(juliet_path: Path, output_path: Path):
    """
    Preprocess all appropriate files in juliet_path and write results to output_path
    """
    output_path.mkdir(exist_ok=True)

    s_regex = re.compile("s[0-9]+")
    for handler in HANDLERS:
        cwe_input_path = juliet_path / "testcases" / handler
        cwe_output_path = output_path / handler
        cwe_output_path.mkdir(exist_ok=True)
        subdirs = [
            subdir
            for subdir in cwe_input_path.iterdir()
            if subdir.is_dir() and s_regex.match(str(subdir.name))
        ]

        if len(subdirs) == 0:
            # No s## directories
            preprocess_directory(cwe_input_path, cwe_output_path)
        else:
            # s## directories present
            for input_sub in subdirs:
                output_sub = cwe_output_path / input_sub.name
                output_sub.mkdir(exist_ok=True)
                preprocess_directory(input_sub, output_sub)


def main():
    args = get_args()
    juliet_path = Path(args.juliet_path)
    output_path = Path(args.output_path)

    if not juliet_path.is_dir():
        raise RuntimeError(f"Juliet directory {juliet_path.resolve()} does not exist")

    if not args.l:
        preprocess_all(juliet_path, output_path)

    label_output = output_path / "labels"
    label_output.mkdir(exist_ok=True)
    process_cwes(output_path, label_output)


if __name__ == "__main__":
    main()
