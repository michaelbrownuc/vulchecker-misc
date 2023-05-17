"""
This script combines individual ll files generated for Juliet into a single optimized ll file for
each Juliet test case.
"""

import sys
from pathlib import Path
import re
from collections import defaultdict
import subprocess

var_regex = re.compile("([0-8][0-9])[a-z]?")


def main(input: Path, output: Path):
    merged = defaultdict(list)

    for f_name in input.iterdir():
        split_name = f_name.name.split("_")
        if var_regex.fullmatch(split_name[-2]):
            var_idx = -2
        elif var_regex.fullmatch(split_name[-3]):
            var_idx = -3
        else:
            raise ValueError("Could not find variant number")

        variant_num = split_name[var_idx]
        base_var = var_regex.fullmatch(variant_num).group(1)
        omit_type = split_name[-1].split(".")[0]
        if var_idx == -3 and base_var == "01":
            # Special handling for good1 and bad only variants
            merged_name = f_name.name
        else:
            merged_name = "_".join(split_name[:var_idx]) + f"_{base_var}_{omit_type}.ll"

        merged[merged_name].append(str(f_name))

    for new_name, single_files in merged.items():
        new_file_path = str(output / new_name)
        if len(single_files) > 1:
            # Link ll files
            command = ["llvm-link", "-S"]
            for single in single_files:
                command.append(single)
            command.extend(["-o", new_file_path])
            subprocess.run(command)
        else:
            # No linking required, copy to output directory
            subprocess.run(["cp", single_files[0], str(output)])

        # Optimize ll files
        subprocess.run(["sed", "-i", "s/noinline//g", new_file_path])
        subprocess.run(["sed", "-i", "s/optnone//g", new_file_path])
        subprocess.run([
            "opt",
            "--indirectbr-expand",
            "--inline-threshold=10000",
            "--inline",
            "-S",
            "-o",
            new_file_path,
            new_file_path
        ])
        subprocess.run(
            f'opt --internalize-public-api-list="main" --internalize --globaldce -S -o {new_file_path} {new_file_path}',
            shell=True
        )


if __name__ == "__main__":
    if len(sys.argv) != 3 or not Path(sys.argv[1]).is_dir() or not Path(sys.argv[2]).is_dir():
        print(f"Usage: python3 {sys.argv[0]} <input-dir> <output-dir>")
        sys.exit(1)
    input = Path(sys.argv[1])
    output = Path(sys.argv[2])
    main(input, output)
