"""
This script combines individual label files generated for Juliet into a single label file for each
Juliet test case.
"""

import sys
from pathlib import Path
import re
from collections import defaultdict
import json


var_regex = re.compile("([0-8][0-9])[a-z]?")


def main(input: Path, output: Path):
    labels = defaultdict(list)

    for f_name in input.iterdir():
        split_name = f_name.name.split("_")
        if var_regex.fullmatch(split_name[-2]):
            var_idx = -2
        elif var_regex.fullmatch(split_name[-3]):
            var_idx = -3
        else:
            raise ValueError("Could not find variant number")

        variant = split_name[var_idx]
        base_var = var_regex.fullmatch(variant).group(1)
        omit_type = split_name[-1].split(".")[0]

        if var_idx == -3 and base_var == "01":
            # Special handling for good1 and bad only variants
            base_name = f_name.name
            base_name.replace(".cpp.json", ".json")
        else:
            base_name = "_".join(split_name[:var_idx]) + f"_{base_var}_{omit_type}.json"

        with f_name.open() as f:
            l = json.load(f)
            labels[base_name].append(l)

    for new_file, label in labels.items():
        out_file = output / new_file
        with out_file.open("w") as f:
            json.dump(label, f)


if __name__ == "__main__":
    if len(sys.argv) != 3 or not Path(sys.argv[1]).is_dir() or not Path(sys.argv[2]).is_dir():
        print(f"Usage: python3 {sys.argv[0]} <input-dir> <output-dir>")
        sys.exit(1)
    input = Path(sys.argv[1])
    output = Path(sys.argv[2])
    main(input, output)
