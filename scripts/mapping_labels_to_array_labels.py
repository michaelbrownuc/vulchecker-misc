import json
import os
from pathlib import Path

from multidict import MultiDict


def fixup_labels(labels_file: Path):
    with open(labels_file) as f:
        labels = json.load(f, object_pairs_hook=MultiDict)
    fixed_labels = []
    for k, v in labels.items():
        filename, line = k.split(":")
        fixed_labels.append(
            {
                "filename": filename,
                "line_number": int(line),
                "label": v["label"],
            }
        )
    labels_file.rename(str(labels_file) + "~")
    with open(labels_file, "w") as f:
        json.dump(fixed_labels, f, indent=4)


def main():
    for dirpath, dirnames, filenames in os.walk("."):
        if "labels.json" in filenames:
            fixup_labels(Path(dirpath, "labels.json"))
            dirnames.clear()


if __name__ == "__main__":
    main()
