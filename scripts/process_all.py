"""
This script runs llap on a particular Juliet CWE.
"""

from pathlib import Path
import re
import sys
import subprocess

c_cpp = re.compile('.*\.c(pp)?')


HECTOR_CWE_MAP = {
    "121": 121,
    "122": 121,
    "190": 190,
    "191": 190,
    "415": 415,
    "416": 416,
}


def main(cwe_number):
    hector_cwe = HECTOR_CWE_MAP[cwe_number]
    cd = Path(".")
    if len(list(cd.glob('*.json'))):
        raise FileExistsError("Clear all json files before running")

    labeled_dataset = Path(f"/home/hector/Desktop/labeled-dataset/CWE{cwe_number}")
    assert labeled_dataset.is_dir()
    ll_files = labeled_dataset / "ll_files/optimized"
    assert labeled_dataset.is_dir()
    labels = labeled_dataset / "source_labels/combined"
    assert labeled_dataset.is_dir()
    output_path = labeled_dataset / "labeled_graphs"
    assert labeled_dataset.is_dir()

    total = len(list(ll_files.iterdir()))
    for i, ll_file in enumerate(ll_files.iterdir()):
        print(f"---------- Processing {i+1}/{total} ----------")
        label_file = labels / ll_file.with_suffix(".json").name
        assert label_file.is_file()
        command = f'opt -load /home/hector/llvm-build/llvm/lib/LLVM_HECTOR_{hector_cwe}.so -HECTOR_{hector_cwe} < ' \
                  f'{str(ll_file)} -labelFilename={str(label_file)} > /dev/null\n'
        sub = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
        subprocess_return = sub.stdout.read()
        print(subprocess_return.decode("utf-8"))
        output = list(cd.glob("*.json"))[0]
        if output.name == "llvm-link.json":
            output.rename(output_path / ll_file.with_suffix(".json").name)
        else:
            output.rename(output_path / output.name.replace(".c.json", ".json").replace(".cpp.json", ".json"))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <CWE_Number>")
    main(sys.argv[1])
