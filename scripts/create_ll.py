"""
This script generates an ll file for each source file in the specified directory.
"""

from pathlib import Path
import re
import sys
import subprocess
from multiprocessing import Pool


c_cpp = re.compile('.*\.c(pp)?')


def create_ll(source_file):
    subprocess.run(["clang", "-O0", "-g", "-S", "-isystem", "/home/hector/llap/tst/include", "-emit-llvm", source_file])


def main(input):
    source_files = []
    for source_file in input.iterdir():
        if c_cpp.fullmatch(source_file.name):
            source_files.append(str(source_file))

    with Pool() as p:
        p.map(create_ll, source_files)


if __name__ == "__main__":
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_dir():
        print(f"Usage: python3 {sys.argv[0]} <source-dir>")
        sys.exit(1)
    main(Path(sys.argv[1]))
