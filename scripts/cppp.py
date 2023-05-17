"""
This script runs cppp on Juliet to perform pre-processing necessary to create omitgood and omitbad
files.
"""

from pathlib import Path
import subprocess


output_dir = Path("../juliet-all")
for f in Path("../JulietMaster").iterdir():
    if f.suffix == ".c":
        output_file_good = output_dir / f.name.replace(".c", "_omitbad.c")
        output_file_bad = output_dir / f.name.replace(".c", "_omitgood.c")
    elif f.suffix == ".cpp":
        output_file_good = output_dir / f.name.replace(".cpp", "_omitbad.cpp")
        output_file_bad = output_dir / f.name.replace(".cpp", "_omitgood.cpp")
    else:
        continue

    subprocess.run(["cppp", "-DOMITGOOD", str(f), str(output_file_bad)])
    subprocess.run(["cppp", "-DOMITBAD", str(f), str(output_file_good)])
