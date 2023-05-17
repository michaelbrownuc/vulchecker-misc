from pathlib import Path
import sys

import cwe121
import cwe122
import cwe190
import cwe191
import cwe415
import cwe416
from label import process_s_dir

HANDLERS = {
    "121": cwe121.process_src,
    "122": cwe122.process_src,
    "190": cwe190.process_src,
    "191": cwe191.process_src,
    "415": cwe415.process_src,
    "416": cwe416.process_src,
}


def main(input_dir, output_dir, cwe_id):
    process_s_dir(input_dir, output_dir, HANDLERS[cwe_id])


if __name__ == "__main__":
    if len(sys.argv) != 4 or not Path(sys.argv[1]).is_dir() or not Path(sys.argv[2]).is_dir():
        print(f"Usage: python3 {sys.argv[0]} <input-dir> <output-dir> <cwe-number>")
        sys.exit(1)
    cwe_id = sys.argv[3]
    if cwe_id not in HANDLERS:
        print(f"No available handler for CWE-{cwe_id}")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2], cwe_id)
