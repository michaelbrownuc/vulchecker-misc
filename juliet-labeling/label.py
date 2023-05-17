#!/usr/bin/env python
#
# Copyright 2020 Carter Yagemann
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
from __future__ import print_function

from multiprocessing import Pool
import os
import re
import sys

import cwe121
import cwe122
import cwe190
import cwe191
import cwe415
import cwe416

HANDLERS = {
    'CWE121_Stack_Based_Buffer_Overflow': cwe121.process_src,
    'CWE122_Heap_Based_Buffer_Overflow': cwe122.process_src,
    'CWE190_Integer_Overflow': cwe190.process_src,
    'CWE191_Integer_Underflow': cwe191.process_src,
    'CWE415_Double_Free': cwe415.process_src,
    'CWE416_Use_After_Free': cwe416.process_src,
}

def listdir(dir_path):
    return [os.path.join(dir_path, entry) for entry in os.listdir(dir_path)]

def is_src_file(filepath):
    return os.path.isfile(filepath) and (filepath.endswith(".c") or filepath.endswith(".cpp"))

def process_s_dir(input_dir, output_dir, handler):
    files = [entry for entry in listdir(input_dir) if is_src_file(entry)]
    num_files = len(files)

    workers = Pool()

    for i, _ in enumerate(workers.imap_unordered(handler, zip(files, [output_dir] * num_files)), 1):
        sys.stdout.write('        done {0:%}\r'.format(i / num_files))
        sys.stdout.flush()

    workers.close()

def process_testcases(input_dir, output_dir, handler):
    """Parse input_dir and created JSON label files in output_dir.

    input_dir is expected to have the following structure:

    <CWE123_Description>/
        s01/
            *.c
            *.cpp
            *.h
        s02/
            ...
        ...
    """
    s_regex = re.compile("s[0-9]+")
    s_dirs = [entry for entry in listdir(input_dir)
                if s_regex.match(os.path.basename(entry))]

    if len(s_dirs) != 0:
        for s_dir in s_dirs:
            print("    Processing %s" % s_dir)
            process_s_dir(s_dir, output_dir, handler)
    else:
        process_s_dir(input_dir, output_dir, handler)

def process_cwes(input_dir, output_dir):
    entries = listdir(input_dir)
    for entry in entries:
        entry_name = os.path.basename(entry)
        if entry_name in HANDLERS:
            print("Processing %s" % entry)
            process_testcases(entry, output_dir, HANDLERS[entry_name])

def main():
    if len(sys.argv) != 3:
        print('Usage: %s <path_to_testcases> <output_dir>' % sys.argv[0])
        sys.exit(1)

    process_cwes(sys.argv[1], sys.argv[2])

if __name__ == '__main__':
    main()
