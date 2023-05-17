from __future__ import print_function

import os
import re

from util import write_json


def flaw_first_free(idx, labels):
    # next line is the root cause (idx is 0-indexed)
    labels[idx + 2] = {'label': 'first_free'}


def flaw_second_free(idx, labels):
    # next line is the root cause (idx is 0-indexed)
    labels[idx + 2] = {'label': 'second_free'}


def no_label(idx, labels):
    print("No label for flaw")


def process_src(args):
    src_file, output_dir = args
    filename = os.path.basename(src_file)
    labels = dict()

    # omitbad files are bug-free
    if '_omitbad' in filename:
        write_json(labels, output_dir, filename)
        return

    with open(src_file) as ifile:
        lines = ifile.readlines()

    # Every type of "Potential Flaw" in Juliet CWE190 and a function to handle it
    # (or None if it should be ignored)
    flaws = {
        "/* POTENTIAL FLAW: Free data in the source - the bad sink frees data as well */": flaw_first_free,
        "/* POTENTIAL FLAW: Possibly freeing memory twice */": flaw_second_free,
        "/* POTENTIAL FLAW: delete data in the source - the bad sink deletes data as well */": flaw_first_free,
        "/* POTENTIAL FLAW: Possibly deleting memory twice */": flaw_second_free,
        "/* POTENTIAL FLAW: delete the array data in the source - the bad sink deletes the array data as well */": flaw_first_free,
        "/* FLAW: There is no assignment operator in the class - this will cause a double free in the destructor */": no_label,
        "/* FLAW: There is no copy constructor in the class - this will cause a double free in the destructor */": no_label,
    }

    comment_regex = re.compile('/\* POTENTIAL FLAW: .* \*/')

    for idx, line in enumerate(lines):
        hit = comment_regex.search(line)
        if hit is not None:
            comment = hit.group(0)

            # flaws is suppose to contain every possible "Potential Flaw"
            assert comment in flaws

            handler = flaws[comment]
            if handler is not None:
                handler(idx, labels)

    write_json(labels, output_dir, filename)
