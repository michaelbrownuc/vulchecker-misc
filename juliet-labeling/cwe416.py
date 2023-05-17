from __future__ import print_function

import os
import re

from util import write_json


def flaw_free(idx, labels):
    # next line is the root cause (idx is 0-indexed)
    labels[idx + 2] = {'label': 'freed_variable'}


def flaw_uaf(idx, labels):
    # next line is the root cause (idx is 0-indexed)
    labels[idx + 2] = {'label': 'use_after_free'}


def flaw_self_assign_uaf(idx, labels):
    labels[idx + 1] = {'label': 'use_after_free'}


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
        "/* POTENTIAL FLAW: Use of data that may have been freed */": flaw_uaf,
        "/* POTENTIAL FLAW: Free data in the source - the bad sink attempts to use data */": flaw_free,
        "/* POTENTIAL FLAW: Use of data that may have been deleted */": flaw_uaf,
        "/* POTENTIAL FLAW: Delete data in the source - the bad sink attempts to use data */": flaw_free,
        "/* FLAW: Freeing a memory block and then returning a pointer to the freed memory */": flaw_free,
    }

    comment_regex = re.compile('/\* (POTENTIAL )?FLAW: .* \*/')

    for idx, line in enumerate(lines):
        hit = comment_regex.search(line)
        if hit is not None:
            comment = hit.group(0)

            # flaws is suppose to contain every possible "Potential Flaw"
            assert comment in flaws

            handler = flaws[comment]
            if handler is not None:
                handler(idx, labels)
        elif "/* FLAW - if this is a self-assignment," in line:
            flaw_self_assign_uaf(idx, labels)
        elif (
                "CWE416_Use_After_Free__return_freed_ptr_" in filename and
                line.strip() == 'char * reversedString = helperBad("BadSink");'
        ):
            flaw_uaf(idx, labels)

    write_json(labels, output_dir, filename)
