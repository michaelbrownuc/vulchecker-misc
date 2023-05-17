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

import os
import re

from util import write_json


def flaw_ovf2call(idx, labels):
    # next line is the root cause (idx is 0-indexed)
    labels[idx + 2] = {'label': 'overflowed_variable'}
    # line after is *always* the call
    labels[idx + 3] = {'label': 'overflowed_call'}

def flaw_inc2call(idx, labels):
    # next line is the root cause (idx is 0-indexed)
    labels[idx + 2] = {'label': 'overflowed_variable'}
    # next line saves to an intermediate variable
    # next line is *always* the call
    labels[idx + 4] = {'label': 'overflowed_call'}


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
        '/* POTENTIAL FLAW: Adding 1 to data could cause an overflow */':       flaw_ovf2call,
        '/* POTENTIAL FLAW: if (data*2) > CHAR_MAX, this will overflow */':     flaw_ovf2call,
        '/* POTENTIAL FLAW: if (data*2) > INT_MAX, this will overflow */':      flaw_ovf2call,
        '/* POTENTIAL FLAW: if (data*2) > LLONG_MAX, this will overflow */':    flaw_ovf2call,
        '/* POTENTIAL FLAW: if (data*2) > SHRT_MAX, this will overflow */':     flaw_ovf2call,
        '/* POTENTIAL FLAW: if (data*2) > UINT_MAX, this will overflow */':     flaw_ovf2call,
        '/* POTENTIAL FLAW: if (data*data) > CHAR_MAX, this will overflow */':  flaw_ovf2call,
        '/* POTENTIAL FLAW: if (data*data) > INT_MAX, this will overflow */':   flaw_ovf2call,
        '/* POTENTIAL FLAW: if (data*data) > LLONG_MAX, this will overflow */': flaw_ovf2call,
        '/* POTENTIAL FLAW: if (data*data) > SHRT_MAX, this will overflow */':  flaw_ovf2call,
        '/* POTENTIAL FLAW: if (data*data) > UINT_MAX, this will overflow */':  flaw_ovf2call,
        '/* POTENTIAL FLAW: Incrementing data could cause an overflow */':      flaw_inc2call,
        '/* POTENTIAL FLAW: Read data from the console using fgets() */':       None,
        '/* POTENTIAL FLAW: Read data from the console using fscanf() */':      None,
        '/* POTENTIAL FLAW: Read data using a connect socket */':               None,
        '/* POTENTIAL FLAW: Read data using a listen socket */':                None,
        '/* POTENTIAL FLAW: Set data to a random value */':                     None,
        '/* POTENTIAL FLAW: Use a random value */':                             None,
        '/* POTENTIAL FLAW: Use a value input from the console */':             None,
        '/* POTENTIAL FLAW: Use the maximum size of the data type */':          None,
        '/* POTENTIAL FLAW: Use the maximum value for this type */':            None,
    }

    comment_regex = re.compile('/\* POTENTIAL FLAW: .* \*/')

    for idx, line in enumerate(lines):
        hit = comment_regex.search(line)
        if not hit is None:
            comment = hit.group(0)

            # flaws is suppose to contain every possible "Potential Flaw"
            assert comment in flaws

            handler = flaws[comment]
            if not handler is None:
                handler(idx, labels)

    write_json(labels, output_dir, filename)
