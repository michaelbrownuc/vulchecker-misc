from __future__ import print_function

import os
import re

from util import write_json


def flaw_next_line(idx, labels, lines):
    # next line is the root cause (idx is 0-indexed)
    labels[idx + 2] = {'label': 'stack_overflow'}


def root_cause_next(idx, labels, lines):
    # next line is the root cause (idx is 0-indexed)
    labels[idx + 2] = {'label': 'declared_buffer'}


def root_cause_this_line(idx, labels, lines):
    labels[idx + 1] = {'label': 'declared_buffer'}


def flaw_this_line(idx, labels, lines):
    # this line is the root cause (idx is 0-indexed)
    labels[idx + 1] = {'label': 'stack_overflow'}


def flaw_write_to_idx(idx, labels, lines):
    labels[idx + 5] = {'label': 'stack_overflow'}


def flaw_wchar(idx, labels, lines):
    labels[idx + 4] = {'label': 'stack_overflow'}


def flaw_find_line(idx, labels, lines):
    next_line = lines[idx + 1]
    if "for (i = 0;" in next_line:
        labels[idx + 4] = {'label': 'stack_overflow'}
    else:
        labels[idx + 2] = {'label': 'stack_overflow'}


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
        '/* FLAW: Allocate memory without using sizeof(int) */':                                                                None,
        '/* FLAW: Initialize data as a large buffer that is larger than the small buffer used in the sink */':                  None,
        '/* FLAW: Set a pointer to a "small" buffer. This buffer will be used in the sinks as a destination':                   None,
        '/* FLAW: Set a pointer to a buffer that does not leave room for a NULL terminator when performing':                    None,
        '/* FLAW: Use the sizeof(structCharVoid) which will overwrite the pointer voidSecond */':                               flaw_next_line,
        '/* POTENTIAL FLAW: Attempt to write to an index of the array that is above the upper bound':                           flaw_write_to_idx,
        '/* POTENTIAL FLAW: Initialize data to a buffer smaller than the sizeof(TwoIntsClass) */':                              None,
        '/* POTENTIAL FLAW: Possible buffer overflow if data < 100 */':                                                         flaw_find_line,
        '/* POTENTIAL FLAW: Possible buffer overflow if data is larger than dest */':                                           flaw_find_line,
        '/* POTENTIAL FLAW: Possible buffer overflow if data is larger than sizeof(dest)-strlen(dest)*/':                       flaw_next_line,
        '/* POTENTIAL FLAW: Possible buffer overflow if data is larger than sizeof(dest)-wcslen(dest)*/':                       flaw_next_line,
        '/* POTENTIAL FLAW: Possible buffer overflow if data was not allocated correctly in the source */':                     flaw_find_line,
        '/* POTENTIAL FLAW: Possible buffer overflow if the size of data is less than the length of source */':                 flaw_find_line,
        '/* POTENTIAL FLAW: Possible buffer overflow if the sizeof(data)-strlen(data) is less than the length of source */':    flaw_next_line,
        '/* POTENTIAL FLAW: Read data from the console using fgets() */':                                                       None,
        '/* POTENTIAL FLAW: Read data from the console using fscanf() */':                                                      None,
        '/* POTENTIAL FLAW: Read data using a connect socket */':                                                               None,
        '/* POTENTIAL FLAW: Read data using a listen socket */':                                                                None,
        '/* POTENTIAL FLAW: Set data to a random value */':                                                                     None,
        '/* POTENTIAL FLAW: Set data to point to a wide string */':                                                             None,
        '/* POTENTIAL FLAW: Use an invalid index */':                                                                           None,
        '/* POTENTIAL FLAW: data may not be large enough to hold a TwoIntsClass */':                                            root_cause_next,
        '/* POTENTIAL FLAW: data may not have enough space to hold source */':                                                  flaw_find_line,
        '/* POTENTIAL FLAW: treating pointer as a char* when it may point to a wide string */':                                 flaw_wchar,
        '/* POTENTIAL FLAW: If sizeof(data) < sizeof(TwoIntsClass) then this line will be a buffer overflow */':                flaw_this_line,
    }

    decl = {
        "charVoid structCharVoid;",
        "int buffer[10] = { 0 };",
        "data = (int *)ALLOCA(10);",
        "void * dest = (void *)ALLOCA((dataLen+1) * sizeof(wchar_t));",
        "char * dataBadBuffer = (char *)ALLOCA((10)*sizeof(char));",
        "char dataBadBuffer[10];",
        "wchar_t * dataBadBuffer = (wchar_t *)ALLOCA((10)*sizeof(wchar_t));",
        "wchar_t dataBadBuffer[10];",
        "wchar_t dataBadBuffer[50];",
        "char * dataBadBuffer = (char *)ALLOCA(50*sizeof(char));",
        "char dataBadBuffer[50];",
        "int64_t * dataBadBuffer = (int64_t *)ALLOCA(50*sizeof(int64_t));",
        "int64_t dataBadBuffer[50];",
        "int * dataBadBuffer = (int *)ALLOCA(50*sizeof(int));",
        "int dataBadBuffer[50];",
        "twoIntsStruct * dataBadBuffer = (twoIntsStruct *)ALLOCA(50*sizeof(twoIntsStruct));",
        "twoIntsStruct dataBadBuffer[50];",
        'char dest[50] = "";',
        "wchar_t * dataBadBuffer = (wchar_t *)ALLOCA(50*sizeof(wchar_t));",
        'wchar_t dest[50] = L"";',
    }

    found_decl = False

    comment_regex = re.compile('/\* (POTENTIAL )?FLAW: .*')

    for idx, line in enumerate(lines):

        if line.strip() in decl and not found_decl:
            root_cause_this_line(idx, labels, lines)
            found_decl = True

        hit = comment_regex.search(line)
        if hit is not None:
            comment = hit.group(0)

            # flaws is suppose to contain every possible "Potential Flaw"
            assert comment in flaws

            handler = flaws[comment]
            if handler is not None:
                handler(idx, labels, lines)

    write_json(labels, output_dir, filename)
