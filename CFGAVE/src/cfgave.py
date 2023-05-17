###############################################################################
# DARPA AIMEE - CFGAVE: Tool that Extracts Control Flow Graph Attribute Vectors
# Author: Michael D. Brown
# Derived From: ACFG recovery code originally authored by GT Graduate Student
# Copyright Georgia Tech Research Institute, 2020
###############################################################################

# Standard library imports
import argparse
import os
import sys

# Third party imports
import networkx as nx
import binaryninja as binja

# Local imports
from BB_node import *
import util

blocklist = ["_init", "_start", "deregister_tm_clones", "register_tm_clones", "__do_global_dtors_aux", "frame_dummy", "printLine",
             "printWLine", "printIntLine", "printShortLine", "printFloatLine", "printLongLine", "printLongLongLine", "printSizeTLine",
             "printHexCharLine", "printWcharLine", "printUnsignedLine", "printHexUnsignedCharLine", "printDoubleLine", "printStructLine",
             "printBytesLine", "decodeHexChars", "decodeHexWChars", "globalReturnsTrue", "globalReturnsFalse", "globalReturnsTrueOrFalse",
             "good1", "good2", "good3", "good4", "good5", "good6", "good7", "good8", "good9", "bad1", "bad2", "bad3", "bad4", "bad5",
             "bad6", "bad7", "bad8", "bad9", "internal_start", "stdThreadCreate", "stdThreadJoin", "stdThreadDestroy", "stdThreadLockCreate",
             "stdThreadLockAcquire", "stdThreadLockRelease", "stdThreadLockDestroy", "__libc_csu_init", "__libc_csu_fini", "_fini",
            "_Znam", "printf", "pthread_join", "__isoc99_swscanf", "pthread_create", "pthread_mutex_unlock", "time", "srand", "__isoc99_sscanf", 
            "__ctype_b_loc", "__stack_chk_fail", "pthread_mutex_destroy", "free", "_ZdaPv", "malloc", "wprintf", "pthread_mutex_lock", 
            "pthread_mutex_init", "puts", "pthread_exit", "iswxdigit", "__cxa_finalize", "_Znwm", "_ZdlPvm", "__cxa_rethrow", "memmove",
            "__cxa_end_catch", "_Unwind_Resume", "_ZnwmPv", "__cxa_begin_catch", "exit", "_ZdlPv", "_ZdlPvS_", "strlen", "strcpy", 
            "staticReturnsTrue", "staticReturnsFalse", "memset", "__isoc99_fscanf", "recv", "htons", "close", "listen", "bind", "accept",
            "atoi", "socket", "rand", "fscanf", "fgets", "connect", "inet_addr", "strncat", "strncpy", "strcat", "snprintf", "memcpy", "strcpy",
            "wcscpy", "wcslen", "wmemset", "calloc", ]

# Generates a networkx graph with attributes for a given function
def generate_graph(func):
    G = nx.DiGraph()

    bbs_added = {}    
    
    # Iterate through basic blocks of function, create nodes
    for bb in func.basic_blocks:
        # Create node from basic block
        new_node = BB_node(bb.start, bb.instruction_count, len(bb.outgoing_edges))

        # Iterate through instructions of this block to detrermine attribute values
        insts = bb.get_disassembly_text()

        for e,inst in enumerate(insts):
            # First text of disassembly is function name and address
            if e == 0:
                continue

            # Get mnemonic
            new_node.count('{0}'.format(inst.tokens[0]))

            # Get call symbol (if it exists)
            new_node.get_symbol(inst.tokens)

        # Add this BB to the graph and the map of added BBs for later generation of edges.
        G.add_node(new_node)
        bbs_added[bb.start] = new_node
        
    # Make a second pass through and add edges
    for bb in func.basic_blocks:
        source_node = bbs_added[bb.start]
        for edge in bb.outgoing_edges:
            dest_node = bbs_added[edge.target.start]
            G.add_edge(source_node, dest_node)

    return G

def _main():
    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', help='Binary (or directory of binaries) to extract CFG attribute vectors from.', type=str)
    parser.add_argument("-cap", "--memory_cap", help="Set the maximum number of binaries to bulk process.", type=int, default=2000)
    args = parser.parse_args()

    file_list = []

    if os.path.isfile(args.binary):
        file_list = [args.binary]
    elif os.path.isdir(args.binary):
        for path in os.listdir(args.binary):
            file_list.append(os.path.join(args.binary, path))
    else:
        sys.exit("Input value is not a binary or directory, aborting operation...")

    # Cap maximum number of files to be processed to prevent being killed for excessive memory use.
    # Skipped files are not counted, so for large sample directories you can just re-run command over and over until it processes all binaries.
    mem_cap = args.memory_cap
    processed = 0

    # For each file to analyze:
    for file in file_list:    
        # Check for hitting the memory cap
        if processed == mem_cap:
            sys.exit("Memory cap reached. Stopping for now.  Please run command again.")
        
        # Create Output Directory - Skip if directory already exists   
        try:
            filename = file[file.rfind("/")+1 : ]
            directory_name = util.create_output_directory("output/" + filename, False)
        except OSError as oserr:
            print("An OS Error occurred during creation of output directory: " + oserr.strerror)
            print("Output cannot be saved, skipping operation...")
            continue

        print("Analyzing sample: " + filename)

        # Analyze Binary 
        bv = binja.BinaryViewType["ELF"].open(file)
        bv.update_analysis_and_wait()

        # For each function, generate a netowrk of attribute 
        for fn in bv.functions:
            # Don't process boilerplate functions
            if fn.name not in blocklist:
                print("  Procesing Function: " + fn.name)
                
                # Generate Network
                cfg_net = generate_graph(fn)

                # Dump Network to YAML (filename limited to system max of 255 chars)
                max_length = 255 - (len(filename) +1)
                nx.write_yaml(cfg_net, directory_name + "/" + filename + "_" + fn.name[:max_length])
        
        processed += 1 
        

if __name__ == '__main__':
    _main()
