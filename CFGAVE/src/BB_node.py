###############################################################################
# DARPA AIMEE - Basic Block class definition. Used as Netx graph nodes.
# Author: Michael D. Brown
# Derived From: ACFG recovery code originally authored by GT Graduate Student
# Copyright Georgia Tech Research Institute, 2020
###############################################################################

# Features from "Scalable Graph-based Bug Search for Firmware Images" (CCS 2016)
# paper

# From: https://github.com/yangshouguo/Graph-based_Bug_Search
#   transfer_instructions = ['MOV','PUSH','POP','XCHG','IN','OUT','XLAT','LEA','LDS','LES','LAHF', 'SAHF' ,'PUSHF', 'POPF']
#   arithmetic_instructions = ['ADD', 'SUB', 'MUL', 'DIV', 'XOR', 'INC','DEC', 'IMUL', 'IDIV', 'OR', 'NOT', 'SLL', 'SRL']

# From: https://github.com/qian-feng/Gencoding/blob/7dcb04cd577e62a6394f5f68b751902db552ebd3/raw-feature-extractor/graph_analysis_ida.py
#   arithmetic_instructions = ['add', 'sub', 'div', 'imul', 'idiv', 'mul', 'shl', 'dec', 'inc']
#   transfer_instrucitons = ['jmp', 'jz', 'jnz', 'js', 'je', 'jne', 'jg', 'jle', 'jge', 'ja', 'jnc', 'call']
#   call_instructions = ['call', 'jal', 'jalr']

transfer_instructions = ['mov','push','pop','xchg','in','out','xlat','lea','lds','les','lahf', 'sahf' ,'pushf', 'popf']
arithmetic_instructions = ['add', 'sub', 'div', 'imul', 'idiv', 'mul', 'shl', 'dec', 'inc', 'xor', 'or', 'not', 'sll', 'srl']
call_instructions = ['call']

class BB_node:
    def __init__(self, addr, num_inst, num_offspring):
        self.entry_addr = addr
        self.num_inst = int(num_inst)
        self.trans_inst = 0
        self.arith_inst = 0
        self.call_inst = 0        
        self.offspring = int(num_offspring)  
        self.api = list()

    # Count instruction mnemonics
    def count(self, mnemonic):
        if mnemonic in transfer_instructions:
            self.trans_inst += 1

        elif mnemonic in arithmetic_instructions:
            self.arith_inst += 1

        elif mnemonic in call_instructions:
            self.call_inst += 1

    # Extract call symbol if it exists
    def get_symbol(self, token):
        token = [str(t) for t in token]

        if token[0] not in call_instructions:
            return

        if '[' not in token:
            return

        start = token.index('[')
        end = token.index(']')
        symbol = ' '.join(token[start+1:end])

        self.api.append(symbol)

    # Returns the attribute vector for this node
    def get_attribute_vector(self, betweeness=0):
        return [ self.entry_addr, 
                 self.num_inst,
                 self.trans_inst,
                 self.arith_inst,
                 self.call_inst,
                 self.offspring,
                 betweeness ]

    def __str__(self):
        rv = 'Basic Block Addr: {0}\n'.format(hex(self.entry_addr))
        rv += '\n'
        rv += '    ++++++ Statistical Features ++++++\n'
        rv += '    Num transfer insts: {0}\n'.format(self.trans_inst)
        rv += '    Num call insts: {0}\n'.format(self.call_inst)
        rv += '    Num insts: {0}\n'.format(self.num_inst)
        rv += '    Num arithmetic insts: {0}\n'.format(self.arith_inst)
        rv += '\n'
        rv += '    ++++++ Structural Features ++++++\n'
        rv += '    Num offspring: {0}\n'.format(self.offspring)
        rv += '\n'
        rv += '    ++++++ API Features ++++++\n'
        rv += '    APIs: {0}\n'.format(';'.join(self.api))
        return rv

    def __repr__(self):
        return '<ACFG for {0}>'.format(hex(self.entry_addr))