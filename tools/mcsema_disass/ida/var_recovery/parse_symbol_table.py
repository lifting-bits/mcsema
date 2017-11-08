#!/usr/bin/env python

import os
import sys
import string
import argparse
import pprint

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.descriptions import (
    describe_ei_class, describe_ei_data, describe_ei_version,
    describe_ei_osabi, describe_e_type, describe_e_machine,
    describe_e_version_numeric, describe_p_type, describe_p_flags,
    describe_sh_type, describe_sh_flags,
    describe_symbol_type, describe_symbol_bind, describe_symbol_visibility,
    describe_symbol_shndx, describe_reloc_type, describe_dyn_tag,
    describe_ver_flags, describe_note
    )

GLOBAL_SYMBOLS = dict()

def _global_var_name(address):
    return "recovered_global_{0:x}".format(address)

def display_symbol_tables(in_file, symbol_name):
    """
        Display the symbol table
    """
    elffile = ELFFile(in_file)
            
    for section in elffile.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        
        if section['sh_entsize'] == 0:
            continue

        print("\nSymbol table '%s' contains %s entries:" % (section.name, section.num_symbols()))

        for nsym, symbol in enumerate(section.iter_symbols()):
            GLOBAL_SYMBOLS[symbol.name] = symbol['st_value']
                
    pprint.pprint(_global_var_name(GLOBAL_SYMBOLS[symbol_name]))

def main(stream=None):
    parser = argparse.ArgumentParser()
    
    parser.add_argument('--binary',
                        help='Name of the binary image.',
                        required=True)
    
    parser.add_argument('--symbol',
                        help='Name of the symbol.',
                        required=True)
    
    args = parser.parse_args(sys.argv[1:])
    
    print args.binary
    
    with open(args.binary, 'rb') as in_file:
        display_symbol_tables(in_file, args.symbol)
    
    
    

if __name__ == '__main__':
    main()
