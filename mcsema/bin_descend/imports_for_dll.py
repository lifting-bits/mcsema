import idautils
import idaapi
import idc
import sys
import os
import argparse

def find_imported_funcs(from_module):
    def imp_cb(ea, name, ord):
        if not name:
            raise Exception("Import by ordinal unsupported for now")
        imports.append(name)
        return True

    imports = []
    nimps = idaapi.get_import_module_qty()
    for i in xrange(0, nimps):
        modname = idaapi.get_import_module_name(i).lower()
        if modname == from_module:
            idaapi.enum_import_names(i, imp_cb)

    return imports


if __name__ == "__main__":

    idaapi.autoWait()

    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--module",
            default=None,
            required=True,
            help="The module from which the functions are imported"
            )
    parser.add_argument("-o", "--outfile",
            default=None,
            required=True,
            type=argparse.FileType('w'),
            help="Output file of imported functions from <module>"
            )

    args = parser.parse_args(args=idc.ARGV[1:])

    imps = find_imported_funcs(args.module.lower())

    # implicit import
    imps.append("DllEntryPoint")

    args.outfile.write("\n".join(imps))

    args.outfile.close()
    
    idc.Exit(0)
