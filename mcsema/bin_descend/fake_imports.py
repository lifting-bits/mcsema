import idaapi
import idautils
import idc
from os import path
import sys
import argparse


FAKE_DLL = """

int __stdcall DllMain(void* inst, unsigned int dwReason, void* lpr) {

    return 1;
}

"""

def parseDefsFile(df):
    emap = {}
    emap_data = {}
    for l in df.readlines():
        #skip comments
        if l[0] == "#":
            continue
         
        l = l.strip()
        
        if l.startswith('DATA:') :
            # process as data
            (marker, symname, dsize) = l.split()
            emap_data[symname] = int(dsize)
        else:

            (fname, args, conv, ret) = l.split()

            if conv == "C":
                realconv = "__cdecl"
            elif conv == "E":
                realconv = "__stdcall"
            elif conv == "F":
                realconv = "__fastacll"
            else:
                raise Exception("Unknown calling convention:"+conv)

            if ret not in ['Y', 'N']:
                raise Exception("Unknown return type:"+ret)

            emap[fname] = (int(args), realconv, ret)

    
    df.close()

    return emap, emap_data

def find_imported_funcs():
    def imp_cb(ea, name, ord):
        if not name:
            raise Exception("Import by ordinal unsupported for now")
        imports[modname].append(name)
        return True

    imports = {}
    modname = ""
    nimps = idaapi.get_import_module_qty()
    for i in xrange(0, nimps):
        modname = idaapi.get_import_module_name(i)
        imports[modname] = []
        idaapi.enum_import_names(i, imp_cb)

    return imports

def isFwdExport(iname, ea):
    l = ea
    if l == idc.BADADDR:
        raise Exception("Cannot find addr for: " + iname)

    pf = idc.GetFlags(l)

    if not idc.isCode(pf) and idc.isData(pf):
        sz = idc.ItemSize(l)
        iname = idaapi.get_many_bytes(l, sz-1)
        return iname

    return None

if __name__ == "__main__":
    idaapi.autoWait()
    myname = idc.GetInputFile()

    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--std-defs", nargs='*', type=argparse.FileType('r'),
        default=None,
	required=True,
        help="std_defs file: definitions and calling conventions of imported functions and data"
        )
    parser.add_argument("-o", "--outdir",
        default=None,
	required=True,
        help="Output directory for generated stub import DLLs"
        )

    args = parser.parse_args(args=idc.ARGV[1:])

    if path.exists(args.outdir) and not path.isdir(args.outdir):
	    raise Exception("Outdir must be a directory!")

    if not path.exists(args.outdir):
	    os.mkdir(args.outdir)

    outpath =  args.outdir

    sys.stdout.write("Gathering imports...\n")
    imps = find_imported_funcs()

    EMAP = {}
    EMAP_DATA = {}

    if args.std_defs:
        for defsfile in args.std_defs:
            sys.stdout.write("Loading Standard Definitions file: {0}\n".format(defsfile.name))
            em_update, emd_update = parseDefsFile(defsfile)
            EMAP.update(em_update)
            EMAP_DATA.update(emd_update)

    batfile = open(path.join(outpath, "makelibs.bat"), 'wb')

    DLLS_TO_STUB = {}

    entrypoints = idautils.Entries()

    for ep_tuple in entrypoints:
        (index, ordinal, ea, name) = ep_tuple

        fwdname = isFwdExport(name, ea)

        if fwdname is not None:
            dll, fname = fwdname.split('.')
            dll = dll.lower()
            d = DLLS_TO_STUB.get(dll, set([]))
            d.add(fname)
            DLLS_TO_STUB[dll] = d

    for dllname, funcs in imps.iteritems():
        name, ext = path.splitext(dllname)
        name = name.lower()
        d = DLLS_TO_STUB.get(name, set([]))

        for func in funcs:
            d.add(func)

        DLLS_TO_STUB[name] = d


    for name, funcs in DLLS_TO_STUB.iteritems():

        deffile = open(path.join(outpath, name+".def"), 'wb')
        deffile.write("EXPORTS\n")
        for func in funcs:

            #if func in EMAP or func in EMAP_DATA:
            deffile.write("{0}\n".format(func))
            #else:

        deffile.close()

        cfile = open(path.join(outpath, name+".c"), 'wb')
        cfile.write(FAKE_DLL)

        for func in funcs:
            argstr = "void"
            if func in EMAP:
                args, conv, ret = EMAP[func]

                argl = ["int a"+str(a) for a in xrange(args)]

                if args > 0:
                   argstr = ", ".join(argl) 

                cfile.write("int {2} {0}({1}) {{return 0;}}\n".format(func, argstr, conv))
            elif func in EMAP_DATA:
                data_size = EMAP_DATA[func]

                cfile.write("unsigned char {1}[{0}];\n".format(data_size, func))

            else:
                sys.stdout.write("WARNING: Stubbing FAKE function for: {0}!{1}\n".format(name, func))
                cfile.write("int __stdcall {0}(void) {{return 0;}}\n".format(func))

        cfile.write("\n")
        cfile.close()

        batfile.write("cl /LD {0}.def {0}.c /link /NODEFAULTLIB /ENTRY:DllMain\n".format(name))
        batfile.write("del {0}.exp {0}.obj {0}.dll\n".format(name))
        batfile.write("\n")

        sys.stdout.write("Processed: {0}\n".format(name))

    batfile.close()
    idc.Exit(0)
