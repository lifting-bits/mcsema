import idautils
import idc

def DEBUG(s):
    #syslog.syslog(str(s))
    sys.stdout.write(str(s))

def _get_flags_from_bits(flag):
    '''
    Translates the flag field in structures (and elsewhere?) into a human readable
    string that is compatible with pasting into IDA or something.
    Returns an empty string if supplied with -1.
    '''
    if -1 == flag:
        return ""
    cls = {
      'MASK':1536,
      1536:'FF_CODE',
      1024:'FF_DATA',
      512:'FF_TAIL',
      0:'FF_UNK',
    }

    comm = {
      'MASK':1046528,
      2048:'FF_COMM',
      4096:'FF_REF',
      8192:'FF_LINE',
      16384:'FF_NAME',
      32768:'FF_LABL',
      65536:'FF_FLOW',
      524288:'FF_VAR',
      49152:'FF_ANYNAME',
    }
 
    _0type = {
      'MASK':15728640,
      1048576:'FF_0NUMH',
      2097152:'FF_0NUMD',
      3145728:'FF_0CHAR',
      4194304:'FF_0SEG',
      5242880:'FF_0OFF',
      6291456:'FF_0NUMB',
      7340032:'FF_0NUMO',
      8388608:'FF_0ENUM',
      9437184:'FF_0FOP',
      10485760:'FF_0STRO',
      11534336:'FF_0STK',
    }
    _1type = {
      'MASK':251658240,
      16777216:'FF_1NUMH',
      33554432:'FF_1NUMD',
      50331648:'FF_1CHAR',
      67108864:'FF_1SEG',
      83886080:'FF_1OFF',
      100663296:'FF_1NUMB',
      117440512:'FF_1NUMO',
      134217728:'FF_1ENUM',
      150994944:'FF_1FOP',
      167772160:'FF_1STRO',
      184549376:'FF_1STK',
    }
    datatype = {
      'MASK':4026531840,
      0:'FF_BYTE',
      268435456:'FF_WORD',
      536870912:'FF_DWRD',
      805306368:'FF_QWRD',
      1073741824:'FF_TBYT',
      1342177280:'FF_ASCI',
      1610612736:'FF_STRU',
      1879048192:'FF_OWRD',
      2147483648:'FF_FLOAT',
      2415919104:'FF_DOUBLE',
      2684354560:'FF_PACKREAL',
      2952790016:'FF_ALIGN',
    }

    output = ""
    output = cls[cls['MASK']&flag]
    
    for category in [comm, _0type, _1type, datatype]:
        #the ida docs define, for example, a FF_0VOID = 0 constant in with the rest
        #  of the 0type constants, but I _think_ that just means
        #  the field is unused, rather than being specific data
        val = category.get(category['MASK']&flag, None)
        if val:
            output = output + " | " + val
    return output

def _collect_func_vars():
    '''
    Collects stack variable data from all functions in the database.
    Returns a list of dictionaries with keys 'name' and 'stackArgs'.
    The 'stackArgs' value is a list of (offset, variable_name, variable_size, variable_flags) tuples.
    Skips stack arguments without names, as well as the special arguments with names " s" and " r".
    Skips functions without frames.
    variable_flags is a string with flag names.
    '''
    functions = list()
    funcs = idautils.Functions()
    for f in funcs:
        name = idc.Name(f)
        end = idc.GetFunctionAttr(f, idc.FUNCATTR_END)
        _locals = idc.GetFunctionAttr(f, idc.FUNCATTR_FRSIZE)
        frame = idc.GetFrame(f)
        if frame is None:
            continue
        stackArgs = list()
        offset = idc.GetFirstMember(frame)
        while offset != 0xffffffff and offset != 0xffffffffffffffff:
            memberName = idc.GetMemberName(frame, offset)
            if memberName is None: 
                #gaps in stack usage are fine, but generate trash output
                #gaps also could indicate a buffer that IDA doesn't recognize
                offset = idc.GetStrucNextOff(frame, offset)
                continue
            if (memberName == " r" or memberName == " s"):
                #the return pointer and start pointer, who cares
                offset = idc.GetStrucNextOff(frame, offset)
                continue
            memberSize = idc.GetMemberSize(frame, offset)
            memberFlag = idc.GetMemberFlag(frame, offset)
            #TODO: handle the case where a struct is encountered (FF_STRU flag)
            flag_str = _get_flags_from_bits(memberFlag)
            stackArgs.append((offset, memberName, memberSize, flag_str))
            offset = idc.GetStrucNextOff(frame, offset)
        functions.append({"name":name, "stackArgs":stackArgs})
    return functions

if __name__ == "__main__":
    print_func_vars()

def print_func_vars():
    print
    print "Stack Vars:"
    func_list = _collect_func_vars()
    for entry in func_list:
        print "{} {{".format(entry['name'])
        for var in entry['stackArgs']:
            print "  {}".format(var)
    print "}"
    print
    print "End Stack Vars"
