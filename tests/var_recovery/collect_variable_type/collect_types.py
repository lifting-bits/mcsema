import idaapi

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
    funcs = Functions()
    for f in funcs:
        func_var_data = _collect_individual_func_vars(f)
        if func_var_data is not None:
            _find_local_references(f, func_var_data)
            functions.append(func_var_data)
    return functions

def _signed_from_unsigned64(val):
    if val & 0x8000000000000000:
        return -0x10000000000000000 + val
    return val

def _signed_from_unsigned32(val):
    if val & 0x80000000:
        return -0x100000000 + val
    return val

if idaapi.get_inf_structure().is_64bit():
    _signed_from_unsigned = _signed_from_unsigned64
    _base_ptr = "rbp"
    _stack_ptr = "rsp"
elif idaapi.get_inf_structure().is_32bit():
    _signed_from_unsigned = _signed_from_unsigned32
    _base_ptr = "ebp"
    _stack_ptr = "esp"

def _collect_individual_func_vars(f):
    name = Name(f)
    end = GetFunctionAttr(f, FUNCATTR_END)
    _locals = GetFunctionAttr(f, FUNCATTR_FRSIZE)
    frame = GetFrame(f)
    if frame is None:
        return None
    stackArgs = dict()
    #grab the offset of the stored frame pointer, so that
    #we can correlate offsets correctly in referant code
    # e.g., EBP+(-0x4) will match up to the -0x4 offset
    delta = GetMemberOffset(frame, " s")
    if -1 == delta:
        #indicates that it wasn't found. Unsure exactly what to do
        # in that case, punting for now
        delta = 0
    offset = GetFirstMember(frame)
    #TODO: the following line should check the binary's address size as appropriate
    while -1 != _signed_from_unsigned(offset):
        memberName = GetMemberName(frame, offset)
        if memberName is None:
            #gaps in stack usage are fine, but generate trash output
            #gaps also could indicate a buffer that IDA doesn't recognize
            offset = GetStrucNextOff(frame, offset)
            continue
        if (memberName == " r" or memberName == " s"):
            #the return pointer and saved registers, skip them
            offset = GetStrucNextOff(frame, offset)
            continue
        memberSize = GetMemberSize(frame, offset)
        memberFlag = GetMemberFlag(frame, offset)
        #TODO: handle the case where a struct is encountered (FF_STRU flag)
        flag_str = _get_flags_from_bits(memberFlag)
        stackArgs[offset-delta] = [memberName, memberSize, flag_str]
        offset = GetStrucNextOff(frame, offset)
    return {"name":name, "stackArgs":stackArgs}

def _find_local_references(func, func_var_data):
    #naive approach at first
    base_ptr_format = "[{}+".format(_base_ptr)
    stack_ptr_format = "[{}+".format(_stack_ptr)
    frame = GetFrame(func)
    if frame is None:
        return
    regs = dict()
    referers = set() #members of this set contain the address of an element on the stack
    dereferences = dict() #members of this collection contain the data of an element on the stack
    for addr in FuncItems(func):
        if "lea"==GetMnem(addr):
            if base_ptr_format in GetOpnd(addr, 1) or stack_ptr_format in GetOpnd(addr, 1):
                #right now just capture that it's a local reference, not its referant
                referers.add(GetOpnd(addr, 0))
        if "mov"==GetMnem(addr):
            referers.discard(GetOpnd(addr, 0))
            dereferences.pop(GetOpnd(addr, 0), None)
            if GetOpnd(addr, 1) in referers:
                target_op = GetOpnd(addr, 0)
                if base_ptr_format in target_op:
                    target_offset = target_op[len(base_ptr_format):target_op.index(']')]
                    offset = _signed_from_unsigned(GetOperandValue(addr, 0))
                    if offset in func_var_data["stackArgs"].keys():
                        func_var_data["stackArgs"][offset][2] += " | LOCAL_REFERER"
                else:
                    # lea eax, [ebp-8]
                    # mov ebx, eax
                    # mov [ebp-4], ebx
                    referers.add(target_op)
            elif base_ptr_format in GetOpnd(addr, 1) or stack_ptr_format in GetOpnd(addr, 1):
                offset = _signed_from_unsigned(GetOperandValue(addr, 1))
                if offset in func_var_data["stackArgs"].keys():
                    dereferences[GetOpnd(addr, 0)] = offset
        if "call"== GetMnem(addr):
            target_op = GetOpnd(addr, 0)
            if target_op in referers:
                pass
            if target_op in dereferences:
                # mov eax, [ebp+4]
                # call eax
                func_var_data["stackArgs"][dereferences[target_op]][2] += " | CODE_PTR"
            #clear the referers and dereferences?

var_data = _collect_func_vars()
for entry in sorted(var_data, key=lambda x:x['name']):
    print "{} {{".format(entry['name'])
    for offset in sorted(entry['stackArgs'].keys())
        print "  {} {}".format(offset, entry['stackArgs'][offset])
    print "}"
