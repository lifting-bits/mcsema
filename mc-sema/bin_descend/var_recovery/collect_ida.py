import idaapi
import idautils
import idc

def DEBUG(s):
    #syslog.syslog(str(s))
    sys.stdout.write(str(s))

def _signed_from_unsigned64(val):
    if val & 0x8000000000000000:
        return -0x10000000000000000 + val
    return val

def _signed_from_unsigned32(val):
    if val & 0x80000000:
        return -0x100000000 + val
    return val

def _mark_function_args_ms64(referers, dereferences, func_var_data):
    for reg in ["rcx", "rdx", "r8", "r9"]:
        _mark_func_arg(reg, referers, dereferences, func_var_data)

def _mark_function_args_sysv64(referers, dereferences, func_var_data):
    for reg in ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]:
        _mark_func_arg(reg, referers, dereferences, func_var_data)

def _mark_function_args_x86(referers, dereferences, func_var_data):
    pass #TODO. urgh.

def _mark_func_arg(reg, referers, dereferences, func_var_data):
    if reg in referers:
        # lea rdi, [rbp+4]
        # call rax
        offset = referers[reg]
        if offset in func_var_data["stackArgs"]:
            func_var_data["stackArgs"][offset]["flags"].add("FUNC_ARG_REF")
    if reg in dereferences:
        # mov rdi, [rbp+4]
        # call rax
        offset = dereferences[reg]
        if offset in func_var_data["stackArgs"]:
            func_var_data["stackArgs"][offset]["flags"].add("FUNC_ARG_VALUE")

def _translate_reg_32(reg):
    return reg

def _translate_reg_64(reg):
    return {"edi":"rdi",
            "esi":"rsi",
            "eax":"rax",
            "ebx":"rbx",
            "ecx":"rcx",
            "edx":"rdx",
            "ebp":"rbp",
            "esp":"rsp"}.get(reg, reg)


if idaapi.get_inf_structure().is_64bit():
    _signed_from_unsigned = _signed_from_unsigned64
    _base_ptr = "rbp"
    _stack_ptr = "rsp"
    _trashed_regs = ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"]
    _mark_args = _mark_function_args_sysv64
    _translate_reg = _translate_reg_64
elif idaapi.get_inf_structure().is_32bit():
    _signed_from_unsigned = _signed_from_unsigned32
    _base_ptr = "ebp"
    _stack_ptr = "esp"
    _trashed_regs = ["eax", "ecx", "edx"]
    _mark_args = _mark_function_args_x86
    _translate_reg = _translate_reg_32
_base_ptr_format = "[{}+".format(_base_ptr)
_stack_ptr_format = "[{}+".format(_stack_ptr)

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

    flags = set()
    flags.add(cls[cls['MASK']&flag])

    for category in [comm, _0type, _1type, datatype]:
        #the ida docs define, for example, a FF_0VOID = 0 constant in with the rest
        #  of the 0type constants, but I _think_ that just means
        #  the field is unused, rather than being specific data
        val = category.get(category['MASK']&flag, None)
        if val:
            flags.add(val)
    return flags

def BlockItems(BB):
    '''
    Return a list of items in a basic block

    @param BB: basic block object

    @return: ea of each item in block
    '''
    fii = idaapi.func_item_iterator_t()
    ok = fii.set_range(BB.startEA, BB.endEA)
    while ok:
        yield fii.current()
        ok = fii.next_code()

def collect_func_vars(F, global_var_data):
    '''
    Collect stack variable data from a single function F.
    Returns a dict of stack variables 'stackArgs'.
    Skips stack arguments without names, as well as the special arguments with names " s" and " r".
    variable_flags is a string with flag names.
    '''

    f = F.entry_address
    return collect_function_vars(f, global_var_data)

def collect_function_vars(f, global_var_data):
    stackArgs = dict()
    name = idc.Name(f)
    end = idc.GetFunctionAttr(f, idc.FUNCATTR_END)
    _locals = idc.GetFunctionAttr(f, idc.FUNCATTR_FRSIZE)
    _uses_bp = 0 != (idc.GetFunctionFlags(f) & idc.FUNC_FRAME)
    frame = idc.GetFrame(f)
    if frame is None:
        return stackArgs

    #grab the offset of the stored frame pointer, so that
    #we can correlate offsets correctly in referent code
    # e.g., EBP+(-0x4) will match up to the -0x4 offset
    delta = idc.GetMemberOffset(frame, " s")
    if -1 == delta:
        #indicates that it wasn't found. Unsure exactly what to do
        # in that case, punting for now
        delta = 0

    offset = idc.GetFirstMember(frame)
    while -1 != _signed_from_unsigned(offset):
        memberName = idc.GetMemberName(frame, offset)
        if memberName is None:
            # gaps in stack usage are fine, but generate trash output
            # gaps also could indicate a buffer that IDA doesn't recognize
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
        stackArgs[offset-delta] = {"name":memberName,
                                   "size":memberSize,
                                   "flags":flag_str,
                                   "writes":set(),
                                   "referent":set(),
                                   "reads":set()}
        offset = idc.GetStrucNextOff(frame, offset)
    #functions.append({"name":name, "stackArgs":stackArgs})
    if len(stackArgs) > 0:
        _find_local_references(f, {"name":name, "stackArgs":stackArgs, "uses_bp":_uses_bp, "globals":dict()}, global_var_data)

    return stackArgs

def collect_variables():
    '''
    Collects stack variable data from all functions in the database.
    Returns a list of dictionaries with keys 'ea' and 'stackArgs'.
    The 'stackArgs' value is a list of (offset, variable_name, variable_size, variable_flags) tuples.
    Skips stack arguments without names, as well as the special arguments with names " s" and " r".
    Skips functions without frames.
    variable_flags is a string with flag names.
    '''
    class functionWrapper(object):
        def __init__(self, addr):
            self.entry_address = addr

    functions = list()
    global_var_data = dict() #global address -> usage
    funcs = idautils.Functions()
    for f in funcs:
        #name = idc.Name(f)
        f_ea = idc.GetFunctionAttr(f, idc.FUNCATTR_START)
        f_vars = collect_func_vars(functionWrapper(f), global_var_data)
        functions.append({"ea":f_ea, "stackArgs":f_vars, "name":idc.Name(f)})

    return {"functions":functions, "globals":global_var_data}

def _process_mov_inst(addr, referers, dereferences, func_var_data, global_var_data):
    '''
    - type data regarding the target operand is discarded
    - if the source operand contains an address of a stack variable:
        if the target is a reg, just update the target as tainted with the address
        if the target is a stack var, flag it as a local reference
    - if the target operand is a stack var, add the EA of the inst to that var's operators
    '''

    #remove the target operand from the taint collections
    target_op = _translate_reg(idc.GetOpnd(addr, 0))
    read_op = _translate_reg(idc.GetOpnd(addr, 1))
    target_on_stack = (_stack_ptr_format in target_op) or (func_var_data["uses_bp"] and (_base_ptr_format in target_op))
    read_on_stack = (_stack_ptr_format in read_op) or (func_var_data["uses_bp"] and (_base_ptr_format in read_op))

    target_global = idc.GetOpType(addr, 0) == 2 #2 is a memory reference
    read_global = idc.GetOpType(addr, 1) == 2

    referers.pop(target_op, None)
    dereferences.pop(target_op, None)


    if read_op in referers:
        # handling the two following mov cases in this block:
        #   lea eax, [ebp-8]  #collecting the address of a stack variable
        #   mov ebx, eax  # copying referent data around
        #   mov [ebp-4], ebx   # copying referent data into a stack variable (i.e., moving an address into a pointer)

        if target_on_stack:
            #moving referent data into a stack variable (i.e., moving an address into a pointer)
            offset = _signed_from_unsigned(idc.GetOperandValue(addr, 0))
            if offset in func_var_data["stackArgs"].keys():
                func_var_data["stackArgs"][offset]["flags"].add("LOCAL_REFERER")
                # collect which stack variable offset this variable points to
                func_var_data["stackArgs"][offset]["referent"].add(referers[read_op])
        else:
            #moving referent data around
            referers[target_op] = referers[read_op]
    elif read_op in dereferences:
        if target_on_stack:
            offset = _signed_from_unsigned(idc.GetOperandValue(addr, 0))
            if offset in func_var_data["stackArgs"].keys():
                func_var_data["stackArgs"][offset]["flags"].add("LOCAL_COPY")
        else:
            #moving dereferenced data around
            dereferences[target_op] = dereferences[read_op]
    elif read_on_stack:
        # mov eax, [ebp-4]  //eax now tainted with stack var data
        offset = _signed_from_unsigned(idc.GetOperandValue(addr, 1))
        if offset in func_var_data["stackArgs"].keys():
            dereferences[target_op] = offset

    ''' collect EAs of instructions that write to stack variables'''
    if target_on_stack:
        # mov [ebp-4], eax
        offset = _signed_from_unsigned(idc.GetOperandValue(addr, 0))
        if offset in func_var_data["stackArgs"].keys():
            func_var_data["stackArgs"][offset]["writes"].add(addr)

    if target_global:
        memory_ref = _signed_from_unsigned(idc.GetOperandValue(addr, 0))
        var_name = idc.GetOpnd(addr, 0)
        if var_name not in global_var_data:
            global_var_data[var_name] = dict(reads=set(), writes=set(), offset=memory_ref)
        global_var_data[var_name]["writes"].add(addr)
        if var_name not in func_var_data["globals"]:
            func_var_data["globals"][var_name] = dict(reads=set(), writes=set(), offset=memory_ref)
        func_var_data["globals"][var_name]["writes"].add(addr)


    ''' collect EAs of instructions that read from stack variables'''
    if read_on_stack:
        # mov eax, [ebp-4]
        offset = _signed_from_unsigned(idc.GetOperandValue(addr, 1))
        if offset in func_var_data["stackArgs"].keys():
            func_var_data["stackArgs"][offset]["reads"].add(addr)

    if read_global:
        memory_ref = _signed_from_unsigned(idc.GetOperandValue(addr, 1))
        var_name = idc.GetOpnd(addr, 1)
        if var_name not in global_var_data:
            global_var_data[var_name] = dict(reads=set(), writes=set(), offset=memory_ref)
        global_var_data[var_name]["reads"].add(addr)
        if memory_ref not in func_var_data["globals"]:
            func_var_data["globals"][var_name] = dict(reads=set(), writes=set(), offset=memory_ref)
        func_var_data["globals"][var_name]["reads"].add(addr)

def _process_lea_inst(addr, referers, dereferences, func_var_data, global_var_data):
    read_op = _translate_reg(idc.GetOpnd(addr, 1))
    target_op = _translate_reg(idc.GetOpnd(addr, 0))
    read_on_stack = (_stack_ptr_format in read_op) or (func_var_data["uses_bp"] and (_base_ptr_format in read_op))
    read_global = idc.GetOpType(addr, 1) == 2
    if read_on_stack:
        #referers[operand] = offset
        referers[target_op] = _signed_from_unsigned(idc.GetOperandValue(addr, 1))

def _process_call_inst(addr, referers, dereferences, func_var_data, global_var_data):
    target_op = _translate_reg(idc.GetOpnd(addr, 0))
    if target_op in referers:
        #maybe do something here? explicitly calling to the stack. Hrm.
        pass
    if target_op in dereferences:
        # mov eax, [ebp+4]
        # call eax
        func_var_data["stackArgs"][dereferences[target_op]]["flags"].add("CODE_PTR")

    try:
        _mark_args(referers, dereferences, func_var_data)
    except KeyError as e:
        print "Key Error at addr {:x}".format(addr)
        raise

    # clear reference data for non preserved regs
    for reg in _trashed_regs:
        dereferences.pop(reg, None)
        referers.pop(reg, None)

def _process_basic_block(BB, func_var_data, referers, dereferences, visited_bb, global_var_data):
    if BB.startEA in visited_bb:
        return
    visited_bb.add(BB.startEA)
    for addr in BlockItems(BB):
        _funcs = {"lea":_process_lea_inst,
                  "mov":_process_mov_inst,
                  "call":_process_call_inst}
        func = _funcs.get(idc.GetMnem(addr), None)
        if func:
            func(addr, referers, dereferences, func_var_data, global_var_data)
        else:
            #check for reads from stack var
            read_op = _translate_reg(idc.GetOpnd(addr, 1))
            read_on_stack = (_stack_ptr_format in read_op) or (func_var_data["uses_bp"] and (_base_ptr_format in read_op))
            if read_on_stack:
                offset = _signed_from_unsigned(idc.GetOperandValue(addr, 1))
                if offset in func_var_data["stackArgs"].keys():
                    func_var_data["stackArgs"][offset]["reads"].add(addr)
                else:
                    pass # Hmmm. Unsure what just happened.
                    #print "offset {} not found at address {}".format(hex(offset), hex(addr))

    for block in BB.succs():
        _process_basic_block(block, func_var_data, referers.copy(), dereferences.copy(), visited_bb, global_var_data)

def _find_local_references(func, func_var_data, global_var_data):
    frame = idc.GetFrame(func)
    if frame is None:
        return
    referers = dict() # members of this collection contain the address of an element on the stack. keys are operands, values are stack offset
    dereferences = dict() # members of this collection contain the data of an element on the stack
    visited_bb = set()
    next_bb = list()

    #build the dict of addr->basicblock objects
    fc = idaapi.FlowChart(idaapi.get_func(func))
    _process_basic_block(fc[0], func_var_data, referers, dereferences, visited_bb, global_var_data)

def print_func_vars():
    print
    variable_data = collect_variables()

    print "Global Vars:"
    import pprint
    pprint.pprint(variable_data["globals"])
    print "End Global Vars\n"
    print "Stack Vars:"
    for entry in variable_data["functions"]:
        print "{} {{".format(entry['name'])
        for offset in sorted(entry['stackArgs'].keys()):
            print "  {}: {}".format(hex(offset), entry['stackArgs'][offset])
    print "}"
    print
    print "End Stack Vars"

if __name__ == "__main__":
   print_func_vars()
