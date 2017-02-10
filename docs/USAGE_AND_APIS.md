# Usage and APIs

The `mcsema-lift` tool takes a control flow graph in Google protocol buffer format, and translates it into LLVM bitcode. The generated bitcode is not optimized and will be very noisy with unnecessarily live variables. Unoptimized bitcode is useful for debugging translation errors, but before use this bitcode should be run through the LLVM `opt` tool.

## CFG Recovery

CFG recovery is performed using an IDAPython script, `mc-sema/bin_descend/get_cfg.py`. The output is a serialized Google protocol buffer, defined in `CFG.proto`. This CFG is then used in by the translator to generate LLVM bitcode. 

The following is a description of the current (November, 2013) of the fields in the protocol.

### CFG Definition

The Instruction message represents a single native instruction. 

    message Instruction {
        required    bytes             inst_bytes = 1;
        required    int64             inst_addr = 2;
        optional    int64             true_target = 3;
        optional    int64             false_target = 4;
        required    int32             inst_len = 5;
        optional    int64             data_offset = 6;
        optional    string            ext_call_name = 7;
        optional    int64             call_target = 8;
        optional    int32             reloc_offset = 9;
        optional    JumpTbl           jump_table = 10;
        optional    JumpIndexTbl      jump_index_table = 11;
        optional    string            ext_data_name = 12;
    }

* `inst_bytes`: The bytes comprising this instruction.
* `inst_addr`: The virtual address of where the instruction appears in the original binary.
* `true_target`: Filled in if this is a branch and has a target when true
* `false_target`: Filled in if this is a branch and has a target when false 
* `inst_len`: The instruction length.
* `data_offset`: If this instruction references an item in the data section, this field is the offset from the start of the data section where the said item is located.
* `ext_call_name`: If this instruction references an external API, the name of the external API.
* `call_target`: If this instruction references another function, the virtual address of that function.
* `reloc_offset`: If this instruction has a relocated operand, this field is the offset, in bytes, from the start of the instruction to the beginning of the relocation.
* `jump_table`: This instruction references a jump table
* `jump_index_table`: This instruction references a jump index table (a table used to get the jump table index).
* `ext_data_name`: This instruction references external data



The Block message represents a single basic block.

    message Block {
        repeated    Instruction insts = 1;
        required    int64       base_address = 2;
        repeated    int64       block_follows = 3;
    }

* `insts`: A list of Instruction messages that make up the instructions in this basic block.
* `base_address`: The starting virtual address of the first instruction in this block.
* `block_folows`: The `block_follows` list is used to rebuild the basic block CFG, so it should contain the list of `base_address`es of blocks following this block in the CFG.

The Function message represents a function with a single entry point. Functions that have multiple entry points should be described as separate Function messages.

    message Function {
        repeated    Block   blocks = 1;
        required    int64   entry_address = 2;
    }


* `blocks`: The basic blocks that make up this function.
* `entry_address`: The virtual address that is the entry point of this function. This should be the beginning of the first basic block of the function.

A JumpTbl message represents a jump table. 

    message JumpTbl {
        repeated    int64       table_entries = 1;
        required    int32       zero_offset = 2;
    }

* `table_entries`: Locations of where the jump table points
* `zero_offset`: The index for location 0 in this jump table. This is not always zero because some jumptables jump backwards.


A Jump Index table (a lookup table for jump table indexes).

    message JumpIndexTbl {
        required    bytes       table_entries = 1;
        required    int32       zero_offset = 2;
    }

* `table_entries`: Jump table index values
* `zero_offset`: The index for location 0 in this index table. This is not always zero because some index tables may index backwards.

ExternalFunction messages represent calls to external functions. These can be API calls, or calls to functions in other compilation units.

    message ExternalFunction {
        enum CallingConvention {
          CallerCleanup = 0;
          CalleeCleanup = 1;
          FastCall      = 2;
        }
    
        required    string            symbol_name = 1;
        required    CallingConvention calling_convention = 2;
        required    bool              has_return = 3;
        required    bool              no_return = 4;
        required    int32             argument_count = 5;
    }

* `symbol_name`: The name of the external symbol that should be called.
* `calling_convention`: The calling convention of the function. That is, how arguments are passed to the function, and who cleans up the stack. Currently only CallerCleanup (aka stdcall) and CalleeCleanup (aka cdecl) are supported as calling conventions. 
* `has_return`: This function will return control flow to the caller.
* `no_return`: This function does not return control flow to the caller. Examples of such functions are process terminatino functions. 
* `argument_count`: How many arguments this function takes. In practice, this means how many DWORDs should be pushed on the stack before transferring control to the external function.

ExternalData messages represent external data references. They simply consist of a symbol name and the size of the referenced data.

    message ExternalData {
        required    string      symbol_name = 1;
        required    int32       data_size = 2;
    }

`symbol_name`: name of external data
`data_size`: how much data is referenced?


Normally data is represented as an opaque blob. However, some data has contextual meaning. The DataSymbol message is used to represent data values that are references to other parts of the program, such as function pointers, references to other data items, etc.

    message DataSymbol {
        required int64 base_address = 1;
        required string symbol_name = 2;
    }

* `base_address`: The virtual address of the symbol reference in the data section.
* `symbol_name`: The name of the symbol being referenced.


The Data message represents a data section, which is a blob of opaque data and references to known symbols.

    message Data {
        required    int64           base_address = 1;
        required    bytes           data = 2;
        repeated    DataSymbol      symbols = 3;
        required    bool            read_only = 4;
    }

* `base_address`: The virtual address of the start of the data section.
* `data`: An opaque blob that represents all the data in the data section. Any location that corresponts to a symbol reference should be filled with zeros. 
* `symbols`: References to code or data present in this data section.
* `read_only`: True if this data section is a read only section. Some binary formats require data elements to be present in read-only sections.

Extra data required to fully specify an entry symbol, if the calling convention, argument count and whether the function returns are known during translation.

    message EntrySymbolExtra {
        required    int32                               entry_argc = 1;
        required    ExternalFunction.CallingConvention  entry_cconv = 2;
        required    bool                                does_return = 3;
    }

* `entry_argc`: How many arguments does this entry point take?
* `entry_cconv`: The calling convention of this entry
* `does_return`: Whether this function will return

Specify an entry point into this module

    message EntrySymbol {
        required    string                              entry_name = 1;
        required    int64                               entry_address = 2;
        optional    EntrySymbolExtra                    entry_extra = 3;
    }

* `entry_name`: Name of the entry point
* `entry_address`: Address of the entry point in the module
* `entry_extra`: Information to automatically create a driver for this entry

The Module message represents all the recovered information about the input program.

    message Module {
        repeated    Function            internal_funcs = 1;
        repeated    ExternalFunction    external_funcs = 2;
        repeated    Data                internal_data = 3;
        required    string              module_name = 4;
        repeated    EntrySymbol         entries = 5;
        repeated    ExternalData        external_data = 6;
    }

* `internal_funcs`: A list of functions that were recovered from the program.
* `extrnal_funcs`: APIs and other external functions referenced by the program.
* `internal_data`: Data sections of the program.
* `module_name`: The program name.
* `entries`: A list of entry points into this module. These will be created as drivers by cfg_to_bc.
* `external_data`: A list of external data references

### External Calls

Since external calls (e.g. calls to APIs or other compilation units) are not translated by mcsema, their semantics must be accurately known to reference them from translated code. The information needed about external calls is external name, calling convention, number of arguments, and whether or not the call returns. A default mapping, that includes the vast majority of the Windows API, is provided in `mc-sema/std_defs/std_defs.txt`.

## Translation

The `cfg_to_bc` tool translates a serialized CFG into LLVM bitcode. The bitcode is then consumable by other LLVM tools. The translation step is very noisy and no optimizaiton is attempted. By design, the LLVM optimization tools should remove any un-needed computations later. This makes the translation process fundamentally simple: for each instruction, the translator only needs to emit a native processor to LLVM bitcode translation.

### Function Calls


Functions are modeled as a series of instructions that change register and memory state of the native processor. Due to this, all transalted functions accept a single argument, which is a pointer to a register context structure. The structure represents the complete processor state of the native CPU. During function entry, the context is spilled into local variables. The function then operates on these local variables. During function exit, the local variables are stored back into the register context.

Translation is by design simple and noisy, so a call from one transalted function to another will store local variables to context, only to spill them again upon entering the new function. It is the job of the LLVM optimizer to remove these redundant operations.

External functions, such as APIs and functions in other compilation units, are not translated. These do not take a register context, and instead are called with their actual arguments. The calling convention of external functions must be one that LLVM supports. Currently, the translator only support the stdcall and cdecl calling conventions, but any LLVM supported calling convention can be added in the future.

### Callbacks

Translated functions may be used as callbacks by external functions. An example of this is the Windows API call `CreateThread` -- one of the arguments is a local function that will be the new thread routine. The translator will heuristically detect callbacks, and when found, create a new stub driver for each one. The driver is the inverse of an external call: it will take native CPU state, and use it to populate a register context. Then it will call the translated function with the register context. Upon function exit, the driver will spill the register context into native processor registers and return.

### Assumptions

The translator currently assumes that pointers are 32-bits in width when placing references to code and data in a data section. 

All functions referenced in the data section are assumed to be used as callbacks.

## Using the bitcode

The bitcode output can be used as input to `opt` for optimization and to `llc` as input for object file generation. The demos in `mc-sema/tests` show how to use `cfg_to_bc`, `opt` and `llc` to take a COFF object, translate it, and link it with existing code.

Prior to using any generated bitcode, it is recommended to run it through `opt` with the `-O3` optimization level.

