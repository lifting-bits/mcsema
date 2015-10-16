/*
Copyright (c) 2014, Trail of Bits
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

  Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

  Redistributions in binary form must reproduce the above copyright notice, this  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.

  Neither the name of Trail of Bits nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include <iostream>
#include "X86.h"
#include "peToCFG.h"
#include "CFG.pb.h"
#include <boost/graph/breadth_first_search.hpp>
#include "../cfgToLLVM/Externals.h"
#include "../cfgToLLVM/JumpTables.h"
#include "../common/to_string.h"
#include "LExcn.h"

using namespace llvm;
using namespace std;


NativeModule::NativeModule(string modName, list<NativeFunctionPtr> f, llvm::MCInstPrinter *p) :
                                                        funcs(f),
                                                        callGraph(f.size()),
                                                        nextID(0),
                                                        nameStr(modName),
                                                        MyPrinter(p)
{

    return;
}

string NativeModule::printModule(void) {
    string  s = "";

    return s;
}

NativeBlockPtr NativeFunction::block_from_id(uint64_t id) {
    NativeBlockPtr                            b;
    map<uint64_t, NativeBlockPtr>::iterator   it;

    it = this->IDtoBlock.find(id);
    if( it != this->IDtoBlock.end() ) {
        b = (*it).second;
    }

    return b;
}

uint64_t NativeFunction::entry_block_id() const {

    map<VA, uint64_t>::const_iterator   it = this->baseToID.find(this->funcEntryVA);
    LASSERT(it != this->baseToID.end(), "Block not found");

    uint64_t    fBID = (*it).second;

    return fBID;
}

NativeBlockPtr NativeFunction::block_from_base(VA base) {
    NativeBlockPtr  b;

    map<VA, uint64_t>::iterator   it = this->baseToID.find(base);
    LASSERT(it != this->baseToID.end(), "Block not found");

    uint64_t    fBID = (*it).second;

    b = this->block_from_id(fBID);

    LASSERT( b, "" );

    return b;
}

void NativeFunction::compute_graph(void) {
    //build a CFG in boost BGL from the data structures we have
    this->graph = new CFG(this->nextBlockID);

    //iterate over all of the keys in IDtoBlock
    for(map<uint64_t, NativeBlockPtr>::iterator it = this->IDtoBlock.begin();
        it != this->IDtoBlock.end();
        ++it)
    {
        uint64_t        blockId = (*it).first;
        NativeBlockPtr  block = (*it).second;
        list<VA>        &blockFollows = block->get_follows();


        for(list<VA>::iterator fit = blockFollows.begin();
            fit != blockFollows.end();
            ++fit)
        {
            uint64_t    fVA = *fit;
            uint64_t    fBID;

            //find the block ID for this VA
            map<VA,uint64_t>::iterator mit = this->baseToID.find(fVA);
            LASSERT( mit != this->baseToID.end(), "" );
            fBID = (*mit).second;

            //add an edge between the current block ID and the following
            //block ID
            add_edge(blockId, fBID, *(this->graph));
        }
    }

    return;
}

NativeBlock::NativeBlock(VA b, MCInstPrinter *p) : baseAddr(b), MyPrinter(p) { }

string NativeBlock::print_block(void) {
    string                  s;
    list<InstPtr>::iterator it;

    s.append(to_string<uint64_t>(this->get_base(), hex)+"\\n ");
    for(it = this->instructions.begin();
        it != this->instructions.end();
        ++it)
    {
        InstPtr ip = *it;
        string st = ip->printInst();
        s.append(st+"\\n ");
    }

    return s;
}

void NativeBlock::add_inst(InstPtr p) {
    this->instructions.push_back(p);
    return;
}

void NativeFunction::add_block(NativeBlockPtr b) {
    uint64_t    blockBase = b->get_base();
    uint64_t    curBlockID = this->nextBlockID;

    this->nextBlockID++;

    //check and make sure that we haven't added this block before
    map<VA, uint64_t>::iterator   it = this->baseToID.find(blockBase);
    LASSERT(it == this->baseToID.end(), "Added duplicate block!");

    this->baseToID[blockBase] = curBlockID;
    this->IDtoBlock[curBlockID] = b;

    return;
}

const llvm::Target *findDisTarget(string arch) {
    const llvm::Target  *tgt = NULL;

    for(llvm::TargetRegistry::iterator  it = llvm::TargetRegistry::begin(),
        ie = llvm::TargetRegistry::end();
        it != ie;
        ++it)
    {
        if( arch == it->getName() ) {
            tgt = &*it;
            break;
        }
    }

    return tgt;
}

class cfg_visitor : public boost::default_bfs_visitor {
private:
    NativeFunctionPtr   natFun;
    NativeModulePtr     natMod;
public:
    cfg_visitor(NativeFunctionPtr n, NativeModulePtr m) :
        natFun(n), natMod(m) { }

    template < typename Vertex, typename Graph >
    void discover_vertex(Vertex u, const Graph & g) const;
};

template <typename Vertex, typename Graph>
void cfg_visitor::discover_vertex(Vertex u, const Graph &g) const {
    NativeBlockPtr  curBlock = this->natFun->block_from_id(u);

    LASSERT( curBlock, "");

    list<InstPtr>   stmts = curBlock->get_insts();

    for(list<InstPtr>::iterator it = stmts.begin();
        it != stmts.end();
        ++it)
    {
        InstPtr inst = *it;

        if( inst->has_ext_call_target() ) {
            ExternalCodeRefPtr   ex = inst->get_ext_call_target();

            this->natMod->addExtCall(ex);
        }

        if( inst->has_ext_data_ref() ) {
            ExternalDataRefPtr  ex = inst->get_ext_data_ref();

            this->natMod->addExtDataRef(ex);
        }
    }

    return;
}

void addExterns(list<NativeFunctionPtr> funcs, NativeModulePtr mod) {
    for(list<NativeFunctionPtr>::iterator fit = funcs.begin();
        fit != funcs.end();
        ++fit)
    {
        NativeFunctionPtr   fun = *fit;
        cfg_visitor         visitor(fun, mod);
        CFG                 funcGraph = fun->get_cfg();

        boost::breadth_first_search(funcGraph,
                                boost::vertex(0, funcGraph),
                                boost::visitor(visitor));
    }

    return;
}

string NativeFunction::get_name(void) {
    return string("sub_"+to_string<VA>(this->funcEntryVA, hex));
}

string NativeBlock::get_name(void) {
    return string("block_0x"+to_string<VA>(this->baseAddr, hex));
}

void NativeModule::addDataSection(VA base, std::vector<uint8_t> &bytes)
{

  DataSection ds;
  DataSectionEntry dse(base, bytes);
  ds.addEntry(dse);

  this->dataSecs.push_back(ds);
}

void NativeModule::addDataSection(const DataSection &d)
{
    this->dataSecs.push_back(d);
}

InstPtr deserializeInst(const ::Instruction &inst, LLVMByteDecoder &decoder)
{
  VA                      addr = inst.inst_addr();
  boost::int64_t          tr_tgt = inst.true_target();
  boost::int64_t          fa_tgt = inst.false_target();
  //uint32_t         len = inst.inst_len();
  string                  instData = inst.inst_bytes();
  vector<uint8_t>  bytes(instData.begin(), instData.end());
  BaseBufferMemoryObject  bbmo(bytes, addr);

  //produce an MCInst from the instruction buffer using the ByteDecoder
  InstPtr ip = decoder.getInstFromBuff(addr, &bbmo);

  if(tr_tgt > 0)
    ip->set_tr(tr_tgt);

  if(fa_tgt > 0)
    ip->set_fa(fa_tgt);

  if(inst.has_data_offset())
    ip->set_data_offset(inst.data_offset());

  if(inst.has_ext_call_name())
  {
    ExternalCodeRefPtr p(new ExternalCodeRef(inst.ext_call_name()));
    ip->set_ext_call_target(p);
  }

  if(inst.has_ext_data_name())
  {
    ExternalDataRefPtr p(new ExternalDataRef(inst.ext_data_name()));
    ip->set_ext_data_ref(p);
  }

  if(inst.has_call_target())
  {
      ip->set_call_tgt(inst.call_target());
  }

  if(inst.has_reloc_offset()) {
      ip->set_reloc_offset(inst.reloc_offset());
  }

  if(inst.has_jump_table()) {
      // create new jump table

      const ::JumpTbl &jmp_tbl = inst.jump_table();
      vector<VA> table_entries;

      for(int i = 0; i < jmp_tbl.table_entries_size(); i++) {
          table_entries.push_back(jmp_tbl.table_entries(i));
      }

      VA data_offset = (VA)(-1);
      if (jmp_tbl.has_offset_from_data()) {
          data_offset = jmp_tbl.offset_from_data();
      }
      MCSJumpTable *jmp = new MCSJumpTable(
              table_entries,
              jmp_tbl.zero_offset(),
              data_offset);
      ip->set_jump_table(MCSJumpTablePtr(jmp));
  }

  if(inst.has_jump_index_table()) {
      // create new jump table

      const ::JumpIndexTbl &idx_tbl = inst.jump_index_table();
      const string& serialized_tbl = idx_tbl.table_entries();
      vector<uint8_t> tbl_bytes(serialized_tbl.begin(), serialized_tbl.end());

      JumpIndexTable *idx = new JumpIndexTable(tbl_bytes, idx_tbl.zero_offset());
      ip->set_jump_index_table(JumpIndexTablePtr(idx));
  }

  if(inst.has_system_call_number()) {
      ip->set_system_call_number(inst.system_call_number());
  }

  if(inst.has_local_noreturn()) {
      ip->set_local_noreturn();
  }

  return ip;
}

NativeBlockPtr  deserializeBlock( const ::Block   &block,
                                  LLVMByteDecoder &decoder)
{
  NativeBlockPtr  natB =
    NativeBlockPtr(new NativeBlock(block.base_address(), decoder.getPrinter()));
  /* read all the instructions in */
  for(int i = 0; i < block.insts_size(); i++)
    natB->add_inst(deserializeInst(block.insts(i), decoder));

  /* add the follows */
  for(int i = 0; i < block.block_follows_size(); i++)
    natB->add_follow(block.block_follows(i));

  return natB;
}

NativeFunctionPtr deserializeFunction(const ::Function  &func,
                                      LLVMByteDecoder   &decoder)
{
  NativeFunctionPtr natF =
    NativeFunctionPtr(new NativeFunction(func.entry_address()));

  //read all the blocks from this function
  for(int i = 0; i < func.blocks_size(); i++)
  {
    natF->add_block(deserializeBlock(func.blocks(i), decoder));
  }

  natF->compute_graph();
  return natF;
}

ExternalCodeRef::CallingConvention deserCC(::ExternalFunction::CallingConvention k)
{
  switch(k)
  {
    case ::ExternalFunction::CallerCleanup:
      return ExternalCodeRef::CallerCleanup;
      break;

    case ::ExternalFunction::CalleeCleanup:
      return ExternalCodeRef::CalleeCleanup;
      break;

    case ::ExternalFunction::FastCall:
      return ExternalCodeRef::FastCall;
      break;

    default:
      throw LErr(__LINE__, __FILE__, "Unsupported CC");
  }
}

ExternalCodeRefPtr deserializeExt(const ::ExternalFunction &f)
{
  ExternalCodeRef::CallingConvention c = deserCC(f.calling_convention());
  string                        symName = f.symbol_name();
  ExternalCodeRef::ReturnType        retTy;
  uint32_t                      argCount = f.argument_count();

  if(f.has_return())
  {
    retTy = ExternalCodeRef::IntTy;
  }
  else
  {
    retTy = ExternalCodeRef::VoidTy;
  }

  if(f.no_return())
  {
    retTy = ExternalCodeRef::NoReturn;
  }

  ExternalCodeRefPtr ext =
    ExternalCodeRefPtr(new ExternalCodeRef(symName, argCount, c, retTy));

  return ext;
}

ExternalDataRefPtr deserializeExtData(const ::ExternalData &ed)
{
  string                        symName = ed.symbol_name();
  uint32_t                      data_size = ed.data_size();

  ExternalDataRefPtr ext =
    ExternalDataRefPtr(new ExternalDataRef(symName, data_size));

  return ext;
}

static DataSectionEntry deserializeDataSymbol(const ::DataSymbol &ds) {
    cout << "Deserializing symbol at: " 
         << to_string<VA>(ds.base_address(), hex) << ", "
         << ds.symbol_name() << ", "
         << to_string<VA>(ds.symbol_size(), hex) << endl;

    return DataSectionEntry(ds.base_address(), ds.symbol_name(), ds.symbol_size());
}

static DataSectionEntry makeDSEBlob(
        const vector<uint8_t> &bytes,
        uint64_t start, // offset in bytes vector
        uint64_t end, // offset in bytes vector
        uint64_t base_va)  // virtual address these bytes are based at
{
    vector<uint8_t> blob_bytes(
            bytes.begin() + (start),
            bytes.begin() + (end)
            );
    return DataSectionEntry(base_va, blob_bytes);

}

static
void deserializeData(const ::Data &d, DataSection &ds)
{
  string            dt = d.data();
  vector<uint8_t>   bytes(dt.begin(), dt.end());
  uint64_t base_address = d.base_address();
  uint64_t cur_pos = base_address;

  ds.setReadOnly(d.read_only());

  //DataSectionEntry  dse(d.base_address(), bytes);
  vector<uint8_t>::iterator bytepos = bytes.begin();

  // assumes symbols are in-order
  for(int i = 0; i < d.symbols_size(); i++) {
        DataSectionEntry dse_sym = deserializeDataSymbol(d.symbols(i));
        string sym_name;
        dse_sym.getSymbol(sym_name);
        uint64_t dse_base = dse_sym.getBase();
        // symbol next to blob
        cout << "cur_pos: " << to_string<VA>(cur_pos, hex) << endl;
        cout << "dse_base: " << to_string<VA>(dse_base, hex) << endl;
        if(dse_base > cur_pos) {
            ds.addEntry(makeDSEBlob(
                        bytes,
                        cur_pos-base_address,
                        dse_base-base_address,
                        cur_pos)
                    );
            ds.addEntry(dse_sym);

            cur_pos = dse_base+dse_sym.getSize();
            cout << "new_cur_pos: " << to_string<VA>(cur_pos, hex) << endl;

        }
        // symbols next to each other
        else if (dse_base == cur_pos) {
            ds.addEntry(dse_sym);

            cur_pos = dse_base+dse_sym.getSize();
            cout << "new_cur_pos2: " << to_string<VA>(cur_pos, hex) << endl;
            string sym_name;
            dse_sym.getSymbol(sym_name);
        } else {
            cerr << __FILE__ << ":" << __LINE__ << endl;
            cerr << "Deserialized an out-of-order symbol!" << endl;
            throw LErr(__LINE__, __FILE__, "Deserialized an out-of-order symbol!");
        }
  }

  // there is a data blob after the last symbol
  // or there are no symbols
  if(cur_pos < base_address+bytes.size()) {
     ds.addEntry(makeDSEBlob(
                 bytes,
                 cur_pos-base_address,
                 bytes.size(),
                 cur_pos)
             );
  }


}

NativeModulePtr readProtoBuf(std::string fName, const llvm::Target *T) {
  NativeModulePtr m;
  ::Module        serializedMod;
  ifstream        inStream(fName.c_str(), ios::binary);
  LLVMByteDecoder decode(std::string(T->getName()));

  GOOGLE_PROTOBUF_VERIFY_VERSION;

  if(!inStream.good()) {
    cout << "Failed to open file " << fName << endl;
    return m;
  }

  //read the protobuf object in
  if(serializedMod.ParseFromIstream(&inStream)) {
    //now, make everything we need to build a NativeModulePtr
    list<NativeFunctionPtr> foundFuncs;
    list<ExternalCodeRefPtr>     externFuncs;
    list<ExternalDataRefPtr>     externData;
    list<DataSection>              dataSecs;

    //iterate over every function
    for(int i = 0; i < serializedMod.internal_funcs_size(); i++) {
      const ::Function  &f = serializedMod.internal_funcs(i);
      cout << "Deserializing functions..." << endl;
      foundFuncs.push_back(deserializeFunction(f, decode));
    }

    //iterate over every data element
    for(int i = 0; i < serializedMod.internal_data_size(); i++) {
      const ::Data  &d = serializedMod.internal_data(i);
      DataSection ds;
      cout << "Deserializing data..." << endl;
      deserializeData(d, ds);
      dataSecs.push_back(ds);
    }

    //iterate over every external function definition
    for(int i = 0; i < serializedMod.external_funcs_size(); i++) {
      const ::ExternalFunction  &f = serializedMod.external_funcs(i);
      cout << "Deserializing externs..." << endl;
      externFuncs.push_back(deserializeExt(f));
    }

    //iterate over every external data definition
    for(int i = 0; i < serializedMod.external_data_size(); i++) {
      const ::ExternalData  &ed = serializedMod.external_data(i);
      cout << "Deserializing external data..." << endl;
      externData.push_back(deserializeExtData(ed));
    }

    //create the module
    cout << "Creating module..." << endl;
    m = NativeModulePtr(
          new NativeModule(serializedMod.module_name(), foundFuncs, NULL));

    cout << "Setting target..." << endl;
    m->setTarget(T);
    cout << "Done setting target" << endl;

    //populate the module with externals calls
    cout << "Adding external funcs..." << endl;
    for(list<ExternalCodeRefPtr>::iterator it = externFuncs.begin();
        it != externFuncs.end();
        ++it)
    {
      m->addExtCall(*it);
    }

    //populate the module with externals data
    cout << "Adding external data..." << endl;
    for(list<ExternalDataRefPtr>::iterator it = externData.begin();
        it != externData.end();
        ++it)
    {
      m->addExtDataRef(*it);
    }

    //populate the module with internal data
    cout << "Adding internal data..." << endl;
    for(list<DataSection>::iterator it = dataSecs.begin();
        it != dataSecs.end();
        ++it)
    {
      m->addDataSection(*it);
    }

    // set entry points for the module
    cout << "Adding entry points..." << endl;
    for(int i = 0; i < serializedMod.entries_size(); i++) {
        const ::EntrySymbol &es = serializedMod.entries(i);

        NativeModule::EntrySymbol native_es(es.entry_name(), es.entry_address());
        if(es.has_entry_extra()) {
            const ::EntrySymbolExtra &ese = es.entry_extra();
            ExternalCodeRef::CallingConvention c = deserCC(ese.entry_cconv());
            native_es.setExtra(ese.entry_argc(), ese.does_return(), c);
        }
        m->addEntryPoint(native_es);
    }

  } else {
    cout << "Failed to deserialize protobuf module" << endl;
  }

  cout << "Returning modue..." << endl;
  return m;
}

NativeModulePtr readModule( std::string         fName,
                            ModuleInputFormat   inf,
                            list<VA>            entries,
                            const llvm::Target *T)
{
    NativeModulePtr m;

    switch(inf) {
        case PEFile:
        case COFFObject:
            throw LErr(__LINE__, __FILE__, "Please use bin_descend instead");
            break;
        case ProtoBuff:
            m = readProtoBuf(fName, T);
            break;
        default:
            LASSERT(false, "NOT IMPLEMENTED");
    }

    return m;
}

NativeBlockPtr blockFromBuff(   VA                      startVA,
                                BufferMemoryObject      &bmo,
                                const MCDisassembler    *D,
                                MCInstPrinter           *P) {
    NativeBlockPtr    curBlock =
        NativeBlockPtr(new NativeBlock(startVA, P));
    VA  curVA = startVA;
    VA  nextVA;
    bool has_follow = true;
    while( curVA < bmo.getExtent() ) {
        uint64_t    insLen;
        MCInst      inst;
        llvm::MCDisassembler::DecodeStatus  s;
        MCOperand oper;

        nextVA = curVA;

        s = D->getInstruction(  inst,
                                insLen,
                                bmo,
                                (uint64_t)curVA,
                                llvm::nulls(),
                                llvm::nulls());

        LASSERT( llvm::MCDisassembler::Success ==  s, "" );

        string                      outS;
        llvm::raw_string_ostream    osOut(outS);
        P->printInst(&inst, osOut, "");
        vector<uint8_t>  bytes;
        InstPtr             p = InstPtr(new Inst(   curVA,
                                                    insLen,
                                                    inst,
                                                    osOut.str(),
                                                    Inst::NoPrefix,
                                                    bytes));
        //do some amount of checking for true and false branches
        switch(inst.getOpcode()) {
            case X86::JMP_4:
            case X86::JMP_1:
                oper = inst.getOperand(0);
                if( oper.isImm() ) {
                    nextVA += oper.getImm() + insLen;
                    curBlock->add_follow(nextVA);
                    p->set_tr(nextVA);
                } else {
                    throw LErr(__LINE__, __FILE__, "should not happen");
                }
                has_follow = false;
                break;
            case X86::LOOP:
            case X86::LOOPE:
            case X86::LOOPNE:
            case X86::JO_4:
            case X86::JO_1:
            case X86::JNO_4:
            case X86::JNO_1:
            case X86::JB_4:
            case X86::JB_1:
            case X86::JAE_4:
            case X86::JAE_1:
            case X86::JE_4:
            case X86::JE_1:
            case X86::JNE_4:
            case X86::JNE_1:
            case X86::JBE_4:
            case X86::JBE_1:
            case X86::JA_4:
            case X86::JA_1:
            case X86::JS_4:
            case X86::JS_1:
            case X86::JNS_4:
            case X86::JNS_1:
            case X86::JP_4:
            case X86::JP_1:
            case X86::JNP_4:
            case X86::JNP_1:
            case X86::JL_4:
            case X86::JL_1:
            case X86::JGE_4:
            case X86::JGE_1:
            case X86::JLE_4:
            case X86::JLE_1:
            case X86::JG_4:
            case X86::JG_1:
            case X86::JCXZ:
            case X86::JECXZ_32:
            case X86::JRCXZ:
                oper = inst.getOperand(0);
                if( oper.isImm() ) {
                    nextVA += oper.getImm() + insLen;
                    curBlock->add_follow(nextVA);
                    curBlock->add_follow(curVA+insLen);
                    p->set_tr(nextVA);
                    p->set_fa(curVA+insLen);
                } else {
                    throw LErr(__LINE__, __FILE__, "should not happen");
                }
                has_follow = false;
                break;
        }

        curBlock->add_inst(p);

        curVA += insLen;

        if( has_follow == false ) {

            break;
        }
    }

    return curBlock;
}

NativeFunctionPtr funcFromBuff( VA                      startVA,
                                BufferMemoryObject      &bmo,
                                const MCDisassembler    *D,
                                MCInstPrinter           *P)
{
    NativeFunctionPtr   curF = NativeFunctionPtr(new NativeFunction(startVA));
    VA                  curVA = 0;

    while( curVA < bmo.getExtent() ) {
        NativeBlockPtr  b = blockFromBuff(curVA, bmo, D, P);

        curF->add_block(b);
        curVA += b->get_size();
    }

    curF->compute_graph();
    return curF;
}

static void instFromNatInst(InstPtr i, ::Instruction *protoInst) {
  /* add the raw bytes for an instruction */
  vector<uint8_t>  bytes = i->get_bytes();
  protoInst->set_inst_bytes(string(bytes.begin(), bytes.end()));

  /* add the instruction address */
  protoInst->set_inst_addr(i->get_loc());

  /* add targets for true and false */
  if(i->get_tr() != 0)
    protoInst->set_true_target(i->get_tr());
  else
    protoInst->set_true_target(-1);

  if(i->get_fa() != 0)
    protoInst->set_false_target(i->get_fa());
  else
    protoInst->set_false_target(-1);

  protoInst->set_inst_len(i->get_len());

  if(i->is_data_offset()) {
    protoInst->set_data_offset(i->get_data_offset());
  }

  if(i->has_ext_call_target()) {
    string  s = i->get_ext_call_target()->getSymbolName();
    protoInst->set_ext_call_name(s);
  }

  if(i->has_ext_data_ref()) {

    string  s = i->get_ext_data_ref()->getSymbolName();
    protoInst->set_ext_data_name(s);
  }

  if(i->has_call_tgt()) {
      protoInst->set_call_target(i->get_call_tgt(0));
  }

  protoInst->set_reloc_offset(i->get_reloc_offset());

  if(i->has_jump_table()) {
      MCSJumpTablePtr native_jmp = i->get_jump_table();
      ::JumpTbl *proto_jmp = protoInst->mutable_jump_table();
      const vector<VA>& the_table = native_jmp->getJumpTable();

      vector<VA>::const_iterator  it = the_table.begin();
      while(it != the_table.end())
      {
        proto_jmp->add_table_entries(*it);
        ++it;
      }

      proto_jmp->set_zero_offset(native_jmp->getInitialEntry());
  }

  if(i->has_jump_index_table()) {
      JumpIndexTablePtr native_idx = i->get_jump_index_table();
      ::JumpIndexTbl *proto_idx = protoInst->mutable_jump_index_table();
      const vector<uint8_t>& idx_table = native_idx->getJumpIndexTable();

      proto_idx->set_table_entries(string(idx_table.begin(), idx_table.end()));
      proto_idx->set_zero_offset(native_idx->getInitialEntry());
  }

  return;
}

static void blockFromNatBlock(NativeBlockPtr b, ::Block *protoBlock) {
  /* add the base address */
  protoBlock->set_base_address(b->get_base());

  /* add the block follows */
  list<VA>  &follows = b->get_follows();
  list<VA>::iterator  it = follows.begin();
  while(it != follows.end())
  {
    protoBlock->add_block_follows(*it);
    ++it;
  }

  /* add the instructions */
  list<InstPtr> insts = b->get_insts();
  list<InstPtr>::iterator iit = insts.begin();
  while(iit != insts.end()) {
    instFromNatInst(*iit, protoBlock->add_insts());
    ++iit;
  }

  return;
}

static ExternalFunction::CallingConvention serializeCC(ExternalCodeRef::CallingConvention c)
{
  switch(c) {
    case ExternalCodeRef::CallerCleanup:
      return ExternalFunction::CallerCleanup;
      break;

    case ExternalCodeRef::CalleeCleanup:
      return ExternalFunction::CalleeCleanup;
      break;

    case ExternalCodeRef::FastCall:
      return ExternalFunction::FastCall;
      break;

    default:
      throw LErr(__LINE__, __FILE__, "Unknown case");
  }
}

static void extFuncFromNat(ExternalCodeRefPtr e, ::ExternalFunction *protoExt)
{
  protoExt->set_symbol_name(e->getSymbolName());
  protoExt->set_argument_count(e->getNumArgs());

  if(e->getReturnType() == ExternalCodeRef::NoReturn)
  {
      protoExt->set_no_return(true);
  }
  else
  {
      protoExt->set_no_return(false);

  }

  if(e->getReturnType() != ExternalCodeRef::VoidTy)
  {
      protoExt->set_has_return(true);
  }
  else
  {
      protoExt->set_has_return(false);
  }

  protoExt->set_calling_convention(serializeCC(e->getCallingConvention()));
 // protoExt->set_signature(e->getFunctionSignature());

  //printf("%s : %s\n", (e->getSymbolName()).c_str(), (e->getFunctionSignature()).c_str()), fflush(stdout);
  return;
}

static void extDataRefFromNat(ExternalDataRefPtr dr, ::ExternalData *protoExt)
{
    std::string sym = dr->getSymbolName();
    protoExt->set_symbol_name(sym);
    protoExt->set_data_size(dr->getDataSize());

    return;
}

static void funcFromNat(NativeFunctionPtr f, ::Function *fProto) {
  fProto->set_entry_address(f->get_start());

  /* iterate over the blocks and add them */
  CFG funcCFG = f->get_cfg();

  pair<boost::graph_traits<CFG>::vertex_iterator,
        boost::graph_traits<CFG>::vertex_iterator>
          vitp = boost::vertices(funcCFG);

  boost::graph_traits<CFG>::vertex_iterator vit = vitp.first;
  boost::graph_traits<CFG>::vertex_iterator end = vitp.second;

  while(vit != end) {
    blockFromNatBlock(f->block_from_id(*vit), fProto->add_blocks());
    ++vit;
  }

  return;
}

static void dumpData(DataSection &d, ::Data *protoData)
{
  vector<uint8_t> bytes = d.getBytes();
  protoData->set_base_address(d.getBase());
  protoData->set_data(string(bytes.begin(), bytes.end()));
  protoData->set_read_only(d.isReadOnly());

  const std::list<DataSectionEntry> &entries = d.getEntries();
  for(std::list<DataSectionEntry>::const_iterator deitr = entries.begin();
          deitr != entries.end();
          deitr++)
  {
    string sym_name;
    if(deitr->getSymbol(sym_name)) {
        // is a symbol
        ::DataSymbol *ds = protoData->add_symbols();
        ds->set_base_address(deitr->getBase());
        ds->set_symbol_name(sym_name);
		ds->set_symbol_size(deitr->getSize());
		printf("dumpData : base %x, size, %d\n", deitr->getBase(), deitr->getSize());
    }
  }

  return;
}

string dumpProtoBuf(NativeModulePtr  m) {
  /* first, we want to serialize and dump this module ptr into a proto buf */
  ::Module  protoMod;

  GOOGLE_PROTOBUF_VERIFY_VERSION;

  /* write the modules name */
  protoMod.set_module_name(m->name());

  /* dump all the functions and external functions */
  list<ExternalCodeRefPtr> extCalls = m->getExtCalls();
  list<ExternalCodeRefPtr>::iterator it = extCalls.begin();
  while(it != extCalls.end())
  {
    extFuncFromNat(*it, protoMod.add_external_funcs());
    ++it;
  }

  list<ExternalDataRefPtr> extDataRefs = m->getExtDataRefs();
  list<ExternalDataRefPtr>::iterator dref_it = extDataRefs.begin();
  while(dref_it != extDataRefs.end())
  {
    extDataRefFromNat(*dref_it, protoMod.add_external_data());
    ++dref_it;
  }


  list<NativeFunctionPtr> natFuncs = m->get_funcs();
  list<NativeFunctionPtr>::iterator fit = natFuncs.begin();

  while(fit != natFuncs.end())
  {
    funcFromNat(*fit, protoMod.add_internal_funcs());
    ++fit;
  }

  /* then dump data references */
  list<DataSection>  &dataSegs = m->getData();
  list<DataSection>::iterator  dit = dataSegs.begin();
  while(dit != dataSegs.end())
  {
   	dumpData(*dit, protoMod.add_internal_data());
    ++dit;
  }

  const std::vector<NativeModule::EntrySymbol> &eps = m->getEntryPoints();
  std::vector<NativeModule::EntrySymbol>::const_iterator ep_itr = eps.begin();
  while(ep_itr != eps.end()) {
      ::EntrySymbol *new_es = protoMod.add_entries();
      new_es->set_entry_name(ep_itr->getName());
      new_es->set_entry_address(ep_itr->getAddr());
      if(ep_itr->hasExtra()) {
          ::EntrySymbolExtra *ese = new_es->mutable_entry_extra();
          ese->set_entry_argc(ep_itr->getArgc());
          ese->set_entry_cconv(serializeCC(ep_itr->getConv()));
          ese->set_does_return(ep_itr->doesReturn());
      }
      ++ep_itr;
  }


  /* finally, serialize the module as a string object and return it */
  return protoMod.SerializeAsString();
}
