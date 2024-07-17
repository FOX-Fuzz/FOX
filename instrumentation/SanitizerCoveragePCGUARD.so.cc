//===-- SanitizerCoverage.cpp - coverage instrumentation for sanitizers ---===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Coverage instrumentation done on LLVM IR level, works with Sanitizers.
//
//===----------------------------------------------------------------------===//
#include <sstream>
#include <stddef.h>
#include <unordered_set>
#include "llvm/Transforms/Instrumentation/SanitizerCoverage.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallVector.h"
#if LLVM_VERSION_MAJOR >= 15
  #if LLVM_VERSION_MAJOR < 17
    #include "llvm/ADT/Triple.h"
  #endif
#endif
#include "llvm/Analysis/PostDominators.h"
#if LLVM_VERSION_MAJOR < 15
  #include "llvm/IR/CFG.h"
#endif
#include "llvm/IR/Constant.h"
#include "llvm/IR/DataLayout.h"
#if LLVM_VERSION_MAJOR < 15
  #include "llvm/IR/DebugInfo.h"
#endif
#include "llvm/IR/Dominators.h"
#if LLVM_VERSION_MAJOR >= 17
  #include "llvm/IR/EHPersonalities.h"
#else
  #include "llvm/Analysis/EHPersonalities.h"
#endif
#include "llvm/IR/Function.h"
#if LLVM_VERSION_MAJOR >= 16
  #include "llvm/IR/GlobalVariable.h"
#endif
#include "llvm/IR/IRBuilder.h"
#if LLVM_VERSION_MAJOR < 15
  #include "llvm/IR/InlineAsm.h"
#endif
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMContext.h"
#if LLVM_VERSION_MAJOR < 15
  #include "llvm/IR/MDBuilder.h"
  #include "llvm/IR/Mangler.h"
#endif
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/IR/Type.h"
#if LLVM_VERSION_MAJOR < 17
  #include "llvm/InitializePasses.h"
#endif
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/SpecialCaseList.h"
#include "llvm/Support/VirtualFileSystem.h"
#if LLVM_VERSION_MAJOR < 15
  #include "llvm/Support/raw_ostream.h"
#endif
#if LLVM_VERSION_MAJOR < 17
  #include "llvm/Transforms/Instrumentation.h"
#else
  #include "llvm/TargetParser/Triple.h"
#endif
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/IR/Constants.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Support/LockFileManager.h"
#include <sys/file.h>
#include <cmath>

#include "config.h"
#include "debug.h"
#include "afl-llvm-common.h"

using namespace llvm;
using namespace std;
#define DEBUG_TYPE "sancov"

static const uint64_t SanCtorAndDtorPriority = 2;

const char SanCovTracePCName[] = "__sanitizer_cov_trace_pc";
const char SanCovTraceCmp1[] = "__sanitizer_cov_trace_cmp1";
const char SanCovTraceCmp2[] = "__sanitizer_cov_trace_cmp2";
const char SanCovTraceCmp4[] = "__sanitizer_cov_trace_cmp4";
const char SanCovTraceCmp8[] = "__sanitizer_cov_trace_cmp8";
const char SanCovTraceConstCmp1[] = "__sanitizer_cov_trace_const_cmp1";
const char SanCovTraceConstCmp2[] = "__sanitizer_cov_trace_const_cmp2";
const char SanCovTraceConstCmp4[] = "__sanitizer_cov_trace_const_cmp4";
const char SanCovTraceConstCmp8[] = "__sanitizer_cov_trace_const_cmp8";
const char SanCovTraceSwitchName[] = "__sanitizer_cov_trace_switch";
const char log_br8[] = "log_br8";
const char log_br16[] = "log_br16";
const char log_br32[] = "log_br32";
const char log_br64[] = "log_br64";
const char log_br8_unsign[] = "log_br8_unsign";
const char log_br16_unsign[] = "log_br16_unsign";
const char log_br32_unsign[] = "log_br32_unsign";
const char log_br64_unsign[] = "log_br64_unsign";

const char log_br8_r[] = "log_br8_r";
const char log_br16_r[] = "log_br16_r";
const char log_br32_r[] = "log_br32_r";
const char log_br64_r[] = "log_br64_r";
const char log_br8_unsign_r[] = "log_br8_unsign_r";
const char log_br16_unsign_r[] = "log_br16_unsign_r";
const char log_br32_unsign_r[] = "log_br32_unsign_r";
const char log_br64_unsign_r[] = "log_br64_unsign_r";

const char strcmp_log[] = "strcmp_log";
const char strncmp_log[] = "strncmp_log";
const char memcmp_log[] = "memcmp_log";
const char strstr_log[] = "strstr_log";
const char sw_log_br8[] = "sw_log_br8";
const char sw_log_br16[] = "sw_log_br16";
const char sw_log_br32[] = "sw_log_br32";
const char sw_log_br64[] = "sw_log_br64";
const char eq_log_br8[] =  "eq_log_br8";
const char eq_log_br16[] = "eq_log_br16";
const char eq_log_br32[] = "eq_log_br32";
const char eq_log_br64[] = "eq_log_br64";

const char SanCovModuleCtorTracePcGuardName[] =
    "sancov.module_ctor_trace_pc_guard";
const char SanCovTracePCGuardInitName[] = "__sanitizer_cov_trace_pc_guard_init";

const char SanCovTracePCGuardName[] = "__sanitizer_cov_trace_pc_guard";

const char SanCovGuardsSectionName[] = "sancov_guards";
const char SanCovCountersSectionName[] = "sancov_cntrs";
const char SanCovBoolFlagSectionName[] = "sancov_bools";
const char SanCovPCsSectionName[] = "sancov_pcs";

const char SanCovLowestStackName[] = "__sancov_lowest_stack";

static const char *skip_nozero;
static const char *use_threadsafe_counters;

namespace {

SanitizerCoverageOptions OverrideFromCL(SanitizerCoverageOptions Options) {

  Options.CoverageType = SanitizerCoverageOptions::SCK_Edge;
  Options.NoPrune = true;
  Options.TracePCGuard = true;  // TracePCGuard is default.
  return Options;

}

using DomTreeCallback = function_ref<const DominatorTree *(Function &F)>;
using PostDomTreeCallback =
    function_ref<const PostDominatorTree *(Function &F)>;

class ModuleSanitizerCoverageAFL
    : public PassInfoMixin<ModuleSanitizerCoverageAFL> {

 public:
  ModuleSanitizerCoverageAFL(
      const SanitizerCoverageOptions &Options = SanitizerCoverageOptions())
      : Options(OverrideFromCL(Options)) {

  }

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
  bool              instrumentModule(Module &M, DomTreeCallback DTCallback,
                                     PostDomTreeCallback PDTCallback);

 private:
  void instrumentFunction(Function &F, DomTreeCallback DTCallback,
                          PostDomTreeCallback PDTCallback, int* InstrumentCntPtr, ofstream &,  ofstream &);
  void InjectTraceForCmp(Function &F, ArrayRef<Instruction *> CmpTraceTargets);
    void OptfuzzInjectTraceForCmp(Function &F, ArrayRef<Instruction *> CmpTraceTargets, ArrayRef<Instruction *> SancovForCmp,  int * InstrumentCntPtr,  ofstream &, DenseMap<Instruction *, size_t> &SancovMapIndex);
  void OptfuzzInjectTraceForCmpNonTerminator(Function &F, ArrayRef<Instruction *> CmpTraceTargetsNonTerminator, ArrayRef<Instruction *> SancovForCmpNonTerminator, ArrayRef<Instruction *> SelectInstArray, int * InstrumentCntPtr, ofstream &errlog);

  void OptfuzzInjectTraceForStrcmp(Function &F, ArrayRef<Instruction *> StrcmpTraceTargets,ArrayRef<Instruction *> SancovForStrcmp, int * InstrumentCntPtr,  ofstream &, ofstream &, DenseMap<Instruction *, size_t> &SancovMapIndex);
  void OptfuzzInjectTraceForStrcmpNonTerminator(Function &F, ArrayRef<Instruction *> StrcmpTraceTargetsNonTerminator, int * InstrumentCntPtr);
  
  void OptfuzzInjectTraceForSwitch(Function &F, ArrayRef<Instruction *> SwitchTraceTargets, ArrayRef<Instruction *> SancovForSwitch, ArrayRef<Instruction *> case_target_list, ArrayRef<ConstantInt *> case_val_list, std::vector<int> int_val_list, int * InstrumentCntPtr,  ofstream &errlog, DenseMap<Instruction *, size_t> &SancovMapIndex);

  void InjectTraceForSwitch(Function               &F,
                            ArrayRef<Instruction *> SwitchTraceTargets);
  bool InjectCoverage(Function &F, ArrayRef<BasicBlock *> AllBlocks, DenseMap<Instruction *, size_t> &SancovMapIndex, DenseMap<BasicBlock *, size_t> &BBMapIndex,
                      bool IsLeafFunc = true);
  GlobalVariable *CreateFunctionLocalArrayInSection(size_t    NumElements,
                                                    Function &F, Type *Ty,
                                                    const char *Section);
  GlobalVariable *CreatePCArray(Function &F, ArrayRef<BasicBlock *> AllBlocks);
  void CreateFunctionLocalArrays(Function &F, ArrayRef<BasicBlock *> AllBlocks,
                                 uint32_t special);
  void InjectCoverageAtBlock(Function &F, BasicBlock &BB, size_t Idx, DenseMap<Instruction *, size_t> &SancovMapIndex,
                             bool IsLeafFunc = true);
  Function *CreateInitCallsForSections(Module &M, const char *CtorName,
                                       const char *InitFunctionName, Type *Ty,
                                       const char *Section);
  std::pair<Value *, Value *> CreateSecStartEnd(Module &M, const char *Section,
                                                Type *Ty);

  void SetNoSanitizeMetadata(Instruction *I) {

#if LLVM_VERSION_MAJOR >= 16
    I->setMetadata(LLVMContext::MD_nosanitize, MDNode::get(*C, std::nullopt));
#else
    I->setMetadata(I->getModule()->getMDKindID("nosanitize"),
                   MDNode::get(*C, None));
#endif

  }

  std::string     getSectionName(const std::string &Section) const;
  std::string     getSectionStart(const std::string &Section) const;
  std::string     getSectionEnd(const std::string &Section) const;
  FunctionCallee  SanCovTracePC, SanCovTracePCGuard;
  FunctionCallee  SanCovTraceCmpFunction[4];
  FunctionCallee  SanCovTraceConstCmpFunction[4];
  FunctionCallee  SanCovTraceSwitchFunction;
  FunctionCallee  OptfuzzTraceCmpFunction[8];
  FunctionCallee  OptfuzzTraceCmpFunctionWithRandomId[8];
  FunctionCallee  OptfuzzTraceSwitchFunction[4];
  FunctionCallee  OptfuzzTraceEqualFunction[4];
  FunctionCallee  OptfuzzTraceStrcmpFunction[4];
  GlobalVariable *SanCovLowestStack;
  Type *IntptrTy, *IntptrPtrTy, *Int64Ty, *Int64PtrTy, *Int32Ty, *Int32PtrTy,
      *Int16Ty, *Int8Ty, *Int8PtrTy, *Int1Ty, *Int1PtrTy;
  Module           *CurModule;
  std::string       CurModuleUniqueId;
  Triple            TargetTriple;
  LLVMContext      *C;
  const DataLayout *DL;

  GlobalVariable *FunctionGuardArray;        // for trace-pc-guard.
  GlobalVariable *Function8bitCounterArray;  // for inline-8bit-counters.
  GlobalVariable *FunctionBoolArray;         // for inline-bool-flag.
  GlobalVariable *FunctionPCsArray;          // for pc-table.
  SmallVector<GlobalValue *, 20> GlobalsToAppendToUsed;
  SmallVector<GlobalValue *, 20> GlobalsToAppendToCompilerUsed;

  SanitizerCoverageOptions Options;

  uint32_t        instr = 0, selects = 0, unhandled = 0;
  GlobalVariable *AFLMapPtr = NULL;
  GlobalVariable *BrCovMapPtr = NULL;
  ConstantInt    *One = NULL;
  ConstantInt    *Zero = NULL;

};

}  // namespace

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {

  return {LLVM_PLUGIN_API_VERSION, "SanitizerCoveragePCGUARD", "v0.2",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {

#if LLVM_VERSION_MAJOR == 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
#endif
#if LLVM_VERSION_MAJOR >= 16
            PB.registerOptimizerEarlyEPCallback(
#else
            PB.registerOptimizerLastEPCallback(
#endif
                [](ModulePassManager &MPM, OptimizationLevel OL) {

                  MPM.addPass(ModuleSanitizerCoverageAFL());

                });

          }};

}

PreservedAnalyses ModuleSanitizerCoverageAFL::run(Module                &M,
                                                  ModuleAnalysisManager &MAM) {

  ModuleSanitizerCoverageAFL ModuleSancov(Options);
  auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
  auto  DTCallback = [&FAM](Function &F) -> const DominatorTree  *{

    return &FAM.getResult<DominatorTreeAnalysis>(F);

  };

  auto PDTCallback = [&FAM](Function &F) -> const PostDominatorTree * {

    return &FAM.getResult<PostDominatorTreeAnalysis>(F);

  };

  if (ModuleSancov.instrumentModule(M, DTCallback, PDTCallback))
    return PreservedAnalyses::none();
  return PreservedAnalyses::all();

}

std::pair<Value *, Value *> ModuleSanitizerCoverageAFL::CreateSecStartEnd(
    Module &M, const char *Section, Type *Ty) {

  // Use ExternalWeak so that if all sections are discarded due to section
  // garbage collection, the linker will not report undefined symbol errors.
  // Windows defines the start/stop symbols in compiler-rt so no need for
  // ExternalWeak.
  GlobalValue::LinkageTypes Linkage = TargetTriple.isOSBinFormatCOFF()
                                          ? GlobalVariable::ExternalLinkage
                                          : GlobalVariable::ExternalWeakLinkage;
  GlobalVariable *SecStart = new GlobalVariable(M, Ty, false, Linkage, nullptr,
                                                getSectionStart(Section));
  SecStart->setVisibility(GlobalValue::HiddenVisibility);
  GlobalVariable *SecEnd = new GlobalVariable(M, Ty, false, Linkage, nullptr,
                                              getSectionEnd(Section));
  SecEnd->setVisibility(GlobalValue::HiddenVisibility);
  IRBuilder<> IRB(M.getContext());
  if (!TargetTriple.isOSBinFormatCOFF())
    return std::make_pair(SecStart, SecEnd);

  // Account for the fact that on windows-msvc __start_* symbols actually
  // point to a uint64_t before the start of the array.
  auto SecStartI8Ptr = IRB.CreatePointerCast(SecStart, Int8PtrTy);
  auto GEP = IRB.CreateGEP(Int8Ty, SecStartI8Ptr,
                           ConstantInt::get(IntptrTy, sizeof(uint64_t)));
  return std::make_pair(IRB.CreatePointerCast(GEP, PointerType::getUnqual(Ty)),
                        SecEnd);

}

Function *ModuleSanitizerCoverageAFL::CreateInitCallsForSections(
    Module &M, const char *CtorName, const char *InitFunctionName, Type *Ty,
    const char *Section) {

  auto      SecStartEnd = CreateSecStartEnd(M, Section, Ty);
  auto      SecStart = SecStartEnd.first;
  auto      SecEnd = SecStartEnd.second;
  Function *CtorFunc;
  Type     *PtrTy = PointerType::getUnqual(Ty);
  std::tie(CtorFunc, std::ignore) = createSanitizerCtorAndInitFunctions(
      M, CtorName, InitFunctionName, {PtrTy, PtrTy}, {SecStart, SecEnd});
  assert(CtorFunc->getName() == CtorName);

  if (TargetTriple.supportsCOMDAT()) {

    // Use comdat to dedup CtorFunc.
    CtorFunc->setComdat(M.getOrInsertComdat(CtorName));
    appendToGlobalCtors(M, CtorFunc, SanCtorAndDtorPriority, CtorFunc);

  } else {

    appendToGlobalCtors(M, CtorFunc, SanCtorAndDtorPriority);

  }

  if (TargetTriple.isOSBinFormatCOFF()) {

    // In COFF files, if the contructors are set as COMDAT (they are because
    // COFF supports COMDAT) and the linker flag /OPT:REF (strip unreferenced
    // functions and data) is used, the constructors get stripped. To prevent
    // this, give the constructors weak ODR linkage and ensure the linker knows
    // to include the sancov constructor. This way the linker can deduplicate
    // the constructors but always leave one copy.
    CtorFunc->setLinkage(GlobalValue::WeakODRLinkage);

  }

  return CtorFunc;

}

bool ModuleSanitizerCoverageAFL::instrumentModule(
    Module &M, DomTreeCallback DTCallback, PostDomTreeCallback PDTCallback) {
  
  int InstrumentCnt = 0;
  FILE* file_lock = fopen("/dev/shm/mylock", "w");
  if (file_lock == NULL)
      perror("open lock file failed");

  int lock_fd = fileno(file_lock);
  if (lock_fd == -1)
      perror("Failed to open the file");

  if (flock(lock_fd, LOCK_EX) == -1)
      perror("Failed to acquire the lock");
 
  ifstream ifile("/dev/shm/instrument_cnt"); 
  if(ifile.fail()) 
    InstrumentCnt = 0;  
  else{ 
    string tmp; 
    getline(ifile, tmp); 
    InstrumentCnt = stoi(tmp); 
    ifile.close(); 
  }
  
  ofstream errlog;
  errlog.open("/dev/shm/strcmp_err_log", ios::app);
  
  ofstream datalog;
  datalog.open("/dev/shm/instrument_meta_data", ios::app);

  setvbuf(stdout, NULL, _IONBF, 0);

  if (getenv("AFL_DEBUG")) { debug = 1; }

  if ((isatty(2) && !getenv("AFL_QUIET")) || debug) {

    SAYF(cCYA "SanitizerCoveragePCGUARD" VERSION cRST "\n");

  } else {

    be_quiet = 1;

  }

  skip_nozero = getenv("AFL_LLVM_SKIP_NEVERZERO");
  use_threadsafe_counters = getenv("AFL_LLVM_THREADSAFE_INST");

  initInstrumentList();
  scanForDangerousFunctions(&M);

  C = &(M.getContext());
  DL = &M.getDataLayout();
  CurModule = &M;
  CurModuleUniqueId = getUniqueModuleId(CurModule);
  TargetTriple = Triple(M.getTargetTriple());
  FunctionGuardArray = nullptr;
  Function8bitCounterArray = nullptr;
  FunctionBoolArray = nullptr;
  FunctionPCsArray = nullptr;
  IntptrTy = Type::getIntNTy(*C, DL->getPointerSizeInBits());
  IntptrPtrTy = PointerType::getUnqual(IntptrTy);
  Type       *VoidTy = Type::getVoidTy(*C);
  IRBuilder<> IRB(*C);
  Int64PtrTy = PointerType::getUnqual(IRB.getInt64Ty());
  Int32PtrTy = PointerType::getUnqual(IRB.getInt32Ty());
  Int8PtrTy = PointerType::getUnqual(IRB.getInt8Ty());
  Int1PtrTy = PointerType::getUnqual(IRB.getInt1Ty());
  Int64Ty = IRB.getInt64Ty();
  Int32Ty = IRB.getInt32Ty();
  Int16Ty = IRB.getInt16Ty();
  Int8Ty = IRB.getInt8Ty();
  Int1Ty = IRB.getInt1Ty();

  LLVMContext &Ctx = M.getContext();
  AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");
  BrCovMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__br_cov_ptr");

  One = ConstantInt::get(IntegerType::getInt8Ty(Ctx), 1);
  Zero = ConstantInt::get(IntegerType::getInt8Ty(Ctx), 0);

  // Make sure smaller parameters are zero-extended to i64 if required by the
  // target ABI.
  AttributeList SanCovTraceCmpZeroExtAL;
  SanCovTraceCmpZeroExtAL =
      SanCovTraceCmpZeroExtAL.addParamAttribute(*C, 0, Attribute::ZExt);
  SanCovTraceCmpZeroExtAL =
      SanCovTraceCmpZeroExtAL.addParamAttribute(*C, 1, Attribute::ZExt);
  
  AttributeList OptfuzzTraceCmpZeroExtAL;
  OptfuzzTraceCmpZeroExtAL =
      OptfuzzTraceCmpZeroExtAL.addParamAttribute(*C, 0, Attribute::ZExt);
  OptfuzzTraceCmpZeroExtAL =
      OptfuzzTraceCmpZeroExtAL.addParamAttribute(*C, 1, Attribute::ZExt);
  OptfuzzTraceCmpZeroExtAL =
      OptfuzzTraceCmpZeroExtAL.addParamAttribute(*C, 2, Attribute::ZExt);
  SanCovTraceCmpFunction[0] =
      M.getOrInsertFunction(SanCovTraceCmp1, SanCovTraceCmpZeroExtAL, VoidTy,
                            IRB.getInt8Ty(), IRB.getInt8Ty());
  SanCovTraceCmpFunction[1] =
      M.getOrInsertFunction(SanCovTraceCmp2, SanCovTraceCmpZeroExtAL, VoidTy,
                            IRB.getInt16Ty(), IRB.getInt16Ty());
  SanCovTraceCmpFunction[2] =
      M.getOrInsertFunction(SanCovTraceCmp4, SanCovTraceCmpZeroExtAL, VoidTy,
                            IRB.getInt32Ty(), IRB.getInt32Ty());
  SanCovTraceCmpFunction[3] =
      M.getOrInsertFunction(SanCovTraceCmp8, VoidTy, Int64Ty, Int64Ty);
  
  OptfuzzTraceCmpFunction[0] =
   M.getOrInsertFunction(log_br8, OptfuzzTraceCmpZeroExtAL, VoidTy,Int32Ty,
                      IRB.getInt8Ty(), IRB.getInt8Ty());
  OptfuzzTraceCmpFunction[1] =
   M.getOrInsertFunction(log_br16, OptfuzzTraceCmpZeroExtAL, VoidTy,Int32Ty,
                      IRB.getInt16Ty(), IRB.getInt16Ty());
  OptfuzzTraceCmpFunction[2] =
   M.getOrInsertFunction(log_br32, OptfuzzTraceCmpZeroExtAL, VoidTy,Int32Ty,
                      IRB.getInt32Ty(), IRB.getInt32Ty());
  OptfuzzTraceCmpFunction[3] =
         M.getOrInsertFunction(log_br64, OptfuzzTraceCmpZeroExtAL, VoidTy,Int32Ty, Int64Ty, Int64Ty);
  OptfuzzTraceCmpFunction[4] =
   M.getOrInsertFunction(log_br8_unsign, OptfuzzTraceCmpZeroExtAL, VoidTy,Int32Ty,
                      IRB.getInt8Ty(), IRB.getInt8Ty());
  OptfuzzTraceCmpFunction[5] =
   M.getOrInsertFunction(log_br16_unsign, OptfuzzTraceCmpZeroExtAL, VoidTy,Int32Ty,
                      IRB.getInt16Ty(), IRB.getInt16Ty());
  OptfuzzTraceCmpFunction[6] =
   M.getOrInsertFunction(log_br32_unsign, OptfuzzTraceCmpZeroExtAL, VoidTy,Int32Ty,
                      IRB.getInt32Ty(), IRB.getInt32Ty());
  OptfuzzTraceCmpFunction[7] =
         M.getOrInsertFunction(log_br64_unsign, OptfuzzTraceCmpZeroExtAL, VoidTy,Int32Ty, Int64Ty, Int64Ty);


  OptfuzzTraceStrcmpFunction[0] =
   M.getOrInsertFunction(strcmp_log, VoidTy,Int32Ty,
                      Int8PtrTy, Int8PtrTy, Int64Ty);

  OptfuzzTraceStrcmpFunction[1] =
   M.getOrInsertFunction(strncmp_log, VoidTy,Int32Ty,
                      Int8PtrTy, Int8PtrTy, Int64Ty);

  OptfuzzTraceStrcmpFunction[2] =
   M.getOrInsertFunction(memcmp_log, VoidTy,Int32Ty,
                      Int8PtrTy, Int8PtrTy, Int64Ty);
  
  OptfuzzTraceStrcmpFunction[3] =
   M.getOrInsertFunction(strstr_log, VoidTy,Int32Ty,
                      Int8PtrTy, Int8PtrTy, Int64Ty);

  OptfuzzTraceCmpFunctionWithRandomId[0] =
   M.getOrInsertFunction(log_br8_r, OptfuzzTraceCmpZeroExtAL, VoidTy,Int32Ty,
                      IRB.getInt8Ty(), IRB.getInt8Ty());
  OptfuzzTraceCmpFunctionWithRandomId[1] =
   M.getOrInsertFunction(log_br16_r, OptfuzzTraceCmpZeroExtAL, VoidTy,Int32Ty,
                      IRB.getInt16Ty(), IRB.getInt16Ty());
  OptfuzzTraceCmpFunctionWithRandomId[2] =
   M.getOrInsertFunction(log_br32_r, OptfuzzTraceCmpZeroExtAL, VoidTy,Int32Ty,
                      IRB.getInt32Ty(), IRB.getInt32Ty());
  OptfuzzTraceCmpFunctionWithRandomId[3] =
         M.getOrInsertFunction(log_br64_r, OptfuzzTraceCmpZeroExtAL, VoidTy,Int32Ty, Int64Ty, Int64Ty);
  OptfuzzTraceCmpFunctionWithRandomId[4] =
   M.getOrInsertFunction(log_br8_unsign_r, OptfuzzTraceCmpZeroExtAL, VoidTy,Int32Ty,
                      IRB.getInt8Ty(), IRB.getInt8Ty());
  OptfuzzTraceCmpFunctionWithRandomId[5] =
   M.getOrInsertFunction(log_br16_unsign_r, OptfuzzTraceCmpZeroExtAL, VoidTy,Int32Ty,
                      IRB.getInt16Ty(), IRB.getInt16Ty());
  OptfuzzTraceCmpFunctionWithRandomId[6] =
   M.getOrInsertFunction(log_br32_unsign_r, OptfuzzTraceCmpZeroExtAL, VoidTy,Int32Ty,
                      IRB.getInt32Ty(), IRB.getInt32Ty());
  OptfuzzTraceCmpFunctionWithRandomId[7] =
         M.getOrInsertFunction(log_br64_unsign_r, OptfuzzTraceCmpZeroExtAL, VoidTy,Int32Ty, Int64Ty, Int64Ty);

  OptfuzzTraceSwitchFunction[0] =
   M.getOrInsertFunction(sw_log_br8, OptfuzzTraceCmpZeroExtAL, VoidTy,Int32Ty,
                      IRB.getInt8Ty(), IRB.getInt8Ty());
  OptfuzzTraceSwitchFunction[1] =
   M.getOrInsertFunction(sw_log_br16, OptfuzzTraceCmpZeroExtAL, VoidTy,Int32Ty,
                      IRB.getInt16Ty(), IRB.getInt16Ty());
  OptfuzzTraceSwitchFunction[2] =
   M.getOrInsertFunction(sw_log_br32, OptfuzzTraceCmpZeroExtAL, VoidTy,Int32Ty,
                      IRB.getInt32Ty(), IRB.getInt32Ty());
  OptfuzzTraceSwitchFunction[3] =
         M.getOrInsertFunction(sw_log_br64, OptfuzzTraceCmpZeroExtAL, VoidTy,Int32Ty, Int64Ty, Int64Ty);


  OptfuzzTraceEqualFunction[0] =
   M.getOrInsertFunction(eq_log_br8, OptfuzzTraceCmpZeroExtAL, VoidTy,Int32Ty,
                      IRB.getInt8Ty(), IRB.getInt8Ty());
  OptfuzzTraceEqualFunction[1] =
   M.getOrInsertFunction(eq_log_br16, OptfuzzTraceCmpZeroExtAL, VoidTy,Int32Ty,
                      IRB.getInt16Ty(), IRB.getInt16Ty());
  OptfuzzTraceEqualFunction[2] =
   M.getOrInsertFunction(eq_log_br32, OptfuzzTraceCmpZeroExtAL, VoidTy,Int32Ty,
                      IRB.getInt32Ty(), IRB.getInt32Ty());
  OptfuzzTraceEqualFunction[3] =
         M.getOrInsertFunction(eq_log_br64, OptfuzzTraceCmpZeroExtAL, VoidTy,Int32Ty, Int64Ty, Int64Ty);



  SanCovTraceConstCmpFunction[0] = M.getOrInsertFunction(
      SanCovTraceConstCmp1, SanCovTraceCmpZeroExtAL, VoidTy, Int8Ty, Int8Ty);
  SanCovTraceConstCmpFunction[1] = M.getOrInsertFunction(
      SanCovTraceConstCmp2, SanCovTraceCmpZeroExtAL, VoidTy, Int16Ty, Int16Ty);
  SanCovTraceConstCmpFunction[2] = M.getOrInsertFunction(
      SanCovTraceConstCmp4, SanCovTraceCmpZeroExtAL, VoidTy, Int32Ty, Int32Ty);
  SanCovTraceConstCmpFunction[3] =
      M.getOrInsertFunction(SanCovTraceConstCmp8, VoidTy, Int64Ty, Int64Ty);

  SanCovTraceSwitchFunction =
      M.getOrInsertFunction(SanCovTraceSwitchName, VoidTy, Int64Ty, Int64PtrTy);

  Constant *SanCovLowestStackConstant =
      M.getOrInsertGlobal(SanCovLowestStackName, IntptrTy);
  SanCovLowestStack = dyn_cast<GlobalVariable>(SanCovLowestStackConstant);
  if (!SanCovLowestStack || SanCovLowestStack->getValueType() != IntptrTy) {

    C->emitError(StringRef("'") + SanCovLowestStackName +
                 "' should not be declared by the user");
    flock(lock_fd, LOCK_UN);
    fclose(file_lock);
    return true;

  }

  SanCovLowestStack->setThreadLocalMode(
      GlobalValue::ThreadLocalMode::InitialExecTLSModel);

  SanCovTracePC = M.getOrInsertFunction(SanCovTracePCName, VoidTy);
  SanCovTracePCGuard =
      M.getOrInsertFunction(SanCovTracePCGuardName, VoidTy, Int32PtrTy);

  for (auto &F : M)
    instrumentFunction(F, DTCallback, PDTCallback, &InstrumentCnt, errlog, datalog);

  Function *Ctor = nullptr;

  if (FunctionGuardArray)
    Ctor = CreateInitCallsForSections(M, SanCovModuleCtorTracePcGuardName,
                                      SanCovTracePCGuardInitName, Int32PtrTy,
                                      SanCovGuardsSectionName);

  if (Ctor && debug) {

    fprintf(stderr, "SANCOV: installed pcguard_init in ctor\n");

  }

  appendToUsed(M, GlobalsToAppendToUsed);
  appendToCompilerUsed(M, GlobalsToAppendToCompilerUsed);

  if (!be_quiet) {

    if (!instr) {

      WARNF("No instrumentation targets found.");

    } else {

      char modeline[128];
      snprintf(modeline, sizeof(modeline), "%s%s%s%s%s%s",
               getenv("AFL_HARDEN") ? "hardened" : "non-hardened",
               getenv("AFL_USE_ASAN") ? ", ASAN" : "",
               getenv("AFL_USE_MSAN") ? ", MSAN" : "",
               getenv("AFL_USE_TSAN") ? ", TSAN" : "",
               getenv("AFL_USE_CFISAN") ? ", CFISAN" : "",
               getenv("AFL_USE_UBSAN") ? ", UBSAN" : "");
      OKF("Instrumented %u locations with no collisions (%s mode) of which are "
          "%u handled and %u unhandled selects.",
          instr, modeline, selects, unhandled);

    }

  }
  errlog.flush(); 
  errlog.close();
  
  datalog.flush(); 
  datalog.close();

  ofstream ofile("/dev/shm/instrument_cnt");
  if (ofile.is_open())
  {
    ofile << InstrumentCnt << "\n";
    ofile.flush();
    ofile.close();
  } else
  {
    perror("open file failed");
  }
  flock(lock_fd, LOCK_UN);
  fclose(file_lock);

  return true;

}

// True if block has successors and it dominates all of them.
static bool isFullDominator(const BasicBlock *BB, const DominatorTree *DT) {

  if (succ_empty(BB)) return false;

  return llvm::all_of(successors(BB), [&](const BasicBlock *SUCC) {

    return DT->dominates(BB, SUCC);

  });

}

// True if block has predecessors and it postdominates all of them.
static bool isFullPostDominator(const BasicBlock        *BB,
                                const PostDominatorTree *PDT) {

  if (pred_empty(BB)) return false;

  return llvm::all_of(predecessors(BB), [&](const BasicBlock *PRED) {

    return PDT->dominates(BB, PRED);

  });

}

static bool shouldInstrumentBlock(const Function &F, const BasicBlock *BB,
                                  const DominatorTree            *DT,
                                  const PostDominatorTree        *PDT,
                                  const SanitizerCoverageOptions &Options) {

  // Don't insert coverage for blocks containing nothing but unreachable: we
  // will never call __sanitizer_cov() for them, so counting them in
  // NumberOfInstrumentedBlocks() might complicate calculation of code coverage
  // percentage. Also, unreachable instructions frequently have no debug
  // locations.
  if (isa<UnreachableInst>(BB->getFirstNonPHIOrDbgOrLifetime())) return false;

  // Don't insert coverage into blocks without a valid insertion point
  // (catchswitch blocks).
  if (BB->getFirstInsertionPt() == BB->end()) return false;

  if (Options.NoPrune || &F.getEntryBlock() == BB) return true;

  // Do not instrument full dominators, or full post-dominators with multiple
  // predecessors.
  return !isFullDominator(BB, DT) &&
         !(isFullPostDominator(BB, PDT) && !BB->getSinglePredecessor());

}

// Returns true iff From->To is a backedge.
// A twist here is that we treat From->To as a backedge if
//   * To dominates From or
//   * To->UniqueSuccessor dominates From
#if 0
static bool IsBackEdge(BasicBlock *From, BasicBlock *To,
                       const DominatorTree *DT) {

  if (DT->dominates(To, From))
    return true;
  if (auto Next = To->getUniqueSuccessor())
    if (DT->dominates(Next, From))
      return true;
  return false;

}

#endif

// Prunes uninteresting Cmp instrumentation:
//   * CMP instructions that feed into loop backedge branch.
//
// Note that Cmp pruning is controlled by the same flag as the
// BB pruning.
#if 0
static bool IsInterestingCmp(ICmpInst *CMP, const DominatorTree *DT,
                             const SanitizerCoverageOptions &Options) {

  if (!Options.NoPrune)
    if (CMP->hasOneUse())
      if (auto BR = dyn_cast<BranchInst>(CMP->user_back()))
        for (BasicBlock *B : BR->successors())
          if (IsBackEdge(BR->getParent(), B, DT))
            return false;
  return true;

}

#endif

static bool IsBackEdge(BasicBlock *From, BasicBlock *To,
                       const DominatorTree *DT) {

  if (DT->dominates(To, From))
    return true;
  if (auto Next = To->getUniqueSuccessor())
    if (DT->dominates(Next, From))
      return true;
  return false;

}

bool OptfuzzIsInterestingCmpPtr(ICmpInst *CMP, const DominatorTree *DT,
                      const SanitizerCoverageOptions &Options, const DataLayout *DL) {
  if (CMP->hasOneUse())
    if (auto BR = dyn_cast<BranchInst>(CMP->user_back()))
      for (BasicBlock *B : BR->successors())
        if (IsBackEdge(BR->getParent(), B, DT)) return false;

  Value *A0 = CMP->getOperand(0);
  if (!A0->getType()->isPointerTy()) return false;

  return true;

}
bool OptfuzzIsInterestingCmp(ICmpInst *CMP, const DominatorTree *DT,
                      const SanitizerCoverageOptions &Options, const DataLayout *DL) {
  if (CMP->hasOneUse())
    if (auto BR = dyn_cast<BranchInst>(CMP->user_back()))
      for (BasicBlock *B : BR->successors())
        if (IsBackEdge(BR->getParent(), B, DT)) return false;

  Value *A0 = CMP->getOperand(0);
  if (!A0->getType()->isIntegerTy()) return false;
  //uint64_t TypeSize = DL->getTypeStoreSizeInBits(A0->getType());
  unsigned TypeSize = (cast<IntegerType>(A0->getType()))->getBitWidth();
  if ((TypeSize != 8) && (TypeSize != 16)&& (TypeSize != 32) && (TypeSize != 64)) return false;

  return true;

}

void ModuleSanitizerCoverageAFL::instrumentFunction(
    Function &F, DomTreeCallback DTCallback, PostDomTreeCallback PDTCallback, int * InstrumentCntPtr, ofstream &errlog, ofstream &datalog) {

  if (F.empty()) return;
  if (!isInInstrumentList(&F, FMNAME)) return;
  if (F.getName().find(".module_ctor") != std::string::npos)
    return;  // Should not instrument sanitizer init functions.
  if (F.getName().startswith("__sanitizer_"))
    return;  // Don't instrument __sanitizer_* callbacks.
  // Don't touch available_externally functions, their actual body is elewhere.
  if (F.getLinkage() == GlobalValue::AvailableExternallyLinkage) return;
  // Don't instrument MSVC CRT configuration helpers. They may run before normal
  // initialization.
  if (F.getName() == "__local_stdio_printf_options" ||
      F.getName() == "__local_stdio_scanf_options")
    return;
  if (isa<UnreachableInst>(F.getEntryBlock().getTerminator())) return;
  // Don't instrument functions using SEH for now. Splitting basic blocks like
  // we do for coverage breaks WinEHPrepare.
  // FIXME: Remove this when SEH no longer uses landingpad pattern matching.
  if (F.hasPersonalityFn() &&
      isAsynchronousEHPersonality(classifyEHPersonality(F.getPersonalityFn())))
    return;
  if (F.hasFnAttribute(Attribute::NoSanitizeCoverage)) return;
  if (Options.CoverageType >= SanitizerCoverageOptions::SCK_Edge)
    SplitAllCriticalEdges(
        F, CriticalEdgeSplittingOptions().setIgnoreUnreachableDests());
  SmallVector<BasicBlock *, 16> BlocksToInstrument;
  
  SmallVector<Instruction *, 8>       CmpTraceTargets; // cmp
  SmallVector<Instruction *, 8>       SancovForCmp;    
  
  SmallVector<Instruction *, 8>       CmpTraceTargetsNonTerminator; // cmp
  SmallVector<Instruction *, 8>       SancovForCmpNonTerminator;
  SmallVector<Instruction *, 8>       SelectInstArray; // select
  
  SmallVector<Instruction *, 8>       StrcmpTraceTargets; // strcmp
  SmallVector<Instruction *, 8>       SancovForStrcmp;
  
  SmallVector<Instruction *, 8>       StrcmpTraceTargetsNonTerminator;
  
  SmallVector<Instruction *, 8>       SwitchTraceTargets; // switch
  SmallVector<Instruction *, 8>       SancovForSwitch; 
  SmallVector<ConstantInt*, 128>      case_val_list;
  SmallVector<Instruction*, 128>      case_target_list;  // target BB: load @sancov_gen
  std::vector<int>                    int_val_list;

  DenseMap<Instruction *, size_t>     SancovMapIndex;
  DenseMap<BasicBlock*, size_t> BBMapIndex;

  const DominatorTree     *DT = DTCallback(F);
  const PostDominatorTree *PDT = PDTCallback(F);
  bool                     IsLeafFunc = true;
  
  unordered_set<string> funcName{"strcmp", "xmlStrcmp", "xmlStrEqual", "g_strcmp0", "curl_strequal", "strcsequal", "memcmp", "bcmp", "CRYPTO_memcmp", "OPENSSL_memcmp", "memcmp_const_time", "memcmpct", "strncmp", "xmlStrncmp", "curl_strnequal", "strcasecmp", "stricmp", "ap_cstr_casecmp", "OPENSSL_strcasecmp", "xmlStrcasecmp", "g_strcasecmp", "g_ascii_strcasecmp", "Curl_strcasecompare", "Curl_safe_strcasecompare", "cmsstrcasecmp", "strncasecmp", "strnicmp", "ap_cstr_casecmpn", "OPENSSL_strncasecmp", "xmlStrncasecmp", "g_ascii_strncasecmp", "Curl_strncasecompare", "g_strncasecmp", "strstr", "g_strstr_len", "ap_strcasestr", "xmlStrstr", "xmlStrcasestr", "g_str_has_prefix", "g_str_has_suffix"};

  bool IsBlockInstrumented = false;
  bool IsBlcokInstrumentedWithCMP = false;
  for (auto &BB : F) {
    IsBlockInstrumented = false;
    IsBlcokInstrumentedWithCMP = false;
    if (shouldInstrumentBlock(F, &BB, DT, PDT, Options)) {
      BlocksToInstrument.push_back(&BB);
      IsBlockInstrumented = true;
    }
      
    /*
        for (auto &Inst : BB) {

          if (Options.TraceCmp) {

            if (ICmpInst *CMP = dyn_cast<ICmpInst>(&Inst))
              if (IsInterestingCmp(CMP, DT, Options))
                CmpTraceTargets.push_back(&Inst);
            if (isa<SwitchInst>(&Inst))
              SwitchTraceTargets.push_back(&Inst);

          }

        }

    */

  }


  InjectCoverage(F, BlocksToInstrument, SancovMapIndex, BBMapIndex, IsLeafFunc);
  // InjectTraceForCmp(F, CmpTraceTargets);
  // InjectTraceForSwitch(F, SwitchTraceTargets);

  // find mapping from sancov id to br_dist_edge_id
  IsBlockInstrumented = false;
  IsBlcokInstrumentedWithCMP = false;
  for (auto &BB : F) {
    IsBlockInstrumented = false;
    IsBlcokInstrumentedWithCMP = false;
    if (shouldInstrumentBlock(F, &BB, DT, PDT, Options)) {
      IsBlockInstrumented = true;
    }
    
    for (auto &Inst : BB) {
      if (ICmpInst *CMP = dyn_cast<ICmpInst>(&Inst)) {
        if (OptfuzzIsInterestingCmp(CMP, DT, Options, DL)) {  
          int found_cmp_terminator = 0;
          // 1. check CMP as branch condition
          if (auto* br_inst = dyn_cast<BranchInst>(BB.getTerminator())) {
            if (br_inst->isConditional()) {
              if (CmpInst* cmp_inst = dyn_cast<CmpInst> (br_inst->getCondition())){
                if (cmp_inst == CMP){
                  found_cmp_terminator = 1;
                  // if CMP is like CMP(strcmp(...), CONST), instrument strcmp instead of CMP
                  Value *A0 = CMP->getOperand(0);
                  Value *A1 = CMP->getOperand(1);
                  
                  bool FirstIsConst = isa<ConstantInt>(A0);
                  bool SecondIsConst = isa<ConstantInt>(A1);
                  bool instrumentStrcmp = 0;
                  if (!FirstIsConst && SecondIsConst) {
                    if (auto* callInst = dyn_cast<CallInst>(A0)){
                      Function *Callee = callInst->getCalledFunction();
                      if (!Callee) continue;
                      if (callInst->getCallingConv() != llvm::CallingConv::C) continue;
                      std::string tmp_name = Callee->getName().str();
                      // skip instrument CMP
                      if (funcName.find(tmp_name) != funcName.end()){
                        instrumentStrcmp = 1;
                        int found_sancov = 0;
                        for (auto &J : BB) {
                          if (LoadInst *ldInst = dyn_cast<LoadInst>(&J)) {
                            std::string ldInst_str;
                            llvm::raw_string_ostream ldss(ldInst_str);
                            J.print(ldss);
                            ldInst_str.erase(std::remove(ldInst_str.begin(), ldInst_str.end(), '\n'), ldInst_str.cend());
                            std::size_t found = ldInst_str.find("@__sancov_gen_");
                            if (found != std::string::npos) {
                              StrcmpTraceTargets.push_back(callInst);
                              SancovForStrcmp.push_back(ldInst);
                              found_sancov = 1;
                              break;
                            }
                          }
                        }
                        if (!found_sancov){
                          errs()<< "\n [BUG] strcmp fails to find sancov\n";
                        }
                      }
                    }    
                  }
                  // rare case
                  else if (FirstIsConst && !SecondIsConst) {
                    if (auto* callInst = dyn_cast<CallInst>(A1)){
                      Function *Callee = callInst->getCalledFunction();
                      if (!Callee) continue;
                      if (callInst->getCallingConv() != llvm::CallingConv::C) continue;
                      std::string tmp_name = Callee->getName().str();
                      // skip instrument CMP for strcmp
                      if (funcName.find(tmp_name) != funcName.end()){
                        instrumentStrcmp = 1;
                        int found_sancov = 0;
                        for (auto &J : BB) {
                          if (LoadInst *ldInst = dyn_cast<LoadInst>(&J)) {
                            std::string ldInst_str;
                            llvm::raw_string_ostream ldss(ldInst_str);
                            J.print(ldss);
                            ldInst_str.erase(std::remove(ldInst_str.begin(), ldInst_str.end(), '\n'), ldInst_str.cend());
                            std::size_t found = ldInst_str.find("@__sancov_gen_");
                            if (found != std::string::npos) {
                              StrcmpTraceTargets.push_back(callInst);
                              SancovForStrcmp.push_back(ldInst);
                              found_sancov = 1;
                              break;
                            }
                          }
                        }
                        if (!found_sancov){
                          errs()<< "\n [BUG] strcmp fails to find sancov\n";
                        }
                      }
                    }    
                  }

                  if (!instrumentStrcmp){
                    int found_sancov = 0;
                    for (auto &J : BB) {
                      if (LoadInst *ldInst = dyn_cast<LoadInst>(&J)) {
                        std::string ldInst_str;
                        llvm::raw_string_ostream ldss(ldInst_str);
                        J.print(ldss);
                        ldInst_str.erase(std::remove(ldInst_str.begin(), ldInst_str.end(), '\n'), ldInst_str.cend());
                        std::size_t found = ldInst_str.find("@__sancov_gen_");
                        if (found != std::string::npos) {
                          CmpTraceTargets.push_back(&Inst);
                          SancovForCmp.push_back(ldInst);
                          found_sancov = 1;
                          break;
                        }
                      }
                    }
                    if (!found_sancov){
                      errs()<< "\n [BUG] cmp fails to find sancov\n";
                    }
                  }
                }
              }
            }
          }
          if (found_cmp_terminator == 0){
            // 2. check cmp not as br condition
            // TODO: add support for nested condition.
            //
            // handle select inst
            for (User *U : CMP->users()) {
              if (SelectInst *Inst_tmp = dyn_cast<SelectInst>(U)) {
                std::string ldInst_str;
                llvm::raw_string_ostream ldss(ldInst_str);
                Inst_tmp->print(ldss);
                ldInst_str.erase(std::remove(ldInst_str.begin(), ldInst_str.end(), '\n'), ldInst_str.cend());
                std::size_t found = ldInst_str.find("@__sancov_gen_");
                if (found != std::string::npos) {
                  // ICMP used as select condition
                  if (CmpInst* tmp_cmp_inst = dyn_cast<CmpInst> (Inst_tmp->getCondition())){
                    if (tmp_cmp_inst == CMP){
                      int found_sancov = 0;
                      for (auto &J : BB) {
                        if (LoadInst *ldInst = dyn_cast<LoadInst>(&J)) {
                          std::string ldInst_str;
                          llvm::raw_string_ostream ldss(ldInst_str);
                          J.print(ldss);
                          ldInst_str.erase(std::remove(ldInst_str.begin(), ldInst_str.end(), '\n'), ldInst_str.cend());
                          std::size_t found = ldInst_str.find("@__sancov_gen_");
                          if (found != std::string::npos) {
			                CmpTraceTargetsNonTerminator.push_back(CMP);
			                SelectInstArray.push_back(Inst_tmp);
                            SancovForCmpNonTerminator.push_back(ldInst);
                            found_sancov = 1;
                            break;
                          }
                        }
                      }
                      if (!found_sancov){
                        errs()<< "\n [BUG] select fails to find sancov\n";
                      }
                      break;
                    }
                  }
                }
              }
            }
          } 
          IsBlcokInstrumentedWithCMP = true;
        }
        // TODO: is this code block necessary? Double-check if we really need this.
        else if (OptfuzzIsInterestingCmpPtr(CMP, DT, Options, DL)) {  
          // 1. check CMP as branch condition
          if (auto* br_inst = dyn_cast<BranchInst>(BB.getTerminator())) {
            if (br_inst->isConditional()) {
              if (CmpInst* cmp_inst = dyn_cast<CmpInst> (br_inst->getCondition())){
                if (cmp_inst == CMP){
                  // if CMP is like CMP(strcmp(...), CONST), instrument strcmp instead of CMP
                  Value *A0 = CMP->getOperand(0);
                  Value *A1 = CMP->getOperand(1);
                  bool FirstIsConst = isa<ConstantPointerNull>(A0);
                  bool SecondIsConst = isa<ConstantPointerNull>(A1);
                  bool instrumentStrcmp = 0;
                  if (!FirstIsConst && SecondIsConst) {
                    if (auto* callInst = dyn_cast<CallInst>(A0)){
                      Function *Callee = callInst->getCalledFunction();
                      if (!Callee) continue;
                      if (callInst->getCallingConv() != llvm::CallingConv::C) continue;
                      std::string tmp_name = Callee->getName().str();
                      // skip instrument CMP
                      if (funcName.find(tmp_name) != funcName.end()){
                        instrumentStrcmp = 1;
                        int found_sancov = 0;
                        for (auto &J : BB) {
                          if (LoadInst *ldInst = dyn_cast<LoadInst>(&J)) {
                            std::string ldInst_str;
                            llvm::raw_string_ostream ldss(ldInst_str);
                            J.print(ldss);
                            ldInst_str.erase(std::remove(ldInst_str.begin(), ldInst_str.end(), '\n'), ldInst_str.cend());
                            std::size_t found = ldInst_str.find("@__sancov_gen_");
                            if (found != std::string::npos) {
                              StrcmpTraceTargets.push_back(callInst);
                              SancovForStrcmp.push_back(ldInst);
                              found_sancov = 1;
                              break;
                            }
                          }
                        }
                        if (!found_sancov){
                          errs()<< "\n [BUG] strcmp fails to find sancov\n";
                        }
                      }
                    }    
                  }
                  // rare case
                  else if (FirstIsConst && !SecondIsConst) {
                    if (auto* callInst = dyn_cast<CallInst>(A1)){
                      Function *Callee = callInst->getCalledFunction();
                      if (!Callee) continue;
                      if (callInst->getCallingConv() != llvm::CallingConv::C) continue;
                      std::string tmp_name = Callee->getName().str();
                      // skip instrument CMP
                      if (funcName.find(tmp_name) != funcName.end()){
                        instrumentStrcmp = 1;
                        int found_sancov = 0;
                        for (auto &J : BB) {
                          if (LoadInst *ldInst = dyn_cast<LoadInst>(&J)) {
                            std::string ldInst_str;
                            llvm::raw_string_ostream ldss(ldInst_str);
                            J.print(ldss);
                            ldInst_str.erase(std::remove(ldInst_str.begin(), ldInst_str.end(), '\n'), ldInst_str.cend());
                            std::size_t found = ldInst_str.find("@__sancov_gen_");
                            if (found != std::string::npos) {
                              StrcmpTraceTargets.push_back(callInst);
                              SancovForStrcmp.push_back(ldInst);
                              found_sancov = 1;
                              break;
                            }
                          }
                        }
                        if (!found_sancov){
                          errs()<< "\n [BUG] strcmp fails to find sancov\n";
                        }
                      }
                    }    
                  }
                }
              }
            }
          }
        }
      }

      if (SwitchInst* SI = dyn_cast<SwitchInst>(&Inst)){
        Value* op1 = SI->getCondition();
        if (!op1->getType()->isIntegerTy()) continue;
        //uint64_t TypeSize = DL->getTypeStoreSizeInBits(op1->getType());
        unsigned TypeSize = (cast<IntegerType>(op1->getType()))->getBitWidth();
        int      CallbackIdx = TypeSize == 8    ? 0
                               : TypeSize == 16 ? 1
                               : TypeSize == 32 ? 2
                               : TypeSize == 64 ? 3
                                                : -1;
        if (CallbackIdx < 0) continue;
    
        SwitchTraceTargets.push_back(&Inst);
        // find sancov id for sw  
        int found_sancov = 0;
        for (auto &J : BB) {
          if (LoadInst *ldInst = dyn_cast<LoadInst>(&J)) {
            std::string ldInst_str;
            llvm::raw_string_ostream ldss(ldInst_str);
            J.print(ldss);
            ldInst_str.erase(std::remove(ldInst_str.begin(), ldInst_str.end(), '\n'), ldInst_str.cend());
            std::size_t found = ldInst_str.find("@__sancov_gen_");
            if (found != std::string::npos) {
              SancovForSwitch.push_back(ldInst);
              found_sancov = 1;
              break;
            }
          }
        }
        if (!found_sancov){
          errs()<< "\n[BUG] switch fails to find sancov 3\n";
        }
        // find target sancov id for each case
        for (auto i = SI->case_begin(), e = SI->case_end(); i != e;++i) {
          ConstantInt* op2 = dyn_cast<ConstantInt>(i->getCaseValue());
          BasicBlock* targetBB = i->getCaseSuccessor();
          found_sancov = 0; 
          for (auto &J : *targetBB) {
            if (LoadInst *ldInst = dyn_cast<LoadInst>(&J)) {
              std::string ldInst_str;
              llvm::raw_string_ostream ldss(ldInst_str);
              J.print(ldss);
              ldInst_str.erase(std::remove(ldInst_str.begin(), ldInst_str.end(), '\n'), ldInst_str.cend());
              std::size_t found = ldInst_str.find("@__sancov_gen_");
              if (found != std::string::npos) {
                int_val_list.push_back(op2->getSExtValue());
                case_val_list.push_back(op2);
                case_target_list.push_back(ldInst);
                found_sancov = 1;
                break;
              }
            }
          }
          if (!found_sancov){
            errs()<< "\n[BUG] switch fails to find target BB sancov 2\n";
          }
        }

        // find case value for default case
        std::vector<int> tmp_val_list;
        for (auto i = SI->case_begin(), e = SI->case_end(); i != e;++i) {
          ConstantInt* op2 = dyn_cast<ConstantInt>(i->getCaseValue());
          tmp_val_list.push_back(op2->getSExtValue());
        }
	if (tmp_val_list.empty()) {
            case_target_list.push_back(NULL);
            int_val_list.push_back(0);
            case_val_list.push_back(NULL);
            continue;
        }
        int max_int = *max_element(tmp_val_list.begin(), tmp_val_list.end());
        int min_int = *min_element(tmp_val_list.begin(), tmp_val_list.end());
        Value * de_val;
        int found_target_val = 0;
        for (int default_val = min_int; default_val < max_int; default_val ++ ){
          if (std::find(tmp_val_list.begin(), tmp_val_list.end(), default_val) == tmp_val_list.end()) {
            de_val = ConstantInt::get(op1->getType(), default_val);
            found_target_val = 1;
            break;
          }
        }
        if (!found_target_val)
          de_val = ConstantInt::get(op1->getType(), max_int+1);

        BasicBlock* targetBB = SI->getDefaultDest();
        found_sancov = 0;
        for (auto &J : *targetBB) {
          if (LoadInst *ldInst = dyn_cast<LoadInst>(&J)) {
            std::string ldInst_str;
            llvm::raw_string_ostream ldss(ldInst_str);
            J.print(ldss);
            ldInst_str.erase(std::remove(ldInst_str.begin(), ldInst_str.end(), '\n'), ldInst_str.cend());
            std::size_t found = ldInst_str.find("@__sancov_gen_");
            if (found != std::string::npos) {
              case_target_list.push_back(ldInst);
              ConstantInt* op2 = dyn_cast<ConstantInt>(de_val);
              int_val_list.push_back(op2->getSExtValue());
              case_val_list.push_back(op2);
              found_sancov = 1;
              break;
            }
          }
        }
        if (!found_sancov){
          // write dummy value for empty default case
          case_target_list.push_back(NULL);
          int_val_list.push_back(0);
          case_val_list.push_back(NULL);
          
          SI->print(errs());
          errs()<< "\n[LOG] skipped the dead default switch case\n";
        }
      } 
      
      if (isa<CallInst>(&Inst)) {
        CallInst* callInst = dyn_cast<CallInst>(&Inst);
        Function *Callee = callInst->getCalledFunction();
        if (!Callee) continue;
        if (callInst->getCallingConv() != llvm::CallingConv::C) continue;
        
        std::string tmp_name = Callee->getName().str();
        if (funcName.find(tmp_name) != funcName.end()){
          
          // case1: strcmp used in terminator condition
          bool found_item = 0;
          for (auto tmpI : StrcmpTraceTargets) {
            if (tmpI == callInst){
              found_item = 1;
              break;
            }
          }
          // case 2: Strcmp not used in terminator condition
          if (!found_item)    
            StrcmpTraceTargetsNonTerminator.push_back(callInst);
        }
      } 
    }
  }
  
  // handle select instruction FIRST!!!! 
  //OptfuzzInjectTraceForCmpNonTerminator(F, CmpTraceTargetsNonTerminator, SancovForCmpNonTerminator,  SelectInstArray,  InstrumentCntPtr, datalog);

  //cmp
  OptfuzzInjectTraceForCmp(F, CmpTraceTargets, SancovForCmp, InstrumentCntPtr, datalog, SancovMapIndex);
  //strcmp
  OptfuzzInjectTraceForStrcmp(F, StrcmpTraceTargets, SancovForStrcmp, InstrumentCntPtr, errlog, datalog, SancovMapIndex);
  
  //switch
  OptfuzzInjectTraceForSwitch(F, SwitchTraceTargets, SancovForSwitch, case_target_list, case_val_list, int_val_list, InstrumentCntPtr, datalog, SancovMapIndex);

}

GlobalVariable *ModuleSanitizerCoverageAFL::CreateFunctionLocalArrayInSection(
    size_t NumElements, Function &F, Type *Ty, const char *Section) {

  ArrayType *ArrayTy = ArrayType::get(Ty, NumElements);
  auto       Array = new GlobalVariable(
      *CurModule, ArrayTy, false, GlobalVariable::PrivateLinkage,
      Constant::getNullValue(ArrayTy), "__sancov_gen_");

  if (TargetTriple.supportsCOMDAT() &&
      (TargetTriple.isOSBinFormatELF() || !F.isInterposable()))
    if (auto Comdat = getOrCreateFunctionComdat(F, TargetTriple))
      Array->setComdat(Comdat);
  Array->setSection(getSectionName(Section));
#if LLVM_VERSION_MAJOR >= 16
  Array->setAlignment(Align(DL->getTypeStoreSize(Ty).getFixedValue()));
#else
  Array->setAlignment(Align(DL->getTypeStoreSize(Ty).getFixedSize()));
#endif

  // sancov_pcs parallels the other metadata section(s). Optimizers (e.g.
  // GlobalOpt/ConstantMerge) may not discard sancov_pcs and the other
  // section(s) as a unit, so we conservatively retain all unconditionally in
  // the compiler.
  //
  // With comdat (COFF/ELF), the linker can guarantee the associated sections
  // will be retained or discarded as a unit, so llvm.compiler.used is
  // sufficient. Otherwise, conservatively make all of them retained by the
  // linker.
  if (Array->hasComdat())
    GlobalsToAppendToCompilerUsed.push_back(Array);
  else
    GlobalsToAppendToUsed.push_back(Array);

  return Array;

}

GlobalVariable *ModuleSanitizerCoverageAFL::CreatePCArray(
    Function &F, ArrayRef<BasicBlock *> AllBlocks) {

  size_t N = AllBlocks.size();
  assert(N);
  SmallVector<Constant *, 32> PCs;
  IRBuilder<>                 IRB(&*F.getEntryBlock().getFirstInsertionPt());
  for (size_t i = 0; i < N; i++) {

    if (&F.getEntryBlock() == AllBlocks[i]) {

      PCs.push_back((Constant *)IRB.CreatePointerCast(&F, IntptrPtrTy));
      PCs.push_back((Constant *)IRB.CreateIntToPtr(
          ConstantInt::get(IntptrTy, 1), IntptrPtrTy));

    } else {

      PCs.push_back((Constant *)IRB.CreatePointerCast(
          BlockAddress::get(AllBlocks[i]), IntptrPtrTy));
#if LLVM_VERSION_MAJOR >= 16
      PCs.push_back(Constant::getNullValue(IntptrPtrTy));
#else
      PCs.push_back((Constant *)IRB.CreateIntToPtr(
          ConstantInt::get(IntptrTy, 0), IntptrPtrTy));
#endif

    }

  }

  auto *PCArray = CreateFunctionLocalArrayInSection(N * 2, F, IntptrPtrTy,
                                                    SanCovPCsSectionName);
  PCArray->setInitializer(
      ConstantArray::get(ArrayType::get(IntptrPtrTy, N * 2), PCs));
  PCArray->setConstant(true);

  return PCArray;

}

void ModuleSanitizerCoverageAFL::CreateFunctionLocalArrays(
    Function &F, ArrayRef<BasicBlock *> AllBlocks, uint32_t special) {

  if (Options.TracePCGuard)
    FunctionGuardArray = CreateFunctionLocalArrayInSection(
        AllBlocks.size() + special, F, Int32Ty, SanCovGuardsSectionName);

}

bool ModuleSanitizerCoverageAFL::InjectCoverage(
    Function &F, ArrayRef<BasicBlock *> AllBlocks, DenseMap<Instruction *, size_t> &SancovMapIndex, DenseMap<BasicBlock*, size_t> &BBMapIndex, bool IsLeafFunc) {

  if (AllBlocks.empty()) return false;

  uint32_t        cnt_cov = 0, cnt_sel = 0, cnt_sel_inc = 0;
  static uint32_t first = 1;

  for (auto &BB : F) {

    for (auto &IN : BB) {

      CallInst *callInst = nullptr;

      if ((callInst = dyn_cast<CallInst>(&IN))) {

        Function *Callee = callInst->getCalledFunction();
        if (!Callee) continue;
        if (callInst->getCallingConv() != llvm::CallingConv::C) continue;
        StringRef FuncName = Callee->getName();
        if (!FuncName.compare(StringRef("dlopen")) ||
            !FuncName.compare(StringRef("_dlopen"))) {

          fprintf(stderr,
                  "WARNING: dlopen() detected. To have coverage for a library "
                  "that your target dlopen()'s this must either happen before "
                  "__AFL_INIT() or you must use AFL_PRELOAD to preload all "
                  "dlopen()'ed libraries!\n");
          continue;

        }

        if (!FuncName.compare(StringRef("__afl_coverage_interesting"))) {

          cnt_cov++;

        }

      }

      SelectInst *selectInst = nullptr;

      if ((selectInst = dyn_cast<SelectInst>(&IN))) {

        Value *c = selectInst->getCondition();
        auto   t = c->getType();
        if (t->getTypeID() == llvm::Type::IntegerTyID) {

          cnt_sel++;
          cnt_sel_inc += 2;

        }

        else if (t->getTypeID() == llvm::Type::FixedVectorTyID) {

          FixedVectorType *tt = dyn_cast<FixedVectorType>(t);
          if (tt) {

            cnt_sel++;
            cnt_sel_inc += (tt->getElementCount().getKnownMinValue() * 2);

          }

        }

      }

    }

  }

  CreateFunctionLocalArrays(F, AllBlocks, first + cnt_cov + cnt_sel_inc);

  if (first) { first = 0; }
  selects += cnt_sel;

  uint32_t special = 0, local_selects = 0, skip_next = 0;

  for (auto &BB : F) {

    for (auto &IN : BB) {

      CallInst *callInst = nullptr;

      if ((callInst = dyn_cast<CallInst>(&IN))) {

        Function *Callee = callInst->getCalledFunction();
        if (!Callee) continue;
        if (callInst->getCallingConv() != llvm::CallingConv::C) continue;
        StringRef FuncName = Callee->getName();
        if (FuncName.compare(StringRef("__afl_coverage_interesting"))) continue;

        IRBuilder<> IRB(callInst);

        if (!FunctionGuardArray) {

          fprintf(stderr,
                  "SANCOV: FunctionGuardArray is NULL, failed to emit "
                  "instrumentation.");
          continue;

        }

        Value *GuardPtr = IRB.CreateIntToPtr(
            IRB.CreateAdd(
                IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                ConstantInt::get(IntptrTy, (special++ + AllBlocks.size()) * 4)),
            Int32PtrTy);

        LoadInst *Idx = IRB.CreateLoad(IRB.getInt32Ty(), GuardPtr);
        ModuleSanitizerCoverageAFL::SetNoSanitizeMetadata(Idx);

        callInst->setOperand(1, Idx);

      }

      SelectInst *selectInst = nullptr;

      if (!skip_next && (selectInst = dyn_cast<SelectInst>(&IN))) {

        uint32_t    vector_cnt = 0;
        Value      *condition = selectInst->getCondition();
        Value      *result;
        auto        t = condition->getType();
        IRBuilder<> IRB(selectInst->getNextNode());

        if (t->getTypeID() == llvm::Type::IntegerTyID) {

          if (!FunctionGuardArray) {

            fprintf(stderr,
                    "SANCOV: FunctionGuardArray is NULL, failed to emit "
                    "instrumentation.");
            continue;

          }

          auto GuardPtr1 = IRB.CreateIntToPtr(
              IRB.CreateAdd(
                  IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                  ConstantInt::get(
                      IntptrTy,
                      (cnt_cov + local_selects++ + AllBlocks.size()) * 4)),
              Int32PtrTy);

          auto GuardPtr2 = IRB.CreateIntToPtr(
              IRB.CreateAdd(
                  IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                  ConstantInt::get(
                      IntptrTy,
                      (cnt_cov + local_selects++ + AllBlocks.size()) * 4)),
              Int32PtrTy);

          result = IRB.CreateSelect(condition, GuardPtr1, GuardPtr2);

        } else

#if LLVM_VERSION_MAJOR >= 14
            if (t->getTypeID() == llvm::Type::FixedVectorTyID) {

          FixedVectorType *tt = dyn_cast<FixedVectorType>(t);
          if (tt) {

            uint32_t elements = tt->getElementCount().getFixedValue();
            vector_cnt = elements;
            if (elements) {

              FixedVectorType *GuardPtr1 =
                  FixedVectorType::get(Int32PtrTy, elements);
              FixedVectorType *GuardPtr2 =
                  FixedVectorType::get(Int32PtrTy, elements);
              Value *x, *y;

              if (!FunctionGuardArray) {

                fprintf(stderr,
                        "SANCOV: FunctionGuardArray is NULL, failed to emit "
                        "instrumentation.");
                continue;

              }

              Value *val1 = IRB.CreateIntToPtr(
                  IRB.CreateAdd(
                      IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                      ConstantInt::get(
                          IntptrTy,
                          (cnt_cov + local_selects++ + AllBlocks.size()) * 4)),
                  Int32PtrTy);
              x = IRB.CreateInsertElement(GuardPtr1, val1, (uint64_t)0);

              Value *val2 = IRB.CreateIntToPtr(
                  IRB.CreateAdd(
                      IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                      ConstantInt::get(
                          IntptrTy,
                          (cnt_cov + local_selects++ + AllBlocks.size()) * 4)),
                  Int32PtrTy);
              y = IRB.CreateInsertElement(GuardPtr2, val2, (uint64_t)0);

              for (uint64_t i = 1; i < elements; i++) {

                val1 = IRB.CreateIntToPtr(
                    IRB.CreateAdd(
                        IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                        ConstantInt::get(IntptrTy, (cnt_cov + local_selects++ +
                                                    AllBlocks.size()) *
                                                       4)),
                    Int32PtrTy);
                x = IRB.CreateInsertElement(x, val1, i);

                val2 = IRB.CreateIntToPtr(
                    IRB.CreateAdd(
                        IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                        ConstantInt::get(IntptrTy, (cnt_cov + local_selects++ +
                                                    AllBlocks.size()) *
                                                       4)),
                    Int32PtrTy);
                y = IRB.CreateInsertElement(y, val2, i);

              }

              result = IRB.CreateSelect(condition, x, y);

            }

          }

        } else

#endif
        {

          // fprintf(stderr, "UNHANDLED: %u\n", t->getTypeID());
          unhandled++;
          continue;

        }

        uint32_t vector_cur = 0;

        /* Load SHM pointer */

        LoadInst *MapPtr =
            IRB.CreateLoad(PointerType::get(Int8Ty, 0), AFLMapPtr);
        ModuleSanitizerCoverageAFL::SetNoSanitizeMetadata(MapPtr);

        while (1) {

          /* Get CurLoc */
          LoadInst *CurLoc = nullptr;
          Value    *MapPtrIdx = nullptr;

          /* Load counter for CurLoc */
          if (!vector_cnt) {

            CurLoc = IRB.CreateLoad(IRB.getInt32Ty(), result);
            ModuleSanitizerCoverageAFL::SetNoSanitizeMetadata(CurLoc);
            MapPtrIdx = IRB.CreateGEP(Int8Ty, MapPtr, CurLoc);

          } else {

            auto element = IRB.CreateExtractElement(result, vector_cur++);
            auto elementptr = IRB.CreateIntToPtr(element, Int32PtrTy);
            auto elementld = IRB.CreateLoad(IRB.getInt32Ty(), elementptr);
            ModuleSanitizerCoverageAFL::SetNoSanitizeMetadata(elementld);
            MapPtrIdx = IRB.CreateGEP(Int8Ty, MapPtr, elementld);

          }

          if (use_threadsafe_counters) {

            IRB.CreateAtomicRMW(llvm::AtomicRMWInst::BinOp::Add, MapPtrIdx, One,
#if LLVM_VERSION_MAJOR >= 13
                                llvm::MaybeAlign(1),
#endif
                                llvm::AtomicOrdering::Monotonic);

          } else {

            LoadInst *Counter = IRB.CreateLoad(IRB.getInt8Ty(), MapPtrIdx);
            ModuleSanitizerCoverageAFL::SetNoSanitizeMetadata(Counter);

            /* Update bitmap */

            Value *Incr = IRB.CreateAdd(Counter, One);

            if (skip_nozero == NULL) {

              auto cf = IRB.CreateICmpEQ(Incr, Zero);
              auto carry = IRB.CreateZExt(cf, Int8Ty);
              Incr = IRB.CreateAdd(Incr, carry);

            }

            StoreInst *StoreCtx = IRB.CreateStore(Incr, MapPtrIdx);
            ModuleSanitizerCoverageAFL::SetNoSanitizeMetadata(StoreCtx);

          }

          if (!vector_cnt) {

            vector_cnt = 2;
            break;

          } else if (vector_cnt == vector_cur) {

            break;

          }

        }

        skip_next = 1;
        instr += vector_cnt;

      } else {

        skip_next = 0;

      }

    }

  }

  if (AllBlocks.empty() && !special && !local_selects) return false;

  if (!AllBlocks.empty())
    for (size_t i = 0, N = AllBlocks.size(); i < N; i++)
    {
      BBMapIndex[AllBlocks[i]] = i;
      InjectCoverageAtBlock(F, *AllBlocks[i], i,SancovMapIndex, IsLeafFunc);
    }
      

  if (!AllBlocks.empty())
    for (size_t i = 0, N = AllBlocks.size(); i < N; i++){
      // for all succs of BB, record the edge
      BasicBlock *BB = AllBlocks[i];
      size_t pred_index = i;
      IRBuilder<> Builder(*C);
      for (auto *Succ : successors(BB)){
        // first check Succ is in AllBlocks
        if (std::find(AllBlocks.begin(), AllBlocks.end(), Succ) != AllBlocks.end()){
          size_t succ_index = BBMapIndex[Succ];
          Type *PtrType = Int32Ty->getPointerTo();
          StructType* MyStructType = StructType::get(*C, {PtrType, PtrType});
          Constant *PredPtr = ConstantExpr::getGetElementPtr(FunctionGuardArray->getValueType(), FunctionGuardArray, ArrayRef<Constant*>({Builder.getInt32(0), Builder.getInt32(pred_index)}));
          Constant *SuccPtr = ConstantExpr::getGetElementPtr(FunctionGuardArray->getValueType(), FunctionGuardArray, ArrayRef<Constant*>({Builder.getInt32(0), Builder.getInt32(succ_index)}));
          Constant* StructInit = ConstantStruct::get(MyStructType, {PredPtr, SuccPtr});
          GlobalVariable* MyStructGlobal = new GlobalVariable(*CurModule, MyStructType, true, GlobalValue::InternalLinkage, StructInit, "pred_succ_edge");
          
          MyStructGlobal->setSection(".cfg_log_section");
          if (TargetTriple.supportsCOMDAT() && (TargetTriple.isOSBinFormatELF() || !F.isInterposable()))
            if (auto Comdat = getOrCreateFunctionComdat(F, TargetTriple))
                MyStructGlobal->setComdat(Comdat);
          
          if (MyStructGlobal->hasComdat())
            GlobalsToAppendToCompilerUsed.push_back(MyStructGlobal);
          else
            GlobalsToAppendToUsed.push_back(MyStructGlobal);
        }
      }
    }

  return true;

}

void ModuleSanitizerCoverageAFL::OptfuzzInjectTraceForSwitch(Function &F, ArrayRef<Instruction *> SwitchTraceTargets, ArrayRef<Instruction *> SancovForSwitch, ArrayRef<Instruction *> case_target_list, ArrayRef<ConstantInt *> case_val_list, std::vector<int> int_val_list, int * InstrumentCntPtr,  ofstream &datalog, DenseMap<Instruction *, size_t> &SancovMapIndex) {
  int iter_cnt = -1;
  int caseCnt = -1;
  for (auto I : SwitchTraceTargets) {
    iter_cnt += 1;
    if (SwitchInst *SI = dyn_cast<SwitchInst>(I)) {

      Value* op1 = SI->getCondition();
      //uint64_t TypeSize = DL->getTypeStoreSizeInBits(op1->getType());
      unsigned TypeSize = (cast<IntegerType>(op1->getType()))->getBitWidth();
      int      CallbackIdx = TypeSize == 8    ? 0
                             : TypeSize == 16 ? 1
                             : TypeSize == 32 ? 2
                             : TypeSize == 64 ? 3
                                              : -1;
      if (CallbackIdx < 0) continue;
      
      auto CallbackFunc = OptfuzzTraceSwitchFunction[CallbackIdx];
      
      int num_cases = SI->getNumCases();
      
      std::string ldInst_str;
      llvm::raw_string_ostream ldss(ldInst_str);
      SancovForSwitch[iter_cnt]->print(ldss);
      ldInst_str.erase(std::remove(ldInst_str.begin(), ldInst_str.end(), '\n'), ldInst_str.cend());

      for (int i = 0; i< num_cases;i++) {
        caseCnt += 1;
        std::string str,cmp_str, key;
        llvm::raw_string_ostream ss(str);
        SI->print(ss);
        str.erase(std::remove(str.begin(), str.end(), '\n'), str.cend());
        cmp_str = str;
        
        std::string target_str;
        llvm::raw_string_ostream lds(target_str);
        Instruction* loadInst = case_target_list[caseCnt];
        int cur_case_val = int_val_list[caseCnt];
        loadInst->print(lds);
        target_str.erase(std::remove(target_str.begin(), target_str.end(), '\n'), target_str.cend());
        int instrument_id = *InstrumentCntPtr;

        // br_dist_edge_id|inst: sancov id |inst: cmp/strcmp/sw| inst: select| case_val; inst: sw target
        // string concatination
        std::ostringstream oss;
        oss << "3|" << instrument_id << "|" << ldInst_str << "| | |"  << cur_case_val << ";" << target_str << "|" << TypeSize / 8 << "\n";
        datalog << oss.str();

      Instruction *SancovLoad = SancovForSwitch[iter_cnt];
      size_t index = SancovMapIndex[SancovLoad];

      // create one global variable for each switch case
      Type *ElemPtrType = Int32Ty->getPointerTo();
      IRBuilder<> Builder(*C);
      Constant *ArrayElemPtr = ConstantExpr::getGetElementPtr(FunctionGuardArray->getValueType(), FunctionGuardArray, ArrayRef<Constant*>({Builder.getInt32(0), Builder.getInt32(index)}));
      StructType* MyStructType = StructType::get(*C, {ElemPtrType, Int32Ty});
      Constant* StructInit = ConstantStruct::get(MyStructType, {ArrayElemPtr, ConstantInt::get(Int32Ty, instrument_id)});
      GlobalVariable* MyStructGlobal = new GlobalVariable(*CurModule, MyStructType, true, GlobalValue::InternalLinkage, StructInit, "san_cov_dummy_id");
      if (TargetTriple.supportsCOMDAT() && (TargetTriple.isOSBinFormatELF() || !F.isInterposable()))
        if (auto Comdat = getOrCreateFunctionComdat(F, TargetTriple))
          MyStructGlobal->setComdat(Comdat);
      
      MyStructGlobal->setSection(".log_section");
      if (MyStructGlobal->hasComdat())
        GlobalsToAppendToCompilerUsed.push_back(MyStructGlobal);
      else
        GlobalsToAppendToUsed.push_back(MyStructGlobal);

        IRBuilder<> IRB(SI);
        Value* br_id =  ConstantInt::get(Int32Ty, instrument_id);
        auto *LoadBrCovMap = IRB.CreateLoad(PointerType::get(Int8Ty, 0), BrCovMapPtr);
        auto *BrCovPtr = IRB.CreateGEP(Int8Ty, LoadBrCovMap, br_id);
        auto Load = IRB.CreateLoad(Int8Ty, BrCovPtr);
        MDNode* N = MDNode::get(SI->getContext(), MDString::get(SI->getContext(), "Optfuzz"));
        Load->setMetadata("NoGraph", N);
        SetNoSanitizeMetadata(Load);
        SetNoSanitizeMetadata(LoadBrCovMap);
          
        Value* op2 = case_val_list[caseCnt];
        auto ThenTerm =  SplitBlockAndInsertIfThen(IRB.CreateIsNull(Load), SI, false);
        IRBuilder<> ThenIRB(ThenTerm);
        ThenIRB.CreateCall(CallbackFunc, {br_id, op1, op2});
        // update global instrumentCnt if we instrument a new site, update hash map
          if (TypeSize == 64)
            *InstrumentCntPtr = instrument_id + 2;
          else
            *InstrumentCntPtr = instrument_id + 1;
      }
    
      // handle default case: choose a target value for defacut case
      
      caseCnt+=1;
      Value* op2 = case_val_list[caseCnt]; // default case value   
      
      if (!op2){
        errs()<< "\n[LOG] skip to instrument an empty default case.\n";
        continue;
      }

      std::string str, cmp_str, key;
      llvm::raw_string_ostream ss(str);
      SI->print(ss);
      str.erase(std::remove(str.begin(), str.end(), '\n'), str.cend());
      cmp_str = str;
      
      std::string target_str;
      llvm::raw_string_ostream lds(target_str);
      Instruction* loadInst = case_target_list[caseCnt];
      int cur_case_val = int_val_list[caseCnt];
      loadInst->print(lds);
      target_str.erase(std::remove(target_str.begin(), target_str.end(), '\n'), target_str.cend());
      int instrument_id = *InstrumentCntPtr;
      
      std::ostringstream oss;
      oss << "3|" << instrument_id << "|" << ldInst_str << "| | |"  << cur_case_val << ";" << target_str << "|" << TypeSize / 8 << "\n";
      datalog << oss.str();

      Instruction *SancovLoad = SancovForSwitch[iter_cnt];
      size_t index = SancovMapIndex[SancovLoad];
      // create one global variable for each switch case
      Type *ElemPtrType = Int32Ty->getPointerTo();
      IRBuilder<> Builder(*C);
      Constant *ArrayElemPtr = ConstantExpr::getGetElementPtr(FunctionGuardArray->getValueType(), FunctionGuardArray, ArrayRef<Constant*>({Builder.getInt32(0), Builder.getInt32(index)}));
      StructType* MyStructType = StructType::get(*C, {ElemPtrType, Int32Ty});
      Constant* StructInit = ConstantStruct::get(MyStructType, {ArrayElemPtr, ConstantInt::get(Int32Ty, instrument_id)});
      GlobalVariable* MyStructGlobal = new GlobalVariable(*CurModule, MyStructType, true, GlobalValue::InternalLinkage, StructInit, "san_cov_dummy_id");
      if (TargetTriple.supportsCOMDAT() && (TargetTriple.isOSBinFormatELF() || !F.isInterposable()))
        if (auto Comdat = getOrCreateFunctionComdat(F, TargetTriple))
          MyStructGlobal->setComdat(Comdat);
      
      MyStructGlobal->setSection(".log_section");
      if (MyStructGlobal->hasComdat())
        GlobalsToAppendToCompilerUsed.push_back(MyStructGlobal);
      else
        GlobalsToAppendToUsed.push_back(MyStructGlobal);
      
      IRBuilder<> IRB(SI);
      Value* br_id =  ConstantInt::get(Int32Ty, instrument_id);
      auto *LoadBrCovMap = IRB.CreateLoad(PointerType::get(Int8Ty, 0), BrCovMapPtr);
      auto *BrCovPtr = IRB.CreateGEP(Int8Ty, LoadBrCovMap, br_id);
      auto Load = IRB.CreateLoad(Int8Ty, BrCovPtr);
      MDNode* N = MDNode::get(SI->getContext(), MDString::get(SI->getContext(), "Optfuzz"));
      Load->setMetadata("NoGraph", N);
      SetNoSanitizeMetadata(Load);
      SetNoSanitizeMetadata(LoadBrCovMap);
        
      auto ThenTerm =  SplitBlockAndInsertIfThen(IRB.CreateIsNull(Load), SI, false);
      IRBuilder<> ThenIRB(ThenTerm);
      ThenIRB.CreateCall(CallbackFunc, {br_id, op1, op2});

        if (TypeSize == 64)
          *InstrumentCntPtr = instrument_id + 2;
        else
          *InstrumentCntPtr = instrument_id + 1;
    }
  }
}


// For every switch statement we insert a call:
// __sanitizer_cov_trace_switch(CondValue,
//      {NumCases, ValueSizeInBits, Case0Value, Case1Value, Case2Value, ... })

void ModuleSanitizerCoverageAFL::InjectTraceForSwitch(
    Function &, ArrayRef<Instruction *> SwitchTraceTargets) {

  for (auto I : SwitchTraceTargets) {

    if (SwitchInst *SI = dyn_cast<SwitchInst>(I)) {

      IRBuilder<>                 IRB(I);
      SmallVector<Constant *, 16> Initializers;
      Value                      *Cond = SI->getCondition();
      if (Cond->getType()->getScalarSizeInBits() >
          Int64Ty->getScalarSizeInBits())
        continue;
      Initializers.push_back(ConstantInt::get(Int64Ty, SI->getNumCases()));
      Initializers.push_back(
          ConstantInt::get(Int64Ty, Cond->getType()->getScalarSizeInBits()));
      if (Cond->getType()->getScalarSizeInBits() <
          Int64Ty->getScalarSizeInBits())
        Cond = IRB.CreateIntCast(Cond, Int64Ty, false);
      for (auto It : SI->cases()) {

        Constant *C = It.getCaseValue();
        if (C->getType()->getScalarSizeInBits() <
            Int64Ty->getScalarSizeInBits())
          C = ConstantExpr::getCast(CastInst::ZExt, It.getCaseValue(), Int64Ty);
        Initializers.push_back(C);

      }

      llvm::sort(drop_begin(Initializers, 2),
                 [](const Constant *A, const Constant *B) {

                   return cast<ConstantInt>(A)->getLimitedValue() <
                          cast<ConstantInt>(B)->getLimitedValue();

                 });

      ArrayType *ArrayOfInt64Ty = ArrayType::get(Int64Ty, Initializers.size());
      GlobalVariable *GV = new GlobalVariable(
          *CurModule, ArrayOfInt64Ty, false, GlobalVariable::InternalLinkage,
          ConstantArray::get(ArrayOfInt64Ty, Initializers),
          "__sancov_gen_cov_switch_values");
      IRB.CreateCall(SanCovTraceSwitchFunction,
                     {Cond, IRB.CreatePointerCast(GV, Int64PtrTy)});

    }

  }

}

void ModuleSanitizerCoverageAFL::OptfuzzInjectTraceForCmp(
    Function &F, ArrayRef<Instruction *> CmpTraceTargets,  ArrayRef<Instruction *> SancovForCmp, int * InstrumentCntPtr , ofstream &datalog, DenseMap<Instruction *, size_t> &SancovMapIndex) {

  int iter_cnt = -1;
  for (auto I : CmpTraceTargets) {
    iter_cnt += 1;
    if (ICmpInst *ICMP = dyn_cast<ICmpInst>(I)) {
      int cmp_opcode = 12;
      ICmpInst::Predicate pred = ICMP->getPredicate();
      switch (pred) {
         case ICmpInst::ICMP_UGT:
             cmp_opcode = 0;//"ICMP_UGT";
             break;
         case ICmpInst::ICMP_SGT: // 001
             cmp_opcode = 1;//"ICMP_SGT";
             break;
         case ICmpInst::ICMP_EQ:   // 010
             cmp_opcode = 2;//"ICMP_EQ";
             break;
         case ICmpInst::ICMP_UGE:   // 011
             cmp_opcode = 3;//"ICMP_UGE";
             break;
         case ICmpInst::ICMP_SGE:  // 011
             cmp_opcode = 4;//"ICMP_SGE";
             break;
         case ICmpInst::ICMP_ULT:  // 100
             cmp_opcode = 5;//"ICMP_ULT";
             break;
         case ICmpInst::ICMP_SLT:   // 100
             cmp_opcode = 6;//"ICMP_SLT";
             break;
         case ICmpInst::ICMP_NE:    // 101
             cmp_opcode = 7;//"ICMP_NE";
             break;
         case ICmpInst::ICMP_ULE:  // 110
             cmp_opcode = 8;//"ICMP_ULE";
             break;
         case ICmpInst::ICMP_SLE:  // 110
             cmp_opcode = 9;//"ICMP_SLE";
             break;
         // 10 for strcmp
         // 11 for switch
         // 12 for strncmp
         // 14 for memcmp
         // 15 for strstr
         default:
             cmp_opcode = 13;//"no_type";
      }
      if (cmp_opcode>9)
          continue;
      
      Value      *A0 = ICMP->getOperand(0);
      Value      *A1 = ICMP->getOperand(1);
      // TODO: add support to pointer operand.
      if (!A0->getType()->isIntegerTy()) continue;
      //uint64_t TypeSize = DL->getTypeStoreSizeInBits(A0->getType());
      unsigned TypeSize = (cast<IntegerType>(A0->getType()))->getBitWidth();
      int      CallbackIdx = TypeSize == 8    ? 0
                             : TypeSize == 16 ? 1
                             : TypeSize == 32 ? 2
                             : TypeSize == 64 ? 3
                                              : -1;
      if (CallbackIdx < 0) continue;
      // __sanitizer_cov_trace_cmp((type_size << 32) | predicate, A0, A1);
      bool FirstIsConst = isa<ConstantInt>(A0);
      bool SecondIsConst = isa<ConstantInt>(A1);
      // If both are const, then we don't need such a comparison.
      if (FirstIsConst && SecondIsConst) continue;
      
      FunctionCallee CallbackFunc;
      // non-equality cmp
      if (cmp_opcode != 2 && cmp_opcode != 7){
        if (cmp_opcode == 0 || cmp_opcode == 3 || cmp_opcode == 5 || cmp_opcode == 8)
          CallbackIdx = CallbackIdx+4;
        CallbackFunc = OptfuzzTraceCmpFunction[CallbackIdx];
      }
      else{
        CallbackFunc = OptfuzzTraceEqualFunction[CallbackIdx];
      }

      std::string str, key, cmp_str;
      llvm::raw_string_ostream ss(str);
      ICMP->print(ss);
      str.erase(std::remove(str.begin(), str.end(), '\n'), str.cend());
      cmp_str = str;
      
      int instrument_id = *InstrumentCntPtr;
      std::string ldInst_str;
      llvm::raw_string_ostream ldss(ldInst_str);
      SancovForCmp[iter_cnt]->print(ldss);
      ldInst_str.erase(std::remove(ldInst_str.begin(), ldInst_str.end(), '\n'), ldInst_str.cend());

      // type | br_dist_edge_id (dummy_id) | sancov ID (in raw load instruction)| cmp/strcmp/switch instruction | select(optional) | switch(optional) switch case value: target_bb_sancov ID (in raw load instruction) | strlen
      // type: 1 (common binary cmp) (br_dist_edge_id <=> sancov); 2 (strcmp-like cmp) (br_dist_edge_id <=> sancov ); 3 (switch) (br_dist_dist_id <=>[sancov1, sancov2]); 4 (select) (br_dist_edge_id <=> [sancov1, sancov2]) 
      std::ostringstream oss;
      oss << "1|" << instrument_id << "| |" << cmp_str << "| | |" << TypeSize / 8 << "\n";
      datalog << oss.str();

      Instruction *SancovLoad = SancovForCmp[iter_cnt];
      size_t index = SancovMapIndex[SancovLoad];
      // create one global variable for each switch case
      Type *ElemPtrType = Int32Ty->getPointerTo();
      IRBuilder<> Builder(*C);
      Constant *ArrayElemPtr = ConstantExpr::getGetElementPtr(FunctionGuardArray->getValueType(), FunctionGuardArray, ArrayRef<Constant*>({Builder.getInt32(0), Builder.getInt32(index)}));
      StructType* MyStructType = StructType::get(*C, {ElemPtrType, Int32Ty});
      Constant* StructInit = ConstantStruct::get(MyStructType, {ArrayElemPtr, ConstantInt::get(Int32Ty, instrument_id)});
      GlobalVariable* MyStructGlobal = new GlobalVariable(*CurModule, MyStructType, true, GlobalValue::InternalLinkage, StructInit, "san_cov_dummy_id");
      if (TargetTriple.supportsCOMDAT() && (TargetTriple.isOSBinFormatELF() || !F.isInterposable()))
        if (auto Comdat = getOrCreateFunctionComdat(F, TargetTriple))
          MyStructGlobal->setComdat(Comdat);
      
      MyStructGlobal->setSection(".log_section");
      if (MyStructGlobal->hasComdat())
        GlobalsToAppendToCompilerUsed.push_back(MyStructGlobal);
      else
        GlobalsToAppendToUsed.push_back(MyStructGlobal);

      
      IRBuilder<> IRB(ICMP);
      Value* br_id =  ConstantInt::get(Int32Ty, instrument_id);
      auto *LoadBrCovMap = IRB.CreateLoad(PointerType::get(Int8Ty, 0), BrCovMapPtr);
      auto *BrCovPtr = IRB.CreateGEP(Int8Ty, LoadBrCovMap, br_id);
      auto Load = IRB.CreateLoad(Int8Ty, BrCovPtr);
      MDNode* N = MDNode::get(ICMP->getContext(), MDString::get(ICMP->getContext(), "Optfuzz"));
      Load->setMetadata("NoGraph", N);
      SetNoSanitizeMetadata(Load);
      SetNoSanitizeMetadata(LoadBrCovMap);
      
      auto ThenTerm =  SplitBlockAndInsertIfThen(IRB.CreateIsNull(Load), ICMP, false);
      IRBuilder<> ThenIRB(ThenTerm);
      ThenIRB.CreateCall(CallbackFunc, {br_id, A0, A1 });
      if (TypeSize == 64)
        *InstrumentCntPtr = instrument_id + 2;
      else
        *InstrumentCntPtr = instrument_id + 1;
    }
  }
}

void ModuleSanitizerCoverageAFL::OptfuzzInjectTraceForCmpNonTerminator(
    Function &F, ArrayRef<Instruction *> CmpTraceTargetsNonTerminator, ArrayRef<Instruction *> SancovForCmpNonTerminator, ArrayRef<Instruction *> SelectInstArray, int* InstrumentCntPtr, ofstream &datalog) {
  
  int selectCnt = -1;
  for (auto I : CmpTraceTargetsNonTerminator) {
    selectCnt += 1;
    if (ICmpInst *ICMP = dyn_cast<ICmpInst>(I)) {
      int cmp_opcode = 12;
      ICmpInst::Predicate pred = ICMP->getPredicate();
      switch (pred) {
         case ICmpInst::ICMP_UGT:
             cmp_opcode = 0;//"ICMP_UGT";
             break;
         case ICmpInst::ICMP_SGT: // 001
             cmp_opcode = 1;//"ICMP_SGT";
             break;
         case ICmpInst::ICMP_EQ:   // 010
             cmp_opcode = 2;//"ICMP_EQ";
             break;
         case ICmpInst::ICMP_UGE:   // 011
             cmp_opcode = 3;//"ICMP_UGE";
             break;
         case ICmpInst::ICMP_SGE:  // 011
             cmp_opcode = 4;//"ICMP_SGE";
             break;
         case ICmpInst::ICMP_ULT:  // 100
             cmp_opcode = 5;//"ICMP_ULT";
             break;
         case ICmpInst::ICMP_SLT:   // 100
             cmp_opcode = 6;//"ICMP_SLT";
             break;
         case ICmpInst::ICMP_NE:    // 101
             cmp_opcode = 7;//"ICMP_NE";
             break;
         case ICmpInst::ICMP_ULE:  // 110
             cmp_opcode = 8;//"ICMP_ULE";
             break;
         case ICmpInst::ICMP_SLE:  // 110
             cmp_opcode = 9;//"ICMP_SLE";
             break;
         default:
             cmp_opcode = 13;//"no_type";
      }
      if (cmp_opcode>9)
          continue;
      
      Value      *A0 = ICMP->getOperand(0);
      Value      *A1 = ICMP->getOperand(1);
      
      // TODO: add support to pointer operand.
      if (!A0->getType()->isIntegerTy()) continue;
      //uint64_t TypeSize = DL->getTypeStoreSizeInBits(A0->getType());
      unsigned TypeSize = (cast<IntegerType>(A0->getType()))->getBitWidth();
      
      int      CallbackIdx = TypeSize == 8    ? 0
                             : TypeSize == 16 ? 1
                             : TypeSize == 32 ? 2
                             : TypeSize == 64 ? 3
                                              : -1;
      
      if (CallbackIdx < 0) continue;
      // __sanitizer_cov_trace_cmp((type_size << 32) | predicate, A0, A1);
      bool FirstIsConst = isa<ConstantInt>(A0);
      bool SecondIsConst = isa<ConstantInt>(A1);
      // If both are const, then we don't need such a comparison.
      if (FirstIsConst && SecondIsConst) continue;
      if (cmp_opcode == 0 || cmp_opcode == 3 || cmp_opcode == 5 || cmp_opcode == 8)
          CallbackIdx = CallbackIdx+4;
      //auto CallbackFunc = OptfuzzTraceCmpFunctionWithRandomId[CallbackIdx];
      auto CallbackFunc = OptfuzzTraceCmpFunction[CallbackIdx];
      
      std::string str,cmp_str, key;
      llvm::raw_string_ostream ss(str);
      ICMP->print(ss);
      str.erase(std::remove(str.begin(), str.end(), '\n'), str.cend());
      cmp_str = str;
      
      int instrument_id = *InstrumentCntPtr;

      std::string ldInst_str;
      llvm::raw_string_ostream ldss(ldInst_str);
      SancovForCmpNonTerminator[selectCnt]->print(ldss);
      ldInst_str.erase(std::remove(ldInst_str.begin(), ldInst_str.end(), '\n'), ldInst_str.cend());
      
      std::string select_str;
      llvm::raw_string_ostream sltstr(select_str);
      SelectInstArray[selectCnt]->print(sltstr);
      select_str.erase(std::remove(select_str.begin(), select_str.end(), '\n'), select_str.cend());

        // type | br_dist_edge_id (dummy_id) | sancov ID (in raw load instruction)| cmp/strcmp/switch instruction | select(optional) | switch(optional) switch case value: target_bb_sancov ID (in raw load instruction) | strlen
        // type: 1 (common binary cmp) (br_dist_edge_id <=> sancov); 2 (strcmp-like cmp) (br_dist_edge_id <=> sancov ); 3 (switch) (br_dist_dist_id <=>[sancov1, sancov2]); 4 (select) (br_dist_edge_id <=> [sancov1, sancov2]) 
        // br_dist_edge_id|inst: sancov id |inst: cmp/strcmp/sw| inst: select| inst: sw target
        std::ostringstream oss;
        oss <<"4|" << instrument_id << "|" << ldInst_str << "|" << cmp_str << "|" << select_str << "| |" << TypeSize / 8 << "\n" ;
        datalog << oss.str();
      
      IRBuilder<> IRB(ICMP);
      Value* br_id =  ConstantInt::get(Int32Ty, instrument_id);
      auto *LoadBrCovMap = IRB.CreateLoad(PointerType::get(Int8Ty, 0), BrCovMapPtr);
      auto *BrCovPtr = IRB.CreateGEP(Int8Ty, LoadBrCovMap, br_id);
      auto Load = IRB.CreateLoad(Int8Ty, BrCovPtr);
      MDNode* N = MDNode::get(ICMP->getContext(), MDString::get(ICMP->getContext(), "Optfuzz"));
      Load->setMetadata("NoGraph", N);
      SetNoSanitizeMetadata(Load);
      SetNoSanitizeMetadata(LoadBrCovMap);
      
      auto ThenTerm =  SplitBlockAndInsertIfThen(IRB.CreateIsNull(Load), ICMP, false);
      IRBuilder<> ThenIRB(ThenTerm);
      ThenIRB.CreateCall(CallbackFunc, {br_id, A0, A1 });
        if (TypeSize == 64)
          *InstrumentCntPtr = instrument_id + 2;
        else
          *InstrumentCntPtr = instrument_id + 1;
    }
  }
}

// strcmp:


void ModuleSanitizerCoverageAFL::OptfuzzInjectTraceForStrcmp(
    Function &F, ArrayRef<Instruction *> StrcmpTraceTargets, ArrayRef<Instruction *> SancovForStrcmp, int* InstrumentCntPtr, ofstream &errlog, ofstream &datalog, DenseMap<Instruction *, size_t> &SancovMapIndex) {

  unordered_set<string> isStrcmp{"strcmp", "xmlStrcmp", "xmlStrEqual", "g_strcmp0", "curl_strequal", "strcsequal", "strcasecmp", "stricmp", "ap_cstr_casecmp", "OPENSSL_strcasecmp", "xmlStrcasecmp", "g_strcasecmp", "g_ascii_strcasecmp", "Curl_strcasecompare",                     "Curl_safe_strcasecompare", "cmsstrcasecmp"};
  unordered_set<string> isMemcmp{"memcmp", "bcmp", "CRYPTO_memcmp", "OPENSSL_memcmp", "memcmp_const_time", "memcmpct"};
  unordered_set<string> isStrncmp{"strncmp", "xmlStrncmp", "curl_strnequal", "strncasecmp", "strnicmp", "ap_cstr_casecmpn", "OPENSSL_strncasecmp", "xmlStrncasecmp", "g_ascii_strncasecmp", "Curl_strncasecompare", "g_strncasecmp"};
  unordered_set<string> isStrstr{"strstr", "g_strstr_len", "ap_strcasestr", "xmlStrstr", "xmlStrcasestr", "g_str_has_prefix", "g_str_has_suffix"};
  //unordered_set<string> isStrcasecmp{"strcasecmp", "stricmp", "ap_cstr_casecmp", "OPENSSL_strcasecmp", "xmlStrcasecmp", "g_strcasecmp", "g_ascii_strcasecmp", "Curl_strcasecompare", "Curl_safe_strcasecompare", "cmsstrcasecmp"};
  //unordered_set<string> isStrncasecmp{"strncasecmp", "strnicmp", "ap_cstr_casecmpn", "OPENSSL_strncasecmp", "xmlStrncasecmp", "g_ascii_strncasecmp", "Curl_strncasecompare", "g_strncasecmp"};
  int cmpCnt = -1;
  for (auto I : StrcmpTraceTargets) {
    cmpCnt += 1;
    // handle strcmp(VAR1, const) or strcmp(const, VAR2) 
    if (CallInst *callInst = dyn_cast<CallInst>(I)) {
      Function *Callee = callInst->getCalledFunction();
      std::string tmp_name = Callee->getName().str();
      //if (isStrcmp.find(tmp_name) == isStrcmp.end()) continue;
      int funcIdx = 0;

      if (isStrcmp.find(tmp_name) != isStrcmp.end())
        funcIdx = 1;
      if (isStrncmp.find(tmp_name) != isStrncmp.end())
        funcIdx = 2;
      if (isMemcmp.find(tmp_name) != isMemcmp.end())
        funcIdx = 3;
      if (isStrstr.find(tmp_name) != isStrstr.end())
        funcIdx = 4;
      if (!funcIdx) continue;
      Value *A0 = callInst->getArgOperand(0);
      Value *A1 = callInst->getArgOperand(1);
      Value *A2 = NULL;
      std::string Str;
      StringRef   TmpStr1, TmpStr2;
      int num_constant_byte =0;
      int constant_loc = 0;
      getConstantStringInfo(A0, TmpStr1);
      if(TmpStr1.empty()){
        auto *Ptr = dyn_cast<ConstantExpr>(A0);
        if (Ptr && Ptr->getOpcode() == Instruction::GetElementPtr) {
          if (auto *Var = dyn_cast<GlobalVariable>(Ptr->getOperand(0))) {
            if (Var->hasInitializer()) {
              if (auto *Array = dyn_cast<ConstantDataArray>(Var->getInitializer())) {
                TmpStr1 = Array->getRawDataValues();
              }
            }
          }
        }
      }

      getConstantStringInfo(A1, TmpStr2);
      if (TmpStr2.empty()){
        auto *Ptr = dyn_cast<ConstantExpr>(A1);
        if (Ptr && Ptr->getOpcode() == Instruction::GetElementPtr) {
          if (auto *Var = dyn_cast<GlobalVariable>(Ptr->getOperand(0))) {
            if (Var->hasInitializer()) {
              if (auto *Array = dyn_cast<ConstantDataArray>(Var->getInitializer())) {
                TmpStr2 = Array->getRawDataValues();
              }
            }
          }
        }
      }

      if (TmpStr1.empty() && !TmpStr2.empty()){
        Str = TmpStr2.str();
        constant_loc = 1;
      }
      else if (TmpStr2.empty() && !TmpStr1.empty()){
        Str = TmpStr1.str();
        constant_loc = 0;
      }
      else {

        std::string err_str;
        llvm::raw_string_ostream ss(err_str);
        I->print(ss);
        err_str.erase(std::remove(err_str.begin(), err_str.end(), '\n'), err_str.cend());
        errlog << "! " << err_str <<"\n";
        continue;
      }
      num_constant_byte = Str.length();
      
      if (funcIdx == 2 || funcIdx == 3){
        A2 = callInst->getArgOperand(2);
        if (ConstantInt *CI = dyn_cast<ConstantInt>(A2)){
          num_constant_byte = (int)(CI->getSExtValue());
        }
        else{
          //errs() << "<<<<< ERR Strncmp/memcmp\n ";
          std::string err_str;
          llvm::raw_string_ostream ss(err_str);
          I->print(ss);
          err_str.erase(std::remove(err_str.begin(), err_str.end(), '\n'), err_str.cend());
          errlog << "# " << err_str <<"\n";
          //continue;
        }
      }
      // every byte diff can be [-255, 255], taking up a s64 location
      
      //errs() << "!!!!!!! DBG Strcmp " << Str << " " <<num_constant_byte << " " << num_edge_slots << " " << BlocksToInstrumentWithNoCMP.size()  << "\n";

      // ARGS: {edge_id, strcmp_arg1, strcmp_arg2, num_of_edge_slots_taken, num_of_bytes}

      std::string str, key, cmp_str;
      llvm::raw_string_ostream ss(str);
      callInst->print(ss);
      str.erase(std::remove(str.begin(), str.end(), '\n'), str.cend());
      cmp_str = str;

      int instrument_id = *InstrumentCntPtr;

      std::string ldInst_str;
      llvm::raw_string_ostream ldss(ldInst_str);
      SancovForStrcmp[cmpCnt]->print(ldss);
      ldInst_str.erase(std::remove(ldInst_str.begin(), ldInst_str.end(), '\n'), ldInst_str.cend());

      // br_dist_edge_id|inst: sancov id |inst: cmp/strcmp/sw| inst: select| inst: sw target
      std::ostringstream oss;
      oss <<"2|" << instrument_id << "| |" << cmp_str << "| | |" << num_constant_byte <<"\n";
      datalog << oss.str();


      Instruction *SancovLoad = SancovForStrcmp[cmpCnt];
      size_t index = SancovMapIndex[SancovLoad];
      // create one global variable for each switch case
      Type *ElemPtrType = Int32Ty->getPointerTo();
      IRBuilder<> Builder(*C);
      Constant *ArrayElemPtr = ConstantExpr::getGetElementPtr(FunctionGuardArray->getValueType(), FunctionGuardArray, ArrayRef<Constant*>({Builder.getInt32(0), Builder.getInt32(index)}));
      StructType* MyStructType = StructType::get(*C, {ElemPtrType, Int32Ty});
      Constant* StructInit = ConstantStruct::get(MyStructType, {ArrayElemPtr, ConstantInt::get(Int32Ty, instrument_id)});
      GlobalVariable* MyStructGlobal = new GlobalVariable(*CurModule, MyStructType, true, GlobalValue::InternalLinkage, StructInit, "san_cov_dummy_id");
      if (TargetTriple.supportsCOMDAT() && (TargetTriple.isOSBinFormatELF() || !F.isInterposable()))
        if (auto Comdat = getOrCreateFunctionComdat(F, TargetTriple))
          MyStructGlobal->setComdat(Comdat);
      
      MyStructGlobal->setSection(".log_section");
      if (MyStructGlobal->hasComdat())
        GlobalsToAppendToCompilerUsed.push_back(MyStructGlobal);
      else
        GlobalsToAppendToUsed.push_back(MyStructGlobal);


      Value* br_id =  ConstantInt::get(Int32Ty, instrument_id);
      IRBuilder<> IRB(callInst);
      auto *LoadBrCovMap = IRB.CreateLoad(PointerType::get(Int8Ty, 0), BrCovMapPtr);
      auto *BrCovPtr = IRB.CreateGEP(Int8Ty, LoadBrCovMap, br_id);
      auto Load = IRB.CreateLoad(Int8Ty, BrCovPtr);
      SetNoSanitizeMetadata(Load);
      SetNoSanitizeMetadata(LoadBrCovMap);
      MDNode* N = MDNode::get(callInst->getContext(), MDString::get(callInst->getContext(), "Optfuzz"));
      Load->setMetadata("NoGraph", N);
      
      auto ThenTerm =  SplitBlockAndInsertIfThen(IRB.CreateIsNull(Load), callInst, false);
      IRBuilder<> ThenIRB(ThenTerm);
      auto CallbackFunc = OptfuzzTraceStrcmpFunction[funcIdx-1];
      if (constant_loc == 1){
        SmallVector<Value* > Args =  {br_id, A1, A0, ConstantInt::get(Int64Ty, num_constant_byte)};
        ThenIRB.CreateCall(CallbackFunc, Args);
      }
      else{
        SmallVector<Value* > Args =  {br_id, A0, A1, ConstantInt::get(Int64Ty, num_constant_byte)};
        ThenIRB.CreateCall(CallbackFunc, Args);
      }
      *InstrumentCntPtr = instrument_id + ((int)ceil(((float)(num_constant_byte+1))/4));
    }
  }
}

void ModuleSanitizerCoverageAFL::InjectTraceForCmp(
    Function &, ArrayRef<Instruction *> CmpTraceTargets) {

  for (auto I : CmpTraceTargets) {

    if (ICmpInst *ICMP = dyn_cast<ICmpInst>(I)) {

      IRBuilder<> IRB(ICMP);
      Value      *A0 = ICMP->getOperand(0);
      Value      *A1 = ICMP->getOperand(1);
      if (!A0->getType()->isIntegerTy()) continue;
     //uint64_t TypeSize = DL->getTypeStoreSizeInBits(A0->getType());
      unsigned TypeSize = (cast<IntegerType>(A0->getType()))->getBitWidth();
      int      CallbackIdx = TypeSize == 8    ? 0
                             : TypeSize == 16 ? 1
                             : TypeSize == 32 ? 2
                             : TypeSize == 64 ? 3
                                              : -1;
      if (CallbackIdx < 0) continue;
      // __sanitizer_cov_trace_cmp((type_size << 32) | predicate, A0, A1);
      auto CallbackFunc = SanCovTraceCmpFunction[CallbackIdx];
      bool FirstIsConst = isa<ConstantInt>(A0);
      bool SecondIsConst = isa<ConstantInt>(A1);
      // If both are const, then we don't need such a comparison.
      if (FirstIsConst && SecondIsConst) continue;
      // If only one is const, then make it the first callback argument.
      if (FirstIsConst || SecondIsConst) {

        CallbackFunc = SanCovTraceConstCmpFunction[CallbackIdx];
        if (SecondIsConst) std::swap(A0, A1);

      }

      auto Ty = Type::getIntNTy(*C, TypeSize);
      IRB.CreateCall(CallbackFunc, {IRB.CreateIntCast(A0, Ty, true),
                                    IRB.CreateIntCast(A1, Ty, true)});

    }

  }

}

void ModuleSanitizerCoverageAFL::InjectCoverageAtBlock(Function   &F,
                                                       BasicBlock &BB,
                                                       size_t      Idx,
                                                       DenseMap<Instruction *, size_t> &SancovMapIndex, 
                                                       bool        IsLeafFunc) {

  BasicBlock::iterator IP = BB.getFirstInsertionPt();
  bool                 IsEntryBB = &BB == &F.getEntryBlock();
  DebugLoc             EntryLoc;

  if (IsEntryBB) {

    if (auto SP = F.getSubprogram())
      EntryLoc = DILocation::get(SP->getContext(), SP->getScopeLine(), 0, SP);
    // Keep static allocas and llvm.localescape calls in the entry block.  Even
    // if we aren't splitting the block, it's nice for allocas to be before
    // calls.
    IP = PrepareToSplitEntryBlock(BB, IP);
#if LLVM_VERSION_MAJOR < 15

  } else {

    EntryLoc = IP->getDebugLoc();
    if (!EntryLoc)
      if (auto *SP = F.getSubprogram())
        EntryLoc = DILocation::get(SP->getContext(), 0, 0, SP);
#endif

  }

#if LLVM_VERSION_MAJOR >= 16
  InstrumentationIRBuilder IRB(&*IP);
#else
  IRBuilder<> IRB(&*IP);
#endif
  if (EntryLoc) IRB.SetCurrentDebugLocation(EntryLoc);
  if (Options.TracePCGuard) {

    /*
      auto GuardPtr = IRB.CreateIntToPtr(
          IRB.CreateAdd(IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                        ConstantInt::get(IntptrTy, Idx * 4)),
          Int32PtrTy);
      IRB.CreateCall(SanCovTracePCGuard, GuardPtr)->setCannotMerge();
    */

    /* Get CurLoc */
    Value *GuardPtr = IRB.CreateIntToPtr(
        IRB.CreateAdd(IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                      ConstantInt::get(IntptrTy, Idx * 4)),
        Int32PtrTy);

    LoadInst *CurLoc = IRB.CreateLoad(IRB.getInt32Ty(), GuardPtr);
    SancovMapIndex[CurLoc] = Idx;
    ModuleSanitizerCoverageAFL::SetNoSanitizeMetadata(CurLoc);

    /* Load SHM pointer */

    LoadInst *MapPtr = IRB.CreateLoad(PointerType::get(Int8Ty, 0), AFLMapPtr);
    ModuleSanitizerCoverageAFL::SetNoSanitizeMetadata(MapPtr);

    /* Load counter for CurLoc */

    Value *MapPtrIdx = IRB.CreateGEP(Int8Ty, MapPtr, CurLoc);

    if (use_threadsafe_counters) {

      IRB.CreateAtomicRMW(llvm::AtomicRMWInst::BinOp::Add, MapPtrIdx, One,
#if LLVM_VERSION_MAJOR >= 13
                          llvm::MaybeAlign(1),
#endif
                          llvm::AtomicOrdering::Monotonic);

    } else {

      LoadInst *Counter = IRB.CreateLoad(IRB.getInt8Ty(), MapPtrIdx);
      ModuleSanitizerCoverageAFL::SetNoSanitizeMetadata(Counter);

      /* Update bitmap */

      Value *Incr = IRB.CreateAdd(Counter, One);

      if (skip_nozero == NULL) {

        auto cf = IRB.CreateICmpEQ(Incr, Zero);
        auto carry = IRB.CreateZExt(cf, Int8Ty);
        Incr = IRB.CreateAdd(Incr, carry);

      }

      StoreInst *StoreCtx = IRB.CreateStore(Incr, MapPtrIdx);
      ModuleSanitizerCoverageAFL::SetNoSanitizeMetadata(StoreCtx);

    }

    // done :)

    //    IRB.CreateCall(SanCovTracePCGuard, Offset)->setCannotMerge();
    //    IRB.CreateCall(SanCovTracePCGuard, GuardPtr)->setCannotMerge();
    ++instr;

  }

}

std::string ModuleSanitizerCoverageAFL::getSectionName(
    const std::string &Section) const {

  if (TargetTriple.isOSBinFormatCOFF()) {

    if (Section == SanCovCountersSectionName) return ".SCOV$CM";
    if (Section == SanCovBoolFlagSectionName) return ".SCOV$BM";
    if (Section == SanCovPCsSectionName) return ".SCOVP$M";
    return ".SCOV$GM";  // For SanCovGuardsSectionName.

  }

  if (TargetTriple.isOSBinFormatMachO()) return "__DATA,__" + Section;
  return "__" + Section;

}

std::string ModuleSanitizerCoverageAFL::getSectionStart(
    const std::string &Section) const {

  if (TargetTriple.isOSBinFormatMachO())
    return "\1section$start$__DATA$__" + Section;
  return "__start___" + Section;

}

std::string ModuleSanitizerCoverageAFL::getSectionEnd(
    const std::string &Section) const {

  if (TargetTriple.isOSBinFormatMachO())
    return "\1section$end$__DATA$__" + Section;
  return "__stop___" + Section;

}

