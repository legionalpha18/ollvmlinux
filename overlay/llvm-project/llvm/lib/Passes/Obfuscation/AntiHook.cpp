/*
    LLVM Anti Hooking Pass
    Copyright (C) 2017 Zhang(https://github.com/Naville/)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "AntiHook.h"
#include "CryptoUtils.h"
#include "Utils.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Linker/Linker.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <fstream>

// Arm A64 Instruction Set for A-profile architecture 2022-12, Page 56
#define AARCH64_SIGNATURE_B 0b000101
// Arm A64 Instruction Set for A-profile architecture 2022-12, Page 75
#define AARCH64_SIGNATURE_BR 0b1101011000011111000000
// Arm A64 Instruction Set for A-profile architecture 2022-12, Page 79
#define AARCH64_SIGNATURE_BRK 0b11010100001

using namespace llvm;

static cl::opt<std::string>
    PreCompiledIRPath("adhexrirpath",
                      cl::desc("External Path Pointing To Pre-compiled Anti "
                               "Hooking Handler IR"),
                      cl::value_desc("filename"), cl::init(""));

static cl::opt<bool> CheckInlineHook("ah_inline", cl::init(true), cl::NotHidden,
                                     cl::desc("Check Inline Hook for AArch64"));
static bool CheckInlineHookTemp = true;

static cl::opt<bool> AntiRebindSymbol("ah_antirebind", cl::init(false),
                                      cl::NotHidden,
                                      cl::desc("Make fishhook unavailable"));
static bool AntiRebindSymbolTemp = false;

namespace {

static bool initializeAntiHook(Module &M, Triple &triple) {
  triple = Triple(M.getTargetTriple());
  if (PreCompiledIRPath == "") {
    SmallString<32> Path;
    if (sys::path::home_directory(Path)) { // Stolen from LineEditor.cpp
      sys::path::append(Path, "Hikari");
      sys::path::append(Path,
                        "PrecompiledAntiHooking-" +
                            Triple::getArchTypeName(triple.getArch()) + "-" +
                            Triple::getOSTypeName(triple.getOS()) + ".bc");
      PreCompiledIRPath = Path.c_str();
    }
  }
  std::ifstream f(PreCompiledIRPath);
  if (f.good()) {
    errs() << "Linking PreCompiled AntiHooking IR From:" << PreCompiledIRPath
           << "\n";
    SMDiagnostic SMD;
    std::unique_ptr<Module> ADBM(
        parseIRFile(StringRef(PreCompiledIRPath), SMD, M.getContext()));
    if (ADBM)
      Linker::linkModules(M, std::move(ADBM), Linker::Flags::OverrideFromSrc);
  } else {
    errs() << "Failed To Link PreCompiled AntiHooking IR From:"
           << PreCompiledIRPath << "\n";
  }
  return true;
}

static void CreateCallbackAndJumpBack(IRBuilder<> *IRBB, BasicBlock *C,
                                      const Triple &triple) {
  Module *M = C->getModule();
  Function *AHCallBack = M->getFunction("AHCallBack");
  if (AHCallBack) {
    IRBB->CreateCall(AHCallBack);
  } else {
    if (triple.isOSDarwin() && triple.isAArch64()) {
      std::string exitsvcasm = "mov w16, #1\n";
      exitsvcasm +=
          "svc #" + std::to_string(cryptoutils->get_range(65536)) + "\n";
      InlineAsm *IA =
          InlineAsm::get(FunctionType::get(IRBB->getVoidTy(), false),
                         exitsvcasm, "", true, false);
      IRBB->CreateCall(IA);
    } else {
      FunctionType *ABFT =
          FunctionType::get(Type::getVoidTy(M->getContext()), false);
      Function *abort_declare =
          cast<Function>(M->getOrInsertFunction("abort", ABFT).getCallee());
      abort_declare->addFnAttr(Attribute::AttrKind::NoReturn);
      IRBB->CreateCall(abort_declare);
    }
  }
  IRBB->CreateBr(C);
}

static void HandleInlineHookAArch64(Function *F, const Triple &triple) {
  BasicBlock *A = &(F->getEntryBlock());
  BasicBlock *C = A->splitBasicBlock(A->getFirstNonPHIOrDbgOrLifetime());
  BasicBlock *B =
      BasicBlock::Create(F->getContext(), "HookDetectedHandler", F);
  BasicBlock *Detect = BasicBlock::Create(F->getContext(), "", F);
  BasicBlock *Detect2 = BasicBlock::Create(F->getContext(), "", F);
  // Change A's terminator to jump to B
  // We'll add new terminator in B to jump C later
  A->getTerminator()->eraseFromParent();
  BranchInst::Create(Detect, A);

  IRBuilder<> IRBDetect(Detect);
  IRBuilder<> IRBDetect2(Detect2);
  IRBuilder<> IRBB(B);

  Type *Int64Ty = Type::getInt64Ty(F->getContext());
  Type *Int32Ty = Type::getInt32Ty(F->getContext());
  Type *Int32PtrTy = PointerType::get(F->getContext(), 0);

  Value *Load =
      IRBDetect.CreateLoad(Int32Ty, IRBDetect.CreateBitCast(F, Int32PtrTy));
  Value *LS2 = IRBDetect.CreateLShr(Load, ConstantInt::get(Int32Ty, 26));
  Value *ICmpEQ2 = IRBDetect.CreateICmpEQ(
      LS2, ConstantInt::get(Int32Ty, AARCH64_SIGNATURE_B));
  Value *LS3 = IRBDetect.CreateLShr(Load, ConstantInt::get(Int32Ty, 21));
  Value *ICmpEQ3 = IRBDetect.CreateICmpEQ(
      LS3, ConstantInt::get(Int32Ty, AARCH64_SIGNATURE_BRK));
  Value *Or = IRBDetect.CreateOr(ICmpEQ2, ICmpEQ3);
  IRBDetect.CreateCondBr(Or, B, Detect2);

  Value *PTI = IRBDetect2.CreatePtrToInt(F, Int64Ty);
  Value *AddFour = IRBDetect2.CreateAdd(PTI, ConstantInt::get(Int64Ty, 4));
  Value *ITP = IRBDetect2.CreateIntToPtr(AddFour, Int32PtrTy);
  Value *Load2 = IRBDetect2.CreateLoad(Int32Ty, ITP);
  Value *LS4 = IRBDetect2.CreateLShr(Load2, ConstantInt::get(Int32Ty, 10));
  Value *ICmpEQ4 = IRBDetect2.CreateICmpEQ(
      LS4, ConstantInt::get(Int32Ty, AARCH64_SIGNATURE_BR));
  Value *AddEight = IRBDetect2.CreateAdd(PTI, ConstantInt::get(Int64Ty, 8));
  Value *ITP2 = IRBDetect2.CreateIntToPtr(AddEight, Int32PtrTy);
  Value *Load3 = IRBDetect2.CreateLoad(Int32Ty, ITP2);
  Value *LS5 = IRBDetect2.CreateLShr(Load3, ConstantInt::get(Int32Ty, 10));
  Value *ICmpEQ5 = IRBDetect2.CreateICmpEQ(
      LS5, ConstantInt::get(Int32Ty, AARCH64_SIGNATURE_BR));
  Value *Or2 = IRBDetect2.CreateOr(ICmpEQ4, ICmpEQ5);
  IRBDetect2.CreateCondBr(Or2, B, C);
  CreateCallbackAndJumpBack(&IRBB, C, triple);
}

} // namespace

PreservedAnalyses AntiHook::run(Module &M, ModuleAnalysisManager &AM) {
  Triple triple(M.getTargetTriple());
  bool initialized = false;
  for (Function &F : M) {
    if (toObfuscate(flag, &F, "antihook")) {
      errs() << "Running AntiHooking On " << F.getName() << "\n";
      if (!initialized)
        initialized = initializeAntiHook(M, triple);
      if (!toObfuscateBoolOption(&F, "ah_inline", &CheckInlineHookTemp))
        CheckInlineHookTemp = CheckInlineHook;
      if (triple.isAArch64() && CheckInlineHookTemp) {
        HandleInlineHookAArch64(&F, triple);
      }
      if (!toObfuscateBoolOption(&F, "ah_antirebind", &AntiRebindSymbolTemp))
        AntiRebindSymbolTemp = AntiRebindSymbol;
      if (AntiRebindSymbolTemp)
        for (Instruction &I : instructions(F))
          if (CallBase *CB = dyn_cast<CallBase>(&I)) {
            Function *Called = CB->getCalledFunction();
            if (!Called)
              Called = dyn_cast<Function>(
                  CB->getCalledOperand()->stripPointerCasts());
            if (Called && Called->isDeclaration() &&
                Called->isExternalLinkage(Called->getLinkage()) &&
                !Called->isIntrinsic() &&
                !Called->getName().startswith("clang.")) {
              GlobalVariable *GV = cast<GlobalVariable>(M.getOrInsertGlobal(
                  ("AntiRebindSymbol_" + Called->getName()).str(),
                  Called->getType()));
              if (!GV->hasInitializer()) {
                GV->setConstant(true); // make the gv not writable
                GV->setInitializer(Called);
                GV->setLinkage(GlobalValue::LinkageTypes::PrivateLinkage);
              }
              appendToCompilerUsed(M, {GV});
              Value *Load =
                  new LoadInst(GV->getValueType(), GV, Called->getName(), &I);
              Value *BitCasted = BitCastInst::CreateBitOrPointerCast(
                  Load, CB->getCalledOperand()->getType(), "", &I);
              CB->setCalledFunction(BitCasted);
            }
          }
    }
  }
  return PreservedAnalyses::none();
}
