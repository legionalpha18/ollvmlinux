#include "Obfuscation/AntiDebugging.h"
#include "Obfuscation/Utils.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/GlobalVariable.h"

using namespace llvm;

PreservedAnalyses AntiDebugging::run(Function &F, FunctionAnalysisManager &AM) {
  if (enabled || getFunctionAnnotation(&F).find("antidbg") != std::string::npos) {
    process(F);
    return PreservedAnalyses::none();
  }
  return PreservedAnalyses::all();
}

void AntiDebugging::process(Function &F) {
  if (F.isDeclaration() || F.empty())
    return;

  Module *M = F.getParent();
  LLVMContext &Ctx = M->getContext();
  BasicBlock &Entry = F.getEntryBlock();
  Instruction *InsertPt = &*Entry.getFirstInsertionPt();
  Type *I32Ty = Type::getInt32Ty(Ctx);

  GlobalVariable *adbGuard = M->getGlobalVariable("__obfu_adb_guard");
  if (!adbGuard) {
    adbGuard = new GlobalVariable(*M, I32Ty, false,
                                  GlobalValue::CommonLinkage,
                                  ConstantInt::get(I32Ty, 0),
                                  "__obfu_adb_guard");
  }

  // Minimal volatile operations at function entry
  // These create side effects that can't be optimized out
  // and appear as real computation to static analysis
  LoadInst *V1 = new LoadInst(I32Ty, adbGuard, "", true, InsertPt);
  LoadInst *V2 = new LoadInst(I32Ty, adbGuard, "", true, InsertPt);

  BinaryOperator *Xor = BinaryOperator::CreateXor(V1, V2, "", InsertPt);
  BinaryOperator *Add = BinaryOperator::CreateAdd(Xor, V2, "", InsertPt);

  new StoreInst(Add, adbGuard, true, InsertPt);
}
