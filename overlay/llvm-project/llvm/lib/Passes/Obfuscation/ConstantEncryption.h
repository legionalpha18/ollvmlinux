#ifndef LLVM_CONSTANT_ENCRYPTION_H
#define LLVM_CONSTANT_ENCRYPTION_H

#include "llvm/IR/PassManager.h"
#include <unordered_set>

namespace llvm {

struct ConstantEncryption : public PassInfoMixin<ConstantEncryption> {
  bool flag;
  bool dispatchonce;
  std::unordered_set<GlobalVariable *> handled_gvs;

  ConstantEncryption() : flag(true), dispatchonce(false) {}
  ConstantEncryption(bool flag) : flag(flag), dispatchonce(false) {}

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);

  bool shouldEncryptConstant(Instruction *I);
  bool isDispatchOnceToken(GlobalVariable *GV);
  bool isAtomicLoaded(GlobalVariable *GV);
  void EncryptConstants(Function &F);
  void Constant2GlobalVariable(Function &F);
  void HandleConstantIntInitializerGV(GlobalVariable *GVPtr);
  void HandleConstantIntOperand(Instruction *I, unsigned opindex);
  std::pair<ConstantInt * /*key*/, ConstantInt * /*new*/>
  PairConstantInt(ConstantInt *C);
};

} // namespace llvm

#endif
