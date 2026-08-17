#ifndef LLVM_ANTIHOOK_H
#define LLVM_ANTIHOOK_H

#include "llvm/IR/PassManager.h"

namespace llvm {

struct AntiHook : public PassInfoMixin<AntiHook> {
  bool flag;
  AntiHook() : flag(true) {}
  AntiHook(bool flag) : flag(flag) {}
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
};

} // namespace llvm

#endif
