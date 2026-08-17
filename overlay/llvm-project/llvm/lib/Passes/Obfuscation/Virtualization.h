#ifndef LLVM_VIRTUALIZATION_H
#define LLVM_VIRTUALIZATION_H

#include "llvm/IR/PassManager.h"

namespace llvm {

struct Virtualization : public PassInfoMixin<Virtualization> {
  bool flag;
  bool postFlatten;
  Virtualization() : flag(true), postFlatten(false) {}
  Virtualization(bool f, bool postFla = false)
      : flag(f), postFlatten(postFla) {}
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &FAM);
};

} // namespace llvm

#endif
