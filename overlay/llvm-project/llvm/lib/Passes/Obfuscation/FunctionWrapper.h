#pragma once
#include "llvm/Passes/PassBuilder.h"

using namespace llvm;

struct FunctionWrapper : PassInfoMixin<FunctionWrapper> {
  bool enabled;
  FunctionWrapper(bool enabled = false) : enabled(enabled) {}
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
  bool process(Module &M);
  static bool isRequired() { return true; }
};
