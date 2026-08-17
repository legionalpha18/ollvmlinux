#pragma once

#include "llvm/Passes/PassBuilder.h"

using namespace llvm;

struct BogusControlFlow2 : PassInfoMixin<BogusControlFlow2> {
  bool enabled;
  BogusControlFlow2(bool enabled = false) : enabled(enabled) {}
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
  static bool isRequired() { return true; }
};
