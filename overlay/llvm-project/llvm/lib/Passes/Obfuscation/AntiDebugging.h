#pragma once
#include "llvm/Passes/PassBuilder.h"

using namespace llvm;

struct AntiDebugging : PassInfoMixin<AntiDebugging> {
  bool enabled;
  AntiDebugging(bool enabled = false) : enabled(enabled) {}
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
  void process(Function &F);
  static bool isRequired() { return true; }
};
