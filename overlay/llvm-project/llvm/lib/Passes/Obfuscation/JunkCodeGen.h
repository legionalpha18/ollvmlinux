#pragma once

#include "llvm/Passes/PassBuilder.h"

using namespace llvm;

struct JunkCodeGen : PassInfoMixin<JunkCodeGen> {
  bool enabled;
  JunkCodeGen(bool enabled = false) : enabled(enabled) {}
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
  void process(Function &F);
  void insertJunkBlock(BasicBlock *originBB, Function &F);
  static bool isRequired() { return true; }
};
