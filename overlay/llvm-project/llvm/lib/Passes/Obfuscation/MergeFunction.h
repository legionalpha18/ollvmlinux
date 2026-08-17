#pragma once

#include "llvm/Passes/PassBuilder.h"

using namespace llvm;

struct MergeInfo {
  Function *F = nullptr;
  BasicBlock *NewEntryBB = nullptr;
  uint32_t ArgIndex = 0;
  uint32_t SwitchVal = 0;
};

struct MergeFunction : PassInfoMixin<MergeFunction> {
  bool enabled;
  MergeFunction(bool enabled = false) : enabled(enabled) {}
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
  bool process(Module &M);
  void merge(Module &M, std::vector<Function *> &ToMerge);
  static bool isRequired() { return true; }
};
