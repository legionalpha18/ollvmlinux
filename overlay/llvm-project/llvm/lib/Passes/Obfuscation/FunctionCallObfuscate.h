#ifndef LLVM_FUNCTION_CALL_OBFUSCATE_H
#define LLVM_FUNCTION_CALL_OBFUSCATE_H

#include "llvm/IR/PassManager.h"
#include "llvm/TargetParser/Triple.h"
#include <map>
#include <string>

namespace llvm {

struct FunctionCallObfuscate : public PassInfoMixin<FunctionCallObfuscate> {
  bool flag;
  bool initialized;
  Triple triple;
  std::map<std::string, std::string> Configuration;

  FunctionCallObfuscate() : flag(true), initialized(false) {}
  FunctionCallObfuscate(bool flag) : flag(flag), initialized(false) {}

  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
  bool initialize(Module &M);
};

} // namespace llvm

#endif
