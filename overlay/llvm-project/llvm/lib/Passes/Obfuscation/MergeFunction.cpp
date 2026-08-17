#include "Obfuscation/MergeFunction.h"
#include "Obfuscation/Utils.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Module.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include <vector>

using namespace llvm;

PreservedAnalyses MergeFunction::run(Module &M, ModuleAnalysisManager &AM) {
  bool Changed = process(M);
  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

void MergeFunction::merge(Module &M, std::vector<Function *> &ToMerge) {
  if (ToMerge.empty())
    return;

  IRBuilder<> IRB(M.getContext());
  std::vector<Type *> ArgTypes;
  ClonedCodeInfo CodeInfo;
  SmallVector<ReturnInst *, 8> Returns;
  ArgTypes.push_back(IRB.getInt32Ty());
  std::vector<MergeInfo> Info;
  uint32_t Idx = 1;
  for (Function *F : ToMerge) {
    if (!F->getReturnType()->isVoidTy())
      continue;
    MergeInfo MI;
    MI.F = F;
    MI.ArgIndex = Idx;
    for (Argument &Arg : F->args()) {
      ArgTypes.push_back(Arg.getType());
      Idx++;
    }
    Info.push_back(MI);
  }

  if (Info.empty())
    return;

  FunctionType *FT =
      FunctionType::get(Type::getVoidTy(M.getContext()), ArgTypes, false);
  Function *MergedF = Function::Create(FT, GlobalValue::PrivateLinkage,
                                       "__merged_function", M);
  BasicBlock *SwitchBB =
      BasicBlock::Create(M.getContext(), "switchBB", MergedF);
  BasicBlock *RetBB = BasicBlock::Create(M.getContext(), "returnBB", MergedF);
  ValueToValueMapTy VMap;
  std::vector<uint32_t> SwitchMap;
  for (MergeInfo &MI : Info) {
    VMap.clear();
    Returns.clear();
    Idx = MI.ArgIndex;
    for (Argument &Arg : MI.F->args()) {
      VMap[&Arg] = MergedF->getArg(Idx++);
    }
    CloneFunctionInto(MergedF, MI.F, VMap,
                      CloneFunctionChangeType::LocalChangesOnly, Returns, "",
                      &CodeInfo, nullptr, nullptr);
    MI.NewEntryBB = static_cast<BasicBlock *>(MapValue(&MI.F->getEntryBlock(), VMap));
    uint32_t SwitchVal = getUniqueNumber(SwitchMap);
    SwitchMap.push_back(SwitchVal);
    MI.SwitchVal = SwitchVal;
  }
  IRB.SetInsertPoint(SwitchBB);
  SwitchInst *SW = IRB.CreateSwitch(MergedF->getArg(0), RetBB);
  for (MergeInfo &MI : Info) {
    SW->addCase(IRB.getInt32(MI.SwitchVal), MI.NewEntryBB);
  }
  IRB.SetInsertPoint(RetBB);
  IRB.CreateRetVoid();

  for (MergeInfo &MI : Info) {
    std::vector<CallInst *> RemoveList;
    for (Function &F : M) {
      for (BasicBlock &BB : F) {
        for (Instruction &I : BB) {
          if (!isa<CallInst>(I))
            continue;

          CallInst &Call = cast<CallInst>(I);
          if (Call.getCalledFunction() != MI.F)
            continue;

          std::vector<Value *> Args;
          Args.push_back(IRB.getInt32(MI.SwitchVal));
          for (size_t i = 1; i < MergedF->arg_size(); i++) {
            if (i >= MI.ArgIndex && i < MI.ArgIndex + MI.F->arg_size()) {
              Args.push_back(Call.getArgOperand(i - MI.ArgIndex));
            } else {
              Args.push_back(
                  Constant::getNullValue(MergedF->getArg(i)->getType()));
            }
          }
          IRB.SetInsertPoint(&Call);
          IRB.CreateCall(FunctionCallee(MergedF), Args);
          RemoveList.push_back(&Call);
        }
      }
    }
    for (CallInst *C : RemoveList) {
      C->eraseFromParent();
    }
  }
  for (MergeInfo &MI : Info) {
    MI.F->eraseFromParent();
  }
}

bool MergeFunction::process(Module &M) {
  std::vector<Function *> MergeList;
  SmallVector<ReturnInst *, 8> Returns;
  ValueToValueMapTy VMap;
  ClonedCodeInfo CodeInfo;
  IRBuilder<> IRB(M.getContext());
  for (Function &F : M) {
    if (!enabled &&
        getFunctionAnnotation(&F).find("mergefunction") == std::string::npos)
      continue;

    VMap.clear();
    Returns.clear();
    std::vector<Type *> ArgTypes;
    Type *RetType = F.getReturnType();
    for (Argument &Arg : F.args())
      ArgTypes.push_back(Arg.getType());
    if (!RetType->isVoidTy()) {
      ArgTypes.push_back(RetType->getPointerTo());
    }

    FunctionType *FT =
        FunctionType::get(Type::getVoidTy(M.getContext()), ArgTypes, false);
    Function *NewF = Function::Create(FT, GlobalValue::PrivateLinkage,
                                      F.getName() + "_internal", M);
    Function::arg_iterator Iter = NewF->arg_begin();
    for (Argument &Arg : F.args()) {
      VMap[&Arg] = &*Iter++;
    }
    CloneFunctionInto(NewF, &F, VMap,
                      CloneFunctionChangeType::LocalChangesOnly, Returns, "",
                      &CodeInfo, nullptr, nullptr);
    if (!RetType->isVoidTy()) {
      for (ReturnInst *Ret : Returns) {
        Value *Val = Ret->getReturnValue();
        IRB.SetInsertPoint(Ret);
        IRB.CreateStore(Val, &*Iter);
        IRB.CreateRetVoid();
        Ret->eraseFromParent();
      }
    }
    while (!F.empty()) {
      BasicBlock &BB = F.front();
      BB.eraseFromParent();
    }
    BasicBlock *Entry = BasicBlock::Create(M.getContext(), "entry", &F);
    IRB.SetInsertPoint(Entry);
    Value *V = IRB.CreateAlloca(RetType);
    std::vector<Value *> ArgVal;
    for (Argument &Arg : F.args())
      ArgVal.push_back((Value *)&Arg);
    if (!RetType->isVoidTy()) {
      ArgVal.push_back(V);
    }
    IRB.CreateCall(FunctionCallee(NewF), ArgVal);
    if (!RetType->isVoidTy()) {
      IRB.CreateRet(IRB.CreateLoad(RetType, V));
    }
    MergeList.push_back(NewF);
  }
  bool Changed = !MergeList.empty();
  merge(M, MergeList);
  return Changed;
}
