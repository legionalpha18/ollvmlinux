#include "Obfuscation/BogusControlFlow2.h"
#include "Obfuscation/Utils.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/ValueMapper.h"
#include <vector>

using namespace llvm;

BasicBlock *cloneBasicBlock(BasicBlock *BB) {
  ValueToValueMapTy VMap;
  BasicBlock *cloneBB = CloneBasicBlock(BB, VMap, "cloneBB", BB->getParent());
  BasicBlock::iterator origI = BB->begin();
  for (Instruction &I : *cloneBB) {
    for (int i = 0; i < I.getNumOperands(); i++) {
      Value *V = MapValue(I.getOperand(i), VMap);
      if (V) {
        I.setOperand(i, V);
      }
    }
    SmallVector<std::pair<unsigned, MDNode *>, 4> MDs;
    I.getAllMetadata(MDs);
    for (std::pair<unsigned, MDNode *> Pair : MDs) {
      MDNode *MD = MapMetadata(Pair.second, VMap);
      if (MD) {
        I.setMetadata(Pair.first, MD);
      }
    }
    I.setDebugLoc(origI->getDebugLoc());
    origI++;
  }
  return cloneBB;
}

// One opaque-predicate global pair per module, reused across every call
// site/basic-block that gets this transform, instead of allocating a fresh
// GlobalVariable pair every single time. The old per-call approach could
// add thousands of duplicate "x.N"/"y.N" globals across a real codebase,
// bloating the binary and slowing the build for no extra obfuscation value
// -- the opaqueness comes from the compiler being unable to prove the
// externally-linked globals' contents, not from having many of them.
static GlobalVariable *getOrCreateOpaqueGlobal(Module *M, StringRef Name) {
  LLVMContext &Context = M->getContext();
  if (GlobalVariable *GV = M->getGlobalVariable(Name))
    return GV;
  return new GlobalVariable(
      *M, Type::getInt32Ty(Context), false, GlobalValue::CommonLinkage,
      ConstantInt::get(Type::getInt32Ty(Context), 0), Name);
}

Value *createBogusCmp(BasicBlock *insertAfter) {
  Module *M = insertAfter->getModule();
  LLVMContext &Context = M->getContext();
  GlobalVariable *XPtr = getOrCreateOpaqueGlobal(M, "__obfu_bcf2_x");
  GlobalVariable *YPtr = getOrCreateOpaqueGlobal(M, "__obfu_bcf2_y");

  IRBuilder<> IRB(Context);
  IRB.SetInsertPoint(insertAfter);
  LoadInst *X = IRB.CreateLoad(Type::getInt32Ty(Context), XPtr);
  LoadInst *Y = IRB.CreateLoad(Type::getInt32Ty(Context), YPtr);
  Value *Cond1 =
      IRB.CreateICmpSLT(Y, ConstantInt::get(Type::getInt32Ty(Context), 10));
  Value *Op1 =
      IRB.CreateAdd(X, ConstantInt::get(Type::getInt32Ty(Context), 1));
  Value *Op2 = IRB.CreateMul(Op1, X);
  Value *Op3 =
      IRB.CreateURem(Op2, ConstantInt::get(Type::getInt32Ty(Context), 2));
  Value *Cond2 =
      IRB.CreateICmpEQ(Op3, ConstantInt::get(Type::getInt32Ty(Context), 0));
  return BinaryOperator::CreateOr(Cond1, Cond2, "", insertAfter);
}

PreservedAnalyses BogusControlFlow2::run(Function &F,
                                         FunctionAnalysisManager &AM) {
  if (!enabled &&
      getFunctionAnnotation(&F).find("boguscfg2") == std::string::npos &&
      getFunctionAnnotation(&F).find("bcf2") == std::string::npos) {
    return PreservedAnalyses::all();
  }

  std::vector<BasicBlock *> OrigBB;
  for (BasicBlock &BB : F)
    OrigBB.push_back(&BB);

  for (BasicBlock *BB : OrigBB) {
    if (isa<InvokeInst>(BB->getTerminator()) || BB->isEHPad() ||
        (getRandomNumber() % 100) <= 20) {
      continue;
    }
    BasicBlock *HeadBB = BB;
    BasicBlock *BodyBB =
        BB->splitBasicBlock(BB->getFirstNonPHIOrDbgOrLifetime(), "bodyBB");
    BasicBlock *TailBB =
        BodyBB->splitBasicBlock(BodyBB->getTerminator(), "endBB");
    BasicBlock *CloneBB = cloneBasicBlock(BodyBB);

    BB->getTerminator()->eraseFromParent();
    BodyBB->getTerminator()->eraseFromParent();
    CloneBB->getTerminator()->eraseFromParent();

    Value *Cond1 = createBogusCmp(BB);
    Value *Cond2 = createBogusCmp(BodyBB);

    BranchInst::Create(BodyBB, CloneBB, Cond1, BB);
    BranchInst::Create(TailBB, CloneBB, Cond2, BodyBB);
    BranchInst::Create(BodyBB, CloneBB);
  }
  return PreservedAnalyses::none();
}
