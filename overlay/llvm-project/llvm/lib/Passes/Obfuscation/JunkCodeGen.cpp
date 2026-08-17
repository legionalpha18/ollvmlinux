#include "Obfuscation/JunkCodeGen.h"
#include "Obfuscation/Utils.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Passes/PassBuilder.h"
#include <vector>

using namespace llvm;

PreservedAnalyses JunkCodeGen::run(Function &F, FunctionAnalysisManager &AM) {
  if (enabled || getFunctionAnnotation(&F).find("junkcode") != std::string::npos) {
    process(F);
    return PreservedAnalyses::none();
  }
  return PreservedAnalyses::all();
}

void JunkCodeGen::insertJunkBlock(BasicBlock *originBB, Function &F) {
  Instruction *term = originBB->getTerminator();
  // Only ever safe to rewrite a block whose terminator is a plain,
  // single-target unconditional branch. Anything else (conditional
  // branch, switch, indirect branch...) has other successors that would
  // be silently discarded below, corrupting control flow. This was the
  // root cause of functions decoding into garbage past their real body:
  // the "other" edge of a conditional branch got dropped, so the real
  // exit/return was unreachable and disassemblers fell off into
  // whatever bytes followed.
  auto *Br = dyn_cast<BranchInst>(term);
  if (!Br || !Br->isUnconditional())
    return;

  BasicBlock *realSucc = term->getSuccessor(0);
  Module *M = F.getParent();
  LLVMContext &Ctx = F.getContext();
  Type *I32Ty = Type::getInt32Ty(Ctx);

  BasicBlock *junkBB = BasicBlock::Create(Ctx, "junkBB", &F);
  IRBuilder<> IRB(junkBB);

  GlobalVariable *junkData = M->getGlobalVariable("__obfu_junk_data");
  if (!junkData) {
    junkData = new GlobalVariable(*M, I32Ty, false,
                                  GlobalValue::CommonLinkage,
                                  ConstantInt::get(I32Ty, 0),
                                  "__obfu_junk_data");
  }

  Value *v1 = IRB.CreateLoad(I32Ty, junkData, true);
  Value *v2 = IRB.CreateLoad(I32Ty, junkData, true);
  Value *v3 = IRB.CreateXor(v1, v2);
  Value *v4 = IRB.CreateAnd(v3, ConstantInt::get(I32Ty, 0xDEADBEEF));
  Value *v5 = IRB.CreateOr(v4, v1);
  Value *v6 = IRB.CreateAdd(v5, v2);
  Value *v7 = IRB.CreateSub(v6, v1);
  IRB.CreateStore(v7, junkData, true);

  Value *x = IRB.CreateLoad(I32Ty, junkData, true);
  Value *y = IRB.CreateOr(x, ConstantInt::get(I32Ty, 1));
  Value *y2 = IRB.CreateMul(y, y);
  Value *ym1 = IRB.CreateSub(y2, ConstantInt::get(I32Ty, 1));
  Value *mod8 = IRB.CreateURem(ym1, ConstantInt::get(I32Ty, 8));
  Value *cond = IRB.CreateICmpEQ(mod8, ConstantInt::get(I32Ty, 0));

  for (PHINode &Phi : realSucc->phis()) {
    int Idx = Phi.getBasicBlockIndex(originBB);
    if (Idx >= 0)
      Phi.setIncomingBlock(Idx, junkBB);
  }

  Instruction *oldTerm = originBB->getTerminator();
  oldTerm->eraseFromParent();

  IRBuilder<> OIRB(originBB);
  OIRB.CreateBr(junkBB);

  IRB.CreateCondBr(cond, realSucc, junkBB);
}

void JunkCodeGen::process(Function &F) {
  std::vector<BasicBlock *> Blocks;
  for (BasicBlock &BB : F)
    Blocks.push_back(&BB);

  for (BasicBlock *BB : Blocks) {
    Instruction *term = BB->getTerminator();
    // Only single-successor unconditional branches are safe to rewrite;
    // see insertJunkBlock() for why. Skip everything else up front.
    auto *Br = dyn_cast<BranchInst>(term);
    if (!Br || !Br->isUnconditional())
      continue;
    if (BB->isEHPad())
      continue;

    if ((getRandomNumber() % 100) < 40)
      continue;

    insertJunkBlock(BB, F);
  }
}
