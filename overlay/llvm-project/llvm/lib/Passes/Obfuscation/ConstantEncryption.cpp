/*
    LLVM ConstantEncryption Pass
    Copyright (C) 2017 Zhang(http://mayuyu.io)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "ConstantEncryption.h"
#include "CryptoUtils.h"
#include "SubstituteImpl.h"
#include "Utils.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <unordered_set>

using namespace llvm;

static cl::opt<bool>
    SubstituteXor("constenc_subxor",
                  cl::desc("Substitute xor operator of ConstantEncryption"),
                  cl::value_desc("Substitute xor operator"), cl::init(false),
                  cl::Optional);
static bool SubstituteXorTemp = false;

static cl::opt<uint32_t> SubstituteXorProb(
    "constenc_subxor_prob",
    cl::desc(
        "Choose the probability [%] each xor operator will be Substituted"),
    cl::value_desc("probability rate"), cl::init(40), cl::Optional);
static uint32_t SubstituteXorProbTemp = 40;

static cl::opt<bool>
    ConstToGV("constenc_togv",
              cl::desc("Replace ConstantInt with GlobalVariable"),
              cl::value_desc("ConstantInt to GlobalVariable"), cl::init(false),
              cl::Optional);
static bool ConstToGVTemp = false;

static cl::opt<uint32_t>
    ConstToGVProb("constenc_togv_prob",
                  cl::desc("Choose the probability [%] each ConstantInt will "
                           "replaced with GlobalVariable"),
                  cl::value_desc("probability rate"), cl::init(50),
                  cl::Optional);
static uint32_t ConstToGVProbTemp = 50;

static cl::opt<uint32_t> ObfTimes(
    "constenc_times",
    cl::desc(
        "Choose how many time the ConstantEncryption pass loop on a function"),
    cl::value_desc("Number of Times"), cl::init(1), cl::Optional);
static uint32_t ObfTimesTemp = 1;

bool ConstantEncryption::shouldEncryptConstant(Instruction *I) {
  if (isa<SwitchInst>(I) || isa<IntrinsicInst>(I) ||
      isa<GetElementPtrInst>(I) || isa<PHINode>(I) || I->isAtomic())
    return false;
  if (AllocaInst *AI = dyn_cast<AllocaInst>(I))
    if (AI->isSwiftError())
      return false;
  if (CallBase *CB = dyn_cast<CallBase>(I)) {
    if (Function *CF = CB->getCalledFunction())
      if (CF->getName().startswith("hikari_"))
        return false;
  }
  if (dispatchonce)
    if (AllocaInst *AI = dyn_cast<AllocaInst>(I)) {
      if (AI->getAllocatedType()->isIntegerTy())
        for (User *U : AI->users())
          if (LoadInst *LI = dyn_cast<LoadInst>(U))
            for (User *LU : LI->users())
              if (CallBase *CB = dyn_cast<CallBase>(LU)) {
                Value *calledFunction = CB->getCalledFunction();
                if (!calledFunction)
                  calledFunction = CB->getCalledOperand()->stripPointerCasts();
                if (!calledFunction ||
                    (!isa<ConstantExpr>(calledFunction) &&
                     !isa<Function>(calledFunction)) ||
                    CB->getIntrinsicID() != Intrinsic::not_intrinsic)
                  continue;
                if (calledFunction->getName() == "_dispatch_once" ||
                    calledFunction->getName() == "dispatch_once")
                  return false;
              }
    }
  return true;
}

PreservedAnalyses ConstantEncryption::run(Module &M,
                                          ModuleAnalysisManager &AM) {
  dispatchonce = M.getFunction("dispatch_once") != nullptr;
  handled_gvs.clear();
  for (Function &F : M)
    if (toObfuscate(flag, &F, "constenc") && !F.isPresplitCoroutine()) {
      errs() << "Running ConstantEncryption On " << F.getName() << "\n";
      FixFunctionConstantExpr(&F);
      if (!toObfuscateUint32Option(&F, "constenc_times", &ObfTimesTemp))
        ObfTimesTemp = ObfTimes;
      if (!toObfuscateBoolOption(&F, "constenc_togv", &ConstToGVTemp))
        ConstToGVTemp = ConstToGV;
      if (!toObfuscateBoolOption(&F, "constenc_subxor", &SubstituteXorTemp))
        SubstituteXorTemp = SubstituteXor;
      if (!toObfuscateUint32Option(&F, "constenc_subxor_prob",
                                   &SubstituteXorProbTemp))
        SubstituteXorProbTemp = SubstituteXorProb;
      if (SubstituteXorProbTemp > 100) {
        errs() << "-constenc_subxor_prob=x must be 0 < x <= 100";
        return PreservedAnalyses::none();
      }
      if (!toObfuscateUint32Option(&F, "constenc_togv_prob",
                                   &ConstToGVProbTemp))
        ConstToGVProbTemp = ConstToGVProb;
      if (ConstToGVProbTemp > 100) {
        errs() << "-constenc_togv_prob=x must be 0 < x <= 100";
        return PreservedAnalyses::none();
      }
      uint32_t times = ObfTimesTemp;
      while (times) {
        EncryptConstants(F);
        if (ConstToGVTemp) {
          Constant2GlobalVariable(F);
        }
        times--;
      }
    }
  return PreservedAnalyses::none();
}

bool ConstantEncryption::isDispatchOnceToken(GlobalVariable *GV) {
  if (!dispatchonce)
    return false;
  for (User *U : GV->users()) {
    if (CallBase *CB = dyn_cast<CallBase>(U)) {
      Value *calledFunction = CB->getCalledFunction();
      if (!calledFunction)
        calledFunction = CB->getCalledOperand()->stripPointerCasts();
      if (!calledFunction ||
          (!isa<ConstantExpr>(calledFunction) &&
           !isa<Function>(calledFunction)) ||
          CB->getIntrinsicID() != Intrinsic::not_intrinsic)
        continue;
      if (calledFunction->getName() == "_dispatch_once" ||
          calledFunction->getName() == "dispatch_once") {
        Value *onceToken = U->getOperand(0);
        if (dyn_cast_or_null<GlobalVariable>(
                onceToken->stripPointerCasts()) == GV)
          return true;
      }
    }
    if (StoreInst *SI = dyn_cast<StoreInst>(U))
      for (User *SU : SI->getPointerOperand()->users())
        if (LoadInst *LI = dyn_cast<LoadInst>(SU))
          for (User *LU : LI->users())
            if (CallBase *CB = dyn_cast<CallBase>(LU)) {
              Value *calledFunction = CB->getCalledFunction();
              if (!calledFunction)
                calledFunction = CB->getCalledOperand()->stripPointerCasts();
              if (!calledFunction ||
                  (!isa<ConstantExpr>(calledFunction) &&
                   !isa<Function>(calledFunction)) ||
                  CB->getIntrinsicID() != Intrinsic::not_intrinsic)
                continue;
              if (calledFunction->getName() == "_dispatch_once" ||
                  calledFunction->getName() == "dispatch_once")
                return true;
            }
  }
  return false;
}

bool ConstantEncryption::isAtomicLoaded(GlobalVariable *GV) {
  for (User *U : GV->users()) {
    if (LoadInst *LI = dyn_cast<LoadInst>(U)) {
      if (LI->isAtomic())
        return true;
    }
  }
  return false;
}

void ConstantEncryption::EncryptConstants(Function &F) {
  for (Instruction &I : instructions(F)) {
    if (!shouldEncryptConstant(&I))
      continue;
    CallBase *CB = dyn_cast<CallBase>(&I);
    for (unsigned i = 0; i < I.getNumOperands(); i++) {
      if (CB && CB->isBundleOperand(i))
        continue;
      Value *Op = I.getOperand(i);
      if (isa<ConstantInt>(Op))
        HandleConstantIntOperand(&I, i);
      if (GlobalVariable *G = dyn_cast<GlobalVariable>(Op))
        if (G->hasInitializer() &&
            (G->hasPrivateLinkage() || G->hasInternalLinkage()) &&
            isa<ConstantInt>(G->getInitializer()))
          HandleConstantIntInitializerGV(G);
    }
  }
}

void ConstantEncryption::Constant2GlobalVariable(Function &F) {
  Module &M = *F.getParent();
  const DataLayout &DL = M.getDataLayout();
  for (Instruction &I : instructions(F)) {
    if (!shouldEncryptConstant(&I))
      continue;
    CallBase *CB = dyn_cast<CallBase>(&I);
    for (unsigned int i = 0; i < I.getNumOperands(); i++) {
      if (CB && CB->isBundleOperand(i))
        continue;
      if (ConstantInt *CI = dyn_cast<ConstantInt>(I.getOperand(i))) {
        if (!(cryptoutils->get_range(100) <= ConstToGVProbTemp))
          continue;
        GlobalVariable *GV = new GlobalVariable(
            *F.getParent(), CI->getType(), false,
            GlobalValue::LinkageTypes::PrivateLinkage,
            ConstantInt::get(CI->getType(), CI->getValue()), "CToGV");
        appendToCompilerUsed(*F.getParent(), GV);
        I.setOperand(i, new LoadInst(GV->getValueType(), GV, "", &I));
      }
    }
  }
  for (Instruction &I : instructions(F)) {
    if (!shouldEncryptConstant(&I))
      continue;
    if (BinaryOperator *BO = dyn_cast<BinaryOperator>(&I)) {
      if (!BO->getType()->isIntegerTy())
        continue;
      if (!(cryptoutils->get_range(100) <= ConstToGVProbTemp))
        continue;
      IntegerType *IT = cast<IntegerType>(BO->getType());
      uint64_t dummy;
      if (IT == Type::getInt8Ty(IT->getContext()))
        dummy = cryptoutils->get_uint8_t();
      else if (IT == Type::getInt16Ty(IT->getContext()))
        dummy = cryptoutils->get_uint16_t();
      else if (IT == Type::getInt32Ty(IT->getContext()))
        dummy = cryptoutils->get_uint32_t();
      else if (IT == Type::getInt64Ty(IT->getContext()))
        dummy = cryptoutils->get_uint64_t();
      else
        continue;
      GlobalVariable *GV = new GlobalVariable(
          M, BO->getType(), false, GlobalValue::LinkageTypes::PrivateLinkage,
          ConstantInt::get(BO->getType(), dummy), "CToGV");
      StoreInst *SI =
          new StoreInst(BO, GV, false, DL.getABITypeAlign(BO->getType()));
      SI->insertAfter(BO);
      LoadInst *LI = new LoadInst(GV->getValueType(), GV, "", false,
                                  DL.getABITypeAlign(BO->getType()));
      LI->insertAfter(SI);
      BO->replaceUsesWithIf(LI, [SI](Use &U) { return U.getUser() != SI; });
    }
  }
}

void ConstantEncryption::HandleConstantIntInitializerGV(GlobalVariable *GVPtr) {
  if (!(flag || AreUsersInOneFunction(GVPtr)) || isDispatchOnceToken(GVPtr) ||
      isAtomicLoaded(GVPtr))
    return;
  // Prepare Types and Keys
  std::pair<ConstantInt *, ConstantInt *> keyandnew;
  ConstantInt *Old = dyn_cast<ConstantInt>(GVPtr->getInitializer());
  bool hasHandled = true;
  if (handled_gvs.find(GVPtr) == handled_gvs.end()) {
    hasHandled = false;
    keyandnew = PairConstantInt(Old);
    handled_gvs.insert(GVPtr);
  }
  ConstantInt *XORKey = keyandnew.first;
  ConstantInt *newGVInit = keyandnew.second;
  if (hasHandled || !XORKey || !newGVInit)
    return;
  GVPtr->setInitializer(newGVInit);
  bool isSigned = XORKey->getValue().isSignBitSet() ||
                  newGVInit->getValue().isSignBitSet() ||
                  Old->getValue().isSignBitSet();
  for (User *U : GVPtr->users()) {
    BinaryOperator *XORInst = nullptr;
    if (LoadInst *LI = dyn_cast<LoadInst>(U)) {
      if (LI->getType() != XORKey->getType()) {
        Instruction *IntegerCast =
            BitCastInst::CreateIntegerCast(LI, XORKey->getType(), isSigned);
        IntegerCast->insertAfter(LI);
        XORInst =
            BinaryOperator::Create(Instruction::Xor, IntegerCast, XORKey);
        XORInst->insertAfter(IntegerCast);
        Instruction *IntegerCast2 =
            BitCastInst::CreateIntegerCast(XORInst, LI->getType(), isSigned);
        IntegerCast2->insertAfter(XORInst);
        LI->replaceUsesWithIf(IntegerCast2, [IntegerCast](Use &U) {
          return U.getUser() != IntegerCast;
        });
      } else {
        XORInst = BinaryOperator::Create(Instruction::Xor, LI, XORKey);
        XORInst->insertAfter(LI);
        LI->replaceUsesWithIf(
            XORInst, [XORInst](Use &U) { return U.getUser() != XORInst; });
      }
    } else if (StoreInst *SI = dyn_cast<StoreInst>(U)) {
      XORInst = BinaryOperator::Create(Instruction::Xor, SI->getOperand(0),
                                       XORKey, "", SI);
      SI->replaceUsesOfWith(SI->getValueOperand(), XORInst);
    }
    if (XORInst && SubstituteXorTemp &&
        cryptoutils->get_range(100) <= SubstituteXorProbTemp)
      SubstituteImpl::substituteXor(XORInst);
  }
}

void ConstantEncryption::HandleConstantIntOperand(Instruction *I,
                                                  unsigned opindex) {
  std::pair<ConstantInt * /*key*/, ConstantInt * /*new*/> keyandnew =
      PairConstantInt(cast<ConstantInt>(I->getOperand(opindex)));
  ConstantInt *Key = keyandnew.first;
  ConstantInt *New = keyandnew.second;
  if (!Key || !New)
    return;
  BinaryOperator *NewOperand =
      BinaryOperator::Create(Instruction::Xor, New, Key, "", I);

  I->setOperand(opindex, NewOperand);
  if (SubstituteXorTemp &&
      cryptoutils->get_range(100) <= SubstituteXorProbTemp)
    SubstituteImpl::substituteXor(NewOperand);
}

std::pair<ConstantInt * /*key*/, ConstantInt * /*new*/>
ConstantEncryption::PairConstantInt(ConstantInt *C) {
  if (!C)
    return std::make_pair(nullptr, nullptr);
  IntegerType *IT = cast<IntegerType>(C->getType());
  uint64_t K;
  if (IT == Type::getInt1Ty(IT->getContext()) ||
      IT == Type::getInt8Ty(IT->getContext()))
    K = cryptoutils->get_uint8_t();
  else if (IT == Type::getInt16Ty(IT->getContext()))
    K = cryptoutils->get_uint16_t();
  else if (IT == Type::getInt32Ty(IT->getContext()))
    K = cryptoutils->get_uint32_t();
  else if (IT == Type::getInt64Ty(IT->getContext()))
    K = cryptoutils->get_uint64_t();
  else
    return std::make_pair(nullptr, nullptr);
  ConstantInt *CI =
      cast<ConstantInt>(ConstantInt::get(IT, K ^ C->getValue()));
  return std::make_pair(ConstantInt::get(IT, K), CI);
}
