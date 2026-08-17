#include "AArch64.h"
#include "AArch64Subtarget.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/TargetPassConfig.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetMachine.h"
#include <ctime>
#include <random>
#include <vector>

using namespace llvm;

#define DEBUG_TYPE "aarch64-obfuscation"

static cl::opt<bool> EnableAArch64Obfuscation(
    "aarch64-obfu", cl::init(false), cl::Hidden,
    cl::desc("Enable AArch64 backend obfuscation (anti-dump, anti-decompile)"));

namespace {
class AArch64RubbishCodePass : public MachineFunctionPass {
public:
  static char ID;
  AArch64RubbishCodePass() : MachineFunctionPass(ID) {}
  StringRef getPassName() const override { return "AArch64 Obfuscation"; }

  bool runOnMachineFunction(MachineFunction &MF) override;
};
} // namespace

char AArch64RubbishCodePass::ID = 0;
INITIALIZE_PASS(AArch64RubbishCodePass, DEBUG_TYPE, DEBUG_TYPE, false, false)

FunctionPass *llvm::createAArch64RubbishCodePassPass() {
  return new AArch64RubbishCodePass();
}

bool AArch64RubbishCodePass::runOnMachineFunction(MachineFunction &MF) {
  if (!EnableAArch64Obfuscation)
    return false;

  const Function &F = MF.getFunction();

  bool hasMarker = false;
  for (const BasicBlock &BB : F) {
    for (const Instruction &I : BB) {
      if (auto *CB = dyn_cast<CallBase>(&I)) {
        if (CB->isInlineAsm()) {
          const InlineAsm *IA = dyn_cast<InlineAsm>(CB->getCalledOperand());
          if (IA && StringRef(IA->getAsmString()).contains("backend-obfu")) {
            hasMarker = true;
            break;
          }
        }
      }
    }
    if (hasMarker)
      break;
  }

  if (!hasMarker)
    return false;

  outs() << "[AArch64-Obfu] Processing function: " << F.getName() << "\n";

  std::srand(static_cast<unsigned>(std::time(nullptr)));

  std::vector<MachineBasicBlock *> Blocks;
  for (MachineBasicBlock &MBB : MF)
    Blocks.push_back(&MBB);

  for (MachineBasicBlock *MBB : Blocks) {
    // TODO: Port LLVM-16-era junk-instruction insertion to LLVM 17.
    //       computeRegisterLiveness / LQR_Dead were removed in LLVM 17.
    //       The marker-detection infra + pass registration are ready.
    (void)&MBB;  // suppress unused-parameter warning
  }

  return true;
}
