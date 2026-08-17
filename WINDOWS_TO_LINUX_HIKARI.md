# OLLVM17: Windows → Linux Migration + Hikari Pass Port

Reference doc for AI agents / future maintainers. Everything below was done on
this repo (`legionalpha18/ollvmlinux`). **Never touch the old Windows repo.**

---

## 1. Repositories & Ground Rules

| Repo | Role | URL / Path | Rules |
|---|---|---|---|
| `legionalpha18/newollvm` | OLD Windows working build (source of truth for overlay + patch approach) | `https://github.com/legionalpha18/newollvm` — local: `C:\Users\nabee\OneDrive\Desktop\olllvmLinux` | **DO NOT MODIFY.** It works; used only as reference for the overlay files & patch scripts. |
| `legionalpha18/ollvmlinux` | NEW Linux build (this repo) | `https://github.com/legionalpha18/ollvmlinux` — local: `C:\Users\nabee\AppData\Local\Temp\opencode\ollvmlinux` | Commit & push here; CI auto-builds on push to `main`. |
| `PPKunOfficial/Hikari-fix` | Source of the 4 ported passes (AGPL-3.0) | `https://github.com/PPKunOfficial/Hikari-fix` (branch `master`) — local staging clone: `C:\Users\nabee\AppData\Local\Temp\opencode\Hikari-fix` | Read-only reference. AGPL-3.0 license accepted. |
| `DreamSoule/ollvm17` | Base fork: already-patched PassBuilder.cpp/CMakeLists + its Obfuscation/ passes | `https://github.com/DreamSoule/ollvm17` (branch `master`) | Cloned fresh inside CI (`git clone --depth 1`). |

Git identity used for pushes: `legionalpha18 <legionalpha18@users.noreply.github.com>`.
No `gh` CLI available; push via Windows Credential Manager (`manager` helper).
Build runs are free GitHub Actions, auto-triggered by `push` to `main`.

---

## 2. The Goal

- Build a **Linux x86_64 clang+lld 17.0.6** toolchain with all obfuscation
  passes, drop-in compatible with **Android NDK r26**
  (`toolchains/llvm/prebuilt/linux-x86_64/bin/`).
- The original project was Windows-only **only because of its GitHub Actions
  workflows** (windows-latest + MSVC + `cmake -G "Visual Studio 17 2022"`).
  The C++ pass code is 100% cross-platform (no Windows APIs).
- Add four new Hikari-fix obfuscation features on top of the existing
  DreamSoule + Polaris passes:
  - **ConstantEncryption (`-constenc`)** — module-level
  - **Virtualization / VMP (`-vmp`)** — function-level
  - **Anti-Hooking (`-antihook`)** — module-level, AArch64
  - **FunctionCallObfuscate (`-fco`)** — function-level, Android/Darwin

---

## 3. Windows → Linux Migration (already shipped)

### 3.1 Why it was Windows-only
`legionalpha18/newollvm` builds with the **legacy pass manager** wiring that the
MSVC+VS2017 workflow happened to use; the Linux rebuild uses the **new pass
manager** (`PassInfoMixin`) and LLVM 17.0.6.

### 3.2 Repo layout committed to `ollvmlinux`

```
ollvmlinux/
├── .github/workflows/
│   ├── main_dreamsoul_linux.yml     # Linux build pipeline (20 steps)
│   └── verify-flags-linux.yml       # bash flag verification (21 flags + 4 tiers)
├── overlay/
│   └── llvm-project/llvm/
│       ├── lib/Passes/CMakeLists.txt
│       ├── lib/Passes/Obfuscation/          # <- Polaris + Hikari (ported) sources
│       └── lib/Target/AArch64/AArch64RubbishCode.cpp   # backend obfuscation
└── WINDOWS_TO_LINUX_HIKARI.md               # this file
```

### 3.3 Build pipeline design (`main_dreamsoul_linux.yml`)

- `runs-on: ubuntu-22.04`, `timeout-minutes: 360` (GHA max; typical run 1.5–3 h).
- Steps:
  1. Checkout.
  2. Install `ninja-build` (gcc/g++/cmake/python3 ship on the runner).
  3. Download official `llvm-project-17.0.6.src.tar.xz`, verify `llvm/`, `clang/`, `lld/`.
  4. Clone `DreamSoule/ollvm17` (ships already-patched `PassBuilder.cpp`,
     `CMakeLists.txt`, and its `Obfuscation/` folder).
  5. **Overlay obfuscation files**: copy DreamSoule's `llvm/lib/Passes` tree in.
  6. **Overlay Polaris IR passes**: copy `$GITHUB_WORKSPACE/overlay/...` on top
     (this REPLACES DreamSoule's `CMakeLists.txt` + `Utils.*` with the overlay's).
  7. Patch scripts (python heredocs):
     - `patch_fnh.py` – comment the nearest preceding `private:` above
       `Function::getBasicBlockList()` in `llvm/include/llvm/IR/Function.h`
       (getBasicBlockList is private in LLVM 17; the fork code calls it).
     - `patch_ve.py` – insert a `static bool valueEscapes(Instruction&)` helper
       into `Obfuscation/Utils.cpp` right before `llvm::fixStack(...)`
       (function was removed in LLVM 17).
     - `patch_pb.py` – add includes, `cl::opt` flags (`mba`, `alias`, `junkcode`,
       `bcf2`, `mergefunc`, `antidbg`, `funcwrap`), and FPM/MPM registrations
       anchored on `FPM.addPass(BogusControlFlowPass(s_obf_bcf));` and
       `MPM.addPass(RewriteSymbolPass());`.
     - `patch_pb_hikari.py` – **NEW**: registers the 4 Hikari passes (see §5.4).
     - `patch_aacmake.py` / `patch_aah.py` / `patch_atm.py` – wire
       `AArch64RubbishCode.cpp` into the AArch64 backend.
  8. Enlarge swap: dedicated `/var/ollvm_swapfile` (16G fallocate + mkswap +
     swapon). **Do NOT reuse the runner's active `/swapfile`** – writing to it
     fails with "Text file busy" (first CI run hit this; fixed in commit
     `efe5e36`).
  9. Configure CMake (Ninja + GCC):
     ```
     -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_PROJECTS="clang;lld"
     -DLLVM_TARGETS_TO_BUILD="AArch64;ARM;X86" -DLLVM_ENABLE_ASSERTIONS=OFF
     -DLLVM_ENABLE_EH=OFF -DLLVM_ENABLE_RTTI=OFF
     -DLLVM_INCLUDE_TESTS/EXAMPLES/BENCHMARKS/DOCS=OFF
     -DLLVM_INSTALL_TOOLCHAIN_ONLY=ON -DLLVM_OPTIMIZED_TABLEGEN=ON
     -DLLVM_ENABLE_PLUGINS=OFF
     -DLLVM_PARALLEL_COMPILE_JOBS=2 -DLLVM_PARALLEL_LINK_JOBS=1
     ```
     (job caps prevent OOM on ASTReader.cpp/ASTWriter.cpp TUs).
  10. Build & install (`cmake --build build --target install --parallel $(nproc)`).
  11. Package into `ollvm17-17.0.6-linux-x86_64.tar.gz` (artifact upload).

### 3.4 Verification pipeline (`verify-flags-linux.yml`)

Manual `workflow_dispatch` job that compiles a sample with each `-mllvm` flag
and asserts the pass ran. **21 individual flags** + 4 combo tiers (LOW / MEDIUM /
MAX / ALL). Must be kept in sync with any new flags.

---

## 4. Full File Structure (detail)

### 4.1 `overlay/llvm-project/llvm/lib/Passes/` in THIS repo

```
Passes/
├── CMakeLists.txt                     # authoritative source list (replaces DreamSoule's)
└── Obfuscation/
    ├── vmp/
    │   └── Opcode.h                   # Hikari verbatim: enum Op, BinSubOp, ICmpPred,
    │                                  #   CastKind, kPointerSize = 8, OP_UNREACHABLE = 0x0E
    ├── Utils.h / Utils.cpp            # OVERWRITES DreamSoule's; adds Hikari helpers (§5.3)
    ├── SubstituteImpl.h / .cpp        # Hikari verbatim (+ fixed includes)
    ├── Virtualization.h / .cpp        # Hikari port (new-PM)  [NEW]
    ├── ConstantEncryption.h / .cpp    # Hikari port (new-PM)  [NEW]
    ├── AntiHook.h / .cpp              # Hikari AntiHooking port (new-PM)  [NEW]
    ├── FunctionCallObfuscate.h / .cpp # Hikari port (new-PM)  [NEW]
    ├── LinearMBA.h / .cpp             # Polaris (unchanged)
    ├── MBAMatrix.h / .cpp             # Polaris (unchanged)
    ├── AliasAccess.h / .cpp           # Polaris (unchanged)
    ├── JunkCodeGen.h / .cpp           # Polaris (unchanged)
    ├── BogusControlFlow2.h / .cpp     # Polaris (unchanged)
    ├── MergeFunction.h / .cpp         # Polaris (unchanged)
    ├── AntiDebugging.h / .cpp         # Polaris (unchanged)
    ├── FunctionWrapper.h / .cpp       # Polaris (unchanged)
    │
    # NOT in overlay — provided by DreamSoule clone at CI time (step 5):
    # CryptoUtils.h/.cpp, Flattening.h/.cpp, ObfuscationOptions.h/.cpp,
    # BogusControlFlow.h/.cpp, IPObfuscationContext.h/.cpp,
    # StringEncryption.h/.cpp, SplitBasicBlock.h/.cpp, Substitution.h/.cpp,
    # IndirectBranch.h/.cpp, IndirectCall.h/.cpp, IndirectGlobalVariable.h/.cpp,
    # and any other DreamSoule headers the CMakeLists lists.
```

### 4.2 Hikari-fix `obfuscation/` tree (what we read / ported from)

Full source tree at `https://github.com/PPKunOfficial/Hikari-fix` (branch `master`,
LLVM 22-era, out-of-tree plugin layout):

```
obfuscation/
├── CMakeLists.txt
├── Obfuscation.cpp / include/Obfuscation.h     # plugin entry — NOT used (we register via PassBuilder)
├── AntiDebugging.cpp        (not ported — overlay already has Polaris AntiDebugging)
├── AntiHooking.cpp          -> PORTED as AntiHook.cpp/.h   [antihook]
├── BogusControlFlow.cpp     (not ported)
├── ConstantEncryption.cpp   -> PORTED as ConstantEncryption.cpp/.h   [constenc]
├── CryptoUtils.cpp          (NOT used — reuse DreamSoule's CryptoUtils)
├── Flattening.cpp           (NOT used — reuse DreamSoule's FlatteningPass)
├── FunctionCallObfuscate.cpp-> PORTED as FunctionCallObfuscate.cpp/.h   [fco]
├── FunctionWrapper.cpp      (not ported)
├── IndirectBranch.cpp       (not ported)
├── json.hpp                 (920 KB — NOT used; FCO uses a tiny parser instead)
├── LegacyLowerSwitch.cpp    (not ported)
├── SplitBasicBlocks.cpp     (not ported)
├── StringEncryption.cpp     (not ported)
├── SubstituteImpl.cpp       -> PORTED verbatim (+ fixed includes)
├── Substitution.cpp         (not ported)
├── Utils.cpp / include/Utils.h    (only a few helpers adapted — see §5.3)
├── Virtualization.cpp       -> PORTED as Virtualization.cpp/.h   [vmp]
└── vmp/Opcode.h             -> PORTED verbatim
```

Per-file links (Hikari-fix, `master`):
- `Virtualization.cpp` — https://github.com/PPKunOfficial/Hikari-fix/blob/master/obfuscation/Virtualization.cpp
- `ConstantEncryption.cpp` — https://github.com/PPKunOfficial/Hikari-fix/blob/master/obfuscation/ConstantEncryption.cpp
- `AntiHooking.cpp` — https://github.com/PPKunOfficial/Hikari-fix/blob/master/obfuscation/AntiHooking.cpp
- `FunctionCallObfuscate.cpp` — https://github.com/PPKunOfficial/Hikari-fix/blob/master/obfuscation/FunctionCallObfuscate.cpp
- `SubstituteImpl.cpp` — https://github.com/PPKunOfficial/Hikari-fix/blob/master/obfuscation/SubstituteImpl.cpp
- `SubstituteImpl.h` — https://github.com/PPKunOfficial/Hikari-fix/blob/master/obfuscation/include/SubstituteImpl.h
- `vmp/Opcode.h` — https://github.com/PPKunOfficial/Hikari-fix/blob/master/obfuscation/vmp/Opcode.h
- `Utils.h` — https://github.com/PPKunOfficial/Hikari-fix/blob/master/obfuscation/include/Utils.h
- `Utils.cpp` — https://github.com/PPKunOfficial/Hikari-fix/blob/master/obfuscation/Utils.cpp
- (NOT used) `json.hpp` — https://github.com/PPKunOfficial/Hikari-fix/blob/master/obfuscation/json.hpp
- (NOT used) `compat/CallSite.h` — https://github.com/PPKunOfficial/Hikari-fix/blob/master/obfuscation/include/compat/CallSite.h

---

## 5. Hikari-fix Port (NEW work)

### 5.1 What Hikari-fix is

`PPKunOfficial/Hikari-fix` is an LLVM 22 out-of-tree plugin rewrite of the
classic Hikari obfuscator (LLVM 18-era, AGPL-3.0). Its `Virtualization.cpp` is a
modernized "phase 1+" rewrite: clean translate-to-bytecode + interpreter-lifter,
already opaque-pointer safe.

### 5.2 Porting decisions (agreed with user)

1. Convert every legacy pass (`ModulePass`/`FunctionPass`, `static char ID`,
   `INITIALIZE_PASS`, `create*Pass` factories) to **new pass manager**
   (`PassInfoMixin` + `PreservedAnalyses run(..., AnalysisManager&)`).
2. **CallSite → CallBase**: rewrite all `CallSite` usages to `CallBase*`
   (`getCalledFunction`, `getCalledOperand`, `setCalledFunction`,
   `getIntrinsicID`, `isBundleOperand`). Do NOT vendor `compat/CallSite.h`.
3. **No json.hpp**: `FunctionCallObfuscate` config load replaced with a tiny
   `name=value` file parser; pass is **inert by default** when no config exists.
4. **Reuse DreamSoule's existing `CryptoUtils`** (`Obfuscation/CryptoUtils.cpp`,
   already in CMakeLists). Its API (`get_uint32_t`, `get_uint64_t`,
   `get_uint8_t/16_t`, `get_range(max)`, global `llvm::ManagedStatic<CryptoUtils>
   cryptoutils`) covers 100% of Hikari usage. Do NOT copy Hikari's CryptoUtils
   (different class; would break `IPObfuscationContext.cpp`).
5. **VMP post-flatten → DreamSoule's `FlatteningPass`**: Hikari called its own
   legacy `createFlatteningPass(true)->runOnFunction(...)`. We call
   `FlatteningPass fla(true); fla.run(Fn, FAM);` (DreamSoule's is
   `llvm::FlatteningPass : PassInfoMixin<FlatteningPass>`, ctor `(bool flag)`,
   `run(Function&, FunctionAnalysisManager&)`; declared in
   `Obfuscation/Flattening.h`). DreamSoule's `run` itself re-checks
   `toObfuscate(flag, &F, "fla")` and its `flatten()` calls `fixStack(F)`.
6. Master flags: `-constenc` (module), `-vmp` (function), `-antihook` (module),
   `-fco` (function). Sub-options kept from Hikari:
   - constenc: `-constenc_subxor`, `-constenc_subxor_prob=`, `-constenc_togv`,
     `-constenc_togv_prob=`, `-constenc_times=`
   - vmp: `-vmp-encrypt` (default true), `-vmp-harden` (default false),
     env vars `VMPNOENC` / `VMPENCRYPT` / `VMPHARDEN` (`loadVmpEnv()`)
   - antihook: `-adhexrirpath=`, `-ah_inline` (default true), `-ah_antirebind`
   - fco: `-fco_flag=` (RTLD_DEFAULT value), `-fcoconfig=`
7. Pipeline order (see §5.4): `antihook` early (MPM) → `fco` (FPM) →
   `vmp` (FPM, after all function passes) → `constenc` (MPM, late, just before
   RewriteSymbolPass).
8. Annotations integrate via the overlay's existing `getFunctionAnnotation()`
   (reads `llvm.global.annotations`, lowercased). E.g.
   `__attribute__((annotate("vmp")))` / `annotate("novmp")`,
   `annotate("constenc")`, `annotate("antihook")`, `annotate("fco")`, plus
   bool opts `annotate("vmpenc")`/`annotate("novmpenc")`,
   `annotate("constenc_togv")`, etc.

### 5.3 Utils helpers added to overlay `Obfuscation/Utils.h/.cpp`

Adapted from Hikari `include/Utils.h` / `Utils.cpp` (namespace `llvm`), wired to
the overlay's annotation reader so BOTH `MD_obf` metadata AND
`llvm.global.annotations` work:

- `bool toObfuscateBoolOption(Function *f, std::string option, bool *val);`
  (honors `no<opt>` / `<opt>` in metadata + global annotations)
- `bool toObfuscateUint32Option(Function *f, std::string option, uint32_t *val);`
  (honors `<opt>=<n>` in both metadata + global annotations)
- `void turnOffOptimization(Function *f);`
  (removes MinSize/OptimizeForSize; adds OptimizeNone+NoInline unless already present)
- `bool readAnnotationMetadata(Function *f, std::string annotation);`
  (reads the `"MD_obf"` MDTuple)
- `void writeAnnotationMetadata(Function *f, std::string annotation);`
  (appends to the `"MD_obf"` MDTuple; needs `#include "llvm/IR/MDBuilder.h"`)
- `bool AreUsersInOneFunction(GlobalVariable *GV);`
- internal statics: `obfkindid = "MD_obf"`, `readAnnotationMetadataUint32OptVal`,
  `readAnnotationUint32OptVal`.

`writeAnnotationMetadata(fn, "novmp")` is used by VMP to mark interpreter
helpers (`vmp_eval_*`, `vmp_read_var_*`, `vmp_ch_*`, `vmp_seed_*`) so a second
`-vmp` pass won't re-virtualize them; `Virtualization::run` also bails if
`readAnnotationMetadata(&F, "novmp")`.

### 5.4 PassBuilder registration (workflow step `patch_pb_hikari.py`)

Runs right after the existing `patch_pb.py` step (step 6c2). Idempotent guard:
`if 'Obfuscation/Virtualization.h' in text: skip`. Anchors are lines produced by
`patch_pb.py`:

- includes appended after `#include "Obfuscation/FunctionWrapper.h"`:
  ```
  #include "Obfuscation/Virtualization.h"
  #include "Obfuscation/ConstantEncryption.h"
  #include "Obfuscation/AntiHook.h"
  #include "Obfuscation/FunctionCallObfuscate.h"
  ```
- cl::opts appended after `s_obf_funcwrap`:
  ```
  static cl::opt<bool> s_obf_vmp("vmp", cl::init(false), cl::desc("Virtual Machine Obfuscation (Hikari VMP)"));
  static cl::opt<bool> s_obf_constenc("constenc", cl::init(false), cl::desc("Constant Encryption (Hikari)"));
  static cl::opt<bool> s_obf_antihook("antihook", cl::init(false), cl::desc("Anti-Hooking (Hikari)"));
  static cl::opt<bool> s_obf_fco("fco", cl::init(false), cl::desc("Function Call Obfuscation (Hikari)"));
  ```
- FPM — anchor `FPM.addPass(AntiDebugging(s_obf_antidbg)); // Anti-debugging`,
  appended at the very END of the function-pass pipeline:
  ```
  FPM.addPass(FunctionCallObfuscate(s_obf_fco)); // Function call obfuscation
  FPM.addPass(Virtualization(s_obf_vmp));        // Virtual machine obfuscation
  ```
  NOTE: `Virtualization(s_obf_vmp)` uses default `postFlatten=false`; VMP's
  `run()` computes `wantPost = postFlatten || VmpHarden || toObfuscate(false, &F, "vmpharden")`
  so `-mllvm -vmp-harden` (or `annotate("vmpharden")`) triggers the post-CFF on
  the interpreter + helpers.
- MPM — `AntiHook` inserted BEFORE `MPM.addPass(FunctionWrapper(...))`,
  `ConstantEncryption` inserted AFTER it (still before `RewriteSymbolPass`):
  ```
  MPM.addPass(AntiHook(s_obf_antihook));              // Anti-hooking (early MPM)
  MPM.addPass(FunctionWrapper(s_obf_funcwrap));       // (existing)
  MPM.addPass(ConstantEncryption(s_obf_constenc));    // Constant encryption (late MPM)
  ```

### 5.5 `CMakeLists.txt` additions (overlay `lib/Passes/CMakeLists.txt`)

Added to the source list (CryptoUtils.cpp was already present):
```
Obfuscation/SubstituteImpl.cpp
Obfuscation/Virtualization.cpp
Obfuscation/ConstantEncryption.cpp
Obfuscation/AntiHook.cpp
Obfuscation/FunctionCallObfuscate.cpp
```
`vmp/Opcode.h` resolves relative to `Obfuscation/` — no extra include dir needed.

### 5.6 Verification additions (`verify-flags-linux.yml`)

- Added `vmp constenc antihook fco` to the 21-flag list.
- Added the 4 new flags to the "ALL" combo tier (`[21 passes]`).
- (VMP runtime correctness test still TBD — see §7 "Next steps".)

---

## 6. Porting Recipe (legacy → new PM / LLVM 17)

| Hikari (legacy PM / LLVM 22) | Ported (new PM / LLVM 17.0.6) |
|---|---|
| `class X : public FunctionPass { static char ID; ... }` | `struct X : public PassInfoMixin<X> { bool flag; X(bool f); ... }` |
| `bool runOnFunction(Function &F) override` | `PreservedAnalyses run(Function &F, FunctionAnalysisManager &FAM)` |
| `bool runOnModule(Module &M) override` | `PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM)` |
| `INITIALIZE_PASS(X, ...)` / `char X::ID = 0` | removed |
| `X *createXPass(bool flag)` factory | ctor `X(bool flag)` (instantiated directly in PassBuilder) |
| `return true;` / `return false;` | `return PreservedAnalyses::none();` / `::all();` |
| `CallSite CS(&I)` | `CallBase *CB = dyn_cast<CallBase>(&I)` |
| `CS.getCalledFunction()` | `CB->getCalledFunction()` |
| `CS.getCalledValue()` | `CB->getCalledOperand()` |
| `CS.setCalledFunction(V)` | `CB->setCalledFunction(V)` |
| `CS.getIntrinsicID()` | `CB->getIntrinsicID()` |
| `CS.isBundleOperand(i)` | `CB->isBundleOperand(i)` |
| `CS->getParent()` | `CB->getParent()` |
| `createFlatteningPass(true)->runOnFunction(F)` | `FlatteningPass fla(true); fla.run(F, FAM);` |
| `fixStack(&F)` | `fixStack(F)` (overlay takes a reference) |
| `#include "llvm/ADT/Triple.h"` | `#include "llvm/TargetParser/Triple.h"` (LLVM ≥17) |
| `M.getOrInsertFunction(...)` → `cast<Function>(...)` | same, via `.getCallee()` (FunctionCallee) |
| `appendToCompilerUsed(M, {GV})` | same (`llvm/Transforms/Utils/ModuleUtils.h`) |

---

## 7. Known Gotchas & LLVM 17 API Notes

- **`Function::getBasicBlockList()` is private** in LLVM 17 → build already
  patches `Function.h` visibility (workflow step 6). New passes must NOT call it.
- **`valueEscapes` was removed** in LLVM 17 → `patch_ve.py` re-adds it as a
  `static` in `Utils.cpp` before `fixStack`. Do NOT redeclare it in Utils.h.
- Opaque pointers: ported code uses `PointerType::get(Ctx, 0)` /
  `BitCastInst::CreateBitOrPointerCast`; `CallSite` removed entirely.
- `LoadInst(Type*, Value*, const Twine&, Instruction*)` 4-arg ctor and
  `LoadInst(..., bool IsVolatile, Align, ...)` both exist in LLVM 17.
- `Triple` moved to `llvm/TargetParser/Triple.h` in LLVM 17.
- `StringRef::starts_with`/`ends_with` exist in LLVM 17 (also `startswith`).
- `APInt` free ops: `uint64_t ^ APInt` works (`operator^(uint64_t, const APInt&)`
  is defined in `llvm/ADT/APInt.h`), used by `PairConstantInt`.
- `parseIRFile` + `Linker::linkModules(Module&, std::unique_ptr<Module>, Flags)`
  are the LLVM 17 signatures used by AntiHook's precompiled-IR mode
  (`-mllvm -adhexrirpath=<path>`); without a valid file it warns + continues.
- VMP interpreter helpers get `OptimizeNone` via `turnOffOptimization`; the
  name-based skip guard in `virtualizeFunction` skips `vmp_eval_`/`vmp_read_var_`/
  `vmp_code_`/`vmp_ch_`/`vmp_seed_`/`*.vmp_bak` names (guard extended with
  `vmp_seed_` during the port).
- Substitution/constenc probabilities are percent values; the passes validate
  `<= 100` at runtime and bail the compile if out of range.
- AntiHook inline-hook detection is AArch64-only (`triple.isAArch64()`) and uses
  the A64 B (0b000101) / BR (0b110101…) / BRK (0b11010100001) signatures.
- FCO is only active for Android / Darwin triples
  (`ANDROID64_FLAG = 0x102`, `ANDROID32_FLAG = 0x2`, `DARWIN_FLAG = 0xA`);
  without a config file (`-mllvm -fcoconfig=<path>`, or default
  `~/Hikari/SymbolConfig.json`-style path) it is a no-op.
- **YAML gotcha (CI)**: a step `name:` containing `key: value` (colon+space)
  must be single-quoted, else GitHub rejects the workflow file. Fixed in
  commit `0f11b1b` (`'Patch PassBuilder.cpp (Hikari passes: vmp constenc antihook fco)'`).
- The overlay `Utils.h` keeps `using namespace std;` and the `CONTEXT`/`INIT_CONTEXT`/
  `TYPE_I32`/`CONST_I32` macros — DreamSoule passes rely on them. Do not remove.

---

## 8. How to Use the Artifacts

1. Download `ollvm17-17.0.6-linux-x86_64.tar.gz` from the workflow run.
2. In NDK r26, back up then replace binaries in
   `<NDK>/toolchains/llvm/prebuilt/linux-x86_64/bin/` (clang, clang++,
   ld.lld, lld-link, ...).
3. Pass flags via build.gradle / CMake, e.g.:
   ```
   -mllvm -fla -mllvm -bcf -mllvm -sobf -mllvm -sub -mllvm -split
   -mllvm -mba -mllvm -alias -mllvm -junkcode -mllvm -bcf2
   -mllvm -mergefunc -mllvm -antidbg -mllvm -funcwrap
   -mllvm -constenc -mllvm -constenc_togv -mllvm -vmp -mllvm -vmp-harden
   -mllvm -antihook -mllvm -fco
   ```
4. Per-function control via annotation:
   ```
   __attribute__((annotate("fla bcf sub split mba linearmba aliasaccess junkcode boguscfg2 mergefunction constenc vmp")))
   ```

---

## 9. Commit History (Linux repo)

- `fadf180` – initial Linux repo: overlay + `main_dreamsoul_linux.yml` + `verify-flags-linux.yml`.
- `efe5e36` – swap fix (`/var/ollvm_swapfile`) after first CI failure.
- `ed523c5` – Hikari port: 4 passes + SubstituteImpl + vmp/Opcode.h + Utils helpers
  + CMakeLists + `patch_pb_hikari.py` step + verify flags + this doc skeleton.
- `0f11b1b` – fix YAML: quote step name with colon (workflow previously rejected).

## 10. Current CI Status & Next Steps

- Latest build run: `0f11b1b` (in_progress at time of writing; artifact name
  `ollvm17-17.0.6-linux-x86_64`). Check status via GitHub Actions UI or
  `https://api.github.com/repos/legionalpha18/ollvmlinux/actions/runs`.
- If the build fails: download the failed job log, grep for the first
  `error:` in the `LLVMPasses` compile (that library builds early), fix the
  ported file, push.
- After a green build, run the `Verify OLLVM17 Flags (Linux)` workflow
  (`workflow_dispatch`) to confirm all 21 flags + 4 tiers.
- TBD: add a VMP runtime correctness test (compile a small `a+b` sample with
  `-O2 -mllvm -vmp`, run it on-device/emulator, assert correct result).
