# bobbypin Teacher's Guide

A complete walkthrough for teaching the bobbypin workflow: static triage,
string hunting, branch analysis, and controlled patching of Windows PE
binaries - using lab targets you build and own yourself.

**Audience:** students with basic command-line skills. No assembly background
required; each module has optional deep-dive notes for stronger cohorts.

**Format:** 4 modules (~45-60 min each). Module 1 is instructor-led demo;
Modules 2-3 are student labs with verified answer keys; Module 4 is advanced.

---

## Instructor setup checklist

Verify before class (all confirmed working on the author machine):

```bash
python3 --version                                            # 3.9.x OK (needs 3.7+)
python3 -c "import capstone; print(capstone.__version__)"    # 5.0.x OK
which x86_64-w64-mingw32-gcc                                 # brew install mingw-w64
```

Optional, for runtime demos:

```bash
brew install --cask wine-stable       # run patched .exe locally
python3 -m pip install frida-tools    # Module 4 monitors
```

Smoke test:

```bash
cd course/module1
python3 ../../bobbypin_ai.py plan crackme.exe | python3 -m json.tool | head -20
```

### Legal & ethics briefing (do this first, every cohort)

- All lab targets build from `course/*/crackme*.c` - the class owns them.
- bobbypin assumes the person running it is the owner of the target file —
  every exercise treats the binary as yours.
- Say it plainly: these techniques are dual-use; what makes use legitimate is
  ownership of the target, not the bytes.
- Recommended slide: your jurisdiction's computer-misuse law + your course's
  acceptable-use policy.

---

## Module 0 - Tool tour (30 min)

Goal: students can name every interface and know when to use which.

| Interface | Command | When |
|---|---|---|
| One-shot JSON | `bobbypin_ai.py plan X.exe` | scripting, agent workflows |
| Persistent session | `bobbypin_ai.py serve`, one JSON cmd per line | many queries, fast |
| Interactive CLI | `python3 bobbypin.py X.exe` | human exploration |
| Web GUI | `python3 bobbypin_gui.py 8877` | visual learners, Workflow button |

Demo the GUI's Workflow button briefly - it mirrors this curriculum.

Vocabulary board-work: *triage, tag (AUTH/URL/FAIL/OK), candidate,
ref_off vs jcc_off, NOP, flip, verified*.

---

## Module 1 - The core loop (instructor-led, uses module1/)

Target: single hash-checked license guard. The key is never stored in the
binary (djb2 hash compare), so string-dumping cannot reveal it - branch
patching is the only route. That constraint IS the lesson.

### Step 1: Triage

```bash
cd course/module1
python3 ../../bobbypin_ai.py plan crackme.exe
```

Read aloud: `kind: pe32+`, `dotnet: false`, `packers: []` -> green light.
(Rule: if `.NET`, stop and use dnSpy/ILSpy; if packed, unpack first.)

### Step 2: Read candidates - and distrust them

The plan reports 3 verified candidates:

| idx | jcc_off | referenced string | verdict |
|---|---|---|---|
| 0 | `0xb26` | banner "BobbinSoft Pro..." | THE REAL GUARD (surprising - see Step 3) |
| 1 | `0xe82` | mingw runtime failure | CRT noise |
| 2 | `0xffb` | VirtualProtect failure | CRT noise |

Note the twist: the winning card QUOTES the banner, not a failure
message. Pairing follows code layout, not semantics. Teaching line
stays: **"Candidates are leads. Disassembly/testing is truth."**

(Engine note: forward walks stop at function boundaries (`ret`), so
the old cross-function trap cards no longer appear.)

### Step 3: Locate the real guard by reading code

Address map used throughout (memorize the trick):
`VA = file_offset + 0xA00` (.text raw 0x600, RVA 0x1000, base 0x140000000).

```json
{"cmd":"disasm","path":"crackme.exe","offset":"0xae0","count":40}
```

Annotated reading of what students will see:

```asm
0x140001506  lea  rcx,[rip+0x2b26]   ; "Enter license key: "
0x14000151c  call 0x140001490        ; hash the key (djb2)
0x140001521  cmp  eax,0xbadc0de      ; hash == expected?
0x140001526  jne  0x14000153e        ; <-- THE GUARD (file 0xb26): bad key -> failure
0x140001528  lea  rax,[rip+0x2b09]   ; "Access granted..." (fallthrough = success)
0x14000153e  lea  rax,[rip+0x2b23]   ; "License invalid..." (failure block)
```

Layout lesson: here the jump points AT the failure block, so erasing it
makes every input fall through into the success print. Have a student
trace both branches aloud before any patching.

### Step 4: Choose the patch direction (the money moment)

Ask the class to predict outcomes BEFORE revealing:

| Patch at 0xb26 | Effect on ANY input | Verdict |
|---|---|---|
| `nop` (`75 16` -> `90 90`) | jump gone; always falls into "Access granted" | correct |
| flip (`jne`->`je`, XOR-1) | good keys fail, bad keys pass | inverted license |
| unconditional jmp (`EB 16`) | same result as nop here | works, unnecessary |

Contrast with layouts where the jump points AT success: there nop means
always-fail. Direction depends entirely on where the branch goes -
which is why we read before we patch. (The browser GUI offers nop and
flip buttons only; for this lab nop is the correct click.)

### Step 5: Patch and verify

```json
{"cmd":"bytes","path":"crackme.exe","offset":"0xb26","len":4}
```
Expect `"7516488d"` (jne rel8 +0x16, start of the lea). Then:

```json
{"cmd":"patch","src":"crackme.exe","dst":"crackme_patched.exe",
 "patches":[{"offset":"0xb26","mode":"nop"}]}
{"cmd":"verify","orig":"crackme.exe","new":"crackme_patched.exe"}
```

Expected verify: `same_size: true`, exactly 1 region,
`0xb26-0xb27: 7516 -> 9090`.
Hard rule to state: if verify shows anything other than intended bytes,
stop and re-analyze.

### Step 6: Prove it at runtime (optional, needs wine)

```bash
wine crackme.exe <<< "garbage"          # License invalid...
wine crackme_patched.exe <<< "garbage"  # Access granted...
echo $?                                  # exit codes differ too: 1 vs 0
```

### Module 1 homework

Rebuild the target after changing `0x0BADC0DEu` to another constant.
All offsets shift slightly - proves students understand the workflow rather
than memorizing offsets. (Offsets may shift by a few bytes; that's fine.)

---

## Module 2 - Multi-guard targets (student lab, uses module2/)

Two independent gates: hash check (A) then account-state check (B).
Students patch gate A alone and discover the second failure message -
the single most important realism lesson in the course.

### Student brief

Hand them `crackme2.exe` + the AGENTS.md workflow. Do not show this
section until they've attempted it.

### Instructor answer key (verified by disassembly)

Address map identical to Module 1 (`VA = off + 0xA00`). The checks are
nested: gate B only runs after gate A passes.

```asm
0x140001561  cmp  eax,0xbadc0de
0x140001566  jne  0x1400015a4        ; GATE A (file 0xb66): bad key -> invalid msg
0x14000156f  call account_active
0x140001574  test eax,eax
0x140001576  je   0x14000158e        ; GATE B (file 0xb76): inactive -> suspended
0x140001578  lea  "Access granted"   ; fallthrough = success
```

Both gates point AT their failure block, so NOP is correct on both.

Both gates are listed candidates now (chained-guard scan):

- UI Candidate #1 - gate A, Branch Offset `0xb66`, bytes `75 3c`
- UI Candidate #2 - gate B, Branch Offset `0xb76`, bytes `74 16`,
  quoting "Account suspended. Contact support."

Patch one at a time with verify between:

```json
{"cmd":"patch","src":"crackme2.exe","dst":"crackme2_patched.exe",
 "patches":[{"offset":"0xb66","mode":"nop"}]}
{"cmd":"verify","orig":"crackme2.exe","new":"crackme2_patched.exe"}
```

Runtime after this single patch: garbage key -> "Account suspended".
That's the aha moment. Then finish with gate B:

```json
{"cmd":"patch","src":"crackme2.exe","dst":"crackme2_full.exe",
 "patches":[{"offset":"0xb66","mode":"nop"},{"offset":"0xb76","mode":"nop"}]}
{"cmd":"verify","orig":"crackme2.exe","new":"crackme2_full.exe"}
```

Pre-solved copies ship in the folder: `crackme2_patched.exe`
(gate A only, exactly what the GUI click produces) and
`crackme2_full.exe` (both NOPs).

### Discussion points in this target (after the lab)

- Candidate #1 pairs gate A's jump with the PROMPT string - pairing
  follows code layout, not message semantics.
- The two compiler-message cards are CRT noise; skip on sight.
- How was gate B found? Second scan pass: any conditional jump whose
  TARGET lands directly on a tagged message block becomes a candidate -
  chained guards own no string reference of their own to walk from.
  Forward walks also stop at `ret`, which retired the old
  cross-function trap cards.

### Grading rubric

- NOP-ed gate A and explained the "Account suspended" reveal: pass.
- NOP-ed gate B after the reveal, testing between each change: strong pass.
- Explains how target-matching finds chained guards: excellent.

---

## Module 3 - Hunting without FAIL strings (student lab, uses module3/)

Failure is SILENT (exit code 3, no message). String-tagging finds no
runtime failure message, so students must work backwards from the SUCCESS
string - exactly like software that fails quietly or via generic errors.

### Student brief

"Your only runtime observation: the program exits silently and prints
nothing on a bad key. Find the decision and bypass it."

### Instructor answer key (verified)

```asm
0x14000151c  call 0x140001490        ; hash the key
0x140001521  cmp  eax,0xbadc0de
0x140001526  jne  0x14000153e        ; THE GUARD (file 0xb26): bad key -> silent fail
0x140001528  lea  "Welcome back, licensed user."  ; fallthrough = success
0x14000153e  mov  eax,3              ; silent failure: no message, exit code 3
```

Patch: NOP at file offset **0xb26** (`75 16` -> `90 90`). The jump to the
silent-failure path disappears; every input falls through to the welcome
message with a clean exit.

```json
{"cmd":"patch","src":"crackme3.exe","dst":"crackme3_patched.exe",
 "patches":[{"offset":"0xb26","mode":"nop"}]}
{"cmd":"verify","orig":"crackme3.exe","new":"crackme3_patched.exe"}
```

A pre-solved `crackme3_patched.exe` ships in the folder. The candidate
list here is short: one app guard plus two CRT cards - the same
function-boundary-aware scanning keeps trap cards out of every target.

Teaching extension: exit codes are observable behavior too
(`wine crackme3.exe; echo $?` -> 3 vs 0). Real triage often has nothing
but such signals; strings are a luxury.

---

## Module 4 - Advanced roadmap (optional sessions)

Not fully scripted; pointers for building further classes:

1. **Frida monitors** - generate with the GUI/CLI monitor generator,
   attach to wine, watch the license decision live. Ties static analysis
   to dynamic confirmation. Requires frida-tools.
2. **Response-token guards** - apps checking bare `"true"`/`"false"` API
   responses. bobbypin detects these; great bridge into networked targets
   you own.
3. **Packed/bundled targets** - PyInstaller bundles and Electron ASAR:
   unpack first (per AGENTS.md), then apply the same loop to extracted code.
4. **Compiler-variation day** - rebuild module1 with `-O1`/`-O2` and watch
   guards inline, merge, or vanish. Teaches why offsets never transfer
   between builds and why understanding beats recipes.
5. **GUI workflow drill** - same Module 1 solved entirely in the browser
   GUI; some students need this path.

---

## Common student pitfalls (instructor watch-list)

| Pitfall | Symptom | Fix |
|---|---|---|
| Trusting candidates blindly | patches fgets guard or TLS code | force disasm-before-patch |
| NOP reflex | always-fail or always-crash | teach direction analysis (Module 1 step 4) |
| Flip confusion | anti-license behavior | walk the branch table aloud |
| In-place patching | original overwritten | dst is ALWAYS a _patched copy |
| Skipping verify | multiple mystery diffs | verify after EVERY iteration |
| Batch patching | two changes, unknown which worked | one patch per iteration |
| Wrong address space | patched VA instead of file offset | re-drill the +0xA00 map |

## Assessment ideas

- Written: given a disasm snippet, predict effect of nop/flip/jmp at a
  marked jcc (Module 1 step 4 table format).
- Practical: an unseen rebuild of any crackme with changed constants;
  graded on workflow discipline (triage -> read -> one patch -> verify)
  more than speed.
- Capstone discussion: explain, using Module 2, why automated candidate
  lists can pair the right jump with the wrong string.

## Course business notes

- This guide + three buildable labs is a complete workshop day (6-8 hours
  with breaks). Modules 0-1 alone make a solid 90-minute conference-style
  session.
- Sell the workflow literacy, not "cracking": every exercise emphasizes
  ownership of the target, verification discipline, and reading code over tool
  magic. That framing widens the audience to defenders and QA teams.
