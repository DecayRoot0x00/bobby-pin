# bobbypin

Static-analysis and patching assistant for Windows PE binaries, with support
for Electron ASAR archives, PyInstaller bundles, and Java JARs.

Built for rapid triage: find the strings that matter, locate the conditional
jumps that guard them (verified by a real disassembler, not byte guessing),
and test controlled patches - NOP or branch inversion - without ever touching
the original file.

**Author:** decay.root.0x00
[GitHub](https://github.com/DecayRoot0x00) · [X](https://x.com/DecayRoot0x00)

---

## Features

- **Verified patch candidates** - decodes executable sections with Capstone,
  finds the exact instruction referencing a tagged string, then walks forward
  over real instruction boundaries to the next conditional jump - never
  crossing function edges. A second pass matches conditional jumps whose
  TARGET lands on a later guard's message, so chained checks (the second
  lock behind the first) get their own verified cards. Every candidate is
  a genuine instruction; nothing is pattern-guessed.
- **Library-noise suppression** - dense error-string tables (libcurl, zlib,
  JSON parsers, `SEC_E_*`) are detected and excluded automatically, so you
  get the app's logic, not its dependencies'.
- **Branch patching** - NOP (`0x90`, full instruction length) or inversion
  (any conditional opcode via XOR-1: `je`↔`jne`, `ja`↔`jbe`, long forms too).
  Patches always write to a separate `_patched` copy.
- **Response-token detection** - catches guards on bare `"true"` / `"false"`
  API-response checks that most scanners miss.
- **Frida monitor generation** - auto-generated hook scripts for network,
  auth, registry and SSL APIs; compatible with Frida ≤16 and ≥17.
- **Format awareness** - detects .NET assemblies (points you at dnSpy instead
  of wasting your time), Electron markers, PyInstaller, AutoIt, NSIS, Inno
  Setup, Go builds.
- **AI-controllable** - full machine interface (`bobbypin_ai.py`) plus an
  operating manual (`AGENTS.md`) so an agent can run the entire workflow.

## Supported targets

| Format | Support |
|---|---|
| PE32 / PE32+ `.exe` `.dll` | full triage + patching |
| Electron `.asar` | extraction, string triage, SSL monitor |
| PyInstaller bundles | unpacking, string triage, monitor |
| Java `.jar` | extraction, string scanning |

### Per-format workflow

- **PE32 / PE32+** — the full loop: triage → candidate cards → disassembly →
  NOP/flip patch → verify. The only format the byte-patch engine touches.
- **Java `.jar`** — `python3 bobbypin.py target.jar` auto-extracts to
  `<name>_unpacked/` and scans `.class`/config strings. Decompile with jadx or
  CFR; change behavior in Java source, not bytes.
- **Electron `.asar`** — auto-extract + string triage. Edit plain `.js`
  directly, repack with `npx @electron/asar pack`. Bytenode `.jsc` builds
  can't be branch-patched — use the generated `<name>_hook.js` Frida SSL
  monitor instead.
- **PyInstaller** — auto-unpacks to `<name>_unpacked/`; decompile `.pyc` with
  pycdc or uncompyle6, rebuild, and confirm live with a Frida monitor.

## Requirements

- Python 3.7+ (standard library covers everything core)
- `capstone` - recommended; enables verified candidate scanning
  (auto-offered on first run, or `pip install capstone`)
- `frida-tools` - optional, only for live monitors

## Quick start

### GUI

```bash
python3 bobbypin_gui.py          # http://127.0.0.1:8877
python3 bobbypin_gui.py 9000     # custom port
```

Drop a binary on the page. The **Workflow** button (top right) walks through
the whole process step by step - baseline, string hunting, candidate
selection, byte verification, NOP vs flip decisions, Frida fallback.

### CLI

```bash
python3 bobbypin.py target.exe              # interactive triage
python3 bobbypin.py target.exe --json       # machine-readable report
python3 bobbypin.py target.exe --apply 2    # NOP candidate #2
python3 bobbypin.py target.exe --apply 2 --flip   # invert it instead
```

### AI agent mode

```bash
python3 bobbypin_ai.py plan target.exe      # one-shot JSON report
python3 bobbypin_ai.py serve                # persistent JSON session (see AGENTS.md)
```

Point any AI agent at `AGENTS.md` and it can drive the complete workflow -
triage, candidate review, context disassembly, patching, verification -
through strict JSON commands.

## The workflow

1. Run the original binary; record its failure/success messages.
2. Find those messages in the String Inspector; note their offsets.
3. Match offsets against Patch Console candidates (`FAIL` kind first).
4. Confirm intent with the disassembly view around the branch offset.
5. NOP first; if behavior is unchanged, flip; then move to the next candidate.
6. Stuck? Generate the Frida monitor and watch the decision happen live.

## Legal

bobbypin assumes the person running the app is the owner of the target file
they analyze and patch.
