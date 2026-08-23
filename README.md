# bobbypin

Static-analysis and patching assistant for Windows PE binaries, Electron ASAR
archives, PyInstaller bundles, and Java JARs.

Built for rapid triage: find the strings that matter, locate the conditional
jumps that guard them (verified by a real disassembler, not byte guessing),
and test controlled patches — NOP or branch inversion — without ever touching
the original file.

For Electron apps, a separate JS-layer bypass path handles the full
license-validation flow: identify guards in main.js, stub the API client,
patch the renderer, and repack the ASAR with correct integrity hashes.

**Author:** decay.root.0x00
[GitHub](https://github.com/DecayRoot0x00) · [X](https://x.com/DecayRoot0x00)

---

## Features

### PE / native binary analysis
- **Verified patch candidates** — decodes executable sections with Capstone,
  finds the exact instruction referencing a tagged string, then walks forward
  over real instruction boundaries to the next conditional jump — never
  crossing function edges. A second pass matches conditional jumps whose
  target lands on a later guard's message, so chained checks get their own
  verified cards.
- **Library-noise suppression** — dense error-string tables (libcurl, zlib,
  JSON parsers, `SEC_E_*`) are detected and excluded automatically.
- **Branch patching** — NOP or inversion (any conditional opcode via XOR-1:
  `je`↔`jne`, `ja`↔`jbe`, long forms too). Patches always write to a
  separate `_patched` copy.
- **Response-token detection** — catches guards on bare `"true"` / `"false"`
  API-response checks.
- **Frida monitor generation** — hook scripts for network, auth, registry and
  SSL APIs; compatible with Frida ≤16 and ≥17.

### Electron ASAR analysis and bypass
- **`electron_plan`** — parses the ASAR without extraction; identifies
  boolean license guards (`isLicenseValid=![]` and similar), decodes all
  `ipcMain.handle` channel names from hex-escaped obfuscation, finds the
  secureClient module path, and checks whether the validate-license IPC
  handler uses direct HTTP (`makeKeyAuthRequest`) rather than the API client.
- **`electron_bypass`** — applies three targeted patches and repacks in one
  call:
  1. **main.js** — flips the license guard variable from `![]` (false) to
     `!![]` (true) at its declaration so `startApplication` passes its guard
     check without requiring a real validation response.
  2. **secureClient.js** — replaces the real API client with a `Proxy` stub
     that returns `{success:true}` for every async method call.
  3. **license.html** — fires the `validateLicense` IPC with a dummy
     UUID-format key (passes format checks and sets any main-process state
     the handler writes), then overrides the renderer result to
     `{success:true}` regardless of outcome.
- **`asar_repack`** — general-purpose ASAR repacker: provide a map of ASAR
  paths to local replacement files; the tool rebuilds the archive with
  correct Chromium Pickle header fields and updated per-file SHA256 integrity
  hashes.
- **Format awareness** — detects `.NET` assemblies (points you at dnSpy
  instead), Electron markers, PyInstaller, AutoIt, NSIS, Inno Setup, Go.
- **AI-controllable** — full JSON machine interface (`bobbypin_ai.py`) plus
  an operating manual (`AGENTS.md`) so an agent can drive the entire workflow.

---

## Supported targets

| Format | Support |
|---|---|
| PE32 / PE32+ `.exe` `.dll` | triage, string hunting, verified patching, Frida monitors |
| Electron `.asar` | full JS-layer bypass (`electron_plan` + `electron_bypass`), string triage, ASAR repacking |
| PyInstaller bundles | unpacking, string triage, SSL monitor |
| Java `.jar` | extraction, string scanning |

---

## Requirements

- Python 3.7+ (standard library covers everything core)
- `capstone` — recommended; enables verified candidate scanning
  (auto-offered on first run, or `pip install capstone`)
- `frida-tools` — optional, only for live Frida monitors

---

## Quick start

### GUI

```bash
python3 bobbypin_gui.py          # http://127.0.0.1:8877
python3 bobbypin_gui.py 9000     # custom port
```

Drop a binary on the page. The **Workflow** button (top right) walks through
the whole process step by step.

### CLI — PE binaries

```bash
python3 bobbypin.py target.exe              # interactive triage
python3 bobbypin.py target.exe --json       # machine-readable report
python3 bobbypin.py target.exe --apply 2    # NOP candidate #2
python3 bobbypin.py target.exe --apply 2 --flip   # invert instead
```

### CLI — Electron ASAR (AI agent mode)

```bash
# Analyze the ASAR — identify guards, channels, secureClient path
python3 bobbypin_ai.py electron_plan '{"asar":"path/to/app.asar"}'

# Apply all three patches and repack in one step
python3 bobbypin_ai.py electron_bypass \
  '{"asar":"path/to/app.asar","out":"path/to/app.asar"}'

# Repack with custom file replacements
python3 bobbypin_ai.py asar_repack \
  '{"orig":"app.asar","out":"app_patched.asar","mods":{"/src/main/main.js":"main_patched.js"}}'
```

### AI agent mode (persistent session)

```bash
python3 bobbypin_ai.py serve
{"cmd":"electron_plan","asar":"path/to/app.asar"}
{"cmd":"electron_bypass","asar":"path/to/app.asar","out":"path/to/app.asar"}
{"cmd":"quit"}
```

Point any AI agent at `AGENTS.md` for the complete operating manual.

---

## PE workflow

1. Run the original binary; record its failure/success messages.
2. Find those messages in string output; note their offsets.
3. Match offsets against patch candidates (`FAIL` kind first, `verified:true` preferred).
4. Confirm intent with disassembly around the branch offset (~30 instructions).
5. NOP first; if behavior is unchanged, flip; then try the next candidate.
6. Stuck? Generate the Frida monitor and watch the decision happen live.

## Electron workflow

1. `electron_plan` — confirm the guard variable name, IPC channels, and
   whether `makeKeyAuthRequest` is present (if it is, the boolean guard patch
   is mandatory; stubbing secureClient alone won't bypass validation).
2. `electron_bypass` — applies all three patches. A backup is written
   automatically on first run (`app.asar.bak`); subsequent runs read from
   the backup so reruns are idempotent.
3. If the app still shows a license error, check the troubleshooting keys in
   the bypass response: each error message maps to which patch may have
   missed.

---

## Legal

For analyzing software you own or are explicitly authorized to test.
Don't be the reason this needs a takedown notice.
