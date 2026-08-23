# AGENTS.md — driving bobbypin as an AI agent

bobbypin is a static-analysis + patching assistant for Windows PE binaries
and Electron ASAR archives (also handles JAR / PyInstaller bundles).
This file tells you, the AI, how to operate it end to end. Everything outputs
strict JSON.

**Authorization rule:** only operate on binaries the user owns or is
explicitly authorized to test. Say no otherwise.

---

## Interfaces

One-shot (simplest):
```
python3 bobbypin_ai.py plan target.exe
python3 bobbypin_ai.py electron_plan '{"asar":"app.asar"}'
python3 bobbypin_ai.py help
```

Persistent session (many queries, one process — faster):
```
python3 bobbypin_ai.py serve
{"cmd":"plan","path":"/abs/target.exe"}
{"cmd":"electron_bypass","asar":"app.asar","out":"app.asar"}
{"cmd":"quit"}
```
Every response: `{"ok": bool, "cmd": str, "data" | "error": ...}`.

Human GUI (if the user prefers clicking): `python3 bobbypin_gui.py 8877`
→ http://127.0.0.1:8877

---

## Commands

### PE / native binary commands

| cmd | required args | returns |
|---|---|---|
| `triage` | `path` | kind, hashes, packers, sections, warnings |
| `strings` | `path`, `filter`?, `limit`? | tagged literals (AUTH/URL/FAIL/OK) |
| `candidates` | `path` | disassembler-verified conditional jumps near tagged strings |
| `disasm` | `path`, `offset` (hex), `count`? | decoded instructions with VAs |
| `bytes` | `path`, `offset`, `len`? | raw hex at offset |
| `plan` | `path` | triage + candidates + top strings + suggested next steps |
| `patch` | `src`, `dst`, `patches[]` | applies nop/flip/byte:HEX, writes dst, per-patch status |
| `verify` | `orig`, `new` | byte-diff regions |

### Electron ASAR commands

| cmd | required args | returns |
|---|---|---|
| `electron_plan` | `asar` | license guard variables, IPC channel names, secureClient path, license.html structure, recommended patches |
| `electron_bypass` | `asar`, `out`, `backup`? | full 3-patch bypass + repack; per-patch status + troubleshooting hints |
| `asar_repack` | `orig`, `out`, `mods` ({"/asar/path":"local/file"}) | repack with arbitrary replacements; updates per-file integrity hashes |

---

## PE operating procedure

1. **Triage first:** `plan`. Read `warnings` — if `.NET`, stop and tell the
   user dnSpy/ILSpy is the right tool; do not produce native patches.
2. **Locate the decision:** ask the user what "failure" looks like at runtime
   (exact message). Find it in `strings` output; note its offset.
3. **Pick a candidate:** from `candidates`, choose entries whose `ref_off`
   sits near that string's offset, prefer `kind: FAIL`, require
   `verified: true`.
4. **Confirm by reading code:** `disasm` around each candidate's `jcc_off`
   (~30 instructions). Understand which branch leads to the failure message
   before touching anything.
5. **Patch minimally:** start with one guard:
   ```json
   {"cmd":"patch","src":"a.exe","dst":"a_patched.exe",
    "patches":[{"offset":"0xdef","mode":"nop"}]}
   ```
   Always a separate dst file. Never in place.
6. **Verify:** run `verify` on orig vs patched; confirm exactly the bytes you
   intended changed (`74 xx` → `90 90` for nop, opcode XOR-1 for flip).
7. **Report back:** offsets, before/after hex, expected runtime behavior change,
   and how to test.
8. **Iterate:** if runtime shows no change, try `flip` on the same offset,
   then the next candidate. Change one thing at a time.

---

## Electron operating procedure

### Step 1 — plan

```json
{"cmd":"electron_plan","asar":"path/to/app.asar"}
```

Read the response carefully:

- **`license_guards`** — list of boolean variables (`isLicenseValid=![]` etc.)
  found in main.js. Each entry shows the variable name, occurrence count, and
  the patch string. The first occurrence in the file is always the declaration;
  later ones are reset handlers.
- **`ipc_channels`** — all `ipcMain.handle`/`ipcMain.on` channel names, decoded
  from hex-escaped obfuscation. Look for `validate-license` and
  `start-application` to understand the auth flow.
- **`warnings`** — critical: if `makeKeyAuthRequest` is present in main.js,
  the `validate-license` IPC handler contacts the license server directly via
  HTTP, bypassing the secureClient module entirely. **Stubbing secureClient
  alone will not bypass validation.** The boolean guard patch is mandatory.
- **`patches_needed`** — the three patch types the bypass will apply, confirmed
  as present in this specific ASAR.

### Step 2 — bypass

```json
{"cmd":"electron_bypass","asar":"path/to/app.asar","out":"path/to/app.asar"}
```

What each patch does:

**Patch 1 — main.js boolean guard**
Finds `isLicenseValid=![]` (or any variable with "license"/"valid"/"auth" in
its name followed by `=![]`) and changes it to `!![]` (true) at its first
occurrence — the module-level declaration. The `startApplication` IPC handler
checks this flag before creating the main window; it must be true before that
handler is ever called.

**Patch 2 — secureClient.js stub**
Replaces the real API client module with a `Proxy` that returns
`{success:true, message:'OK', info:{}, status:'ok', statusCode:1}` for every
async method call, regardless of which method is invoked or what arguments are
passed. Covers any IPC handler that does instantiate and call SecureApiClient.

**Patch 3 — license.html IPC bypass**
Replaces:
```js
const result = await window.electronAPI.validateLicense(trimmedKey);
```
with:
```js
window.electronAPI.validateLicense('00000000-0000-0000-0000-000000000000').catch(()=>{});
const result = { success: true };
```
The fire-and-forget IPC call uses a UUID-format dummy key, which passes any
minimum-length or format regex in the handler. This lets the handler complete
normally (setting any state it writes beyond `isLicenseValid`) without blocking
the renderer. The renderer proceeds with `result.success=true` immediately.
The `startApplication` call happens 2 seconds later — enough time for the
background IPC to finish.

### Step 3 — verify behavior

| Symptom | Root cause | Fix |
|---|---|---|
| "Invalid license format" | license.html patch not applied | check `license_html_candidates` in plan; patch manually if path differs |
| "License not validated" after success screen | isLicenseValid guard not patched | the variable name in this app may differ; inspect the `startApplication` handler and add it to the guard keyword scan |
| App opens then errors on startup | `startApplication` has additional checks | inspect ipc_channels output for the handler body; apply a targeted main.js patch via `asar_repack` |

### Backup behavior

`electron_bypass` writes a backup (`app.asar.bak` by default) on the first
run. All subsequent runs read from the backup, so the operation is
idempotent — you can re-run safely after modifying parameters.

---

## ASAR format reference

Chromium Pickle 4-field header (all u32 LE):

```
[0]  4          outer pickle size (always 4)
[1]  H          inner blob size from byte 8  (= 8 + J + pad)
[2]  H - 4      inner payload length         (= 4 + J + pad)
[3]  J          actual JSON byte length
[16 .. 16+J]   JSON index (file tree with offsets and integrity hashes)
[16+J .. 8+H]  zero-padding to 4-byte boundary
[8+H ..]       concatenated file data
```

`file_data_start = 8 + H` (not `12 + jlen` — a common off-by-one).

Per-file `integrity` fields in the JSON must be updated after any replacement
or Electron will reject the file if its built-in ASAR integrity check is
enabled. `repack_asar` in `bobbypin.py` handles this automatically.

The app-level integrity manifest (`integrity-manifest.json`) is separate and
controlled by `ENFORCE_INTEGRITY_CHECK` in main.js — many apps set this to
`false`, making JS file edits undetectable at the app level even without
updating the manifest.

---

## Hard rules

- Never write patches into the source file (`dst` must differ from `src`
  for `patch`; `electron_bypass` enforces a backup automatically).
- One patch type per iteration when debugging; re-test after each.
- If `candidates` are all `verified: false`, capstone is missing:
  `pip install capstone`, then re-run.
- Frida monitors generated by this tool work on Frida ≤16 and ≥17.

---

## Example sessions

### PE binary

```
> python3 bobbypin_ai.py plan sample.exe
{"ok":true,"cmd":"plan","data":{"triage":{"kind":"pe32+"},"candidates":[...]}}

{"cmd":"disasm","path":"sample.exe","offset":"0xdd0","count":20}
{"cmd":"patch","src":"sample.exe","dst":"s_patched.exe",
 "patches":[{"offset":"0xdef","mode":"nop"}]}
{"cmd":"verify","orig":"sample.exe","new":"s_patched.exe"}
```

### Electron ASAR

```
> python3 bobbypin_ai.py serve

{"cmd":"electron_plan","asar":"resources/app.asar"}
# -> read license_guards, warnings (makeKeyAuthRequest?), patches_needed

{"cmd":"electron_bypass","asar":"resources/app.asar","out":"resources/app.asar"}
# -> applied: boolean_guard + stub_replace + ipc_bypass; backup written

# custom replacement only (e.g. revert one file):
{"cmd":"asar_repack","orig":"resources/app.asar.bak","out":"resources/app.asar",
 "mods":{"/src/main/api/secureClient.js":"my_stub.js"}}

{"cmd":"quit"}
```
