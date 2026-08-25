#!/usr/bin/env python3
# ai control layer for bobbypin - decay.root.0x00
#
# two ways to use:
#   1. one-shot:  python3 bobbypin_ai.py plan target.exe        (prints json)
#   2. agent session:  python3 bobbypin_ai.py serve             (one json request
#      per stdin line -> one json response per stdout line, quit with {"cmd":"quit"})
#
# every response: {"ok": bool, "cmd": str, "data": ...} so callers never parse prose.
import json
import os
import re as _re
import shutil
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import bobbypin as bp

MAX_DISASM = 200

# ---------------------------------------------------------------------------
# Electron license bypass: Proxy stub that satisfies any SecureApiClient call
# ---------------------------------------------------------------------------
SECURE_CLIENT_STUB = """\
'use strict';
const SUCCESS={success:true,message:'OK',info:{},status:'ok',statusCode:1};
function makeStubInstance(){
  return new Proxy(Object.create(null),{
    get(_t,prop){
      if(prop==='then')return undefined;
      if(prop===Symbol.toPrimitive||prop==='valueOf'||prop==='toString')
        return()=>'[SecureClientStub]';
      return async function(){return{...SUCCESS};};
    },
  });
}
function SecureApiClient(){return makeStubInstance();}
SecureApiClient.prototype={};
module.exports=new Proxy(SecureApiClient,{
  construct(_t,_a){return makeStubInstance();},
  apply(_t,_th,_a){return makeStubInstance();},
  get(_t,prop){
    if(prop==='prototype')return SecureApiClient.prototype;
    if(prop==='default')return SecureApiClient;
    return SecureApiClient[prop];
  },
});
module.exports.default=module.exports;
"""

# ---------------------------------------------------------------------------
# CASE NOTES - Delta's Lobby-Manager v8.0.0 (target/, authorized test, Aug 2026)
# WORKING reference for future targets with the same protections.
#
# WHY electron_bypass DID NOT APPLY:
#   Main-process logic is compiled to V8 bytecode (bytenode pattern). Recon
#   signatures:
#     - out/main/main.js is a ~70-byte stub:
#         require("./bytecode-loader.cjs"); require("./main.jsc");
#     - .jsc sibling next to every real module (main.jsc, authClient.jsc, ...)
#     - plain-JS out/main/bytecode-loader.js registers Module._extensions[".jsc"]
#   -> no "isLicenseValid=![]" text exists to flip; skip boolean_guard.
#
# WHAT ACTUALLY WORKED (single-file patch, verified at runtime by owner):
#   License checks were proxied through a NATIVE C++ KeyAuth client
#   (build/Release/protection.node) exposed to JS via an UNPACKED plain-JS
#   wrapper:  resources/app.asar.unpacked/out/main/native-protection/index.js
#   Patch = force success on:
#     validateMainLicense / validateProxyLicense / validateInfinityLicense /
#     authenticateCustomApi / checkSession / checkServerHealth
#   Keep REAL (important): generateHWID + security passthroughs, so persisted
#   store state (%APPDATA%/<productName>/config.json) stays self-consistent.
#   main.jsc then sets its own internal flag natively -> zero ASAR edits needed.
#
# GOTCHAS HIT DURING RECON:
#   - asar_repack silently no-ops on entries flagged {"unpacked": true} (they
#     carry no offset). Check the header entry first; such files live on disk
#     under resources/app.asar.unpacked/ and are patched directly.
#   - renderer called window.electronAPI while preload.js exposed deltaAPI;
#     license.html flow: validateLicense(key) -> on success startApplication()
#     fires after a 2000ms setTimeout. Adapt regexes to the API name at runtime
#     (match electronAPI|deltaAPI|custom bridge).
#   - root ASAR entries (/license /production /development /staging /secrets
#     /test/*.js) were anti-analysis decoys with garbage size/offset values.
#   - app.asar header: native module dirs get per-file unpacked:true; the
#     resources/app/ folder next to app.asar had no package.json so it is inert.
#
# BACKUPS LEFT IN PLACE (restore to revert):
#   target/Lobby-Manager/resources/app.asar.bak
#   target/Lobby-Manager/resources/app.asar.unpacked/out/main/native-protection/index.js.bak
#
# NEXT ITERATIONS IF A SIMILAR TARGET BLOCKS THIS HOOK:
#   1. license.html ipc_bypass adapted for the real bridge name (format regex
#      lives in bytecode; dummy-UUID trick from electron_bypass still applies)
#   2. hook IPC registration in the plain main.js stub BEFORE requiring .jsc
#      (wrap ipcMain.handle for 'validate-license'/'get-license-status')
#   3. fabricate HTTP responses if validation verdict comes from server JSON
#      parsed by bytecode code (needs schema from string constants)
# ---------------------------------------------------------------------------


def _err(cmd, msg):
    return {"ok": False, "cmd": cmd, "error": msg}


def _pe(path):
    data = open(path, "rb").read()
    pe = bp.parse_pe(data)
    return data, pe


# ---------------------------------------------------------------------------
# ASAR helpers
# ---------------------------------------------------------------------------

def _decode_hex_str(s):
    """Decode JS \\xNN escape sequences in a Python string (as read from file)."""
    return _re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), s)


def _load_asar(path):
    """Parse ASAR. Returns (raw_bytes, header_json, file_data_start)."""
    data = open(path, "rb").read()
    H = bp.u32(data, 4)
    jlen = bp.u32(data, 12)
    file_data_start = 8 + H
    header_json = json.loads(data[16:16 + jlen])
    return data, header_json, file_data_start


def _asar_read(data, header_json, file_data_start, asar_path):
    """Read one file's bytes from a parsed ASAR."""
    def walk(node, prefix=""):
        for name, child in node.items():
            p = f"{prefix}/{name}"
            if "files" in child:
                r = walk(child["files"], p)
                if r is not None:
                    return r
            elif p == asar_path and "offset" in child and "unpacked" not in child:
                off = int(child["offset"])
                size = int(child.get("size", 0))
                return data[file_data_start + off:file_data_start + off + size]
        return None
    return walk(header_json.get("files", {}))


def _asar_find(header_json, pattern):
    """Return all ASAR paths matching a regex pattern."""
    matches = []
    def walk(node, prefix=""):
        for name, child in node.items():
            p = f"{prefix}/{name}"
            if "files" in child:
                walk(child["files"], p)
            elif _re.search(pattern, p, _re.IGNORECASE):
                matches.append(p)
    walk(header_json.get("files", {}))
    return matches


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_help(_args):
    return {"ok": True, "cmd": "help", "data": {
        "commands": {
            "help": "{} -> command reference",
            "triage": '{"path": "..."} -> format, hashes, packers, warnings',
            "strings": '{"path":"...","filter":"word","limit":50} -> tagged string literals',
            "candidates": '{"path":"..."} -> verified patch candidates with indices',
            "disasm": '{"path":"...","offset":"0xd90","count":30} -> decoded instructions (va annotated)',
            "bytes": '{"path":"...","offset":"0xdef","len":8} -> raw bytes at offset',
            "plan": '{"path":"..."} -> triage + candidates + top strings in one call',
            "patch": '{"src":"...","dst":"...","patches":[{"offset":"0xdef","mode":"nop"}]} '
                     "-> applies nop|flip|byte:<hex>, writes dst, reports per-patch result",
            "verify": '{"orig":"...","new":"..."} -> byte-level diff summary',
            "asar_repack": '{"orig":"...","out":"...","mods":{"/asar/path":"local/file"}} '
                           '-> repack ASAR with file replacements, updates per-file integrity hashes',
            "electron_plan": '{"asar":"path/to/app.asar"} '
                             '-> find isLicenseValid guards, IPC channels, secureClient path, '
                             'license.html structure; returns recommended patches',
            "electron_bypass": '{"asar":"path/to/app.asar","out":"path/to/app.asar","backup":"...bak"} '
                               '-> full 3-step bypass: flip isLicenseValid to true in main.js, '
                               'stub secureClient.js, patch license.html IPC call; repacks ASAR',
            "quit": "{} -> close session",
        },
        "recommended_flow_pe": [
            "plan -> read warnings/candidates first",
            "disasm around each candidate jcc_off to confirm intent",
            "patch with mode nop first, flip if nop changes nothing",
            "verify orig vs new, then hand off to runtime testing",
        ],
        "recommended_flow_electron": [
            "electron_plan {asar} -> identify guards, IPC channels, secureClient path",
            "electron_bypass {asar, out} -> apply all three patches in one step",
            "if 'License not validated' after success screen: isLicenseValid guard wasn't patched",
            "if 'Invalid license format': license.html IPC bypass patch not applied",
            "if app errors after launch: check startApplication IPC handler for additional guards",
        ],
        "electron_bypass_what_it_does": [
            "1. main.js: finds isLicenseValid=![] (and similar) and flips to !![] (true at startup)",
            "   - needed because startApplication IPC checks this flag before creating the main window",
            "   - the validate-license handler uses makeKeyAuthRequest() directly, bypassing secureClient,",
            "     so stubbing secureClient alone does NOT set this flag",
            "2. secureClient.js: replaces with a Proxy stub returning {success:true} for every call",
            "   - handles any SecureApiClient method call from main process IPC handlers",
            "3. license.html: fires validateLicense IPC with a dummy UUID (to satisfy any format check",
            "   and set whatever state the handler does set), then overrides result to {success:true}",
            "   - 2-second delay before startApplication gives the fire-and-forget IPC time to complete",
        ],
            "asar_format_notes": [
                "Chromium Pickle 4-field header: [u32:4][u32:H][u32:H-4][u32:J][JSON(J bytes)][pad][file data]",
                "file_data_start = 8 + H  (NOT 12 + jlen)",
                "JSON at offset 16 (NOT 12); u32@12 is J (JSON length), u32@8 is H-4 (inner payload)",
                "per-file integrity field must be updated after replacement or Electron rejects the file",
                "app.asar.sha256 (whole-ASAR fuse) may not exist; check resources/ dir before worrying",
                "ENFORCE_INTEGRITY_CHECK env var in main.js controls the app-level manifest check (separate)",
            ],
            "case_note_bytenode_native_wrapper": [
                "Lobby-Manager v8.0.0 (target/, Aug 2026): main logic in .jsc bytecode -> electron_bypass N/A",
                "winning hook: plain unpacked JS wrapper around native protection module",
                "(resources/app.asar.unpacked/out/main/native-protection/index.js) - force success on",
                "validate*/authenticateCustomApi/checkSession; keep generateHWID real for store consistency",
                "unpacked:true asar entries have no offset - asar_repack skips them; patch file on disk instead",
                "full writeup incl. decoy entries + next iterations: see CASE NOTES block near top of bobbypin_ai.py",
            ],
        "rules": [
            "never write patches to src path - always a separate dst",
            "only analyze binaries you are authorized to test",
            ".NET targets: say so and recommend dnSpy instead",
        ],
    }}


def _upx_unpack(path, data):
    """Try to unpack a UPX-packed PE next to the original; returns new path or None."""
    if shutil.which("upx") is None:
        return None
    out = os.path.splitext(path)[0] + "_unpacked.exe"
    try:
        import subprocess
        r = subprocess.run(["upx", "-d", "-o", out, path],
                           capture_output=True, timeout=120)
        if r.returncode == 0 and os.path.exists(out):
            return out
    except Exception:
        pass
    return None


def _triage(path):
    data = open(path, "rb").read()
    rep = {}
    import hashlib
    rep["size"] = len(data)
    rep["sha256"] = hashlib.sha256(data).hexdigest()
    if data[:4] == b"PK\x03\x04":
        try:
            import zipfile
            with zipfile.ZipFile(path) as z:
                names = set(z.namelist())
        except Exception:
            names = set()
        if "AndroidManifest.xml" in names or "classes.dex" in names:
            rep["kind"] = "apk"
            rep["note"] = (
                "android package - decode with apktool, decompile classes.dex "
                "with jadx, patch smali/java, rebuild and re-sign"
            )
            return rep
        rep["kind"] = "jar"
        rep["note"] = "java archive - decompile .class files with jadx/cfr"
        return rep
    if bp.parse_asar(data) is not None:
        rep["kind"] = "asar"
        rep["electron"] = True
        rep["note"] = (
            "Electron ASAR archive - JS-level patching applies; "
            "use electron_plan then electron_bypass. "
            "Native branch patching does not apply to the JS layer."
        )
        return rep
    if bp.PYINST_MAGIC in data:
        rep["kind"] = "pyinstaller"
        rep["note"] = "extract then decompile .pyc with pycdc/uncompyle6"
        return rep
    if data[:4] == b"\x7fELF":
        rep["kind"] = "elf"
        rep["arch"] = {1: "32-bit", 2: "64-bit"}.get(data[4] if len(data) > 4 else 0, "?")
        rep["note"] = ("linux/bsd executable - string triage applies; "
                       "capstone disassembles x86/arm/arm64, branch patching is manual")
        return rep
    _mo = data[:4]
    if _mo in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
               b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        rep["kind"] = "macho"
        rep["fat"] = _mo in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca")
        rep["note"] = ("macos executable - string triage applies; "
                       "disassemble with capstone or otool, branch patching is manual")
        return rep
    try:
        pe = bp.parse_pe(data)
    except ValueError as ex:
        rep["kind"] = "unknown"
        rep["note"] = str(ex)
        return rep
    rep["kind"] = "pe32+" if pe["pe32plus"] else "pe32"
    rep["dotnet"] = pe["dotnet"]
    if pe["dotnet"]:
        rep["note"] = (".NET assembly - decompile with ilspycmd/dnSpy, "
                       "edit C# or IL, recompile; native byte patches do not apply")
    rep["electron"] = bp.looks_electron(data)
    rep["packers"] = bp.detect_packers(data)
    if "UPX" in rep["packers"]:
        unpacked = _upx_unpack(path, data)
        if unpacked:
            rep["unpacked_upx"] = unpacked
    rep["imports_total"] = sum(len(i["functions"]) for i in pe["imports"])
    rep["sections"] = [{"name": s["name"], "raw": s["raw"], "vsize": s["vsize"],
                        "exec": bool(s["chars"] & 0x20000000)} for s in pe["sections"]]
    if pe["dotnet"]:
        rep["warning"] = ".NET assembly - prefer dnSpy/ILSpy, native patching may not apply"
    return rep


def cmd_triage(args):
    path = args.get("path")
    if not path:
        return _err("triage", "need path")
    return {"ok": True, "cmd": "triage", "data": _triage(path)}


def cmd_strings(args):
    path = args.get("path")
    if not path:
        return _err("strings", "need path")
    filt = args.get("filter", "")
    limit = int(args.get("limit", 50))
    data = open(path, "rb").read()
    out = []
    for off, enc, s in bp.extract_strings(data, 4):
        tags = ",".join(bp.classify(s)) or ("FAIL" if bp.FAILURE_WORDS.search(s)
                                            else "OK" if bp.SUCCESS_WORDS.search(s) else "")
        if not tags:
            continue
        if filt and filt.lower() not in s.lower():
            continue
        out.append({"offset": f"0x{off:x}", "tags": tags, "string": s[:120]})
        if len(out) >= limit:
            break
    return {"ok": True, "cmd": "strings", "data": out}


def cmd_candidates(args):
    path = args.get("path")
    if not path:
        return _err("candidates", "need path")
    data, pe = _pe(path)
    strings = bp.extract_strings(data, 4)
    cands = bp.find_candidates(data, pe, strings)
    out = [{
        "index": i,
        "kind": c["kind"],
        "jump": c["jump"],
        "bytes": c["bytes"],
        "jcc_off": f"0x{c['jcc_off']:x}",
        "ref_off": f"0x{c['ref_off']:x}",
        "string": c["string"],
        "verified": c.get("verified", False),
    } for i, c in enumerate(cands)]
    return {"ok": True, "cmd": "candidates", "data": out}


def cmd_disasm(args):
    path = args.get("path")
    off = args.get("offset")
    if not path or off is None:
        return _err("disasm", "need path + offset")
    try:
        start = int(off, 16) if isinstance(off, str) else int(off)
    except ValueError:
        return _err("disasm", "offset must be hex like '0xd90'")
    count = min(int(args.get("count", 30)), MAX_DISASM)
    data, pe = _pe(path)
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

    def o2v(o):
        for s in pe["sections"]:
            if s["raw"] <= o < s["raw"] + s["rawsize"]:
                return pe["imagebase"] + s["va"] + (o - s["raw"])
        return None

    va = o2v(start)
    if va is None:
        return _err("disasm", "offset outside any section")
    md = Cs(CS_ARCH_X86, CS_MODE_64 if pe["pe32plus"] else CS_MODE_32)
    out = []
    for i in md.disasm(data[start:start + count * 12], va):
        out.append({"va": f"0x{i.address:x}", "ins": f"{i.mnemonic} {i.op_str}".strip()})
        if len(out) >= count:
            break
    return {"ok": True, "cmd": "disasm", "data": out}


def cmd_bytes(args):
    path = args.get("path")
    off = args.get("offset")
    if not path or off is None:
        return _err("bytes", "need path + offset")
    start = int(off, 16) if isinstance(off, str) else int(off)
    n = min(int(args.get("len", 8)), 256)
    data = open(path, "rb").read()
    return {"ok": True, "cmd": "bytes",
            "data": {"offset": f"0x{start:x}", "hex": data[start:start + n].hex()}}


def cmd_plan(args):
    path = args.get("path")
    if not path:
        return _err("plan", "need path")
    tri = _triage(path)
    data_out = {"triage": tri}
    if tri.get("kind") == "asar":
        # Delegate to electron_plan for JS-level analysis
        ep = cmd_electron_plan({"asar": path})
        data_out["electron_analysis"] = ep.get("data", {})
        data_out["suggested_next"] = [
            "run electron_bypass {asar, out} to apply all patches in one step",
            "or apply manually: flip isLicenseValid guard, stub secureClient, patch license.html",
        ]
    elif tri.get("kind") in ("pe32+", "pe32"):
        data_out["candidates"] = cmd_candidates({"path": path})["data"]
        data_out["interesting_strings"] = cmd_strings({"path": path, "limit": 25})["data"]
        data_out["suggested_next"] = [
            "for each FAIL candidate near auth strings: disasm its jcc_off +/- 40 insns",
            "confirm which guard controls the failure message you care about",
            "patch nop first; if behavior unchanged, flip same offset",
        ]
    elif "note" in tri:
        data_out["suggested_next"] = [tri["note"]]
    return {"ok": True, "cmd": "plan", "data": data_out}


def cmd_patch(args):
    src, dst, patches = args.get("src"), args.get("dst"), args.get("patches")
    if not src or not dst or not isinstance(patches, list) or not patches:
        return _err("patch", 'need src, dst, patches:[{"offset":"0x..","mode":"nop|flip|byte:AABB"}]')
    if src == dst:
        return _err("patch", "refusing: dst must differ from src")
    data = open(src, "rb").read()
    results = []
    for p in patches:
        off_s, mode = p.get("offset"), p.get("mode", "nop")
        off = int(off_s, 16) if isinstance(off_s, str) else int(off_s)
        cur = data[off:off + 6]
        inv = bp._invert_jcc(cur)
        if inv:
            size = 6 if cur[:1] == b"\x0f" else 2
        else:
            size = 1
        before = data[off:off + size]
        if mode == "nop":
            data = data[:off] + b"\x90" * size + data[off + size:]
            results.append({"offset": f"0x{off:x}", "mode": "nop", "before": before.hex(),
                            "after": "90" * size, "status": "applied"})
        elif mode == "flip":
            if not inv:
                results.append({"offset": f"0x{off:x}", "mode": "flip", "status":
                                f"skipped: {cur[:2].hex()} is not an invertible conditional jump"})
                continue
            data = data[:off] + inv + data[off + len(inv):]
            results.append({"offset": f"0x{off:x}", "mode": "flip", "before": before.hex(),
                            "after": (inv + data[off + len(inv):off + size]).hex(), "status": "applied"})
        elif mode.startswith("byte:"):
            repl = bytes.fromhex(mode[5:])
            data = data[:off] + repl + data[off + len(repl):]
            results.append({"offset": f"0x{off:x}", "mode": mode, "before": before[:len(repl)].hex(),
                            "after": repl.hex(), "status": "applied"})
        else:
            results.append({"offset": f"0x{off:x}", "mode": mode, "status": "skipped: unknown mode"})
    open(dst, "wb").write(data)
    return {"ok": True, "cmd": "patch", "data": {"dst": dst, "results": results}}


def cmd_verify(args):
    a, b = args.get("orig"), args.get("new")
    if not a or not b:
        return _err("verify", "need orig + new")
    da, db = open(a, "rb").read(), open(b, "rb").read()
    if len(da) != len(db):
        return {"ok": True, "cmd": "verify",
                "data": {"same_size": False, "len_orig": len(da), "len_new": len(db)}}
    diffs = []
    i, n = 0, len(da)
    while i < n and len(diffs) < 64:
        if da[i] != db[i]:
            j = i
            while j < n and da[j] != db[j]:
                j += 1
            diffs.append({"range": f"0x{i:x}-0x{j - 1:x}",
                          "orig": da[i:j].hex(), "new": db[i:j].hex()})
            i = j
        else:
            i += 1
    return {"ok": True, "cmd": "verify",
            "data": {"same_size": True, "regions_changed": len(diffs), "diffs": diffs}}


# ---------------------------------------------------------------------------
# ASAR repack command
# ---------------------------------------------------------------------------

def cmd_asar_repack(args):
    """
    Repack an ASAR with file replacements.
    mods: {"/asar/path": "local/file/path"}  - local files are read and embedded.
    """
    orig = args.get("orig")
    out = args.get("out")
    mods_map = args.get("mods", {})
    if not orig or not out:
        return _err("asar_repack", "need orig + out")
    if orig == out and not args.get("force"):
        return _err("asar_repack", "orig == out: pass force:true to overwrite in place")
    mods = {}
    for asar_path, local_path in mods_map.items():
        try:
            mods[asar_path] = open(local_path, "rb").read()
        except OSError as ex:
            return _err("asar_repack", f"cannot read {local_path}: {ex}")
    try:
        result = bp.repack_asar(orig, out, mods)
    except Exception as ex:
        return _err("asar_repack", f"repack failed: {ex}")
    return {"ok": True, "cmd": "asar_repack", "data": result}


# ---------------------------------------------------------------------------
# Electron plan command
# ---------------------------------------------------------------------------

def cmd_electron_plan(args):
    """
    Analyze an Electron ASAR for license bypass opportunities.

    Looks for:
      - isLicenseValid / licenseValidated boolean guards in main.js
      - ipcMain.handle channel names (hex-decoded)
      - secureClient require path
      - makeKeyAuthRequest (direct HTTP - bypasses secureClient stub)
      - validateLicense IPC call pattern in license.html
    """
    asar_path = args.get("asar") or args.get("path")
    if not asar_path:
        return _err("electron_plan", "need asar path")
    try:
        data, hdr, fds = _load_asar(asar_path)
    except Exception as ex:
        return _err("electron_plan", f"failed to load ASAR: {ex}")

    findings = {
        "asar": asar_path,
        "patches_needed": [],
        "warnings": [],
        "ipc_channels": [],
    }

    # ---- main.js ----
    main_paths = _asar_find(hdr, r"(?:^|/)main\.js$")
    findings["main_js_candidates"] = main_paths
    main_js_text = None
    main_js_asar_path = None
    for p in main_paths:
        c = _asar_read(data, hdr, fds, p)
        if c and b"ipcMain" in c:
            main_js_text = c.decode("utf-8", "replace")
            main_js_asar_path = p
            break

    if main_js_text:
        findings["main_js"] = main_js_asar_path

        # Boolean guards: variable=![] where name suggests auth/license
        guard_re = _re.compile(r'([a-zA-Z_$][a-zA-Z0-9_$]*)=!\[\]')
        seen_guards = {}
        for m in guard_re.finditer(main_js_text):
            name = m.group(1)
            if name in seen_guards:
                continue
            if any(kw in name.lower() for kw in
                   ("license", "valid", "auth", "verified", "paid", "unlock")):
                count = main_js_text.count(m.group(0))
                seen_guards[name] = {
                    "variable": name,
                    "pattern": m.group(0),
                    "patch": f"{name}=!![]",
                    "occurrences": count,
                    "note": "patch FIRST occurrence (declaration); later ones are reset handlers",
                }
        guards = list(seen_guards.values())
        findings["license_guards"] = guards
        if guards:
            findings["patches_needed"].append({
                "file": main_js_asar_path,
                "type": "boolean_guard",
                "desc": f"change {guards[0]['variable']}=![] to {guards[0]['variable']}=!![] (first occurrence only)",
                "why": "startApplication IPC checks this flag before creating the main window",
            })

        # ipcMain.handle / ipcMain.on channel names (quoted strings only)
        channels = []
        for m in _re.finditer(r"ipcMain\[[^\]]+\]\((['\"][^'\"]+['\"])", main_js_text):
            raw = m.group(1).strip("'\"")
            channels.append(_decode_hex_str(raw))
        findings["ipc_channels"] = sorted(set(channels))

        # Direct HTTP client check
        if "makeKeyAuthRequest" in main_js_text:
            findings["warnings"].append(
                "main.js contains makeKeyAuthRequest() - license validation uses direct HTTP, "
                "not secureClient; stubbing secureClient alone will NOT bypass validation. "
                "The isLicenseValid boolean guard patch is mandatory."
            )

        # secureClient require
        sc_re = _re.compile(r"require\((['\"][^'\"]*[Ss]ecure[Cc]lient[^'\"]*['\"])\)")
        sc_m = sc_re.search(main_js_text)
        if sc_m:
            findings["secureclient_require"] = _decode_hex_str(sc_m.group(1).strip("'\""))
    else:
        findings["warnings"].append(
            "no main.js with ipcMain found - manual analysis needed"
        )

    # ---- secureClient.js ----
    sc_paths = _asar_find(hdr, r"(?:^|/)secure[Cc]lient\.js$")
    findings["secureclient_candidates"] = sc_paths
    if sc_paths:
        findings["patches_needed"].append({
            "file": sc_paths[0],
            "type": "stub_replace",
            "desc": "replace with Proxy stub returning {success:true} for every method call",
            "why": "catches any SecureApiClient calls from IPC handlers that do go through it",
        })

    # ---- license.html ----
    lic_paths = _asar_find(hdr, r"(?:^|/)license\.html$")
    findings["license_html_candidates"] = lic_paths
    for p in lic_paths:
        c = _asar_read(data, hdr, fds, p)
        if c and b"validateLicense" in c:
            findings["license_html"] = p
            html = c.decode("utf-8", "replace")
            if "window.electronAPI.validateLicense" in html:
                has_fmt = "Invalid license format" in html or "format" in html.lower()
                findings["patches_needed"].append({
                    "file": p,
                    "type": "ipc_bypass",
                    "desc": (
                        "fire validateLicense IPC with dummy UUID (to set main-process license state "
                        "and pass any format check), then override result to {success:true}"
                    ),
                    "format_check_present": has_fmt,
                    "why": "prevents 'Invalid license format' without skipping the IPC entirely "
                           "(skipping leaves isLicenseValid unset if makeKeyAuthRequest isn't the setter)",
                })
            break

    findings["recommended_next"] = (
        'electron_bypass {"asar":"...","out":"..."} to apply all patches in one step'
    )
    return {"ok": True, "cmd": "electron_plan", "data": findings}


# ---------------------------------------------------------------------------
# Electron bypass command
# ---------------------------------------------------------------------------

def cmd_electron_bypass(args):
    """
    Full automated Electron license bypass - 3 patches, 1 repack.

    Patch 1 - main.js boolean guard:
      Find isLicenseValid=![] (or similar) and flip to !![] so the
      startApplication IPC handler passes its guard check on startup.
      The validate-license IPC typically calls makeKeyAuthRequest() directly
      (not through secureClient), so this guard is the authoritative bypass.

    Patch 2 - secureClient.js stub:
      Replace the real API client with a Proxy that returns {success:true}
      for every async call, covering any IPC handlers that do use it.

    Patch 3 - license.html IPC call:
      Fire validateLicense IPC with a dummy UUID-format key (passes format
      checks, may set additional state), then force result.success=true so
      the renderer always transitions to the success flow.
      startApplication is called 2 seconds later - by then the fire-and-
      forget IPC has completed and any state it sets is in place.
    """
    asar_path = args.get("asar")
    out_path  = args.get("out") or asar_path
    bak_path  = args.get("backup") or (asar_path + ".bak") if asar_path else None

    if not asar_path:
        return _err("electron_bypass", "need asar")

    # Backup
    backed_up = False
    if not os.path.exists(bak_path):
        shutil.copy2(asar_path, bak_path)
        backed_up = True

    src = bak_path  # always repack from backup so reruns are idempotent

    try:
        data, hdr, fds = _load_asar(src)
    except Exception as ex:
        return _err("electron_bypass", f"failed to load ASAR: {ex}")

    mods = {}
    applied = []
    warnings = []

    # ---- Patch 1: main.js boolean guard ----
    main_js_found = False
    for p in _asar_find(hdr, r"(?:^|/)main\.js$"):
        c = _asar_read(data, hdr, fds, p)
        if not (c and b"ipcMain" in c):
            continue
        main_js_found = True
        text = c.decode("utf-8", "replace")

        guard_re = _re.compile(r'([a-zA-Z_$][a-zA-Z0-9_$]*)=!\[\]')
        patched_text = text
        guard_patched = False
        for m in guard_re.finditer(text):
            name = m.group(1)
            if not any(kw in name.lower() for kw in
                       ("license", "valid", "auth", "verified", "paid", "unlock")):
                continue
            old = m.group(0)          # e.g. "isLicenseValid=![]"
            new = f"{name}=!![]"      # e.g. "isLicenseValid=!![]"
            count = text.count(old)
            # Replace only the first occurrence (the declaration site).
            # Later occurrences are reset handlers (e.g. clear-license IPC) that
            # should remain false so the app can re-lock if needed.
            patched_text = patched_text.replace(old, new, 1)
            guard_patched = True
            applied.append({
                "file": p, "type": "boolean_guard",
                "variable": name, "old": old, "new": new,
                "occurrences_total": count,
                "note": "patched first occurrence (declaration); remaining resets left intact",
            })
            break  # one guard is enough

        if not guard_patched:
            warnings.append(
                f"no license boolean guard found in {p} - "
                "startApplication may have a different check; inspect manually"
            )

        mods[p] = patched_text.encode("utf-8")
        break

    if not main_js_found:
        warnings.append("main.js with ipcMain not found in ASAR")

    # ---- Patch 2: secureClient.js stub ----
    stub_bytes = SECURE_CLIENT_STUB.encode("utf-8")
    sc_paths = _asar_find(hdr, r"(?:^|/)secure[Cc]lient\.js$")
    if sc_paths:
        for p in sc_paths:
            mods[p] = stub_bytes
            applied.append({
                "file": p, "type": "stub_replace",
                "new_size": len(stub_bytes),
            })
    else:
        warnings.append("secureClient.js not found - stub not applied")

    # ---- Patch 3: license.html IPC bypass ----
    lic_found = False
    for p in _asar_find(hdr, r"(?:^|/)license\.html$"):
        c = _asar_read(data, hdr, fds, p)
        if not (c and b"validateLicense" in c):
            continue
        lic_found = True
        html = c.decode("utf-8", "replace")

        # Try exact pattern first, then flexible regex
        DUMMY_KEY = "00000000-0000-0000-0000-000000000000"
        FIRE_AND_FORCE = (
            f"window.electronAPI.validateLicense('{DUMMY_KEY}').catch(()=>{{}});\n"
            "                    const result = { success: true };"
        )

        exact = "const result = await window.electronAPI.validateLicense(trimmedKey);"
        if exact in html:
            html = html.replace(exact, FIRE_AND_FORCE, 1)
            match_type = "exact"
        else:
            flex = _re.compile(
                r"const result\s*=\s*await\s+window\.electronAPI\.validateLicense\([^)]+\);",
                _re.MULTILINE,
            )
            m = flex.search(html)
            if m:
                html = html[:m.start()] + FIRE_AND_FORCE + html[m.end():]
                match_type = "regex"
            else:
                warnings.append(
                    f"validateLicense call not found in {p} - "
                    "license.html may use a different pattern; inspect manually"
                )
                match_type = None

        if match_type:
            mods[p] = html.encode("utf-8")
            applied.append({
                "file": p, "type": "ipc_bypass",
                "match": match_type,
                "desc": (
                    f"fire validateLicense('{DUMMY_KEY}') async (sets main-process state), "
                    "then force result.success=true"
                ),
            })
        break

    if not lic_found:
        warnings.append("license.html not found in ASAR")

    # ---- Repack ----
    try:
        result = bp.repack_asar(src, out_path, mods)
    except Exception as ex:
        return _err("electron_bypass", f"repack failed: {ex}")

    return {
        "ok": True,
        "cmd": "electron_bypass",
        "data": {
            "backed_up": backed_up,
            "backup": bak_path,
            "out": out_path,
            "size": result["size"],
            "applied": applied,
            "warnings": warnings,
            "troubleshooting": {
                "still_says_invalid_format": (
                    "license.html IPC bypass not applied - check license_html_candidates "
                    "and patch manually if the file path differs"
                ),
                "license_not_validated_after_success_screen": (
                    "isLicenseValid guard not found/patched - look for the variable name "
                    "in the startApplication IPC handler and add it to the guard keyword list"
                ),
                "failed_to_start_application": (
                    "startApplication handler has additional checks beyond isLicenseValid - "
                    "run electron_plan and inspect ipc_channels for the handler body"
                ),
            },
        },
    }


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

COMMANDS = {
    "help":             cmd_help,
    "triage":           cmd_triage,
    "strings":          cmd_strings,
    "candidates":       cmd_candidates,
    "disasm":           cmd_disasm,
    "bytes":            cmd_bytes,
    "plan":             cmd_plan,
    "patch":            cmd_patch,
    "verify":           cmd_verify,
    "asar_repack":      cmd_asar_repack,
    "electron_plan":    cmd_electron_plan,
    "electron_bypass":  cmd_electron_bypass,
}


def main():
    args = sys.argv[1:]
    if not args or args[0] != "serve":
        if not args or args[0] not in COMMANDS:
            print(json.dumps(COMMANDS["help"](None)))
            return
        payload = {}
        if len(args) > 1:
            raw = " ".join(args[1:])
            try:
                payload = json.loads(raw)
                if isinstance(payload, str):
                    payload = {"path": payload}
            except ValueError:
                payload = {"path": raw}
        print(json.dumps(COMMANDS[args[0]](payload)))
        return
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            cmd = req.pop("cmd", None)
            if cmd == "quit":
                print(json.dumps({"ok": True, "cmd": "quit"}), flush=True)
                break
            fn = COMMANDS.get(cmd)
            resp = fn(req) if fn else _err(cmd or "?", "unknown command - send help")
        except Exception as ex:
            resp = {"ok": False, "cmd": req.get("cmd", "?"), "error": f"{type(ex).__name__}: {ex}"}
        print(json.dumps(resp), flush=True)


if __name__ == "__main__":
    main()
