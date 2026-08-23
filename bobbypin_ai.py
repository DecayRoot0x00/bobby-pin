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
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import bobbypin as bp

MAX_DISASM = 200


def _err(cmd, msg):
    return {"ok": False, "cmd": cmd, "error": msg}


def _pe(path):
    data = open(path, "rb").read()
    pe = bp.parse_pe(data)
    return data, pe


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
            "quit": "{} -> close session",
        },
        "recommended_flow": [
            "plan -> read warnings/candidates first",
            "disasm around each candidate jcc_off to confirm intent",
            "patch with mode nop first, flip if nop changes nothing",
            "verify orig vs new, then hand off to runtime testing",
        ],
        "rules": [
            "never write patches to src path - always a separate dst",
            "only analyze binaries you are authorized to test",
            ".NET targets: say so and recommend dnSpy instead",
        ],
    }}


def _triage(path):
    data = open(path, "rb").read()
    rep = {}
    import hashlib
    rep["size"] = len(data)
    rep["sha256"] = hashlib.sha256(data).hexdigest()
    if data[:4] == b"PK\x03\x04":
        rep["kind"] = "jar"
        rep["note"] = "java archive - decompile .class files with jadx/cfr"
        return rep
    if bp.parse_asar(data) is not None:
        rep["kind"] = "asar"
        rep["note"] = "electron archive - static branch patching does not apply"
        return rep
    if bp.PYINST_MAGIC in data:
        rep["kind"] = "pyinstaller"
        rep["note"] = "extract then decompile .pyc with pycdc/uncompyle6"
        return rep
    try:
        pe = bp.parse_pe(data)
    except ValueError as ex:
        rep["kind"] = "unknown"
        rep["note"] = str(ex)
        return rep
    rep["kind"] = "pe32+" if pe["pe32plus"] else "pe32"
    rep["dotnet"] = pe["dotnet"]
    rep["electron"] = bp.looks_electron(data)
    rep["packers"] = bp.detect_packers(data)
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
    if tri.get("kind") in ("pe32+", "pe32"):
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
        # short jcc = opcode+rel8 (2 bytes), long form = 0F8x+rel32 (6 bytes)
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


COMMANDS = {
    "help": cmd_help, "triage": cmd_triage, "strings": cmd_strings,
    "candidates": cmd_candidates, "disasm": cmd_disasm, "bytes": cmd_bytes,
    "plan": cmd_plan, "patch": cmd_patch, "verify": cmd_verify,
}


def main():
    args = sys.argv[1:]
    if not args or args[0] != "serve":
        # one-shot: first arg is a command name, rest is a json blob or key=val
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
    # serve mode: one json per line on stdin
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
