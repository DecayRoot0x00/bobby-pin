#!/usr/bin/env python3
import argparse
import io
import json
import os
import re
import struct
import subprocess
import sys

AUTH_KEYWORDS = re.compile(
    r"(passwo?rd|passwd|\bpwd\b|login|logon|sign[-_]?in|auth|token|secret|"
    r"api[_-]?key|apikey|credential|authorization|bearer|oauth|jwt|"
    r"ssh[_-]|openssh|mysql://|postgres(ql)?://|mongodb(\+srv)?://|jdbc:)",
    re.IGNORECASE,
)
FAILURE_WORDS = re.compile(
    r"invalid|expired|wrong|denied|fail|incorrect|not found|unauthorized|"
    r"license|subscription|blacklist|banned|access denied|bad token|"
    r"suspend|locked[ -]?out|\blocked\b|deactivated",
    re.IGNORECASE,
)
SUCCESS_WORDS = re.compile(
    r"\bsuccess|\bvalid\b|welcome|logged[- ]?in|authenticated|activated",
    re.IGNORECASE,
)
# bare api-response tokens: strstr(resp,"true") style guards live on these
RESPONSE_TOKEN = re.compile(r'"?(?:true|false)"?', re.IGNORECASE)
URL_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]{2,20}://[^\s\"'<>]{3,}")

CATEGORY_HINTS = {
    "net": ["socket", "connect", "send", "recv", "winhttp", "wininet", "internetopen", "httpsendrequest", "internetreadfile", "wsastartup"],
    "auth": ["logonuser", "cryptacquirecontext", "cryptencrypt", "cryptdecrypt", "cryptprotectdata", "bcryptdecrypt", "credread"],
    "reg": ["regopenkey", "regqueryvalue", "regsetvalue", "regcreatekey"],
    "file": ["createfile", "readfile", "writefile", "deletefile"],
}

SPECIAL_HOOKS = {
    "createfilew": 'log("[CREATEFILEW] " + args[0].readUtf16String());',
    "createfilea": 'log("[CREATEFILEA] " + args[0].readAnsiString());',
    "winhttpsendrequest": 'log("[HTTP-SEND] sending request...");',
    "winhttpreaddata": (
        "  var buf = args[1]; var len = args[2].toInt32();\n"
        "        log('[HTTP-RECV] ' + buf.readAnsiString(Math.min(len, 512)));"
    ),
    "internetreadfile": (
        "  var buf = args[1];\n"
        "        log('[HTTP-RECV] ' + buf.readAnsiString(512));"
    ),
    "recv": (
        "  log('[SOCK-RECV] ' + hexdump(args[1], {length: Math.min(args[2].toInt32(), 256)}));"
    ),
    "send": (
        "  log('[SOCK-SEND] ' + hexdump(args[1], {length: Math.min(args[2].toInt32(), 256)}));"
    ),
}

JCC_FLIP = {
    b"\x74": b"\x75",
    b"\x75": b"\x74",
    b"\x0f\x84": b"\x0f\x85",
    b"\x0f\x85": b"\x0f\x84",
}

DEPS = [
    ("capstone", "capstone", "decode instructions so patch candidates are verified, not guessed"),
    ("frida", "frida-tools", "run the generated hook.js monitors live (static analysis works without it)"),
]


def ensure_deps(assume_yes=False, prompt=None):
    import importlib
    import shutil
    import subprocess

    if prompt is None:
        prompt = sys.stdin.isatty()
    missing = []
    for module, pkg, why in DEPS:
        try:
            importlib.import_module(module)
            continue
        except ImportError:
            pass
        if shutil.which(module):
            continue
        missing.append((module, pkg, why))

    if not missing:
        return

    print("optional components missing:")
    for _, pkg, why in missing:
        print(f"  - {pkg}: {why}")
    if not prompt:
        print("install anytime with:")
        print("  " + " ".join([sys.executable, "-m", "pip", "install"] + [p for _, p, _ in missing]))
        return
    for _, pkg, _ in missing:
        answer = "y" if assume_yes else input(f"install {pkg} now? [Y/n] ").strip().lower()
        if answer in ("", "y", "yes"):
            subprocess.run([sys.executable, "-m", "pip", "install", pkg], check=False)


def u16(d, o):
    return struct.unpack_from("<H", d, o)[0]


def u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


def u64(d, o):
    return struct.unpack_from("<Q", d, o)[0]


def read_cstr(d, o, limit=256):
    e = d.find(b"\x00", o, o + limit)
    return d[o:e].decode("latin-1") if e != -1 else ""


def parse_pe(data):
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("not an MZ/PE file")
    pe = u32(data, 0x3C)
    if data[pe:pe + 4] != b"PE\x00\x00":
        raise ValueError("missing PE signature")
    machine = u16(data, pe + 4)
    opt = pe + 24
    magic = u16(data, opt)
    plus = magic == 0x20B
    dirs_off = opt + (112 if plus else 96)
    num_dirs = u32(data, opt + (108 if plus else 92))
    exp_rva = imp_rva = 0
    if num_dirs > 0:
        exp_rva = u32(data, dirs_off)
    if num_dirs > 1:
        imp_rva = u32(data, dirs_off + 8)
    imagebase = u64(data, opt + 24) if plus else u32(data, opt + 28)

    nsec = u16(data, pe + 6)
    sec_base = pe + 24 + u16(data, pe + 20)
    sections = []
    for i in range(nsec):
        s = sec_base + i * 40
        sections.append({
            "name": data[s:s + 8].rstrip(b"\x00").decode("latin-1"),
            "vsize": u32(data, s + 8),
            "va": u32(data, s + 12),
            "rawsize": u32(data, s + 16),
            "raw": u32(data, s + 20),
            "chars": u32(data, s + 36),
        })

    def rva2off(rva):
        for sec in sections:
            if sec["va"] <= rva < sec["va"] + max(sec["vsize"], sec["rawsize"]):
                return sec["raw"] + (rva - sec["va"])
        return None

    imports = []
    if imp_rva:
        off = rva2off(imp_rva)
        step = 8 if plus else 4
        while off is not None and off + 20 <= len(data):
            oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", data, off)
            if oft == 0 and name_rva == 0 and ft == 0:
                break
            dll = ""
            n = rva2off(name_rva)
            if n is not None:
                dll = read_cstr(data, n)
            funcs = []
            t = rva2off(oft or ft)
            while t is not None and t + step <= len(data):
                val = u64(data, t) if plus else u32(data, t)
                if val == 0:
                    break
                if not (val & ((1 << 63) if plus else (1 << 31))):
                    h = rva2off(val)
                    if h is not None:
                        funcs.append(read_cstr(data, h + 2))
                t += step
            imports.append({"dll": dll, "functions": funcs})
            off += 20

    exports = []
    if exp_rva:
        e = rva2off(exp_rva)
        if e is not None:
            num_names = u32(data, e + 24)
            names_rva = u32(data, e + 32)
            n = rva2off(names_rva)
            for i in range(min(num_names, 10000)):
                p = u32(data, n + i * 4)
                o = rva2off(p)
                if o is not None:
                    exports.append(read_cstr(data, o))

    return {
        "machine": f"0x{machine:x}",
        "pe32plus": plus,
        "imagebase": imagebase,
        "sections": sections,
        "imports": imports,
        "exports": exports,
        "dotnet": data.find(b"BSJB") != -1,
    }


def extract_strings(data, min_len=4):
    out = [(m.start(), "ascii", m.group().decode("ascii"))
           for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data)]
    out += [(m.start(), "u16le", m.group().decode("utf-16-le"))
            for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, data)]
    return sorted(out)


def tag_for(func):
    low = func.lower()
    return [c for c, keys in CATEGORY_HINTS.items() if any(k in low for k in keys)]


def classify(s):
    tags = []
    if AUTH_KEYWORDS.search(s):
        tags.append("AUTH")
    if URL_RE.search(s):
        tags.append("URL")
    return tags


def off_to_rva(sections, off):
    for sec in sections:
        if sec["raw"] <= off < sec["raw"] + sec["rawsize"]:
            return sec["va"] + (off - sec["raw"])
    return None


# dense runs of failure-looking strings are library error tables, not app logic
def find_string_tables(strings):
    pts = sorted(o for o, e, s in strings if FAILURE_WORDS.search(s))
    tables = []
    i = 0
    while i < len(pts):
        j = i
        while j + 1 < len(pts) and pts[j + 1] - pts[j] < 4096:
            j += 1
        if j - i + 1 >= 25:
            tables.append((pts[i], pts[j]))
        i = j + 1
    return tables


def _is_cond_jump(mnemonic):
    return mnemonic.startswith("j") and mnemonic != "jmp"


def _kind_of(s):
    if FAILURE_WORDS.search(s):
        return "FAIL"
    if SUCCESS_WORDS.search(s):
        return "OK"
    low = s.lower().strip('"')
    if low == "false":
        return "FAIL"
    return "OK"


def find_candidates(data, pe, strings):
    tables = find_string_tables(strings)

    def in_table(off):
        return any(a <= off <= b for a, b in tables)

    exec_secs = [s for s in pe["sections"] if s["chars"] & 0x20000000 and s["rawsize"]]
    va_targets = {}
    for off, enc, s in strings:
        tok = len(s) <= 6 and RESPONSE_TOKEN.fullmatch(s)
        if not tok:
            if len(s) < 8 or not (FAILURE_WORDS.search(s) or SUCCESS_WORDS.search(s)):
                continue
        if in_table(off):
            continue
        rva = off_to_rva(pe["sections"], off)
        if rva is None:
            continue
        va = pe["imagebase"] + rva
        va_targets.setdefault(va, []).append((off, enc, s))

    if not va_targets:
        return []

    try:
        import capstone
    except ImportError:
        return _find_candidates_heuristic(data, pe, exec_secs, va_targets)

    md = capstone.Cs(capstone.CS_ARCH_X86,
                     capstone.CS_MODE_64 if pe["pe32plus"] else capstone.CS_MODE_32)
    md.detail = True
    op_imm = capstone.x86.X86_OP_IMM
    op_mem = capstone.x86.X86_OP_MEM
    reg_rip = capstone.x86.X86_REG_RIP
    low32 = {va & 0xFFFFFFFF: va for va in va_targets}

    cands = []
    for sec in exec_secs:
        blob = data[sec["raw"]:sec["raw"] + sec["rawsize"]]
        base_va = pe["imagebase"] + sec["va"]
        insns = []
        refs = []
        pos = 0
        while pos < len(blob):
            last = None
            for insn in md.disasm(blob[pos:], base_va + pos):
                insns.append((insn.address, insn.size, insn.mnemonic))
                hit = None
                for op in insn.operands:
                    if op.type == op_imm:
                        v = op.imm & 0xFFFFFFFFFFFFFFFF
                        if v in va_targets:
                            hit = v
                            break
                        lv = v & 0xFFFFFFFF
                        if pe["pe32plus"] and lv in low32:
                            hit = low32[lv]
                            break
                    elif op.type == op_mem and op.mem.base == reg_rip:
                        v = insn.address + insn.size + op.mem.disp
                        v &= 0xFFFFFFFFFFFFFFFF
                        if v in va_targets:
                            hit = v
                            break
                if hit is not None:
                    refs.append((insn.address + insn.size, insn.address, hit))
                last = insn
                pos = insn.address - base_va + insn.size
            if last is None:
                pos += 1

        if not refs or not insns:
            continue
        # walk forward over decoded instructions until the first conditional jump
        addrs = [a for a, _, _ in insns]
        import bisect
        for ref_end, ref_start, va in sorted(refs):
            i = bisect.bisect_left(addrs, ref_end)
            steps = 0
            while i < len(insns) and steps < 32:
                addr, size, mnem = insns[i]
                if addr > ref_end + 160:
                    break
                # a ret means we left the enclosing function; a guard for
                # this message cannot live past it
                if mnem == "ret":
                    break
                if _is_cond_jump(mnem):
                    jcc_off = sec["raw"] + (addr - base_va)
                    raw = data[jcc_off:jcc_off + size]
                    for soff, enc, s in va_targets[va]:
                        kind = _kind_of(s)
                        cands.append({
                            "string": s[:60], "kind": kind, "encoding": enc,
                            "str_off": soff,
                            "ref_off": sec["raw"] + (ref_start - base_va),
                            "jcc_off": jcc_off,
                            "jump": mnem, "bytes": raw.hex(),
                            "verified": True,
                        })
                    break
                i += 1
                steps += 1

        # pass 2 - chained guards ("a second check in a row"). Such a jump
        # owns no string reference to walk FORWARD from: it is a conditional
        # jump whose TARGET lands directly on the next guard's failure or
        # success message. Match jump targets against message references so
        # every sequential check gets its own candidate card.
        def _imm_target(off, size, addr):
            for I in md.disasm(blob[off:off + size], addr):
                ops = I.operands
                if ops and ops[0].type == op_imm:
                    return ops[0].imm & 0xFFFFFFFFFFFFFFFF
            return None

        jcct = []
        claimed = {c["str_off"] for c in cands}
        for addr, size, mnem in insns:
            if _is_cond_jump(mnem):
                t = _imm_target(addr - base_va, size, addr)
                if t is not None:
                    jcct.append((t, addr, size, mnem))
        if jcct:
            jcct.sort()
            jt_targets = [j[0] for j in jcct]
            jcc_addrs = sorted(a for a, s_, m_ in insns if _is_cond_jump(m_))
            rstarts = sorted(r[1] for r in refs)
            for ref_end, ref_start, va in sorted(refs):
                if any(soff in claimed for soff, _, _ in va_targets[va]):
                    continue
                lo = bisect.bisect_left(jt_targets, ref_start - 64)
                for t, jaddr, jsize, jmnem in jcct[lo:]:
                    if t > ref_start + 16:
                        break
                    # guards jump FORWARD into their message block;
                    # backward-targeting jumps are loops, not guards
                    if t <= jaddr or t - jaddr > 512:
                        continue
                    k = bisect.bisect_right(jcc_addrs, jaddr)
                    if k < len(jcc_addrs) and jcc_addrs[k] < ref_start:
                        continue
                    ri = bisect.bisect_left(rstarts, ref_start)
                    if ri > 0 and rstarts[ri - 1] >= t:
                        continue
                    jcc_off = sec["raw"] + (jaddr - base_va)
                    raw = data[jcc_off:jcc_off + jsize]
                    for soff, enc, s in va_targets[va]:
                        cands.append({
                            "string": s[:60], "kind": _kind_of(s), "encoding": enc,
                            "str_off": soff,
                            "ref_off": sec["raw"] + (ref_start - base_va),
                            "jcc_off": jcc_off,
                            "jump": jmnem, "bytes": raw.hex(),
                            "verified": True,
                        })

    best = {}
    for c in sorted(cands, key=lambda c: (c["jcc_off"], 0 if c["kind"] == "FAIL" else 1)):
        cur = best.get(c["jcc_off"])
        if cur is None or (cur["kind"] != "FAIL" and c["kind"] == "FAIL"):
            best[c["jcc_off"]] = c
    return sorted(best.values(), key=lambda c: c["str_off"])


def _find_candidates_heuristic(data, pe, exec_secs, va_targets):
    refs = {}
    for sec in exec_secs:
        blob = data[sec["raw"]:sec["raw"] + sec["rawsize"]]
        base_va = pe["imagebase"] + sec["va"]
        for va, tlist in va_targets.items():
            if va <= 0xFFFFFFFF:
                needle = struct.pack("<I", va)
                pos = 0
                while True:
                    k = blob.find(needle, pos)
                    if k == -1:
                        break
                    refs.setdefault(sec["raw"] + k, set()).update(tlist)
                    pos = k + 1
        for k in range(len(blob) - 4):
            disp = struct.unpack_from("<i", blob, k)[0]
            tgt = base_va + k + 4 + disp
            if tgt in va_targets:
                refs.setdefault(sec["raw"] + k + 4, set()).update(va_targets[tgt])

    cands = []
    for ref_off in sorted(refs):
        lo, hi = max(0, ref_off - 384), min(ref_off + 96, len(data))
        window = data[lo:hi]
        hits = []
        for pat, name in [(b"\x0f\x84", "je"), (b"\x0f\x85", "jne"), (b"\x74", "je"), (b"\x75", "jne")]:
            pos = 0
            while True:
                k = window.find(pat, pos)
                if k == -1:
                    break
                hits.append((abs((lo + k) - ref_off), lo + k, name))
                pos = k + 1
        if not hits:
            continue
        hits.sort()
        _, jcc_off, jname = hits[0]
        size = 2 if data[jcc_off:jcc_off + 2] in JCC_FLIP else 1
        for soff, enc, s in refs[ref_off]:
            kind = _kind_of(s)
            cands.append({
                "string": s[:60], "kind": kind, "encoding": enc,
                "str_off": soff, "ref_off": ref_off, "jcc_off": jcc_off,
                "jump": jname, "bytes": data[jcc_off:jcc_off + size].hex(),
                "verified": False,
            })
    best = {}
    for c in sorted(cands, key=lambda c: (c["jcc_off"], abs(c["jcc_off"] - c["ref_off"]), 0 if c["kind"] == "FAIL" else 1)):
        cur = best.get(c["jcc_off"])
        if cur is None or (cur["kind"] != "FAIL" and c["kind"] == "FAIL"):
            best[c["jcc_off"]] = c
    return sorted(best.values(), key=lambda c: c["str_off"])


# works on frida <=16 (static Module.getExportByName) and 17+ (global lookup)
EXP_SHIM_JS = """function __exp(mod, name) {
  try {
    if (Module.findGlobalExportByName) return Module.findGlobalExportByName(name);
    if (mod) return Module.getExportByName(mod, name);
    return Module.getExportByName(name);
  } catch (e) {
    return null;
  }
}"""

SSL_HOOK_JS = """
['SSL_read', 'SSL_write'].forEach(function (fn) {
  var addr = __exp(null, fn);
  if (!addr) { log('[-] ' + fn + ' not found'); return; }
  Interceptor.attach(addr, {
    onEnter: function (args) {
      this.buf = args[1]; this.len = args[2].toInt32(); this.w = fn === 'SSL_write';
    },
    onLeave: function (ret) {
      var n = this.w ? this.len : ret.toInt32();
      if (n <= 0) return;
      var data = '[SSL_' + (this.w ? 'SEND' : 'RECV') + '] ' + n + ' bytes\\n' +
                 Memory.readUtf8String(this.buf, Math.min(n, 1024));
      log(data);
    }
  });
  log('[+] hooked ' + fn);
});
"""


SIG_LINE = "// signed: decay.root.0x00 | bobbypin v2.0 PRO | github.com/DecayRoot0x00"


def gen_monitor_js(pe):
    if pe.get("electron"):
        return ("// bobbypin.py electron monitor - run: frida -f <app>.exe -l hook.js\n"
                + SIG_LINE + "\n"
                "function log(m) { console.log(m); }\n" + EXP_SHIM_JS + "\n" + SSL_HOOK_JS)
    lines = ["// bobbypin.py monitor - run: frida -f <exe> -l hook.js", SIG_LINE, "",
             "function log(m) { console.log(m); }", EXP_SHIM_JS, ""]
    picked = []
    for imp in pe["imports"]:
        dll = imp["dll"]
        for fn in imp["functions"]:
            tags = tag_for(fn)
            if any(t in ("net", "auth", "reg") for t in tags):
                picked.append((dll, fn))
    if not picked:
        for imp in pe["imports"]:
            for fn in imp["functions"][:5]:
                picked.append((imp["dll"], fn))
    for dll, fn in picked:
        body = SPECIAL_HOOKS.get(fn.lower(),
            'log("[%s] " + args[0] + ", " + args[1] + ", " + args[2]);' % fn)
        lines.append("(function () {")
        lines.append("  var addr = __exp('%s', '%s');" % (dll, fn))
        lines.append("  if (!addr) { log('[-] %s not found'); return; }" % fn)
        lines.append("  Interceptor.attach(addr, {")
        lines.append("    onEnter(args) {")
        lines.append("      " + body)
        lines.append("    },")
        lines.append("  });")
        lines.append("})();")
        lines.append("")
    return "\n".join(lines)


# cc opcodes differ by one bit, so xor 1 flips je<->jne, ja<->jbe, etc
def _invert_jcc(raw):
    if not raw:
        return None
    if 0x70 <= raw[0] <= 0x7F:
        return bytes([raw[0] ^ 1])
    if len(raw) >= 2 and raw[0] == 0x0F and 0x80 <= raw[1] <= 0x8F:
        return bytes([raw[0], raw[1] ^ 1])
    return None


def apply_patch(data, cand, mode):
    off = int(cand["jcc_off"], 16) if isinstance(cand["jcc_off"], str) else cand["jcc_off"]
    out = bytearray(data)
    two = bytes(out[off:off + 2])
    inv = _invert_jcc(two)
    size = len(inv) if inv else (2 if two[:1] == b"\x0f" else 1)
    declared = len(cand.get("bytes", "")) // 2
    if declared > size:
        size = declared
    cur = bytes(out[off:off + size])
    name = cand.get("jump", "?")
    if mode == "nop":
        out[off:off + size] = b"\x90" * size
        desc = f"NOPed {cur.hex()} ({name}) at 0x{off:x}"
    elif inv:
        out[off:off + len(inv)] = inv
        desc = f"flipped {cur[:len(inv)].hex()}->{inv.hex()} ({name}) at 0x{off:x}"
    else:
        raise ValueError(f"bytes {two.hex()} at 0x{off:x} are not an invertible conditional jump")
    return bytes(out), desc


def parse_asar(data):
    if len(data) < 16 or data[:4] != b"\x04\x00\x00\x00":
        return None
    obj = None
    try:
        jlen = u32(data, 8)
        if 2 <= jlen <= len(data) - 12:
            obj = json.loads(data[12:12 + jlen])
    except ValueError:
        obj = None
    if obj is None:
        idx = data.find(b'{"files"')
        if idx == -1 or idx > 512:
            return None
        try:
            obj, _ = json.JSONDecoder().raw_decode(data[idx:].decode("utf-8", "replace"))
        except ValueError:
            return None
    if not isinstance(obj, dict) or "files" not in obj:
        return None
    base = 8 + u32(data, 4)
    files = []

    def walk(node, prefix):
        for name, child in node.items():
            path = f"{prefix}/{name}"
            if "files" in child:
                walk(child["files"], path)
            elif "offset" in child and "unpacked" not in child:
                files.append((path, base + int(child["offset"]), int(child.get("size", 0))))

    walk(obj.get("files", {}), "")
    return files


def unpack_asar(data, files, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    for rel, off, size in files:
        dest = os.path.join(out_dir, rel.lstrip("/"))
        os.makedirs(os.path.dirname(dest) or out_dir, exist_ok=True)
        with open(dest, "wb") as f:
            f.write(data[off:off + size])
    return out_dir


def repack_asar(orig_path, out_path, modifications):
    """
    Repack an ASAR archive with file replacements.

    modifications: {"/asar/path": bytes_content}

    Chromium Pickle header layout (4 x u32 LE):
      [0] 4            <- outer pickle size (always 4)
      [1] H            <- inner blob size from offset 8  (= 8 + J + pad)
      [2] H - 4        <- inner payload length           (= 4 + J + pad)
      [3] J            <- actual JSON byte length
      [16 .. 16+J]     <- JSON index
      [16+J .. 8+H]    <- zero-padding to 4-byte align
      [8+H ..]         <- concatenated file data

    Per-file integrity dicts in the JSON are updated for replaced files so
    Electron's built-in ASAR integrity check (if enabled) stays satisfied.
    """
    import hashlib as _hl

    def _integrity(content, bsize=4194304):
        h = _hl.sha256(content).hexdigest()
        blocks = [_hl.sha256(content[i:i + bsize]).hexdigest()
                  for i in range(0, max(len(content), 1), bsize)]
        return {"algorithm": "SHA256", "hash": h, "blockSize": bsize, "blocks": blocks}

    data = open(orig_path, "rb").read()
    H = u32(data, 4)
    jlen = u32(data, 12)
    file_data_start = 8 + H
    header_json = json.loads(data[16:16 + jlen])

    new_blob = bytearray()
    results = []

    def walk(node, prefix=""):
        for name, child in list(node.items()):
            path = f"{prefix}/{name}"
            if "files" in child:
                walk(child["files"], path)
            elif "offset" in child and "unpacked" not in child:
                orig_off = int(child["offset"])
                orig_size = int(child.get("size", 0))
                if path in modifications:
                    content = modifications[path]
                    if "integrity" in child:
                        child["integrity"] = _integrity(content)
                    results.append({"path": path, "orig_size": orig_size,
                                    "new_size": len(content), "replaced": True})
                else:
                    content = data[file_data_start + orig_off:
                                   file_data_start + orig_off + orig_size]
                child["offset"] = str(len(new_blob))
                child["size"] = len(content)
                new_blob.extend(content)

    walk(header_json.get("files", {}))

    new_json = json.dumps(header_json, separators=(",", ":")).encode("utf-8")
    J = len(new_json)
    pad = (4 - J % 4) % 4
    H_new = 8 + J + pad

    with open(out_path, "wb") as f:
        f.write(struct.pack("<I", 4))
        f.write(struct.pack("<I", H_new))
        f.write(struct.pack("<I", H_new - 4))
        f.write(struct.pack("<I", J))
        f.write(new_json)
        f.write(b"\x00" * pad)
        f.write(bytes(new_blob))

    return {"out": out_path, "size": os.path.getsize(out_path), "replacements": results}


ELECTRON_MARKERS = [b"app.asar", b"bytenode", b"ELECTRON_RUN_AS_NODE", b"node_modules"]


def looks_electron(data):
    return sum(m in data for m in ELECTRON_MARKERS[:3]) >= 1


PYINST_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"


def pyinstaller_files(data):
    idx = data.rfind(PYINST_MAGIC)
    if idx == -1:
        return None, []
    lengthof_pkg, toc_rel, toc_len, _pyver = struct.unpack_from("<IIII", data, idx + 8)
    pkg_start = idx - (lengthof_pkg - 24)
    entries = []
    pos = pkg_start + toc_rel
    end = pos + toc_len
    while pos + 18 <= min(end, len(data)):
        entry_len, entry_pos, csize, usize = struct.unpack_from("<IIII", data, pos)
        flag = data[pos + 16]
        etype = chr(data[pos + 17])
        if entry_len < 18 or pos + entry_len > len(data):
            break
        name = data[pos + 18:pos + entry_len].rstrip(b"\x00").decode("latin-1")
        entries.append((name, etype, flag, pkg_start + entry_pos, csize, usize))
        pos += entry_len
    return pkg_start, entries


def unpack_pyinstaller(data, out_dir):
    pkg_start, entries = pyinstaller_files(data)
    if not entries:
        return []
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for name, etype, flag, off, csize, usize in entries:
        if etype in ("z", "o"):
            continue
        blob = data[off:off + csize]
        if flag:
            try:
                import zlib
                blob = zlib.decompress(blob)
            except Exception:
                pass
        safe = name.replace("\\", "/").lstrip("/")
        if etype in ("s", "m", "M") and not safe.endswith((".pyc", ".py")):
            safe += ".pyc"
        dest = os.path.join(out_dir, safe)
        os.makedirs(os.path.dirname(dest) or out_dir, exist_ok=True)
        with open(dest, "wb") as f:
            f.write(blob)
        written.append((safe, len(blob)))
    return written


def detect_packers(data):
    hits = []
    if PYINST_MAGIC in data:
        hits.append("PyInstaller")
    if b"AU3!EA06" in data or b"AU3!EA05" in data:
        hits.append("AutoIt")
    if b"NullsoftInst" in data:
        hits.append("NSIS installer")
    if b"Inno Setup" in data:
        hits.append("Inno Setup installer")
    if b"\xff Go buildinf:" in data:
        hits.append("Go")
    if b"UPX!" in data:
        hits.append("UPX")
    return hits


PACKER_HINTS = {
    "PyInstaller": "extracted below - decompile .pyc with pycdc (Decompyle++) or uncompyle6",
    "AutoIt": "compiled AutoIt script - extract with myAut2Exe / Exe2Aut",
    "NSIS installer": "installer - unpack with 7-Zip or nsisunz to get the real payload",
    "Inno Setup": "installer - extract with innoextract",
    "Go": "Go binary - symbols/strings usually intact, native analysis applies",
    "UPX": "packed - auto-unpack with: upx -d -o target_unpacked.exe target.exe "
           "(or pip-install nothing; upx is a standalone binary)",
}


def scan_blob_strings(blob, limit=60):
    out = []
    for m in re.finditer(rb"[\x20-\x7e]{6,}", blob):
        s = m.group().decode("ascii")
        if classify(s) or FAILURE_WORDS.search(s) or SUCCESS_WORDS.search(s):
            out.append((m.start(), s))
        if len(out) >= limit:
            break
    return out


def pick_file_dialog():
    script = 'POSIX path of (choose file with prompt "Choose a file to analyze")'
    try:
        out = subprocess.run(["osascript", "-e", script],
                             capture_output=True, text=True, timeout=600)
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except Exception:
        pass
    return None


def pick_file_tui():
    cwd = os.path.expanduser("~")
    while True:
        try:
            entries = sorted(os.listdir(cwd))
        except OSError:
            return None
        dirs = [e for e in entries if os.path.isdir(os.path.join(cwd, e)) and not e.startswith(".")]
        files = [e for e in entries if not os.path.isdir(os.path.join(cwd, e))]
        print(f"\n  {cwd}")
        for i, d in enumerate(dirs, 1):
            print(f"  [{i}] {d}/")
        for j, f in enumerate(files, len(dirs) + 1):
            print(f"  [{j}] {f}")
        raw = input("[number] open | . up | q quit > ").strip()
        if raw == "q":
            return None
        if raw == ".":
            cwd = os.path.dirname(cwd) or "/"
            continue
        if raw.isdigit():
            n = int(raw)
            if 1 <= n <= len(dirs):
                cwd = os.path.join(cwd, dirs[n - 1])
                continue
            if len(dirs) < n <= len(dirs) + len(files):
                return os.path.join(cwd, files[n - len(dirs) - 1])
        elif raw:
            p = os.path.join(cwd, raw)
            if os.path.isfile(p):
                return p


def main():
    ap = argparse.ArgumentParser(description="All-in-one RE assistant: search strings, generate monitor hooks, propose/apply patches.")
    ap.add_argument("file", nargs="?", help="target exe/dll (omit to open file picker)")
    ap.add_argument("--min-len", type=int, default=4)
    ap.add_argument("--all-strings", action="store_true", help="print every string, not just interesting ones")
    ap.add_argument("--apply", type=int, metavar="N", help="non-interactively apply patch option N (nop)")
    ap.add_argument("--flip", action="store_true", help="with --apply: invert branch instead of NOPing")
    ap.add_argument("--no-monitor", action="store_true", help="skip writing hook.js")
    ap.add_argument("--json", action="store_true", help="machine-readable report")
    ap.add_argument("-y", "--yes", action="store_true", help="auto-confirm dependency installs")
    ap.add_argument("--skip-deps", action="store_true", help="skip dependency check entirely")
    args = ap.parse_args()

    if not args.skip_deps:
        ensure_deps(assume_yes=args.yes)

    if not args.file and sys.stdin.isatty():
        args.file = pick_file_dialog()
        if not args.file:
            print("picker closed - browsing folders instead (or type a path below)")
            args.file = pick_file_tui()
        if not args.file:
            args.file = input("path to file: ").strip().strip('"')
    if not args.file:
        ap.error("no file selected - drag a file onto the terminal or pass a path")

    data = open(args.file, "rb").read()

    if data[:4] == b"PK\x03\x04":
        import zipfile
        print(f"== {args.file} == (Java archive / zip)")
        out_dir = os.path.splitext(args.file)[0] + "_unpacked"
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = z.namelist()
            z.extractall(out_dir)
        classes = [n for n in names if n.endswith((".class", ".properties", ".json", ".yml"))]
        print(f"{len(names)} entries, extracted to {out_dir}")
        for n in classes:
            with open(os.path.join(out_dir, n), "rb") as f:
                for off, s in scan_blob_strings(f.read(), 15):
                    print(f"  {n}:{off}  {s[:80]}")
        print("\ndecompile .class files with jadx or CFR for readable Java.")
        return

    asar_files = parse_asar(data)
    if asar_files is not None:
        print(f"== {args.file} == (Electron asar archive, {len(asar_files)} files)")
        out_dir = os.path.splitext(args.file)[0] + "_unpacked"
        unpack_asar(data, asar_files, out_dir)
        print(f"extracted to {out_dir}\n")
        blob = bytearray()
        for rel, off, size in asar_files:
            if rel.lower().endswith((".jsc", ".js", ".json", ".html")):
                chunk = data[off:off + size]
                for m in re.finditer(rb"[\x20-\x7e]{6,}", chunk):
                    s = m.group().decode("ascii")
                    if classify(s) or FAILURE_WORDS.search(s) or SUCCESS_WORDS.search(s):
                        print(f"  {rel}:{m.start()}  {s[:80]}")
                blob += chunk
        strings = extract_strings(bytes(blob), args.min_len)
        print(f"\nnative patching does not apply to .jsc bytecode.")
        print("use the monitor (M) - it hooks SSL_read/SSL_write so you see the")
        print("KeyAuth API traffic in plaintext while your app logs in.")
        path = os.path.splitext(args.file)[0] + "_hook.js"
        open(path, "w").write(gen_monitor_js({"imports": [], "electron": True}))
        print(f"wrote {path} - run: frida -f <electron.exe> -l {path}")
        return

    packers = detect_packers(data)
    if "PyInstaller" in packers:
        out_dir = os.path.splitext(args.file)[0] + "_unpacked"
        written = unpack_pyinstaller(data, out_dir)
        print(f"== {args.file} == (PyInstaller bundle)")
        print(f"{len(written)} entries extracted to {out_dir}")
        for safe, size in written[:20]:
            print(f"    {safe} ({size} bytes)")
        if len(written) > 20:
            print(f"    ... {len(written) - 20} more")
        blob = b"".join(open(os.path.join(out_dir, s), "rb").read()
                        for s, _ in written[:200])
        print("   interesting strings inside bundled code:")
        for off, s in scan_blob_strings(blob)[:25]:
            print(f"    {s[:80]}")
        print("\ndecompile .pyc with pycdc (Decompyle++) or uncompyle6.")
        path = os.path.splitext(args.file)[0] + "_hook.js"
        open(path, "w").write(gen_monitor_js({"imports": [], "electron": True}))
        print(f"wrote {path} (SSL monitor - python apps use OpenSSL too)")
        return

    try:
        pe = parse_pe(data)
    except ValueError as ex:
        sys.exit(f"error: not a PE executable or known archive format ({ex})")

    pe["electron"] = looks_electron(data)

    strings = extract_strings(data, args.min_len)
    interesting = [(o, e, s) for o, e, s in strings
                   if args.all_strings or classify(s) or FAILURE_WORDS.search(s) or SUCCESS_WORDS.search(s)]
    cands = find_candidates(data, pe, strings)

    if args.json:
        print(json.dumps({"pe": {k: v for k, v in pe.items() if k != "sections"},
                          "sections": pe["sections"],
                          "strings": [{"offset": o, "encoding": e, "tags": classify(s), "string": s}
                                      for o, e, s in interesting],
                          "candidates": cands}, indent=2))
        return

    print(f"== {args.file} ==")
    print(f"machine={pe['machine']} pe32+={pe['pe32plus']} imagebase=0x{pe['imagebase']:x}")
    if packers:
        print("packager/runtime: " + ", ".join(packers))
        for p in packers:
            if p in PACKER_HINTS:
                print(f"  {p}: {PACKER_HINTS[p]}")
    if pe["dotnet"]:
        print("!! .NET assembly detected (BSJB metadata) - strongly consider dnSpy/ILSpy instead:")
        print("   decompile, edit the license check in C#, save module. Native patching below may not apply.")
    total_imp = sum(len(i["functions"]) for i in pe["imports"])
    print(f"{total_imp} imports, {len(pe['exports'])} exports\n")

    print(f"-- strings ({len(interesting)} interesting / {len(strings)} total) --")
    for o, e, s in interesting[:40]:
        tags = ",".join(classify(s)) or ("FAIL" if FAILURE_WORDS.search(s) else "OK")
        print(f"  {o:6x} {e:5} [{tags:9}] {s[:70]}")
    if len(interesting) > 40:
        print(f"  ... {len(interesting) - 40} more (--json for all)")

    print("\n-- patch candidates (string refs -> nearby branch) --")
    if not cands:
        print("  none found automatically. use the monitor route, or locate the")
        print("  branch manually in x64dbg and feed me the offset later.")
    for i, c in enumerate(cands, 1):
        print(f"  [{i}] {c['kind']:4} \"{c['string']}\"")
        print(f"      str@0x{c['str_off']:x} ref@0x{c['ref_off']:x} -> "
              f"{c['jump']} ({c['bytes']}) @0x{c['jcc_off']:x}")
    print(f"\n  M   write frida monitor script (hook.js)")

    choice = args.apply
    if choice is None and sys.stdin.isatty():
        raw = input("\napply which option? (number / M / Enter to quit) ").strip()
        choice = int(raw) if raw.isdigit() else (raw.upper() if raw else None)

    if choice == "M":
        path = os.path.splitext(args.file)[0] + "_hook.js"
        open(path, "w").write(gen_monitor_js(pe))
        print(f"wrote {path} - run: frida -f {args.file} -l {path}")
    elif isinstance(choice, int) and 1 <= choice <= len(cands):
        cand = cands[choice - 1]
        mode = "flip" if args.flip else "nop"
        patched, desc = apply_patch(data, cand, mode)
        out_path = os.path.splitext(args.file)[0] + "_patched.exe"
        with open(out_path, "wb") as f:
            f.write(patched)
        print(f"[{mode}] {desc}")
        print(f"wrote {out_path}")
    elif choice is not None:
        sys.exit(f"error: no option '{choice}'")


if __name__ == "__main__":
    main()
