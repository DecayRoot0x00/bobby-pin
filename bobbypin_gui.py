#!/usr/bin/env python3
# bobbypin gui - decay.root.0x00

import hashlib
import io
import json
import os
import sys
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import bobbypin as retool
except ImportError:
    import retool

SESSIONS = {}
MAX_SESSIONS = 8  # each holds the full target bytes; don't let RAM balloon
MAX_BODY = 400 * 1024 * 1024  # plenty for any installer we care about


def format_size(num_bytes):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:3.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} TB"


def analyze_bytes(data):
    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()

    rep = {
        "kind": None,
        "packers": [],
        "packer_hints": {},
        "warnings": [],
        "strings": [],
        "candidates": [],
        "counts": {"total_bytes": len(data), "formatted_size": format_size(len(data))},
        "hashes": {"md5": md5, "sha256": sha256},
        "extracted": [],
        "sections": [],
        "imports": [],
        "exports": [],
        "meta": {},
        "hook_code": "",
    }

    if data[:4] == b"PK\x03\x04":
        import zipfile
        rep["kind"] = "jar"
        rep["warnings"].append("Java archive - decompile .class files with jadx or CFR.")
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                names = z.namelist()
            rep["counts"]["entries"] = len(names)
            rep["extracted"] = [{"name": n, "size": 0} for n in names[:500]]
            blob = b""
            for n in names:
                if n.endswith((".class", ".properties", ".json", ".yml", ".js")):
                    try:
                        part = zipfile.ZipFile(io.BytesIO(data)).read(n)
                        blob += part
                    except Exception:
                        pass
            rep["strings"] = [{"offset": f"{o}", "encoding": "ascii", "tags": "JAR", "string": s}
                              for o, s in retool.scan_blob_strings(blob)]
        except Exception as e:
            rep["warnings"].append(f"Zip extraction notice: {e}")
        rep["hook_code"] = retool.gen_monitor_js({"imports": [], "electron": True})
        return rep

    if retool.parse_asar(data) is not None:
        files = retool.parse_asar(data)
        rep["kind"] = "asar"
        rep["warnings"].append("Electron asar archive - bytecode can't be branch-patched; use the Frida SSL monitor.")
        blob = b""
        for rel, off, size in files:
            rep["extracted"].append({"name": rel, "size": size, "formatted": format_size(size)})
            chunk = data[off:off + size]
            if rel.lower().endswith((".jsc", ".js", ".json", ".html")):
                for o, s in retool.scan_blob_strings(chunk, 40):
                    tags = ",".join(retool.classify(s)) or ("FAIL" if retool.FAILURE_WORDS.search(s) else "OK" if retool.SUCCESS_WORDS.search(s) else "")
                    rep["strings"].append({"offset": f"{rel}:{o}", "encoding": "ascii", "tags": tags, "string": s})
                blob += chunk
        rep["counts"]["entries"] = len(files)
        rep["hook_code"] = retool.gen_monitor_js({"imports": [], "electron": True})
        return rep

    if retool.PYINST_MAGIC in data:
        pkg_start, entries = retool.pyinstaller_files(data)
        rep["kind"] = "pyinstaller"
        rep["warnings"].append("PyInstaller bundle - decompile .pyc with pycdc (Decompyle++) or uncompyle6.")
        rep["packers"].append("PyInstaller")
        rep["packer_hints"]["PyInstaller"] = retool.PACKER_HINTS.get("PyInstaller", "Python single-file binary bundle")
        blob = b""
        for name, etype, flag, off, csize, usize in entries:
            rep["extracted"].append({"name": name, "size": usize, "formatted": format_size(usize)})
            if etype in ("z", "o"):
                continue
            part = data[off:off + csize]
            if flag:
                try:
                    import zlib
                    part = zlib.decompress(part)
                except Exception:
                    pass
            for o, s in retool.scan_blob_strings(part, 20):
                tags = ",".join(retool.classify(s)) or ("FAIL" if retool.FAILURE_WORDS.search(s) else "OK" if retool.SUCCESS_WORDS.search(s) else "")
                rep["strings"].append({"offset": f"{name}:{o}", "encoding": "ascii", "tags": tags, "string": s})
            blob += part
        rep["counts"]["entries"] = len(entries)
        rep["hook_code"] = retool.gen_monitor_js({"imports": [], "electron": True})
        return rep

    try:
        pe = retool.parse_pe(data)
    except Exception as ex:
        rep["kind"] = "unknown"
        rep["warnings"].append(f"Unrecognized format or non-PE header: {ex}")
        raw_strings = retool.extract_strings(data, 4)
        rep["counts"]["total_strings"] = len(raw_strings)
        rep["strings"] = [{"offset": f"0x{o:x}", "encoding": e, "tags": ",".join(retool.classify(s)), "string": s}
                          for o, e, s in raw_strings[:500]]
        rep["hook_code"] = retool.gen_monitor_js({"imports": [], "electron": True})
        return rep

    rep["kind"] = "pe"
    pe["electron"] = retool.looks_electron(data)

    rep["meta"] = {
        "machine": pe["machine"],
        "arch_name": "x86_64 (64-bit)" if pe["pe32plus"] else "x86 (32-bit)",
        "pe32plus": pe["pe32plus"],
        "imagebase": f"0x{pe['imagebase']:x}",
        "imports": sum(len(i["functions"]) for i in pe["imports"]),
        "exports": len(pe["exports"]),
        "dotnet": pe["dotnet"],
        "electron": pe["electron"],
        "sections_count": len(pe["sections"]),
    }

    rep["packers"] = retool.detect_packers(data)
    for p in rep["packers"]:
        if p in retool.PACKER_HINTS:
            rep["packer_hints"][p] = retool.PACKER_HINTS[p]

    if pe["dotnet"]:
        rep["warnings"].append(".NET assembly detected (BSJB metadata) - dnSpy / ILSpy is the recommended decompiler.")
    if pe["electron"]:
        rep["warnings"].append("Electron framework markers identified - use Frida SSL monitor for API interception.")

    # sections
    for s in pe.get("sections", []):
        rep["sections"].append({
            "name": s["name"],
            "vsize": s["vsize"],
            "vsize_fmt": format_size(s["vsize"]),
            "va": f"0x{s['va']:x}",
            "rawsize": s["rawsize"],
            "rawsize_fmt": format_size(s["rawsize"]),
            "raw": f"0x{s['raw']:x}",
            "chars": f"0x{s['chars']:x}",
        })

    for imp in pe.get("imports", []):
        dll_name = imp.get("dll", "")
        funcs = imp.get("functions", [])
        tagged_funcs = []
        for fn in funcs:
            tags = retool.tag_for(fn)
            tagged_funcs.append({"name": fn, "tags": tags})
        rep["imports"].append({
            "dll": dll_name,
            "count": len(funcs),
            "functions": tagged_funcs,
        })

    rep["exports"] = pe.get("exports", [])

    strings = retool.extract_strings(data, 4)
    rep["counts"]["total_strings"] = len(strings)

    interesting = [(o, e, s) for o, e, s in strings
                   if retool.classify(s) or retool.FAILURE_WORDS.search(s) or retool.SUCCESS_WORDS.search(s)]

    rep["strings"] = [{
        "offset": f"0x{o:x}",
        "raw_offset": o,
        "encoding": e,
        "tags": ",".join(retool.classify(s)) or ("FAIL" if retool.FAILURE_WORDS.search(s) else "OK" if retool.SUCCESS_WORDS.search(s) else ""),
        "string": s
    } for o, e, s in interesting]

    rep["candidates"] = retool.find_candidates(data, pe, strings)
    rep["hook_code"] = retool.gen_monitor_js(pe)
    return rep


INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>bobbypin // binary analysis & patch cockpit</title>
  <link rel="icon" type="image/svg+xml" href="/logo.svg">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Outfit:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-canvas: #000000;
      --bg-panel: #0a0a0a;
      --bg-card: #121212;
      --bg-card-hover: #1c1c1c;
      --bg-input: #050505;
      --border-subtle: #262626;
      --border-medium: #404040;
      --border-glow: rgba(255, 255, 255, 0.25);
      --accent-white: #ffffff;
      --accent-silver: #e4e4e7;
      --accent-gray: #a1a1aa;
      --accent-darkgray: #27272a;
      --text-main: #ffffff;
      --text-muted: #d4d4d8;
      --text-dim: #71717a;
      --radius-sm: 6px;
      --radius-md: 10px;
      --radius-lg: 14px;
      --font-ui: 'Outfit', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      --font-mono: 'JetBrains Mono', 'Fira Code', Menlo, Monaco, monospace;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    
    body {
      font-family: var(--font-ui);
      background: var(--bg-canvas);
      background-image: 
        radial-gradient(circle at 50% 0%, rgba(255, 255, 255, 0.05) 0%, transparent 60%),
        linear-gradient(rgba(255, 255, 255, 0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255, 255, 255, 0.03) 1px, transparent 1px);
      background-size: 100% 100%, 28px 28px, 28px 28px;
      color: var(--text-main);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
    }

    header {
      background: rgba(10, 10, 10, 0.9);
      backdrop-filter: blur(14px);
      -webkit-backdrop-filter: blur(14px);
      border-bottom: 1px solid var(--border-subtle);
      position: sticky;
      top: 0;
      z-index: 100;
      padding: 12px 24px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.7);
    }

    .brand-group {
      display: flex;
      align-items: center;
      gap: 16px;
    }

    .logo-container {
      display: flex;
      align-items: center;
      gap: 12px;
      text-decoration: none;
    }

    .logo-badge-icon {
      width: 40px;
      height: 40px;
      border-radius: 10px;
      background: #141414;
      border: 1px solid #383838;
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 0 16px rgba(255, 255, 255, 0.15);
      transition: all 0.25s ease;
      overflow: hidden;
    }
    .logo-container:hover .logo-badge-icon {
      border-color: #ffffff;
      box-shadow: 0 0 24px rgba(255, 255, 255, 0.4);
      transform: scale(1.06) rotate(3deg);
    }

    .logo-title {
      font-size: 21px;
      font-weight: 800;
      letter-spacing: -0.5px;
      background: linear-gradient(90deg, #ffffff 60%, #a1a1aa 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .logo-badge {
      font-family: var(--font-mono);
      font-size: 11px;
      font-weight: 600;
      color: #ffffff;
      background: #1c1c1c;
      border: 1px solid var(--border-medium);
      padding: 2px 8px;
      border-radius: 12px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .author-badge {
      font-family: var(--font-mono);
      font-size: 12px;
      font-weight: 600;
      color: #ffffff;
      background: #141414;
      border: 1px solid #333333;
      padding: 4px 12px;
      border-radius: 20px;
      display: flex;
      align-items: center;
      gap: 8px;
      box-shadow: 0 0 10px rgba(255, 255, 255, 0.05);
      transition: all 0.2s ease;
    }
    .author-badge:hover {
      background: #202020;
      border-color: #555555;
      box-shadow: 0 0 14px rgba(255, 255, 255, 0.15);
    }
    .author-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: #ffffff;
      box-shadow: 0 0 8px #ffffff;
      animation: pulse 2s infinite;
    }

    @keyframes pulse {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.35; transform: scale(0.85); }
    }

    .header-actions {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    main {
      flex: 1;
      max-width: 1380px;
      width: 100%;
      margin: 0 auto;
      padding: 28px 24px;
      display: flex;
      flex-direction: column;
      gap: 24px;
    }

    .drop-hero {
      background: var(--bg-panel);
      border: 2px dashed var(--border-medium);
      border-radius: var(--radius-lg);
      padding: 44px 28px;
      text-align: center;
      cursor: pointer;
      position: relative;
      overflow: hidden;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      box-shadow: 0 8px 30px rgba(0, 0, 0, 0.6);
    }
    .drop-hero:hover {
      border-color: #ffffff;
      background: #101010;
      box-shadow: 0 12px 40px rgba(255, 255, 255, 0.1);
      transform: translateY(-2px);
    }
    .drop-hero.dragover {
      border-color: #ffffff;
      background: #171717;
      box-shadow: 0 0 50px rgba(255, 255, 255, 0.2);
      transform: scale(1.01);
    }

    .drop-icon-wrap {
      width: 64px;
      height: 64px;
      margin: 0 auto 16px;
      border-radius: 16px;
      background: #181818;
      border: 1px solid var(--border-medium);
      display: flex;
      align-items: center;
      justify-content: center;
      color: #ffffff;
      font-size: 28px;
      transition: all 0.3s ease;
    }
    .drop-hero:hover .drop-icon-wrap {
      transform: scale(1.1);
      background: #242424;
      border-color: #ffffff;
    }

    .drop-title {
      font-size: 20px;
      font-weight: 600;
      color: #ffffff;
      margin-bottom: 6px;
    }

    .drop-subtitle {
      font-size: 14px;
      color: var(--text-muted);
      margin-bottom: 18px;
    }

    .format-pills {
      display: flex;
      justify-content: center;
      gap: 8px;
      flex-wrap: wrap;
    }

    .pill {
      font-family: var(--font-mono);
      font-size: 11px;
      font-weight: 600;
      padding: 4px 10px;
      border-radius: 6px;
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      color: var(--text-muted);
    }

    .btn {
      font-family: var(--font-ui);
      font-size: 13px;
      font-weight: 600;
      padding: 8px 16px;
      border-radius: var(--radius-sm);
      border: none;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      text-decoration: none;
      user-select: none;
    }

    .btn-primary {
      background: #ffffff;
      color: #000000;
      box-shadow: 0 4px 14px rgba(255, 255, 255, 0.2);
    }
    .btn-primary:hover {
      background: #e4e4e7;
      box-shadow: 0 6px 20px rgba(255, 255, 255, 0.35);
      transform: translateY(-1px);
    }

    .btn-emerald {
      background: #27272a;
      border: 1px solid #52525b;
      color: #ffffff;
    }
    .btn-emerald:hover {
      background: #3f3f46;
      border-color: #ffffff;
      box-shadow: 0 4px 14px rgba(255, 255, 255, 0.15);
      transform: translateY(-1px);
    }

    .btn-amber {
      background: #1f1f23;
      border: 1px solid #404040;
      color: #e4e4e7;
    }
    .btn-amber:hover {
      background: #2d2d32;
      border-color: #71717a;
      transform: translateY(-1px);
    }

    .btn-secondary {
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      color: var(--text-main);
    }
    .btn-secondary:hover {
      background: var(--bg-card-hover);
      border-color: #ffffff;
      color: #ffffff;
      transform: translateY(-1px);
    }

    .btn-sm {
      padding: 5px 10px;
      font-size: 12px;
      border-radius: 4px;
    }

    #status-bar {
      display: none;
      background: var(--bg-panel);
      border: 1px solid var(--border-medium);
      border-radius: var(--radius-md);
      padding: 14px 20px;
      align-items: center;
      gap: 14px;
      font-size: 14px;
      animation: fadeIn 0.3s ease;
    }
    .spinner {
      width: 20px;
      height: 20px;
      border: 2px solid rgba(255, 255, 255, 0.15);
      border-top-color: #ffffff;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }

    #cockpit {
      display: none;
      flex-direction: column;
      gap: 20px;
      animation: fadeIn 0.4s ease;
    }

    .file-banner {
      background: var(--bg-panel);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-lg);
      padding: 20px 24px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 16px;
      box-shadow: 0 4px 24px rgba(0, 0, 0, 0.6);
    }
    .banner-left {
      display: flex;
      align-items: center;
      gap: 16px;
    }
    .banner-icon {
      width: 48px;
      height: 48px;
      border-radius: 12px;
      background: #181818;
      border: 1px solid var(--border-medium);
      display: flex;
      align-items: center;
      justify-content: center;
      color: #ffffff;
      font-size: 20px;
      font-weight: 700;
      font-family: var(--font-mono);
    }
    .banner-details h2 {
      font-size: 18px;
      font-weight: 700;
      color: #ffffff;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .banner-hashes {
      display: flex;
      gap: 16px;
      font-family: var(--font-mono);
      font-size: 12px;
      color: var(--text-dim);
      margin-top: 4px;
    }
    .hash-item {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      cursor: pointer;
      padding: 2px 6px;
      border-radius: 4px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid transparent;
      transition: all 0.15s ease;
    }
    .hash-item:hover {
      background: rgba(255, 255, 255, 0.1);
      border-color: #555555;
      color: #ffffff;
    }

    .cockpit-tabs {
      display: flex;
      gap: 8px;
      border-bottom: 1px solid var(--border-subtle);
      padding-bottom: 8px;
      overflow-x: auto;
    }
    .tab-btn {
      font-family: var(--font-ui);
      font-size: 14px;
      font-weight: 600;
      background: transparent;
      border: none;
      color: var(--text-dim);
      padding: 8px 16px;
      border-radius: var(--radius-sm);
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      transition: all 0.2s ease;
      white-space: nowrap;
    }
    .tab-btn:hover {
      color: var(--text-main);
      background: rgba(255, 255, 255, 0.05);
    }
    .tab-btn.active {
      color: #000000;
      background: #ffffff;
      box-shadow: 0 0 16px rgba(255, 255, 255, 0.2);
    }
    .tab-badge {
      font-family: var(--font-mono);
      font-size: 11px;
      background: rgba(255, 255, 255, 0.12);
      padding: 1px 6px;
      border-radius: 10px;
      color: inherit;
    }
    .tab-btn.active .tab-badge {
      background: #000000;
      color: #ffffff;
    }

    .tab-pane {
      display: none;
      flex-direction: column;
      gap: 20px;
      animation: fadeIn 0.25s ease;
    }
    .tab-pane.active {
      display: flex;
    }

    .grid-4 {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
    }
    .grid-2 {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
      gap: 16px;
    }

    .stat-card {
      background: var(--bg-panel);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      padding: 18px 20px;
      display: flex;
      flex-direction: column;
      gap: 6px;
      transition: all 0.2s ease;
    }
    .stat-card:hover {
      border-color: var(--border-medium);
      transform: translateY(-2px);
    }
    .stat-label {
      font-size: 12px;
      font-weight: 600;
      color: var(--text-dim);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .stat-value {
      font-family: var(--font-mono);
      font-size: 20px;
      font-weight: 700;
      color: #ffffff;
    }
    .stat-sub {
      font-size: 12px;
      color: var(--text-muted);
    }

    .alert-box {
      border-radius: var(--radius-md);
      padding: 14px 18px;
      display: flex;
      align-items: flex-start;
      gap: 12px;
      font-size: 13.5px;
    }
    .alert-warn {
      background: #141414;
      border: 1px solid #333333;
      color: #d4d4d8;
    }
    .alert-pack {
      background: #18181b;
      border: 1px solid #3f3f46;
      color: #f4f4f5;
    }

    .section-map-wrap {
      background: var(--bg-panel);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      padding: 18px 20px;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }
    .section-bars {
      display: flex;
      height: 24px;
      border-radius: 6px;
      overflow: hidden;
      background: #000000;
      border: 1px solid var(--border-subtle);
    }
    .sec-bar {
      height: 100%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: var(--font-mono);
      font-size: 10px;
      font-weight: 700;
      color: #000000;
      padding: 0 4px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      transition: all 0.2s ease;
      cursor: pointer;
    }
    .sec-bar:hover {
      filter: brightness(1.25);
    }

    .candidate-card {
      background: var(--bg-panel);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 14px;
      transition: all 0.2s ease;
    }
    .candidate-card:hover {
      border-color: var(--border-medium);
      box-shadow: 0 6px 20px rgba(0, 0, 0, 0.7);
    }
    .candidate-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }
    .candidate-kind {
      font-family: var(--font-mono);
      font-size: 12px;
      font-weight: 700;
      padding: 3px 10px;
      border-radius: 6px;
      background: #27272a;
      border: 1px solid #52525b;
      color: #ffffff;
    }
    .candidate-kind.ok {
      background: #ffffff;
      border-color: #ffffff;
      color: #000000;
    }
    .candidate-string {
      font-family: var(--font-mono);
      font-size: 13px;
      color: #ffffff;
      background: var(--bg-input);
      padding: 8px 12px;
      border-radius: 6px;
      border: 1px solid var(--border-subtle);
      word-break: break-all;
    }
    .candidate-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 16px;
      font-family: var(--font-mono);
      font-size: 12px;
      color: var(--text-muted);
    }
    .candidate-meta code {
      color: #ffffff;
      font-weight: 600;
    }
    .candidate-actions {
      display: flex;
      gap: 10px;
      align-items: center;
    }

    .filter-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
      background: var(--bg-panel);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      padding: 12px 16px;
    }
    .search-input {
      background: var(--bg-input);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      color: var(--text-main);
      font-family: var(--font-mono);
      font-size: 13px;
      padding: 8px 12px;
      width: 280px;
      outline: none;
      transition: all 0.2s ease;
    }
    .search-input:focus {
      border-color: #ffffff;
      box-shadow: 0 0 12px rgba(255, 255, 255, 0.2);
    }
    .tag-filters {
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
    }
    .filter-chip {
      font-family: var(--font-mono);
      font-size: 11px;
      font-weight: 600;
      padding: 4px 10px;
      border-radius: 12px;
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      color: var(--text-dim);
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .filter-chip:hover {
      color: #ffffff;
      border-color: #ffffff;
    }
    .filter-chip.active {
      background: #ffffff;
      border-color: #ffffff;
      color: #000000;
    }

    /* tables + strings grid */
    .table-card {
      background: var(--bg-panel);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      overflow: hidden;
    }
    .table-scroll {
      max-height: 520px;
      overflow-y: auto;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      text-align: left;
    }
    th {
      background: #111111;
      color: var(--text-dim);
      font-family: var(--font-mono);
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      padding: 10px 14px;
      border-bottom: 1px solid var(--border-subtle);
      position: sticky;
      top: 0;
      z-index: 10;
    }
    td {
      padding: 8px 14px;
      border-bottom: 1px solid #1a1a1a;
      font-family: var(--font-mono);
      color: var(--text-main);
    }
    tr:hover td {
      background: #161616;
    }
    .tag-badge {
      display: inline-block;
      font-size: 10px;
      font-weight: 700;
      padding: 2px 6px;
      border-radius: 4px;
      background: #27272a;
      border: 1px solid #3f3f46;
      color: #ffffff;
    }
    .tag-badge.AUTH { background: #3f3f46; border-color: #71717a; color: #ffffff; }
    .tag-badge.URL { background: #27272a; border-color: #52525b; color: #e4e4e7; }
    .tag-badge.FAIL { background: #1c1917; border-color: #44403c; color: #d6d3d1; }
    .tag-badge.OK { background: #ffffff; border-color: #ffffff; color: #000000; }

    .code-box-wrap {
      background: #050505;
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      overflow: hidden;
    }
    .code-box-header {
      background: #111111;
      border-bottom: 1px solid var(--border-subtle);
      padding: 10px 16px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .code-box-title {
      font-family: var(--font-mono);
      font-size: 12px;
      color: #ffffff;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    pre.code-content {
      padding: 16px;
      font-family: var(--font-mono);
      font-size: 12px;
      color: #e4e4e7;
      line-height: 1.6;
      max-height: 480px;
      overflow-y: auto;
      white-space: pre-wrap;
    }

    .cli-command-box {
      background: var(--bg-input);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      padding: 14px 18px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      font-family: var(--font-mono);
      font-size: 13px;
      color: #ffffff;
    }

    #toast {
      position: fixed;
      bottom: 24px;
      right: 24px;
      background: #18181b;
      border: 1px solid #52525b;
      box-shadow: 0 8px 30px rgba(0, 0, 0, 0.8);
      color: #ffffff;
      padding: 12px 20px;
      border-radius: var(--radius-md);
      font-family: var(--font-ui);
      font-size: 13.5px;
      font-weight: 500;
      display: flex;
      align-items: center;
      gap: 10px;
      z-index: 1000;
      opacity: 0;
      pointer-events: none;
      transform: translateY(12px);
      transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
    }
    #toast.show {
      opacity: 1;
      pointer-events: auto;
      transform: translateY(0);
    }

    footer {
      border-top: 1px solid var(--border-subtle);
      padding: 16px 24px;
      font-size: 12px;
      color: var(--text-dim);
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 16px;
      background: rgba(10, 10, 10, 0.95);
      margin-top: auto;
    }

    .footer-left {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .footer-brand {
      color: #ffffff;
      font-weight: 700;
      font-family: var(--font-mono);
    }
    .footer-sep {
      color: var(--border-medium);
    }
    .footer-desc {
      color: var(--text-dim);
    }

    .footer-socials {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }

    .social-link {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      font-family: var(--font-mono);
      font-size: 11.5px;
      font-weight: 500;
      color: #d4d4d8;
      background: #141414;
      border: 1px solid #27272a;
      padding: 5px 12px;
      border-radius: 20px;
      text-decoration: none;
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      cursor: pointer;
      user-select: none;
    }
    .social-link:hover {
      color: #ffffff;
      background: #222222;
      border-color: #52525b;
      box-shadow: 0 0 12px rgba(255, 255, 255, 0.15);
      transform: translateY(-1px);
    }
    .social-link svg {
      flex-shrink: 0;
    }

    .footer-author {
      font-family: var(--font-mono);
      font-size: 12px;
      color: var(--text-dim);
    }

    .wf-overlay {
      display: none;
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.72);
      backdrop-filter: blur(4px);
      z-index: 900;
      align-items: flex-start;
      justify-content: center;
      padding: 64px 20px;
    }
    .wf-overlay.open { display: flex; }
    .wf-modal {
      background: var(--bg-panel);
      border: 1px solid var(--border-medium);
      border-radius: var(--radius-lg);
      max-width: 660px;
      width: 100%;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.8);
      overflow: hidden;
      animation: fadeIn 0.2s ease;
    }
    .wf-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 14px 18px;
      border-bottom: 1px solid var(--border-subtle);
      background: #111111;
      font-weight: 700;
      color: #ffffff;
      font-size: 15px;
    }
    .wf-body {
      padding: 20px;
      font-family: var(--font-mono);
      font-size: 12.5px;
      line-height: 1.55;
      color: var(--text-muted);
      max-height: 68vh;
      overflow-y: auto;
    }
    .wf-step { margin-bottom: 12px; padding-left: 28px; position: relative; }
    .wf-num {
      position: absolute;
      left: 0;
      top: 1px;
      width: 19px;
      height: 19px;
      border-radius: 50%;
      background: #ffffff;
      color: #000000;
      font-size: 11px;
      font-weight: 700;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .wf-branch {
      margin: 4px 0 4px 28px;
      padding-left: 14px;
      border-left: 1px dashed var(--border-medium);
    }
    .wf-code {
      background: #050505;
      border: 1px solid var(--border-subtle);
      border-radius: 4px;
      padding: 1px 5px;
      color: #ffffff;
      font-size: 11.5px;
    }
    .wf-note {
      margin: 8px 0 0;
      padding: 8px 10px;
      border: 1px solid #3f3f46;
      border-radius: 6px;
      background: #18181b;
      color: #d4d4d8;
      font-size: 11.5px;
    }
    .wf-glossary {
      margin-top: 16px;
      padding: 12px 14px;
      border: 1px solid var(--border-subtle);
      border-radius: 8px;
      background: #0d0d0d;
    }
    .wf-glossary h4 {
      margin: 0 0 8px;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--text-dim);
    }
    .wf-glossary div { margin-bottom: 5px; }
    .wf-ok { color: #ffffff; background: #27272a; border: 1px solid #52525b; border-radius: 4px; padding: 0 5px; font-size: 11px; font-weight: 700; }
    .wf-fail { color: #000000; background: #ffffff; border: 1px solid #ffffff; border-radius: 4px; padding: 0 5px; font-size: 11px; font-weight: 700; }

    /* small screens */
    @media (max-width: 900px) {
      header { flex-direction: column; gap: 12px; align-items: flex-start; }
      .banner-hashes { flex-direction: column; gap: 4px; }
      .search-input { width: 100%; }
      footer { flex-direction: column; gap: 12px; align-items: flex-start; }
    }
  </style>
</head>
<body>

  <header>
    <div class="brand-group">
      <a href="/" class="logo-container">
        <div class="logo-badge-icon" title="bobbypin">
          <svg viewBox="0 0 512 512" width="28" height="28">
            <g transform="translate(256, 256) rotate(-35) translate(-256, -256)">
              <path d="M 400 200 L 140 200 C 90 200, 60 230, 60 260 C 60 290, 90 320, 140 320 L 175 320 C 195 320, 205 270, 225 270 C 245 270, 255 320, 275 320 C 295 320, 305 270, 325 270 C 345 270, 355 320, 375 320 L 410 335" 
                    fill="none" stroke="#ffffff" stroke-width="36" stroke-linecap="round" stroke-linejoin="round"/>
              <circle cx="402" cy="200" r="24" fill="#ffffff"/>
              <circle cx="412" cy="336" r="24" fill="#ffffff"/>
            </g>
          </svg>
        </div>
        <div>
          <div class="logo-title">bobbypin</div>
        </div>
      </a>
      <span class="logo-badge">v2.0 PRO</span>
      <div class="author-badge" title="Developer Signature">
        <div class="author-dot"></div>
        <span>coded by decay.root.0x00</span>
      </div>
    </div>
    <div class="header-actions">
      <button class="btn btn-secondary btn-sm" id="btn-workflow" onclick="toggleWorkflow()">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
        Workflow
      </button>
      <button class="btn btn-secondary btn-sm" id="btn-reset" onclick="resetUI()" style="display:none;">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>
        New Target
      </button>
    </div>
  </header>

  <main>
    <div class="drop-hero" id="dropzone">
      <input type="file" id="file-input" style="display:none;">
      <div class="drop-icon-wrap">
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
          <polyline points="17 8 12 3 7 8"/>
          <line x1="12" y1="3" x2="12" y2="15"/>
        </svg>
      </div>
      <h2 class="drop-title">Select or Drag Target Binary</h2>
      <p class="drop-subtitle">Drop Windows Executable, DLL, Electron ASAR, Java JAR, or PyInstaller package</p>
      <div class="format-pills">
        <span class="pill">.EXE (PE32/PE32+)</span>
        <span class="pill">.DLL</span>
        <span class="pill">.ASAR (Electron)</span>
        <span class="pill">.JAR (Java)</span>
        <span class="pill">PyInstaller Bundle</span>
      </div>
    </div>

    <div id="status-bar">
      <div class="spinner"></div>
      <span id="status-text">Analyzing binary structure...</span>
    </div>

    <div id="cockpit">
      <div class="file-banner">
        <div class="banner-left">
          <div class="banner-icon" id="target-icon">PE</div>
          <div class="banner-details">
            <h2><span id="target-filename">target.exe</span> <span class="logo-badge" id="target-kind-badge">PE</span></h2>
            <div class="banner-hashes">
              <div class="hash-item" onclick="copyText(CURRENT_DATA.hashes.sha256, 'SHA-256 copied!')">
                <span>SHA256:</span> <code id="hash-sha256">...</code>
              </div>
              <div class="hash-item" onclick="copyText(CURRENT_DATA.hashes.md5, 'MD5 copied!')">
                <span>MD5:</span> <code id="hash-md5">...</code>
              </div>
            </div>
          </div>
        </div>
        <div class="banner-right">
          <button class="btn btn-primary" id="btn-download-hook" onclick="downloadHook()">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            Download hook.js
          </button>
        </div>
      </div>

      <div class="cockpit-tabs">
        <button class="tab-btn active" onclick="switchTab('overview')">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
          Triage Overview
        </button>
        <button class="tab-btn" onclick="switchTab('patches')">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
          Patch Console <span class="tab-badge" id="tab-badge-patches">0</span>
        </button>
        <button class="tab-btn" onclick="switchTab('strings')">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="4" y1="9" x2="20" y2="9"/><line x1="4" y1="15" x2="20" y2="15"/><line x1="10" y1="3" x2="8" y2="21"/><line x1="16" y1="3" x2="14" y2="21"/></svg>
          String Inspector <span class="tab-badge" id="tab-badge-strings">0</span>
        </button>
        <button class="tab-btn" onclick="switchTab('imports')">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>
          Imports & APIs <span class="tab-badge" id="tab-badge-imports">0</span>
        </button>
        <button class="tab-btn" onclick="switchTab('frida')">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
          Frida Monitor
        </button>
        <button class="tab-btn" id="tab-btn-extracted" onclick="switchTab('extracted')" style="display:none;">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
          Extracted Files <span class="tab-badge" id="tab-badge-extracted">0</span>
        </button>
      </div>

      <div class="tab-pane active" id="pane-overview">
        <div class="grid-4" id="stats-grid">
        </div>

        <div id="warnings-container"></div>

        <div class="section-map-wrap" id="section-map-wrap" style="display:none;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <span class="stat-label">PE Section Memory Map</span>
            <span class="pill" id="section-count-pill">0 sections</span>
          </div>
          <div class="section-bars" id="section-bars"></div>
          <div class="table-card" style="margin-top:8px;">
            <table>
              <thead>
                <tr>
                  <th>Section</th>
                  <th>Virtual Address</th>
                  <th>Virtual Size</th>
                  <th>Raw Offset</th>
                  <th>Raw Size</th>
                  <th>Characteristics</th>
                </tr>
              </thead>
              <tbody id="section-table-body"></tbody>
            </table>
          </div>
        </div>
      </div>

      <div class="tab-pane" id="pane-patches">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div>
            <h3 style="font-size:16px; font-weight:700;">Conditional Branch Patch Candidates</h3>
            <p style="font-size:13px; color:var(--text-muted);">Detected jumps referencing authentication/license failure logic.</p>
          </div>
        </div>
        <div id="patch-candidates-list" style="display:flex; flex-direction:column; gap:12px;"></div>
      </div>

      <div class="tab-pane" id="pane-strings">
        <div class="filter-bar">
          <input type="text" class="search-input" id="string-query" placeholder="Filter strings (regex/fuzzy)..." oninput="filterStrings()">
          <div class="tag-filters">
            <span class="filter-chip active" onclick="setTagFilter('ALL')">ALL</span>
            <span class="filter-chip" onclick="setTagFilter('AUTH')">AUTH</span>
            <span class="filter-chip" onclick="setTagFilter('URL')">URL</span>
            <span class="filter-chip" onclick="setTagFilter('FAIL')">FAIL</span>
            <span class="filter-chip" onclick="setTagFilter('OK')">OK</span>
          </div>
          <button class="btn btn-secondary btn-sm" onclick="exportStrings()">Export JSON</button>
        </div>
        <div class="table-card">
          <div class="table-scroll">
            <table>
              <thead>
                <tr>
                  <th style="width:120px;">Offset</th>
                  <th style="width:80px;">Encoding</th>
                  <th style="width:100px;">Tags</th>
                  <th>String Literal</th>
                  <th style="width:60px;">Action</th>
                </tr>
              </thead>
              <tbody id="strings-table-body"></tbody>
            </table>
          </div>
        </div>
      </div>

      <div class="tab-pane" id="pane-imports">
        <div class="filter-bar">
          <input type="text" class="search-input" id="import-query" placeholder="Filter imported DLLs / APIs..." oninput="filterImports()">
          <span style="font-size:12px; color:var(--text-muted);" id="import-summary-text"></span>
        </div>
        <div id="imports-container" style="display:flex; flex-direction:column; gap:12px;"></div>
      </div>

      <div class="tab-pane" id="pane-frida">
        <div class="cli-command-box">
          <span id="frida-cli-text">frida -f target.exe -l hook.js</span>
          <button class="btn btn-secondary btn-sm" onclick="copyFridaCli()">Copy Command</button>
        </div>
        <div class="code-box-wrap">
          <div class="code-box-header">
            <div class="code-box-title">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
              <span>hook.js (Dynamic SSL & WinAPI Interceptor)</span>
            </div>
            <button class="btn btn-secondary btn-sm" onclick="copyText(CURRENT_DATA.hook_code, 'Hook script copied!')">Copy Script</button>
          </div>
          <pre class="code-content" id="frida-code-content">// Loading hook generator...</pre>
        </div>
      </div>

      <div class="tab-pane" id="pane-extracted">
        <div class="table-card">
          <div class="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Entry Name</th>
                  <th style="width:120px;">Size</th>
                </tr>
              </thead>
              <tbody id="extracted-table-body"></tbody>
            </table>
          </div>
        </div>
      </div>

    </div>
  </main>

  <div class="wf-overlay" id="wf-overlay" onclick="if(event.target===this)closeWorkflow()">
    <div class="wf-modal">
      <div class="wf-head">
        <span>Patch Workflow</span>
        <button class="btn btn-secondary btn-sm" onclick="closeWorkflow()">Close</button>
      </div>
      <div class="wf-body">
        <div class="wf-step"><span class="wf-num">1</span>
          <div><b style="color:#fff;">Make a baseline &mdash; do not skip this.</b></div>
          <div>Put the original exe in its own folder and run it once. Try to log in / activate with <b style="color:#fff;">deliberately wrong</b> input and write down the <b style="color:#fff;">exact</b> failure text you see (e.g. <i>"License invalid"</i>). If you have working input, run that too and write down the success text (e.g. <i>"Logged In"</i>).</div>
          <div class="wf-note"><b>Why:</b> every patch below is found by locating these two messages inside the file. Without them you're guessing in the dark.</div>
        </div>
        <div class="wf-step"><span class="wf-num">2</span>
          <div><b style="color:#fff;">String Inspector</b> tab &rarr; find your failure message.</div>
          <div>Type <b style="color:#fff;">one unusual word</b> from it into the filter box. Good: <span class="wf-code">Blacklisted</span>, <span class="wf-code">subscription</span>. Bad: <span class="wf-code">failed</span> or <span class="wf-code">invalid</span> alone &mdash; too common, hundreds of rows.</div>
          <div>Find your message in the <b style="color:#fff;">String Literal</b> column, then copy the hex number from the <b style="color:#fff;">Offset</b> column, e.g. <span class="wf-code">0x4b0c6</span>. That number = byte position of that text inside the file.</div>
        </div>
        <div class="wf-step"><span class="wf-num">3</span>
          <div><b style="color:#fff;">Patch Console</b> tab &rarr; find the matching card.</div>
          <div>Each card is one <b style="color:#fff;">disassembler-verified</b> conditional jump that reads a tagged message string:</div>
          <div style="margin:6px 0;">&bull; <span class="wf-fail">FAIL</span> = jump near a <b>failure</b> message &nbsp;/&nbsp; <span class="wf-ok">OK</span> = jump near a <b>success</b> message<br>
          &bull; <b style="color:#fff;">String Ref</b> = where the code grabs that text<br>
          &bull; <b style="color:#fff;">Branch Offset</b> = exact file position of the jump instruction itself</div>
          <div>Pick card(s) whose <span class="wf-code">String Ref</span> matches your step-2 offset (first 4&ndash;5 hex digits are enough). Start with <span class="wf-fail">FAIL</span> cards.</div>
          <div class="wf-note"><b>Skip on sight</b> any card quoting library internals: <span class="wf-code">schannel:</span>, <span class="wf-code">SEC_E_</span>, <span class="wf-code">FTP:</span>, <span class="wf-code">invalid string:</span>, <span class="wf-code">invalid distance...</span>. Those belong to Windows/curl/zlib, not to the app. Patching them does nothing, ever.</div>
        </div>
        <div class="wf-step"><span class="wf-num">4</span>
          <div><b style="color:#fff;">Sanity check &mdash; optional, candidates are already verified.</b></div>
          <div>Every card was produced by decoding real instructions (Capstone disassembler), so the <b style="color:#fff;">Branch Offset</b> is guaranteed to be a true instruction boundary and a genuine conditional jump &mdash; not a random byte that happens to look like one. The card's <span class="wf-code">bytes</span> field shows its exact opcode.</div>
          <div>Want to see it yourself?</div>
          <div>In a terminal run:<br><span class="wf-code">xxd -s 0x&lt;Branch Offset&gt; -l 8 "file.exe"</span>&nbsp; e.g. <span class="wf-code">xxd -s 0x4b0c6 -l 8 "Temp Spoof.exe"</span></div>
          <div>(<span class="wf-code">-s</span> = start position, <span class="wf-code">-l</span> = how many bytes to show)</div>
          <div>The first byte(s) will be a conditional-jump opcode:</div>
          <div style="margin:4px 0;">&bull; <span class="wf-code">74</span>=je, <span class="wf-code">75</span>=jne, <span class="wf-code">78</span>=js, <span class="wf-code">79</span>=jns... (short form)<br>&bull; <span class="wf-code">0f 84</span>, <span class="wf-code">0f 85</span>, ... (long form) &mdash; all of these flip and NOP safely.</div>
          <div class="wf-note">On Windows instead: open the exe in HxD (free hex editor) &rarr; Ctrl+G &rarr; enter the same offset &rarr; read the first byte.</div>
        </div>
        <div class="wf-step"><span class="wf-num">5</span>
          <div><b style="color:#fff;">NOP Jump</b> &mdash; attempt #1.</div>
          <div>What it does: overwrites the jump with <span class="wf-code">0x90</span>, the CPU's "do nothing" instruction, so that code path can never be taken.</div>
          <div>Click <b style="color:#fff;">NOP Jump</b> &rarr; your browser downloads <span class="wf-code">&lt;name&gt;_patched.exe</span> (check Downloads). The original file is never modified.</div>
          <div>Run the patched exe and enter <b style="color:#fff;">wrong</b> credentials on purpose. Three possible outcomes:</div>
          <div class="wf-branch">&#10003; now behaves like logged-in/unlocked &rarr; <b style="color:#fff;">it works</b>, jump to step 9<br>&rarr; behaves exactly like before &rarr; this branch wasn't the decision &rarr; go to step 6<br>&#10007; crashes or acts broken &rarr; delete the patched file, use step 6 instead</div>
        </div>
        <div class="wf-step"><span class="wf-num">6</span>
          <div><b style="color:#fff;">Invert / Flip Branch</b> &mdash; attempt #2, same card.</div>
          <div>What it does: swaps the condition (<span class="wf-code">74&harr;75</span>, <span class="wf-code">0F 84&harr;0F 85</span>) so "jump if equal" becomes "jump if not equal" and the program walks the opposite path.</div>
          <div>Test again with wrong input.</div>
          <div class="wf-branch">&#10003; works &rarr; step 9<br>&rarr; still nothing &rarr; next candidate card (back to step 3), or step 7 if no cards remain</div>
        </div>
        <div class="wf-step"><span class="wf-num">7</span>
          <div><b style="color:#fff;">Try the success side.</b></div>
          <div>Repeat steps 2&ndash;6, but search for the <b style="color:#fff;">success</b> message and use <span class="wf-ok">OK</span>-kind cards. The goal flips too: force the program <i>into</i> the success path instead of away from the fail path.</div>
        </div>
        <div class="wf-step"><span class="wf-num">8</span>
          <div><b style="color:#fff;">Still stuck? Watch it live (Frida).</b></div>
          <div>Some programs check several things or hide the real decision. See it happen in real time:</div>
          <div>1. <b style="color:#fff;">Frida Monitor</b> tab &rarr; <b style="color:#fff;">Download hook.js</b><br>
          2. Terminal: <span class="wf-code">frida -f "program.exe" -l hook.js</span><br>
          3. Log in while it runs &mdash; you'll see file / HTTP / API calls scroll by live.<br>
          4. Whatever fires immediately <i>before</i> your failure message appears = the real target. Note it and go back to step 3.</div>
          <div class="wf-note">First time? Install Frida with <span class="wf-code">pip install frida-tools</span>.</div>
        </div>
        <div class="wf-step"><span class="wf-num">9</span>
          <div><b style="color:#fff;">Write it down.</b></div>
          <div>Record: target name, Branch Offset, mode used (NOP or Flip), and what happened. Keep the untouched original forever as your backup &mdash; patched files are throwaway test copies only. Never distribute them outside testing.</div>
        </div>

        <div class="wf-glossary">
          <h4>Cheat sheet</h4>
          <div><span class="wf-code">0x4b0c6</span> &mdash; an offset: a byte position inside the file, counted in hex.</div>
          <div><span class="wf-code">0x90 (NOP)</span> &mdash; CPU instruction meaning "do nothing". Used to erase jumps.</div>
          <div><span class="wf-code">74 / 75</span> &mdash; je / jne: "jump if equal" / "jump if not equal" (short form).</div>
          <div><span class="wf-code">0F 84 / 0F 85</span> &mdash; same two jumps, long form, for far distances.</div>
          <div><span class="wf-fail">FAIL</span>/<span class="wf-ok">OK</span> badge &mdash; which kind of message (failure/success) the branch guards.</div>
          <div><b style="color:#fff;">String Ref</b> vs <b style="color:#fff;">Branch Offset</b> &mdash; where code reads the text vs where the actual jump instruction sits.</div>
        </div>
      </div>
    </div>
  </div>

  <div id="toast">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 14 14"/></svg>
    <span id="toast-msg">Operation completed</span>
  </div>

  <footer>
    <div class="footer-left">
      <span class="footer-brand">bobbypin</span>
      <span class="footer-sep">•</span>
      <span class="footer-desc">Binary Analysis & Patch Cockpit</span>
    </div>

    <div class="footer-socials">
      <a href="https://github.com/DecayRoot0x00" target="_blank" rel="noopener noreferrer" class="social-link" title="GitHub Profile">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
        <span>DecayRoot0x00</span>
      </a>

      <a href="https://x.com/DecayRoot0x00" target="_blank" rel="noopener noreferrer" class="social-link" title="X Profile">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>
        <span>@DecayRoot0x00</span>
      </a>

      <div class="social-link" onclick="copyText('decay.root.0x00', 'Discord handle copied!')" title="Discord (Click to Copy Handle)">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M20.317 4.37a19.791 19.791 0 00-4.885-1.515.074.074 0 00-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 00-5.487 0 12.64 12.64 0 00-.617-1.25.077.077 0 00-.079-.037A19.736 19.736 0 003.677 4.37a.07.07 0 00-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 00.031.057 19.9 19.9 0 005.993 3.03.078.078 0 00.084-.028c.462-.63.874-1.295 1.226-1.994.021-.041.001-.09-.041-.106a13.107 13.107 0 01-1.872-.892.077.077 0 01-.008-.128 10.2 10.2 0 00.372-.292.074.074 0 01.077-.01c3.929 1.793 8.18 1.793 12.061 0a.074.074 0 01.078.01c.12.098.246.198.373.292a.077.077 0 01-.006.127 12.299 12.299 0 01-1.873.893.077.077 0 00-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 00.084.028 19.839 19.839 0 006.002-3.03.077.077 0 00.032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 00-.031-.028zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/></svg>
        <span>@decay.root.0x00</span>
      </div>
    </div>

    <div class="footer-author">
      <span>coded by</span> <strong style="color:#ffffff;">decay.root.0x00</strong>
    </div>
  </footer>

  <script>
    // sign our work. if this shows up in someone else's build, ask them where it came from
    window.__BP_SIG = Object.freeze({
      tool: 'bobbypin',
      ver: '2.0 PRO',
      author: 'decay.root.0x00',
      gh: 'https://github.com/DecayRoot0x00',
      x: 'https://x.com/DecayRoot0x00'
    });
    console.log('%c bobbypin v2.0 PRO ', 'background:#ffffff;color:#000000;padding:4px 8px;border-radius:4px;font-weight:700;font-family:monospace');
    console.log(
      '%coriginal work by decay.root.0x00\n%cgithub.com/DecayRoot0x00  |  x.com/DecayRoot0x00  |  discord: decay.root.0x00\n\nif you did not get this from me, it is a stolen copy - and stolen copies still carry this signature.\ninspect window.__BP_SIG for the receipt.',
      'color:#e4e4e7;font-weight:600;',
      'color:#71717a;'
    );

    let CURRENT_DATA = null;
    let ACTIVE_TAG = 'ALL';
    let TOKEN = null;
    let FNAME = null;

    const $ = id => document.getElementById(id);
    const dropzone = $('dropzone');
    const fileInput = $('file-input');

    dropzone.onclick = () => fileInput.click();
    dropzone.ondragover = e => { e.preventDefault(); dropzone.classList.add('dragover'); };
    dropzone.ondragleave = () => dropzone.classList.remove('dragover');
    dropzone.ondrop = e => {
      e.preventDefault();
      dropzone.classList.remove('dragover');
      if (e.dataTransfer.files[0]) analyzeFile(e.dataTransfer.files[0]);
    };
    fileInput.onchange = e => {
      if (e.target.files[0]) analyzeFile(e.target.files[0]);
    };

    function showToast(msg) {
      const toast = $('toast');
      $('toast-msg').textContent = msg;
      toast.classList.add('show');
      setTimeout(() => toast.classList.remove('show'), 2600);
    }

    function copyText(txt, toastMsg = 'Copied to clipboard!') {
      navigator.clipboard.writeText(txt).then(() => showToast(toastMsg));
    }

    function copyFridaCli() {
      copyText($('frida-cli-text').textContent, 'CLI command copied!');
    }

    function resetUI() {
      CURRENT_DATA = null;
      TOKEN = null;
      FNAME = null;
      $('cockpit').style.display = 'none';
      $('status-bar').style.display = 'none';
      $('btn-reset').style.display = 'none';
      dropzone.style.display = 'block';
      fileInput.value = '';
    }

    async function analyzeFile(file) {
      FNAME = file.name;
      dropzone.style.display = 'none';
      $('cockpit').style.display = 'none';
      $('status-bar').style.display = 'flex';
      $('status-text').textContent = `Analyzing ${file.name} (${(file.size / 1024 / 1024).toFixed(2)} MB)...`;

      try {
        const res = await fetch('/api/analyze', {
          method: 'POST',
          headers: { 'X-Filename': file.name },
          body: file
        });
        const data = await res.json();
        if (data.error) {
          alert('Analysis Error: ' + data.error);
          resetUI();
          return;
        }
        TOKEN = data.token;
        CURRENT_DATA = data;
        renderCockpit(data);
        $('status-bar').style.display = 'none';
        $('cockpit').style.display = 'flex';
        $('btn-reset').style.display = 'inline-flex';
      } catch (err) {
        alert('Request failed: ' + err);
        resetUI();
      }
    }

    function switchTab(tabId) {
      document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      
      const targetBtn = Array.from(document.querySelectorAll('.tab-btn')).find(b => b.getAttribute('onclick').includes(tabId));
      if (targetBtn) targetBtn.classList.add('active');
      const pane = $('pane-' + tabId);
      if (pane) pane.classList.add('active');
    }

    const SEC_COLORS = ['#ffffff', '#e4e4e7', '#d4d4d8', '#a1a1aa', '#71717a', '#52525b', '#3f3f46']; // greys only so section names stay readable

    function renderCockpit(data) {
      // Banner
      $('target-kind-badge').textContent = data.kind.toUpperCase();
      $('target-filename').textContent = FNAME;
      $('target-icon').textContent = data.kind === 'pe' ? 'PE' : data.kind.toUpperCase().slice(0, 4);
      $('hash-sha256').textContent = data.hashes.sha256.slice(0, 16) + '...' + data.hashes.sha256.slice(-8);
      $('hash-md5').textContent = data.hashes.md5;
      $('frida-cli-text').textContent = `frida -f "${FNAME}" -l hook.js`;

      // Badges
      $('tab-badge-patches').textContent = data.candidates ? data.candidates.length : 0;
      $('tab-badge-strings').textContent = data.strings ? data.strings.length : 0;
      $('tab-badge-imports').textContent = data.imports ? data.imports.length : 0;

      // Extracted Tab visibility
      if (data.extracted && data.extracted.length > 0) {
        $('tab-btn-extracted').style.display = 'inline-flex';
        $('tab-badge-extracted').textContent = data.extracted.length;
        renderExtracted(data.extracted);
      } else {
        $('tab-btn-extracted').style.display = 'none';
      }

      // Stats Grid
      renderStats(data);

      // Warnings
      renderWarnings(data);

      // Sections Memory Map
      if (data.sections && data.sections.length > 0) {
        $('section-map-wrap').style.display = 'flex';
        $('section-count-pill').textContent = `${data.sections.length} sections`;
        renderSections(data.sections);
      } else {
        $('section-map-wrap').style.display = 'none';
      }

      // Patch Candidates
      renderPatches(data.candidates || []);

      // Strings Table
      filterStrings();

      // Imports
      renderImports(data.imports || []);

      // Frida Hook Code
      $('frida-code-content').textContent = data.hook_code || '// No dynamic hook generated for this format';
    }

    function renderStats(data) {
      let stats = [
        { label: 'Format / Kind', val: data.kind.toUpperCase(), sub: data.counts.formatted_size },
        { label: 'Strings', val: data.strings.length, sub: `${data.counts.total_strings || data.strings.length} indexed` },
      ];

      if (data.meta && data.meta.arch_name) {
        stats.push({ label: 'Architecture', val: data.meta.arch_name, sub: `Base: ${data.meta.imagebase}` });
        stats.push({ label: 'API Surface', val: `${data.meta.imports} Imp`, sub: `${data.meta.exports} Exports` });
      } else if (data.counts.entries) {
        stats.push({ label: 'Archive Entries', val: data.counts.entries, sub: 'Extracted components' });
      }

      const grid = $('stats-grid');
      grid.innerHTML = stats.map(s => `
        <div class="stat-card">
          <div class="stat-label">${s.label}</div>
          <div class="stat-value">${s.val}</div>
          <div class="stat-sub">${s.sub}</div>
        </div>
      `).join('');
    }

    function renderWarnings(data) {
      const container = $('warnings-container');
      let html = '';

      if (data.packers && data.packers.length > 0) {
        html += `<div class="alert-box alert-pack">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          <div>
            <b>Protection / Packager Detected:</b> ${data.packers.join(', ')}<br>
            ${Object.entries(data.packer_hints || {}).map(([p, h]) => `<span style="font-size:12px; opacity:0.9;">• <b>${p}</b>: ${h}</span>`).join('<br>')}
          </div>
        </div>`;
      }

      if (data.warnings && data.warnings.length > 0) {
        html += data.warnings.map(w => `
          <div class="alert-box alert-warn" style="margin-top:8px;">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            <div>${w}</div>
          </div>
        `).join('');
      }

      container.innerHTML = html;
    }

    function renderSections(sections) {
      const totalRaw = sections.reduce((acc, s) => acc + (s.rawsize || 1), 0);
      const bars = $('section-bars');
      bars.innerHTML = sections.map((s, idx) => {
        const pct = Math.max(4, Math.round((s.rawsize / totalRaw) * 100));
        const color = SEC_COLORS[idx % SEC_COLORS.length];
        return `<div class="sec-bar" style="width:${pct}%; background:${color};" title="${s.name} (${s.rawsize_fmt})">${s.name}</div>`;
      }).join('');

      const tbody = $('section-table-body');
      tbody.innerHTML = sections.map(s => `
        <tr>
          <td><b style="color:#ffffff;">${s.name}</b></td>
          <td>${s.va}</td>
          <td>${s.vsize_fmt}</td>
          <td>${s.raw}</td>
          <td>${s.rawsize_fmt}</td>
          <td><code>${s.chars}</code></td>
        </tr>
      `).join('');
    }

    function renderPatches(candidates) {
      const list = $('patch-candidates-list');
      if (!candidates || candidates.length === 0) {
        list.innerHTML = `
          <div class="stat-card" style="text-align:center; padding:32px;">
            <div style="font-size:14px; color:var(--text-muted);">No automated conditional branch candidates identified.</div>
            <div style="font-size:12px; color:var(--text-dim); margin-top:6px;">Use the dynamic Frida Monitor or locate the target branch in x64dbg.</div>
          </div>`;
        return;
      }

      list.innerHTML = candidates.map((c, i) => `
        <div class="candidate-card">
          <div class="candidate-header">
            <span class="candidate-kind ${c.kind.toLowerCase() === 'ok' ? 'ok' : ''}">${c.kind}</span>
            <div style="font-family:var(--font-mono); font-size:12px; color:var(--text-muted);">Candidate #${i + 1}</div>
          </div>
          <div class="candidate-string">"${escapeHtml(c.string)}"</div>
          <div class="candidate-meta">
            <span>String Ref: <code>0x${c.ref_off.toString(16)}</code></span>
            <span>Target Jump: <code>${c.jump} (${c.bytes})</code></span>
            <span>Branch Offset: <code>0x${c.jcc_off.toString(16)}</code></span>
          </div>
          <div class="candidate-actions">
            <button class="btn btn-primary btn-sm" onclick="applyPatch(${i}, 'nop')">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
              NOP Jump (0x90)
            </button>
            <button class="btn btn-emerald btn-sm" onclick="applyPatch(${i}, 'flip')">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 3h5v5"/><path d="M4 20L21 3"/><path d="M21 16v5h-5"/><path d="M15 15l6 6"/><path d="M4 4l5 5"/></svg>
              Invert / Flip Branch
            </button>
          </div>
        </div>
      `).join('');
    }

    async function applyPatch(idx, mode) {
      try {
        const res = await fetch('/api/patch', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: TOKEN, index: idx, mode: mode, fname: FNAME })
        });
        if (!res.ok) {
          let msg = await res.text();
          try { msg = JSON.parse(msg).error || msg; } catch (e) {}
          alert('Patch error: ' + msg);
          return;
        }
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = FNAME.replace(/\.\w+$/, '') + '_patched.exe';
        a.click();
        showToast(`Patched binary generated (${mode.toUpperCase()})!`);
      } catch (err) {
        alert('Patch failed: ' + err);
      }
    }

    function setTagFilter(tag) {
      ACTIVE_TAG = tag;
      document.querySelectorAll('.filter-chip').forEach(c => {
        c.classList.toggle('active', c.textContent === tag);
      });
      filterStrings();
    }

    function filterStrings() {
      if (!CURRENT_DATA || !CURRENT_DATA.strings) return;
      const q = $('string-query').value.toLowerCase();
      const tbody = $('strings-table-body');
      
      const filtered = CURRENT_DATA.strings.filter(s => {
        const matchesTag = (ACTIVE_TAG === 'ALL') || (s.tags && s.tags.includes(ACTIVE_TAG));
        const matchesQuery = !q || s.string.toLowerCase().includes(q) || s.offset.toLowerCase().includes(q);
        return matchesTag && matchesQuery;
      });

      tbody.innerHTML = filtered.slice(0, 300).map(s => {
        const tagBadges = s.tags ? s.tags.split(',').map(t => `<span class="tag-badge ${t}">${t}</span>`).join(' ') : '';
        return `
          <tr>
            <td><code>${s.offset}</code></td>
            <td style="color:var(--text-dim);">${s.encoding || 'ascii'}</td>
            <td>${tagBadges}</td>
            <td style="word-break:break-all;">${escapeHtml(s.string.slice(0, 100))}</td>
            <td>
              <button class="btn btn-secondary btn-sm" style="padding:2px 6px;" onclick="copyText('${escapeJs(s.string)}')">Copy</button>
            </td>
          </tr>
        `;
      }).join('');
    }

    function exportStrings() {
      if (!CURRENT_DATA) return;
      const blob = new Blob([JSON.stringify(CURRENT_DATA.strings, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${FNAME}_strings.json`;
      a.click();
    }

    function renderImports(imports) {
      const container = $('imports-container');
      if (!imports || imports.length === 0) {
        container.innerHTML = '<div style="color:var(--text-muted); padding:16px;">No dynamic imports table found.</div>';
        return;
      }
      $('import-summary-text').textContent = `${imports.length} Imported Modules`;
      container.innerHTML = imports.map(imp => `
        <div class="stat-card">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <b style="color:#ffffff; font-family:var(--font-mono);">${imp.dll}</b>
            <span class="pill">${imp.count} functions</span>
          </div>
          <div style="display:flex; flex-wrap:wrap; gap:6px; margin-top:8px;">
            ${imp.functions.map(fn => {
              const tagPill = fn.tags && fn.tags.length > 0 ? `<span class="tag-badge AUTH">${fn.tags.join(',')}</span>` : '';
              return `<span class="pill" style="color:var(--text-main); font-size:11px;">${fn.name} ${tagPill}</span>`;
            }).join('')}
          </div>
        </div>
      `).join('');
    }

    function filterImports() {
      const q = $('import-query').value.toLowerCase();
      if (!CURRENT_DATA || !CURRENT_DATA.imports) return;
      const filtered = CURRENT_DATA.imports.filter(imp => 
        imp.dll.toLowerCase().includes(q) || imp.functions.some(f => f.name.toLowerCase().includes(q))
      );
      renderImports(filtered);
    }

    function renderExtracted(entries) {
      const tbody = $('extracted-table-body');
      tbody.innerHTML = entries.map(e => `
        <tr>
          <td><b style="color:#ffffff; font-family:var(--font-mono);">${escapeHtml(e.name)}</b></td>
          <td style="color:var(--text-dim);">${e.formatted || e.size + ' B'}</td>
        </tr>
      `).join('');
    }

    function downloadHook() {
      if (!TOKEN) return;
      const a = document.createElement('a');
      a.href = `/api/hook?token=${TOKEN}`;
      a.download = 'hook.js';
      a.click();
    }

    function escapeHtml(s) {
      return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function escapeJs(s) {
      return String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n').replace(/\r/g, '');
    }

    function toggleWorkflow() {
      $('wf-overlay').classList.toggle('open');
    }

    function closeWorkflow() {
      $('wf-overlay').classList.remove('open');
    }

    document.addEventListener('keydown', e => { if (e.key === 'Escape') closeWorkflow(); });
  </script>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body, ctype="application/json", extra=b"", status=200):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        if extra:
            for k, v in [line.split(": ", 1) for line in extra.decode().splitlines()]:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self._send(INDEX_HTML.encode(), "text/html; charset=utf-8")
        elif self.path == "/logo.svg":
            logo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bobbypin_logo.svg")
            if os.path.exists(logo_path):
                svg_data = open(logo_path, "rb").read()
                self._send(svg_data, "image/svg+xml")
            else:
                self._send(b'{"error":"not found"}', status=404)
        elif self.path.startswith("/api/hook"):
            qs = dict(p.split("=") for p in self.path.split("?")[1].split("&")) if "?" in self.path else {}
            sess = SESSIONS.get(qs.get("token"))
            js = sess["hook"] if sess else "// expired session"
            self._send(js.encode(), "application/javascript",
                       b"Content-Disposition: attachment; filename=hook.js")
        else:
            self._send(b'{"error":"not found"}', status=404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > MAX_BODY:
            return self._send(b'{"error":"file too large"}', status=413)
        body = self.rfile.read(length)

        if self.path == "/api/analyze":
            fname = self.headers.get("X-Filename", "target.exe")
            token = str(uuid.uuid4())
            try:
                rep = analyze_bytes(body)
            except Exception as ex:
                return self._send(json.dumps({"error": str(ex)}).encode(), status=500)
            rep["token"] = token
            hook = rep.get("hook_code") or gen_hook(rep, body)
            rep["hook_code"] = hook
            SESSIONS[token] = {"data": body, "fname": fname, "rep": rep, "hook": hook}
            while len(SESSIONS) > MAX_SESSIONS:
                del SESSIONS[next(iter(SESSIONS))]
            return self._send(json.dumps(rep).encode())

        if self.path == "/api/patch":
            try:
                req = json.loads(body)
                sess = SESSIONS.get(req.get("token"))
                if not sess:
                    return self._send(b'{"error":"expired session - re-analyze"}', status=400)
                cands = sess["rep"].get("candidates", [])
                i = int(req.get("index", 0))
                if not 0 <= i < len(cands):
                    return self._send(b'{"error":"no such candidate"}', status=400)
                cand = dict(cands[i])
                cand["jcc_off"] = int(cand["jcc_off"], 16) if isinstance(cand["jcc_off"], str) else cand["jcc_off"]
                patched, desc = retool.apply_patch(sess["data"], cand, req.get("mode", "nop"))
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as ex:
                return self._send(json.dumps({"error": f"patch failed: {ex}"}).encode(), status=400)
            out_name = os.path.splitext(sess["fname"])[0] + "_patched.exe"
            print(desc)
            return self._send(patched, "application/octet-stream",
                              f"Content-Disposition: attachment; filename={out_name}".encode())

        self._send(b'{"error":"not found"}', status=404)


def gen_hook(rep, data):
    if rep["kind"] == "pe":
        try:
            pe = retool.parse_pe(data)
            pe["electron"] = retool.looks_electron(data)
            return retool.gen_monitor_js(pe)
        except ValueError:
            pass
    return retool.gen_monitor_js({"imports": [], "electron": True})


class AppServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8877
    srv = AppServer(("127.0.0.1", port), Handler)
    print(f"bobbypin GUI (coded by decay.root.0x00) -> http://127.0.0.1:{port} (Ctrl-C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
