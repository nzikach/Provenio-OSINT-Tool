#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Provenio UI — современный интерфейс (чёрно-фиолетовое стекло, Apple-motion).
Запуск: python provenio_ui.py   (файлы provenio.py и provenio_tools.py рядом)

Окно: если установлен pywebview (pip install pywebview), откроется отдельное окно,
иначе интерфейс откроется в браузере. Сервер слушает только 127.0.0.1 и защищён токеном.
"""
import json
import os
import secrets
import threading
import urllib.parse
import webbrowser
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

import provenio as P
try:
    import provenio_tools as TL
except Exception:
    TL = None

S = P.Store()
LOCK = threading.RLock()
TOKEN = secrets.token_urlsafe(24)


def case_by_id(cid):
    return next((c for c in S.cases() if c["id"] == int(cid)), None)


def state(cid):
    srcs, ents = S.sources(cid), S.entities(cid)
    ok, bad = S.verify_snapshots(cid)
    chain, _ = S.verify_audit()
    keys = ("id", "url", "title", "fetched", "status", "size", "sha256", "snapshot", "reliability", "note")
    audit = [dict(r) for r in S.db.execute(
        "SELECT id,ts,action,detail,hash FROM audit ORDER BY id DESC LIMIT 200")]
    return {
        "sources": [{k: s[k] for k in keys} for s in srcs],
        "entities": [{"id": e["id"], "type": e["type"], "value": e["value"],
                      "conf": e["confidence"], "src": [s["id"] for s in e["sources"]]} for e in ents],
        "audit": audit,
        "integrity": {"snap_ok": ok, "snap_bad": len(bad), "chain": chain},
    }


def api(path, q, body):
    with LOCK:
        if path == "cases":
            return S.cases()
        if path == "case":
            name = str(body.get("name", "")).strip()[:80]
            if not name:
                raise ValueError("Пустое название")
            return {"id": S.add_case(name)}
        if path == "state":
            return state(int(q["case"][0]))
        if path == "add":
            sid, status = S.add_source(int(body["case"]), str(body["url"])[:2000])
            return {"id": sid, "status": status}
        if path == "rel":
            S.update_source(int(body["id"]), reliability=max(1, min(5, int(body["reliability"]))))
            return {}
        if path == "note":
            S.update_source(int(body["id"]), note=str(body["note"])[:500])
            return {}
        if path == "delete":
            S.delete_source(int(body["id"]))
            return {}
    raise KeyError(path)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def out(self, code, body, ctype="application/json; charset=utf-8", headers=()):
        if ctype.startswith("application/json"):
            body = json.dumps(body, ensure_ascii=False)
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def authorized(self, q):
        tok = self.headers.get("X-Token") or (q.get("t") or [""])[0]
        return self.host_ok() and secrets.compare_digest(tok, TOKEN)

    def host_ok(self):
        return self.headers.get("Host", "").split(":")[0] in ("127.0.0.1", "localhost")

    def read_body(self, method):
        if method != "POST":
            return {}
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def handle_any(self, method):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        try:
            if u.path == "/":
                if not self.host_ok():
                    return self.out(403, "forbidden", "text/plain")
                return self.out(200, PAGE.replace("__TOKEN__", TOKEN), "text/html; charset=utf-8")
            if not self.authorized(q):
                return self.out(403, {"error": "forbidden"})
            # Инструменты: без DB-локи (сетевые вызовы не должны блокировать интерфейс)
            if u.path == "/api/tool":
                if TL is None:
                    return self.out(500, {"error": "provenio_tools не найден"})
                body = self.read_body(method)
                try:
                    return self.out(200, {"ok": True, "data": TL.run_tool(str(body.get("name")), body)})
                except Exception as e:
                    return self.out(200, {"ok": False, "error": f"{type(e).__name__}: {str(e)[:200]}"})
            if u.path.startswith("/api/"):
                return self.out(200, api(u.path[5:], q, self.read_body(method)))
            if u.path == "/report":
                with LOCK:
                    c = case_by_id(q["case"][0])
                    S.audit("report_exported", c["name"])
                    return self.out(200, P.build_report(S, c), "text/html; charset=utf-8")
            if u.path.startswith("/snapshot/"):
                name = os.path.basename(urllib.parse.unquote(u.path[10:]))
                with open(os.path.join(P.SNAP_DIR, name), "rb") as f:
                    data = f.read()
                return self.out(200, data, "text/html", [(
                    "Content-Security-Policy",
                    "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:")])
            self.out(404, {"error": "not found"})
        except Exception as e:
            self.out(500, {"error": f"{type(e).__name__}: {e}"})

    def do_GET(self):
        self.handle_any("GET")

    def do_POST(self):
        self.handle_any("POST")


def main():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    url = f"http://127.0.0.1:{srv.server_address[1]}/"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        import webview
        webview.create_window("Provenio", url, width=1360, height=880,
                              min_size=(1040, 660), background_color="#060509")
        webview.start()
    except ImportError:
        print(f"Provenio запущен: {url}\n(Для отдельного окна: pip install pywebview)\nCtrl+C — выход")
        webbrowser.open(url)
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            pass


PAGE = r"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Provenio</title>
<style>
:root{
 --bg:#060509; --bg2:#0a0713; --panel:rgba(20,14,34,.55);
 --card:rgba(255,255,255,.035); --card2:rgba(255,255,255,.06);
 --bd:rgba(168,130,255,.14); --bd2:rgba(168,130,255,.28);
 --tx:#ece8f5; --mu:#9b93b5; --mu2:#6f6690;
 --ac:#8b5cf6; --ac2:#c084fc; --ac3:#a855f7; --mag:#e879f9;
 --ok:#34d399; --warn:#fbbf24; --bad:#fb7185;
 --spring:cubic-bezier(.34,1.56,.64,1); --ease:cubic-bezier(.22,.9,.3,1);
 --glass:saturate(150%) blur(22px);
}
*{box-sizing:border-box;margin:0}
html,body{height:100%}
body{font:14px/1.55 "Inter","Segoe UI",system-ui,sans-serif;background:var(--bg);color:var(--tx);
 height:100vh;overflow:hidden;display:grid;grid-template-columns:272px 1fr;
 -webkit-font-smoothing:antialiased;letter-spacing:.1px}

/* ---------- живой фон: фиолетовый mesh ---------- */
.bg{position:fixed;inset:0;z-index:-2;background:
 radial-gradient(1200px 800px at 15% -10%, #1a0f33 0%, transparent 55%),
 radial-gradient(900px 700px at 100% 0%, #230c3d 0%, transparent 50%),
 radial-gradient(1000px 900px at 50% 120%, #140a24 0%, transparent 55%), var(--bg)}
.mesh{position:fixed;inset:0;z-index:-1;overflow:hidden;pointer-events:none}
.mesh i{position:absolute;width:52vw;height:52vw;border-radius:50%;filter:blur(130px);opacity:.42;
 mix-blend-mode:screen;animation:drift 28s ease-in-out infinite alternate}
.mesh i:nth-child(1){background:#7c3aed;top:-18%;left:-12%}
.mesh i:nth-child(2){background:#c026d3;bottom:-22%;right:-14%;animation-delay:-9s;opacity:.3}
.mesh i:nth-child(3){background:#4c1d95;top:30%;left:38%;animation-delay:-16s;opacity:.28}
.grain{position:fixed;inset:0;z-index:-1;pointer-events:none;opacity:.04;
 background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='120' height='120'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.9' numOctaves='3'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E")}
@keyframes drift{to{transform:translate(9vw,7vh) scale(1.3) rotate(16deg)}}
@keyframes rise{from{opacity:0;transform:translateY(16px)}}
@keyframes pop{from{opacity:0;transform:scale(.9)}}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes shimmer{to{background-position:200% 0}}
@keyframes glowPulse{0%,100%{box-shadow:0 0 22px rgba(139,92,246,.5)}50%{box-shadow:0 0 34px rgba(192,132,252,.75)}}

/* ---------- боковая панель ---------- */
aside{padding:24px 16px;border-right:1px solid var(--bd);background:var(--panel);
 backdrop-filter:var(--glass);-webkit-backdrop-filter:var(--glass);
 display:flex;flex-direction:column;gap:18px;min-height:0;position:relative}
aside::after{content:"";position:absolute;top:0;right:0;width:1px;height:100%;
 background:linear-gradient(180deg,transparent,rgba(192,132,252,.35),transparent)}
.logo{display:flex;gap:12px;align-items:center;font-weight:800;font-size:20px;letter-spacing:.4px}
.logo b{width:36px;height:36px;border-radius:12px;background:linear-gradient(135deg,var(--ac),var(--mag));
 display:grid;place-items:center;font-size:17px;color:#fff;animation:glowPulse 4s var(--ease) infinite;
 position:relative;overflow:hidden}
.logo b::after{content:"";position:absolute;inset:0;background:linear-gradient(115deg,transparent 30%,rgba(255,255,255,.5),transparent 70%);
 background-size:220% 100%;animation:shimmer 3.5s linear infinite}
.logo span{background:linear-gradient(120deg,#fff,var(--ac2));-webkit-background-clip:text;background-clip:text;color:transparent}
.cap{font-size:10.5px;text-transform:uppercase;letter-spacing:1.6px;color:var(--mu2);font-weight:700}
.cases{display:flex;flex-direction:column;gap:5px;overflow:auto;flex:1;margin:0 -4px;padding:0 4px}
.case{padding:11px 13px;border-radius:12px;cursor:pointer;color:var(--mu);border:1px solid transparent;
 transition:all .35s var(--ease);animation:rise .5s var(--ease) both;position:relative;overflow:hidden;font-weight:500}
.case:hover{background:var(--card);color:var(--tx);transform:translateX(5px)}
.case.on{background:linear-gradient(90deg,rgba(139,92,246,.28),rgba(139,92,246,.04));
 border-color:var(--bd2);color:#fff;box-shadow:inset 0 0 0 1px rgba(192,132,252,.15)}
.case.on::before{content:"";position:absolute;left:0;top:18%;bottom:18%;width:3px;border-radius:3px;
 background:linear-gradient(var(--ac),var(--mag));box-shadow:0 0 12px var(--ac)}
.newc{display:flex;gap:7px}
input,textarea,select{background:rgba(255,255,255,.045);border:1px solid var(--bd);color:var(--tx);
 border-radius:12px;padding:11px 13px;font:inherit;outline:none;transition:all .25s var(--ease);min-width:0;width:100%}
input::placeholder{color:var(--mu2)}
input:focus,textarea:focus,select:focus{border-color:var(--ac);box-shadow:0 0 0 3.5px rgba(139,92,246,.22);
 background:rgba(255,255,255,.07)}
.hint{font-size:11px;color:var(--mu2);line-height:1.5}

/* ---------- кнопки ---------- */
.btn{position:relative;border:0;border-radius:12px;padding:11px 17px;font:700 13px inherit;color:#fff;cursor:pointer;
 background:linear-gradient(135deg,var(--ac),var(--ac3));transition:all .25s var(--spring);white-space:nowrap;
 box-shadow:0 8px 24px rgba(139,92,246,.32);overflow:hidden}
.btn::after{content:"";position:absolute;inset:0;background:linear-gradient(115deg,transparent 40%,rgba(255,255,255,.28),transparent 60%);
 background-size:220% 100%;background-position:-120% 0;transition:.5s}
.btn:hover{transform:translateY(-2px) scale(1.02);box-shadow:0 14px 34px rgba(139,92,246,.5)}
.btn:hover::after{background-position:120% 0}
.btn:active{transform:scale(.95)}
.btn.loading{pointer-events:none;color:transparent}
.btn.loading::before{content:"";position:absolute;inset:0;margin:auto;width:17px;height:17px;border-radius:50%;
 border:2px solid #fff;border-top-color:transparent;animation:spin .7s linear infinite}
.ghost{background:var(--card);border:1px solid var(--bd);color:var(--tx);border-radius:11px;padding:8px 13px;
 font:600 12px inherit;cursor:pointer;text-decoration:none;transition:all .25s var(--ease);white-space:nowrap;display:inline-flex;align-items:center;gap:6px}
.ghost:hover{background:var(--card2);transform:translateY(-1px);border-color:var(--bd2)}
.del:hover{color:var(--bad);border-color:rgba(251,113,133,.5)}

/* ---------- основная область ---------- */
main{display:flex;flex-direction:column;min-width:0;height:100vh}
header{padding:22px 28px 10px;display:flex;gap:11px;align-items:center}
header .grow{flex:1}
.pill{padding:7px 14px;border-radius:99px;font-size:12px;font-weight:600;border:1px solid var(--bd);
 transition:all .45s var(--ease);white-space:nowrap;backdrop-filter:blur(10px)}
.pill.ok{color:var(--ok);border-color:rgba(52,211,153,.4);background:rgba(52,211,153,.08)}
.pill.bad{color:var(--bad);border-color:rgba(251,113,133,.5);background:rgba(251,113,133,.1)}
.pill.ok::before,.pill.bad::before{content:"●";margin-right:6px;animation:glowDot 2s infinite}
@keyframes glowDot{50%{opacity:.4}}

.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;padding:12px 28px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:18px;padding:17px;
 backdrop-filter:var(--glass);-webkit-backdrop-filter:var(--glass);transition:all .35s var(--spring);position:relative;overflow:hidden}
.card::before{content:"";position:absolute;inset:0;border-radius:inherit;padding:1px;
 background:linear-gradient(135deg,rgba(255,255,255,.14),transparent 40%);
 -webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask-composite:exclude;pointer-events:none}
.stat{animation:pop .55s var(--spring) both}
.stat:hover{transform:translateY(-4px);border-color:var(--bd2);box-shadow:0 16px 40px rgba(139,92,246,.2)}
.stat .lbl{color:var(--mu);font-size:12px;font-weight:500}
.stat b{display:block;font-size:34px;line-height:1.15;font-weight:800;margin-top:4px;
 background:linear-gradient(135deg,#fff,var(--ac2));-webkit-background-clip:text;background-clip:text;color:transparent}

.tabs{position:relative;display:flex;gap:2px;padding:8px 28px 0;border-bottom:1px solid var(--bd);margin:4px 0 16px}
.tab{background:none;border:0;color:var(--mu);padding:11px 17px;font:700 13px inherit;cursor:pointer;
 transition:color .25s;border-radius:10px 10px 0 0}
.tab:hover,.tab.on{color:#fff}
#ink{position:absolute;bottom:-1px;left:28px;height:2.5px;border-radius:3px;
 background:linear-gradient(90deg,var(--ac),var(--mag));transition:all .5s var(--spring);box-shadow:0 0 14px var(--ac)}
.panels{flex:1;overflow:auto;padding:0 28px 28px;min-height:0}
.panel{display:none}.panel.on{display:block;animation:rise .5s var(--ease)}

/* ---------- источники ---------- */
.src{margin-bottom:13px;animation:rise .55s var(--ease) both;animation-delay:calc(var(--i)*45ms)}
.src:hover{border-color:var(--bd2);transform:translateY(-2px);box-shadow:0 12px 30px rgba(0,0,0,.3)}
.row{display:flex;gap:11px;align-items:center;flex-wrap:wrap}.grow{flex:1;min-width:0}
.ttl{font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.url{color:var(--ac2);font-size:12px;text-decoration:none;display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.url:hover{text-decoration:underline}
.meta{display:flex;gap:15px;font-size:12px;color:var(--mu);margin:9px 0 11px;flex-wrap:wrap}
.sha{font-family:"JetBrains Mono",Consolas,monospace;cursor:pointer;transition:color .2s}.sha:hover{color:var(--ac2)}
.chip{padding:4px 11px;border-radius:99px;font-size:11px;font-weight:700}
.chip.ok{background:rgba(52,211,153,.14);color:var(--ok)}.chip.bad{background:rgba(251,113,133,.14);color:var(--bad)}
.seg{display:flex;gap:4px}.seg button{width:28px;height:28px;border-radius:9px;border:1px solid var(--bd);
 background:var(--card);color:var(--mu);cursor:pointer;font-size:12px;font-weight:600;transition:all .25s var(--spring)}
.seg button.on{background:linear-gradient(135deg,var(--ac),var(--mag));color:#fff;border-color:transparent;box-shadow:0 0 14px rgba(139,92,246,.5)}
.seg button:hover{transform:scale(1.18)}
.note{flex:1;min-width:150px;padding:7px 11px;font-size:12px}

/* ---------- сущности ---------- */
.chips{display:flex;gap:9px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
.fc{padding:7px 14px;border-radius:99px;border:1px solid var(--bd);background:var(--card);color:var(--mu);
 cursor:pointer;font-size:12px;font-weight:600;transition:all .25s var(--spring)}
.fc:hover{color:#fff;transform:translateY(-2px)}
.fc.on{background:rgba(139,92,246,.26);border-color:var(--ac);color:#fff}
.ent{display:grid;grid-template-columns:12px 72px minmax(120px,1fr) 170px 46px 64px;gap:13px;align-items:center;
 padding:12px 15px;border-radius:13px;animation:rise .5s var(--ease) both;animation-delay:calc(var(--i)*28ms);
 transition:background .25s}.ent:hover{background:var(--card)}
.ent .ev{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:500}
.dot{width:11px;height:11px;border-radius:50%;box-shadow:0 0 12px currentColor}
.bar{height:7px;background:rgba(255,255,255,.06);border-radius:9px;overflow:hidden}
.bar i{display:block;height:100%;width:0;border-radius:9px;transition:width 1.1s var(--ease)}

/* ---------- граф ---------- */
#p-graph{height:calc(100vh - 300px);min-height:400px;border-radius:18px;overflow:hidden;border:1px solid var(--bd);
 background:rgba(0,0,0,.3);padding:0;position:relative;backdrop-filter:blur(8px)}
#cv{width:100%;height:100%;display:block;cursor:grab}
.legend{position:absolute;left:16px;bottom:14px;display:flex;gap:14px;font-size:11px;color:var(--mu);pointer-events:none;flex-wrap:wrap}

/* ---------- аудит ---------- */
.tl{position:relative;padding-left:24px}
.tl::before{content:"";position:absolute;left:5px;top:6px;bottom:6px;width:2px;
 background:linear-gradient(var(--ac),var(--mag),transparent)}
.ev2{position:relative;padding:9px 0 13px;animation:rise .5s var(--ease) both;animation-delay:calc(var(--i)*22ms)}
.ev2::before{content:"";position:absolute;left:-23px;top:14px;width:11px;height:11px;border-radius:50%;
 background:var(--ac);box-shadow:0 0 14px var(--ac);border:2px solid var(--bg2)}
.ev2 b{color:var(--ac2)}
.ev2 small{color:var(--mu2);font-family:Consolas,monospace;font-size:11px;word-break:break-all}

/* ---------- инструменты ---------- */
.toolcats{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:18px}
.tgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(310px,1fr));gap:15px}
.tool{animation:rise .5s var(--ease) both;animation-delay:calc(var(--i)*35ms);display:flex;flex-direction:column;gap:11px}
.tool:hover{border-color:var(--bd2);transform:translateY(-3px);box-shadow:0 16px 40px rgba(139,92,246,.18)}
.tool .th{display:flex;gap:11px;align-items:center}
.tool .ic{width:38px;height:38px;border-radius:11px;display:grid;place-items:center;font-size:18px;flex-shrink:0;
 background:linear-gradient(135deg,rgba(139,92,246,.25),rgba(232,121,249,.12));border:1px solid var(--bd2)}
.tool .tn{font-weight:700;font-size:14px}
.tool .td{font-size:11.5px;color:var(--mu);line-height:1.45}
.tool .tin{display:flex;gap:7px}
.tool .tin input,.tool .tin select{padding:9px 12px;font-size:13px}
.tbtn{border:0;border-radius:11px;padding:9px 15px;font:700 13px inherit;color:#fff;cursor:pointer;
 background:linear-gradient(135deg,var(--ac),var(--ac3));transition:all .2s var(--spring);white-space:nowrap;position:relative;min-width:46px}
.tbtn:hover{transform:translateY(-1px);box-shadow:0 8px 20px rgba(139,92,246,.4)}.tbtn:active{transform:scale(.95)}
.tbtn.loading{color:transparent;pointer-events:none}
.tbtn.loading::before{content:"";position:absolute;inset:0;margin:auto;width:15px;height:15px;border-radius:50%;
 border:2px solid #fff;border-top-color:transparent;animation:spin .7s linear infinite}
.tres{display:none;font-size:12.5px;border-top:1px solid var(--bd);padding-top:11px;margin-top:2px;max-height:340px;overflow:auto;animation:rise .4s var(--ease)}
.tres.show{display:block}
.tres pre{font-family:"JetBrains Mono",Consolas,monospace;font-size:11.5px;white-space:pre-wrap;word-break:break-word;color:var(--mu);margin:0}
.kv{display:flex;gap:8px;padding:3px 0;border-bottom:1px solid rgba(255,255,255,.04)}
.kv b{color:var(--ac2);min-width:120px;flex-shrink:0;font-weight:600}
.kv span{word-break:break-word}
.tag{display:inline-block;padding:2px 9px;margin:2px 4px 2px 0;border-radius:7px;font-size:11px;background:var(--card2);border:1px solid var(--bd)}
.tag.good{color:var(--ok);border-color:rgba(52,211,153,.3)}.tag.miss{color:var(--bad);border-color:rgba(251,113,133,.3)}
.grade{display:inline-grid;place-items:center;width:40px;height:40px;border-radius:12px;font-weight:800;font-size:19px}
.found{color:var(--ok);font-weight:600}.notfound{color:var(--mu2)}
.toolnote{font-size:11.5px;color:var(--mu2);background:rgba(139,92,246,.07);border:1px solid var(--bd);
 border-radius:12px;padding:11px 14px;margin-bottom:16px;line-height:1.5}

.empty{text-align:center;color:var(--mu);padding:70px 0;animation:rise .6s var(--ease)}
.empty b{display:block;font-size:17px;color:var(--tx);margin-bottom:6px}
#toasts{position:fixed;right:22px;bottom:22px;display:flex;flex-direction:column;gap:9px;z-index:30}
.toast{background:rgba(18,12,30,.92);border:1px solid var(--bd);border-left:3px solid var(--ac);padding:12px 17px;
 border-radius:13px;backdrop-filter:blur(16px);animation:rise .4s var(--spring);transition:all .35s;max-width:400px;box-shadow:0 12px 32px rgba(0,0,0,.4)}
.toast.ok{border-left-color:var(--ok)}.toast.bad{border-left-color:var(--bad)}
.toast.out{opacity:0;transform:translateX(34px)}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
::-webkit-scrollbar{width:9px;height:9px}
::-webkit-scrollbar-thumb{background:rgba(168,130,255,.2);border-radius:9px}
::-webkit-scrollbar-thumb:hover{background:rgba(168,130,255,.35)}
</style></head><body>
<div class="bg"></div><div class="mesh"><i></i><i></i><i></i></div><div class="grain"></div>
<aside>
 <div class="logo"><b>◈</b><span>Provenio</span></div>
 <div class="cap">Кейсы</div>
 <div class="cases" id="cases"></div>
 <div class="newc"><input id="ncase" placeholder="Новый кейс"><button class="btn" id="addc">+</button></div>
 <div class="hint">Доказательная OSINT-аналитика.<br>Только публичные данные. Соблюдайте закон.</div>
</aside>
<main>
 <header>
  <input class="grow" id="url" placeholder="Вставьте URL (можно несколько через пробел или запятую)…">
  <button class="btn" id="add">Архивировать</button>
  <button class="ghost" id="ver">Проверить</button>
  <button class="ghost" id="rep">Отчёт</button>
  <span class="pill ok" id="pill">целостность</span>
 </header>
 <div class="stats">
  <div class="card stat"><span class="lbl">Источники</span><b id="n1" data-v="0">0</b></div>
  <div class="card stat" style="animation-delay:.06s"><span class="lbl">Сущности</span><b id="n2" data-v="0">0</b></div>
  <div class="card stat" style="animation-delay:.12s"><span class="lbl">Подтверждено 2+ источниками</span><b id="n3" data-v="0">0</b></div>
  <div class="card stat" style="animation-delay:.18s"><span class="lbl">Средняя достоверность, %</span><b id="n4" data-v="0">0</b></div>
 </div>
 <div class="tabs">
  <button class="tab on" data-t="src">Источники</button>
  <button class="tab" data-t="ents">Сущности</button>
  <button class="tab" data-t="graph">Граф</button>
  <button class="tab" data-t="tools">Инструменты</button>
  <button class="tab" data-t="audit">Аудит</button>
  <span id="ink"></span>
 </div>
 <div class="panels">
  <div class="panel on" id="p-src"></div>
  <div class="panel" id="p-ents"><div class="chips" id="chips"></div><div id="ents"></div></div>
  <div class="panel" id="p-graph"><canvas id="cv"></canvas>
   <div class="legend"><span>■ источник</span><span style="color:#fb923c">● email</span><span style="color:#34d399">● телефон</span>
   <span style="color:#60a5fa">● домен</span><span style="color:#c084fc">● IP</span><span style="color:#f87171">● аккаунт</span></div></div>
  <div class="panel" id="p-tools">
   <div class="toolnote">🛡 Все инструменты работают с <b>публичными</b> данными и выполняются на вашей машине.
   Инструменты ИБ здесь <b>защитные</b>: проверка пароля по утечкам идёт по k-anonymity (сам пароль не покидает компьютер).
   Перебора паролей/логинов и сканирования чужих систем здесь нет — используйте всё в рамках закона.</div>
   <div class="toolcats" id="toolcats"></div>
   <div class="tgrid" id="tgrid"></div>
  </div>
  <div class="panel" id="p-audit"><div class="tl" id="tl"></div></div>
 </div>
</main>
<div id="toasts"></div>
<script>
const T="__TOKEN__",$=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];
const esc=s=>String(s==null?"":s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const TY={email:"#fb923c",phone:"#34d399",domain:"#60a5fa",ip:"#c084fc",account:"#f87171",src:"#e5e7eb"};
const TL={email:"Email",phone:"Телефон",domain:"Домен",ip:"IP",account:"Аккаунт"};
let cases=[],cur=null,st=null,tab="src",ef="all",eq="";
const host=u=>{try{return new URL(u).hostname.replace(/^www\./,"")}catch(e){return u}};
async function api(p,b){const r=await fetch("/api/"+p,{method:b?"POST":"GET",headers:{"X-Token":T,"Content-Type":"application/json"},
 body:b?JSON.stringify(b):undefined});const j=await r.json();if(!r.ok)throw new Error(j.error||r.status);return j}
function toast(m,k){const t=document.createElement("div");t.className="toast "+(k||"");t.textContent=m;$("#toasts").append(t);
 setTimeout(()=>{t.classList.add("out");setTimeout(()=>t.remove(),400)},3600)}
function num(el,to){const f=+el.dataset.v||0;el.dataset.v=to;const t0=performance.now();
 (function s(t){const p=Math.min(1,(t-t0)/850),e=1-Math.pow(1-p,3);el.textContent=Math.round(f+(to-f)*e);if(p<1)requestAnimationFrame(s)})(t0)}
function moveInk(){const b=$(".tab.on"),k=$("#ink");if(!b)return;k.style.width=b.offsetWidth+"px";k.style.transform="translateX("+(b.offsetLeft-28)+"px)"}
function setTab(t){tab=t;$$(".tab").forEach(b=>b.classList.toggle("on",b.dataset.t===t));
 $$(".panel").forEach(p=>p.classList.toggle("on",p.id==="p-"+t));moveInk();if(t==="graph")setTimeout(sizeCv,30)}
$$(".tab").forEach(b=>b.onclick=()=>setTab(b.dataset.t));

function renderCases(){$("#cases").innerHTML=cases.map((c,i)=>`<div class="case ${cur&&cur.id===c.id?"on":""}" data-id="${c.id}" style="animation-delay:${i*40}ms">${esc(c.name)}</div>`).join("")||'<div class="mu" style="padding:8px;color:var(--mu2)">Создайте первый кейс ↓</div>'}
$("#cases").onclick=e=>{const d=e.target.closest(".case");if(d){cur=cases.find(c=>c.id==d.dataset.id);renderCases();refresh()}};
async function loadCases(sel){cases=await api("cases");cur=cases.find(c=>c.id===sel)||cur||cases[0]||null;renderCases();if(cur)refresh();else render()}
$("#addc").onclick=async()=>{const n=$("#ncase").value.trim();if(!n)return;try{const r=await api("case",{name:n});$("#ncase").value="";await loadCases(r.id);toast("Кейс создан","ok")}catch(e){toast(e.message,"bad")}};
$("#ncase").onkeydown=e=>{if(e.key==="Enter")$("#addc").click()};

async function refresh(){if(!cur)return;st=await api("state?case="+cur.id);render()}
function render(){
 if(!st||!cur){$("#p-src").innerHTML='<div class="empty"><b>Нет активного кейса</b>Создайте кейс слева и добавьте первый URL</div>';return}
 const E=st.entities,multi=E.filter(e=>e.src.length>1).length,avg=E.length?Math.round(E.reduce((a,e)=>a+e.conf,0)/E.length):0;
 num($("#n1"),st.sources.length);num($("#n2"),E.length);num($("#n3"),multi);num($("#n4"),avg);
 const i=st.integrity,good=!i.snap_bad&&i.chain;$("#pill").className="pill "+(good?"ok":"bad");
 $("#pill").textContent=good?"целостность подтверждена":"целостность нарушена";
 $("#p-src").innerHTML=st.sources.map((s,i)=>`<div class="card src" style="--i:${i}"><div class="row"><div class="grow">
  <div class="ttl">${esc(s.title||host(s.url))}</div><a class="url" href="${esc(s.url)}" target="_blank" rel="noopener noreferrer">${esc(s.url)}</a></div>
  <span class="chip ${s.status.startsWith("OK")?"ok":"bad"}">${esc(s.status.slice(0,30))}</span></div>
  <div class="meta"><span>#${s.id}</span><span>${esc(s.fetched)}</span><span>${(s.size/1024).toFixed(1)} KB</span>
  <span class="sha" data-c="${esc(s.sha256)}" title="Копировать SHA-256">${esc(s.sha256?s.sha256.slice(0,24)+"…":"нет снимка")}</span></div>
  <div class="row"><div class="seg" data-id="${s.id}" title="Надёжность источника">${[1,2,3,4,5].map(n=>`<button data-r="${n}" class="${n<=s.reliability?"on":""}">${n}</button>`).join("")}</div>
  <input class="note" data-id="${s.id}" placeholder="Заметка…" value="${esc(s.note)}">
  ${s.snapshot?`<a class="ghost" target="_blank" href="/snapshot/${encodeURIComponent(s.snapshot)}?t=${T}">Снимок</a>`:""}
  <button class="ghost del" data-id="${s.id}">Удалить</button></div></div>`).join("")||'<div class="empty"><b>Источников пока нет</b>Вставьте URL в поле сверху и нажмите «Архивировать»</div>';
 renderEnts();
 $("#tl").innerHTML=st.audit.map((a,i)=>`<div class="ev2" style="--i:${Math.min(i,20)}"><b>${esc(a.action)}</b> <span style="color:var(--mu)">${esc(a.ts)}</span><br>${esc(a.detail)}<br><small>${esc(a.hash)}</small></div>`).join("");
 buildGraph();moveInk()}
$("#p-src").onclick=async e=>{const b=e.target;
 if(b.dataset.r){await api("rel",{id:b.parentNode.dataset.id,reliability:+b.dataset.r});await refresh()}
 else if(b.classList.contains("del")){if(confirm("Удалить источник? Это попадёт в журнал аудита.")){await api("delete",{id:b.dataset.id});await refresh();toast("Источник удалён","ok")}}
 else if(b.classList.contains("sha")&&b.dataset.c){navigator.clipboard&&navigator.clipboard.writeText(b.dataset.c);toast("SHA-256 скопирован","ok")}};
$("#p-src").onchange=async e=>{if(e.target.classList.contains("note")){await api("note",{id:e.target.dataset.id,note:e.target.value});toast("Заметка сохранена","ok");refresh()}};

function renderEnts(){const types=[...new Set(st.entities.map(e=>e.type))];
 $("#chips").innerHTML=["all",...types].map(t=>`<span class="fc ${ef===t?"on":""}" data-t="${t}">${t==="all"?"Все":TL[t]||t} ${t==="all"?st.entities.length:st.entities.filter(e=>e.type===t).length}</span>`).join("")+
 '<input id="eq" placeholder="Поиск…" style="margin-left:auto;max-width:220px;padding:7px 13px" value="'+esc(eq)+'">';
 const L=st.entities.filter(e=>(ef==="all"||e.type===ef)&&e.value.toLowerCase().includes(eq)).sort((a,b)=>b.conf-a.conf);
 $("#ents").innerHTML=L.map((e,i)=>{const g=e.conf>=75?"#34d399,#22d3ee":e.conf>=45?"#fbbf24,#fb923c":"#f87171,#fb7185";
 return `<div class="ent" style="--i:${Math.min(i,25)}"><span class="dot" style="background:${TY[e.type]};color:${TY[e.type]}"></span><span style="color:var(--mu)">${TL[e.type]||e.type}</span>
 <span class="ev" title="${esc(e.value)}">${esc(e.value)}</span><div class="bar"><i data-w="${e.conf}" style="background:linear-gradient(90deg,${g})"></i></div><b>${e.conf}%</b><span style="color:var(--mu)">${e.src.length} ист.</span></div>`}).join("")||'<div class="empty">Ничего не найдено</div>';
 requestAnimationFrame(()=>requestAnimationFrame(()=>$$(".bar i").forEach(b=>b.style.width=b.dataset.w+"%")));
 const q=$("#eq");if(q)q.oninput=()=>{eq=q.value.toLowerCase();const p=q.selectionStart;renderEnts();const n=$("#eq");n.focus();n.setSelectionRange(p,p)}}
$("#chips").onclick=e=>{const c=e.target.closest(".fc");if(c){ef=c.dataset.t;renderEnts()}};

/* ---------- граф с физикой ---------- */
const cv=$("#cv"),cx=cv.getContext("2d"),G={nodes:[],edges:[],drag:null,hover:null};let W=0,H=0;const dpr=window.devicePixelRatio||1;
function sizeCv(){W=cv.clientWidth;H=cv.clientHeight;cv.width=W*dpr;cv.height=H*dpr}
window.addEventListener("resize",()=>{sizeCv();moveInk()});
function buildGraph(){if(!st)return;const old=new Map(G.nodes.map(n=>[n.id,n])),idx=new Map();const w=W||800,h=H||500;
 const mk=(id,t,l)=>{const o=old.get(id),n={id,t,l,x:w/2+(Math.random()-.5)*260,y:h/2+(Math.random()-.5)*260,vx:0,vy:0,age:0};
  if(o){n.x=o.x;n.y=o.y;n.age=o.age}idx.set(id,n);return n};
 const nodes=st.sources.map(s=>mk("s"+s.id,"src",host(s.url)+" #"+s.id)),edges=[];
 const E=st.entities.length>120?st.entities.filter(e=>e.src.length>1):st.entities;
 E.forEach(e=>{nodes.push(mk("e"+e.id,e.type,e.value));e.src.forEach(i=>{const a=idx.get("s"+i);if(a)edges.push([a,idx.get("e"+e.id)])})});
 G.nodes=nodes;G.edges=edges}
function nearest(x,y){let b=null,bd=1e9;for(const n of G.nodes){const d=Math.hypot(n.x-x,n.y-y);if(d<15&&d<bd){b=n;bd=d}}return b}
const pt=e=>{const r=cv.getBoundingClientRect();return[e.clientX-r.left,e.clientY-r.top]};
cv.onmousedown=e=>{const[x,y]=pt(e);G.drag=nearest(x,y);if(G.drag)cv.style.cursor="grabbing"};
window.addEventListener("mouseup",()=>{G.drag=null;cv.style.cursor="grab"});
cv.onmousemove=e=>{const[x,y]=pt(e);if(G.drag){G.drag.x=x;G.drag.y=y;G.drag.vx=G.drag.vy=0}G.hover=nearest(x,y)};
cv.onmouseleave=()=>G.hover=null;
function tick(){requestAnimationFrame(tick);if(tab!=="graph"||!W)return;const N=G.nodes;
 for(let i=0;i<N.length;i++){const a=N[i];a.age=Math.min(1,a.age+.04);
  for(let j=i+1;j<N.length;j++){const b=N[j];let dx=a.x-b.x,dy=a.y-b.y,d2=dx*dx+dy*dy+.5,m=Math.sqrt(d2),f=2800/d2;dx/=m;dy/=m;a.vx+=dx*f;a.vy+=dy*f;b.vx-=dx*f;b.vy-=dy*f}
  a.vx+=(W/2-a.x)*.0016;a.vy+=(H/2-a.y)*.0016}
 for(const[a,b]of G.edges){const dx=b.x-a.x,dy=b.y-a.y,d=Math.hypot(dx,dy)||1,f=(d-95)*.012;a.vx+=dx/d*f;a.vy+=dy/d*f;b.vx-=dx/d*f;b.vy-=dy/d*f}
 for(const n of N){if(n===G.drag)continue;n.vx*=.84;n.vy*=.84;n.x=Math.min(W-20,Math.max(20,n.x+n.vx));n.y=Math.min(H-20,Math.max(20,n.y+n.vy))}
 cx.setTransform(dpr,0,0,dpr,0,0);cx.clearRect(0,0,W,H);const hv=G.hover,near=new Set();
 if(hv){near.add(hv);G.edges.forEach(([a,b])=>{if(a===hv)near.add(b);if(b===hv)near.add(a)})}
 for(const[a,b]of G.edges){const hot=hv&&(a===hv||b===hv);cx.strokeStyle=hot?"rgba(192,132,252,.9)":"rgba(168,130,255,.14)";cx.lineWidth=hot?1.8:1;cx.beginPath();cx.moveTo(a.x,a.y);cx.lineTo(b.x,b.y);cx.stroke()}
 for(const n of N){const c=TY[n.t]||"#999",e=1-Math.pow(1-n.age,3),dim=hv&&!near.has(n),r=(n.t==="src"?9:6)*e*(n===hv?1.4:1);
  cx.globalAlpha=dim?.22:1;cx.shadowColor=c;cx.shadowBlur=n===hv?26:13;cx.fillStyle=c;cx.beginPath();
  if(n.t==="src")cx.roundRect?cx.roundRect(n.x-r,n.y-r,r*2,r*2,3):cx.rect(n.x-r,n.y-r,r*2,r*2);else cx.arc(n.x,n.y,r,0,7);cx.fill();cx.shadowBlur=0;
  if(n.t==="src"||near.has(n)){cx.fillStyle="#ece8f5";cx.font="11px Segoe UI,sans-serif";cx.textAlign="center";cx.fillText(n.l.slice(0,34),n.x,n.y+r+14)}}
 cx.globalAlpha=1}
requestAnimationFrame(tick);

/* =================== ИНСТРУМЕНТЫ =================== */
const TOOLS=[
 {id:"site_recon",cat:"Разведка сайта",ic:"🛰",tn:"Полная разведка сайта",td:"Технологии, мета, OpenGraph, ссылки, контакты, формы — одним запросом",ph:"example.com",wide:1},
 {id:"tech",cat:"Разведка сайта",ic:"🧩",tn:"Технологии (fingerprint)",td:"CMS, фреймворки, сервер, аналитика, CDN",ph:"example.com"},
 {id:"robots",cat:"Разведка сайта",ic:"🤖",tn:"robots.txt + sitemap",td:"Запрещённые пути и карта сайта (список URL)",ph:"example.com"},
 {id:"redirects",cat:"Разведка сайта",ic:"➡️",tn:"Цепочка редиректов",td:"Все переходы до конечного URL",ph:"http://example.com"},
 {id:"favicon",cat:"Разведка сайта",tn:"Favicon-хэш (Shodan)",td:"mmh3-хэш для пивотинга + готовый поиск Shodan",ph:"example.com"},
 {id:"email_sec",cat:"Разведка сайта",tn:"Антиспуфинг домена",td:"SPF, DMARC, DKIM, MX — защита почты",ph:"example.com"},
 {id:"security_txt",cat:"Разведка сайта",tn:"security.txt",td:"Контакты безопасности (RFC 9116)",ph:"example.com"},
 {id:"dns",cat:"Сеть и домены",ic:"🌐",tn:"DNS-записи",td:"A, AAAA, MX, NS, TXT, CNAME, SOA, CAA через DNS-over-HTTPS",ph:"example.com"},
 {id:"whois",cat:"Сеть и домены",ic:"📜",tn:"WHOIS",td:"Регистратор, даты, статусы и NS домена",ph:"example.com"},
 {id:"rdap",cat:"Сеть и домены",ic:"🗂",tn:"RDAP",td:"Структурный WHOIS для домена / IP / ASN",ph:"example.com или 8.8.8.8"},
 {id:"subdomains",cat:"Сеть и домены",ic:"🧬",tn:"Поддомены",td:"Через Certificate Transparency (crt.sh)",ph:"example.com"},
 {id:"ssl",cat:"Сеть и домены",ic:"🔒",tn:"TLS-сертификат",td:"Издатель, срок действия, SAN, версия TLS",ph:"example.com"},
 {id:"headers",cat:"Сеть и домены",ic:"🧱",tn:"Заголовки безопасности",td:"Оценка HTTP security-заголовков (A–F)",ph:"https://example.com"},
 {id:"reverse_dns",cat:"Сеть и домены",ic:"↩️",tn:"Обратный DNS (PTR)",td:"Имя хоста по IP-адресу",ph:"8.8.8.8"},
 {id:"ip_info",cat:"Сеть и домены",ic:"📍",tn:"Гео и ASN по IP",td:"Страна, город, провайдер, автономная система",ph:"1.1.1.1"},
 {id:"reverse_ip",cat:"Сеть и домены",ic:"🔗",tn:"Reverse IP (соседи)",td:"Другие домены на том же IP (лимит в сутки)",ph:"8.8.8.8"},
 {id:"wayback",cat:"Сеть и домены",ic:"🕰",tn:"Wayback Machine",td:"Ближайший архивный снимок страницы",ph:"https://example.com"},
 {id:"username",cat:"OSINT: люди",ic:"🧑‍💻",tn:"Поиск по нику",td:"Проверка публичных профилей на 20 платформах",ph:"username"},
 {id:"email",cat:"OSINT: люди",ic:"✉️",tn:"Разбор email",td:"Синтаксис, MX-домен, наличие Gravatar",ph:"user@example.com"},
 {id:"phone",cat:"OSINT: люди",ic:"📞",tn:"Разбор телефона",td:"Страна по коду, формат E.164, валидация",ph:"+7 912 345-67-89"},
 {id:"pwned",cat:"Информационная безопасность",ic:"🛡",tn:"Пароль в утечках",td:"k-anonymity HIBP — сам пароль не передаётся",ph:"пароль для проверки",pw:1},
 {id:"strength",cat:"Информационная безопасность",ic:"💪",tn:"Стойкость пароля",td:"Энтропия и оценка времени подбора (локально)",ph:"пароль для оценки",pw:1},
 {id:"hash",cat:"Утилиты",ic:"#️⃣",tn:"Хэши строки",td:"MD5, SHA-1, SHA-256, SHA-512",ph:"текст"},
 {id:"hash_id",cat:"Утилиты",ic:"🔍",tn:"Определить хэш",td:"Тип хэша по длине и алфавиту",ph:"5d41402abc4b2a76b9719d911017c592"},
 {id:"jwt",cat:"Утилиты",ic:"🎫",tn:"JWT-декодер",td:"Header, payload, срок действия (без проверки подписи)",ph:"eyJhbGci…"},
 {id:"cidr",cat:"Утилиты",ic:"🧮",tn:"Калькулятор подсети",td:"Диапазон, маска, число хостов",ph:"192.168.1.0/24"},
 {id:"timestamp",cat:"Утилиты",ic:"⏱",tn:"Конвертер времени",td:"unix ↔ ISO (пусто = сейчас)",ph:"1600000000 или 2020-09-13"},
 {id:"uuid",cat:"Утилиты",ic:"🆔",tn:"UUID",td:"Сгенерировать v4 или разобрать переданный",ph:"пусто = сгенерировать"},
 {id:"idn",cat:"Утилиты",ic:"🔤",tn:"Punycode / IDN",td:"Кодирование домена + детект гомоглифов",ph:"пример.рф"},
 {id:"entropy",cat:"Утилиты",ic:"🎲",tn:"Энтропия Шеннона",td:"Оценка случайности строки (поиск секретов)",ph:"строка"},
 {id:"luhn",cat:"Утилиты",ic:"✅",tn:"Проверка Луна",td:"Валидность карты/IMEI по алгоритму Luhn",ph:"4111 1111 1111 1111"},
 {id:"base",cat:"Утилиты",ic:"🔢",tn:"Системы счисления",td:"dec · hex · oct · bin",ph:"255 или 0xff"},
 {id:"dork",cat:"Утилиты",ic:"🔎",tn:"Google Dorks",td:"Готовые поисковые запросы по домену",ph:"example.com"},
 {id:"transform",cat:"Утилиты",ic:"🔁",tn:"Кодирование",td:"base64 · hex · url · rot13 · binary",ph:"текст",tf:1},
];
let toolCat="все";
function renderTools(){
 const cats=["все",...new Set(TOOLS.map(t=>t.cat))];
 $("#toolcats").innerHTML=cats.map(c=>`<span class="fc ${toolCat===c?"on":""}" data-c="${esc(c)}">${esc(c)}</span>`).join("");
 const list=TOOLS.filter(t=>toolCat==="все"||t.cat===toolCat);
 $("#tgrid").innerHTML=list.map((t,i)=>`<div class="card tool" data-id="${t.id}" style="--i:${i};${t.wide?"grid-column:1/-1;":""}">
  <div class="th"><div class="ic">${t.ic}</div><div><div class="tn">${esc(t.tn)}</div><div class="td">${esc(t.td)}</div></div></div>
  <div class="tin">
   ${t.tf?`<select class="tf-mode" style="max-width:110px"><option value="base64">base64</option><option value="hex">hex</option><option value="url">url</option><option value="rot13">rot13</option><option value="binary">binary</option></select>`:""}
   <input class="tq" type="${t.pw?"password":"text"}" placeholder="${esc(t.ph)}">
   ${t.tf?`<button class="tbtn tf-act" data-act="encode">→</button><button class="tbtn tf-act" data-act="decode" style="background:linear-gradient(135deg,#6d28d9,#4c1d95)">←</button>`:`<button class="tbtn tf-act">Запуск</button>`}
  </div>
  <div class="tres" id="r-${t.id}"></div></div>`).join("");
}
$("#toolcats").onclick=e=>{const c=e.target.closest(".fc");if(c){toolCat=c.dataset.c;renderTools()}};
$("#tgrid").onclick=e=>{const btn=e.target.closest(".tf-act");if(!btn)return;runTool(btn)};
$("#tgrid").onkeydown=e=>{if(e.key==="Enter"&&e.target.classList.contains("tq")){const b=e.target.closest(".tool").querySelector(".tf-act");runTool(b)}};
async function runTool(btn){
 const card=btn.closest(".tool"),id=card.dataset.id,q=card.querySelector(".tq").value.trim();
 if(!q)return toast("Введите значение","bad");
 const res=card.querySelector(".tres");btn.classList.add("loading");
 const body={name:id,q};
 if(card.querySelector(".tf-mode"))body.mode=card.querySelector(".tf-mode").value;
 if(btn.dataset.act&&id==="transform")body.action=btn.dataset.act;
 try{const r=await api("tool",body);
  if(!r.ok){res.innerHTML=`<span style="color:var(--bad)">⚠ ${esc(r.error)}</span>`;}
  else res.innerHTML=fmtTool(id,r.data,body);
  res.classList.add("show");
 }catch(e){res.innerHTML=`<span style="color:var(--bad)">⚠ ${esc(e.message)}</span>`;res.classList.add("show")}
 btn.classList.remove("loading")}

function kv(k,v){return `<div class="kv"><b>${esc(k)}</b><span>${v==null||v===""?"—":esc(v)}</span></div>`}
function fmtTool(id,d,body){
 if(id==="dns"){const r=d.records||{};const keys=Object.keys(r);
  return keys.length?keys.map(k=>kv(k,r[k].join(" · "))).join(""):'<span class="mu">Записей не найдено</span>';}
 if(id==="reverse_dns")return kv("IP",d.ip)+kv("PTR",d.ptr||"нет записи");
 if(id==="ip_info")return kv("IP",d.ip)+kv("Страна",d.country)+kv("Город",`${d.city||""} ${d.region||""}`)+kv("Провайдер",d.isp)+kv("Организация",d.org)+kv("ASN",d.asn)+kv("Координаты",d.lat!=null?d.lat+", "+d.lon:"")+kv("Таймзона",d.timezone);
 if(id==="whois"){const f=d.fields||{};let h=kv("WHOIS-сервер",d.server);
  for(const k in f)h+=kv(k,f[k].join(" · "));return h||'<pre>'+esc((d.raw||"").slice(0,1500))+'</pre>';}
 if(id==="ssl"){const dl=d.days_left;const col=dl==null?"var(--mu)":dl<0?"var(--bad)":dl<21?"var(--warn)":"var(--ok)";
  return kv("CN",d.subject_cn)+kv("Издатель",d.issuer)+kv("Действует до",d.valid_to)+
  `<div class="kv"><b>Осталось дней</b><span style="color:${col};font-weight:700">${dl==null?"—":dl}</span></div>`+
  kv("TLS",d.tls_version)+kv("Шифр",d.cipher)+kv("SAN ("+(d.san||[]).length+")",(d.san||[]).slice(0,14).join(" · "));}
 if(id==="headers"){const gc=d.grade==="A"?"#34d399":d.grade==="B"?"#a3e635":d.grade==="C"?"#fbbf24":d.grade==="D"?"#fb923c":"#fb7185";
  let h=`<div style="display:flex;gap:12px;align-items:center;margin-bottom:10px"><div class="grade" style="background:${gc}22;color:${gc};border:1px solid ${gc}55">${d.grade}</div>
   <div><b>${d.score}%</b> security-заголовков<br><span class="mu" style="font-size:11px">${esc(d.server||"")}</span></div></div>`;
  h+='<div style="margin-bottom:6px">'+Object.keys(d.present).map(k=>`<span class="tag good">✓ ${esc(k)}</span>`).join("")+'</div>';
  h+='<div>'+Object.keys(d.missing).map(k=>`<span class="tag miss">✗ ${esc(k)}</span>`).join("")+'</div>';
  return h;}
 if(id==="subdomains"){const s=d.subdomains||[];return kv("Найдено",d.count)+'<div style="margin-top:8px">'+(s.length?s.slice(0,200).map(x=>`<span class="tag">${esc(x)}</span>`).join(""):'<span class="mu">нет</span>')+'</div>';}
 if(id==="wayback")return kv("В архиве",d.available?"да":"нет")+kv("Снимок",d.closest?'<a class="url" target="_blank" href="'+esc(d.closest)+'">открыть</a>':"—")+kv("Дата",d.timestamp);
 if(id==="username"){const f=d.found||[];let h=`<div style="margin-bottom:8px"><span class="found">Найдено: ${f.length}</span> <span class="mu">из ${d.checked} платформ</span></div>`;
  h+=f.map(x=>`<div class="kv"><b class="found">${esc(x.site)}</b><span><a class="url" target="_blank" href="${esc(x.url)}">${esc(x.url)}</a></span></div>`).join("");
  const ab=(d.absent||[]).map(x=>x.site);if(ab.length)h+=`<div style="margin-top:8px;font-size:11px" class="mu">Не найдено: ${esc(ab.join(", "))}</div>`;
  return h;}
 if(id==="email")return kv("Email",d.email)+kv("Синтаксис",d.valid_syntax?"✓ корректен":"✗ ошибка")+(d.valid_syntax?kv("Домен",d.domain)+kv("MX (почта)",d.has_mx?"✓ "+(d.mx||[]).slice(0,3).join(", "):"✗ нет")+kv("Gravatar",d.gravatar?'✓ есть — '+'<a class="url" target="_blank" href="'+esc(d.gravatar_url)+'">фото</a>':"нет"):"");
 if(id==="phone")return kv("Ввод",d.input)+kv("Страна",d.country||"неизвестно")+kv("Код страны",d.country_code?"+"+d.country_code:"—")+kv("E.164",d.e164)+kv("Нац. номер",d.national)+kv("Валиден",d.valid?"✓ да":"✗ нет");
 if(id==="pwned"){const c=d.breached?"var(--bad)":"var(--ok)";
  return `<div class="kv"><b>Статус</b><span style="color:${c};font-weight:700">${d.breached?"⚠ найден в утечках":"✓ не найден"}</span></div>`+
  (d.breached?kv("Встречался раз",d.count.toLocaleString("ru")):"")+`<div class="mu" style="margin-top:6px;font-size:11px">${esc(d.advice)}</div>`;}
 if(id==="strength"){const map={"очень слабый":"#fb7185","слабый":"#fb923c","средний":"#fbbf24","сильный":"#a3e635","очень сильный":"#34d399"};const c=map[d.verdict]||"#fbbf24";
  return `<div class="kv"><b>Вердикт</b><span style="color:${c};font-weight:700">${esc(d.verdict)}</span></div>`+
  kv("Длина",d.length)+kv("Энтропия",d.entropy_bits+" бит")+kv("Алфавит",d.charset_size+" симв.")+kv("Подбор (offline)",d.crack_time_offline)+
  (d.notes&&d.notes.length?`<div class="mu" style="margin-top:6px;font-size:11px;color:var(--bad)">⚠ ${esc(d.notes.join("; "))}</div>`:"");}
 if(id==="hash"){const hh=d.hashes;return Object.keys(hh).map(k=>`<div class="kv"><b>${k.toUpperCase()}</b><span class="sha" style="font-family:monospace;font-size:11px;cursor:pointer" onclick="navigator.clipboard&&navigator.clipboard.writeText('${hh[k]}')">${esc(hh[k])}</span></div>`).join("");}
 if(id==="hash_id")return kv("Длина",d.length)+kv("Вероятный тип",(d.possible||[]).join(" / "));
 if(id==="transform")return `<pre>${esc(d.result)}</pre>`;
 // ----- разведка сайта -----
 if(id==="site_recon"){const tech=(d.technologies||[]).map(x=>`<span class="tag good">${esc(x)}</span>`).join("")||'<span class="mu">—</span>';
  const socn=(d.socials||[]).map(x=>`<span class="tag">${esc(x)}</span>`).join("")||"—";
  const em=(d.emails||[]).map(x=>`<span class="tag">${esc(x)}</span>`).join("")||'<span class="mu">не найдено</span>';
  const ed=(d.external_domains||[]).slice(0,40).map(x=>`<span class="tag">${esc(x)}</span>`).join("");
  let h=`<div style="display:grid;grid-template-columns:1fr 1fr;gap:4px 18px">`;
  h+=kv("Хост",d.host)+kv("Статус",d.status)+kv("Заголовок",d.title)+kv("Язык",d.language)+
     kv("Сервер",d.server)+kv("Powered-by",d.powered_by)+kv("Размер",d.page_size_kb+" KB")+
     kv("Ссылки",`${d.links_internal} внутр. / ${d.links_external} внеш.`)+
     kv("Формы",d.forms+(d.has_login_form?" (есть форма входа)":""))+
     kv("Sec-заголовки",`${(d.security_headers||[]).length}/${d.security_headers_total}`)+`</div>`;
  if(d.description)h+=kv("Описание",d.description);
  if(d.generator)h+=kv("Generator",d.generator);
  if(d.canonical)h+=kv("Canonical",d.canonical);
  h+=`<div style="margin-top:8px"><b style="color:var(--ac2)">Технологии</b><div style="margin-top:5px">${tech}</div></div>`;
  h+=`<div style="margin-top:8px"><b style="color:var(--ac2)">Соцсети</b><div style="margin-top:5px">${socn}</div></div>`;
  h+=`<div style="margin-top:8px"><b style="color:var(--ac2)">Email на странице</b><div style="margin-top:5px">${em}</div></div>`;
  if(ed)h+=`<div style="margin-top:8px"><b style="color:var(--ac2)">Внешние домены</b><div style="margin-top:5px">${ed}</div></div>`;
  return h;}
 if(id==="tech")return kv("URL",d.final)+kv("Сервер",d.server)+kv("Powered-by",d.powered_by)+
  `<div style="margin-top:6px">${(d.technologies||[]).map(x=>`<span class="tag good">${esc(x)}</span>`).join("")||'<span class="mu">не определено</span>'}</div>`;
 if(id==="robots"){let h=kv("robots.txt",d.robots_found?"✓ есть":"нет")+kv("User-agent блоков",d.user_agents)+kv("Sitemap",(d.sitemaps||[]).join(" "))+kv("URL в sitemap",d.sitemap_urls_count);
  if((d.disallow||[]).length)h+=`<div style="margin-top:8px"><b style="color:var(--ac2)">Disallow</b><div style="margin-top:5px">${d.disallow.slice(0,60).map(x=>`<span class="tag miss">${esc(x)}</span>`).join("")}</div></div>`;
  if((d.sitemap_urls||[]).length)h+=`<div style="margin-top:8px"><b style="color:var(--ac2)">URL из карты</b><div style="margin-top:5px;max-height:160px;overflow:auto">${d.sitemap_urls.slice(0,120).map(x=>`<div style="font-size:11px;color:var(--mu)">${esc(x)}</div>`).join("")}</div></div>`;
  return h;}
 if(id==="redirects"){let h=kv("Переходов",d.count)+kv("Конечный URL",d.final);
  h+=`<div style="margin-top:8px">`+(d.hops||[]).map((x,i)=>`<div class="kv"><b>${i+1}. ${x.status}</b><span>${esc(x.url)}</span></div>`).join("")+`</div>`;return h;}
 if(id==="favicon")return kv("Favicon",d.favicon_url?'<a class="url" target="_blank" href="'+esc(d.favicon_url)+'">открыть</a>':"—")+
  `<div class="kv"><b>mmh3 (Shodan)</b><span style="font-weight:700;color:var(--ac2)">${esc(d.mmh3)}</span></div>`+
  kv("MD5",d.md5)+kv("Размер",d.bytes+" байт")+
  kv("Shodan-поиск",'<a class="url" target="_blank" href="'+esc(d.shodan_url)+'">'+esc(d.shodan)+'</a>');
 if(id==="email_sec"){const b=v=>v?'<span style="color:var(--ok)">✓</span>':'<span style="color:var(--bad)">✗</span>';
  return `<div class="kv"><b>Постура</b><span style="font-weight:700">${esc(d.posture_score)}</span></div>`+
  `<div class="kv"><b>SPF</b><span>${b(d.spf)} ${d.spf?esc(d.spf.slice(0,80)):"нет"}</span></div>`+
  `<div class="kv"><b>DMARC</b><span>${b(d.dmarc)} ${d.dmarc?esc(d.dmarc.slice(0,80)):"нет"}</span></div>`+
  `<div class="kv"><b>DKIM</b><span>${b((d.dkim_selectors||[]).length)} ${(d.dkim_selectors||[]).join(", ")||"не найдены частые селекторы"}</span></div>`+
  `<div class="kv"><b>MX</b><span>${b(d.has_mx)} ${(d.mx||[]).slice(0,3).join(", ")}</span></div>`;}
 if(id==="security_txt")return d.found?kv("Найден",'✓ '+esc(d.url))+Object.keys(d.fields||{}).map(k=>kv(k,(d.fields[k]||[]).join(", "))).join(""):kv("security.txt","не найден");
 if(id==="rdap"){const ev=d.events||{};let h=kv("Тип",d.type)+kv("Имя/диапазон",d.name)+kv("Handle",d.handle)+kv("Страна",d.country)+kv("Статусы",(d.status||[]).join(", "));
  if(d.start)h+=kv("Диапазон",d.start+" – "+d.end);
  for(const k in ev)h+=kv(k,ev[k]);
  if((d.entities||[]).length)h+=kv("Контакты",(d.entities||[]).join("; "));return h;}
 if(id==="reverse_ip"){if(d.error)return `<span style="color:var(--bad)">${esc(d.error)}</span>`;
  return kv("Домены на IP",d.count)+`<div style="margin-top:6px;max-height:200px;overflow:auto">${(d.domains||[]).map(x=>`<span class="tag">${esc(x)}</span>`).join("")}</div>`;}
 // ----- утилиты -----
 if(id==="jwt"){let h=kv("Алгоритм",d.alg)+kv("Тип",d.typ)+kv("Подпись",d.signature_present?"есть":"нет");
  if(d.expiry)h+=`<div class="kv"><b>Срок</b><span style="color:${d.expiry.expired?"var(--bad)":"var(--ok)"}">${d.expiry.expired?"истёк":"действует"} — ${esc(d.expiry.expires)}</span></div>`;
  h+=`<div style="margin-top:6px"><b style="color:var(--ac2)">Payload</b><pre>${esc(JSON.stringify(d.payload,null,2))}</pre></div>`;return h;}
 if(id==="cidr")return kv("Сеть",d.network)+kv("Broadcast",d.broadcast)+kv("Маска",d.netmask+" (/"+d.prefix+")")+kv("Всего адресов",d.total_addresses.toLocaleString("ru"))+kv("Хостов",d.usable_hosts.toLocaleString("ru"))+kv("Диапазон",d.first+" – "+d.last)+kv("Приватная",d.is_private?"да":"нет");
 if(id==="timestamp")return kv("Unix",d.unix)+kv("Unix (мс)",d.unix_ms)+kv("ISO UTC",d.iso_utc)+kv("RFC",d.rfc)+kv("День недели",d.weekday);
 if(id==="uuid")return d.generated?kv("UUID v4",'<span class="sha" style="cursor:pointer" onclick="navigator.clipboard&&navigator.clipboard.writeText(\''+d.generated+'\')">'+esc(d.generated)+'</span>'):kv("UUID",d.uuid)+kv("Версия",d.version)+kv("Вариант",d.variant)+(d.timestamp?kv("Время (v1)",d.timestamp):"");
 if(id==="idn")return kv("Punycode (ASCII)",d.ascii_punycode)+kv("Unicode",d.unicode)+kv("Алфавиты",(d.scripts||[]).join(", "))+(d.homograph_warning?`<div style="margin-top:6px;color:var(--bad);font-size:12px">⚠ Смешанные алфавиты — возможна фишинг-подмена (гомоглифы)</div>`:"");
 if(id==="entropy")return kv("Энтропия",d.entropy+" бит/символ")+kv("Всего",d.bits_total+" бит")+kv("Длина",d.length)+kv("Уникальных",d.unique_chars)+(d.looks_like_secret?`<div style="margin-top:6px;color:var(--warn);font-size:12px">⚠ Похоже на ключ/токен/секрет</div>`:"");
 if(id==="luhn")return `<div class="kv"><b>Результат</b><span style="font-weight:700;color:${d.valid?"var(--ok)":"var(--bad)"}">${d.valid?"✓ валиден":"✗ невалиден"}</span></div>`+kv("Цифр",d.digits);
 if(id==="base")return kv("DEC",d.decimal)+kv("HEX",d.hex)+kv("OCT",d.octal)+kv("BIN",d.binary)+kv("Бит",d.bit_length);
 if(id==="dork"){const L=d.links||{};return Object.keys(L).map(k=>`<div class="kv"><b>${esc(k)}</b><span><a class="url" target="_blank" href="${esc(L[k])}">открыть поиск ↗</a></span></div>`).join("");}
 return '<pre>'+esc(JSON.stringify(d,null,2))+'</pre>';}

/* ---------- верхние действия ---------- */
async function addUrls(){const list=$("#url").value.split(/[\s,]+/).filter(Boolean);if(!list.length)return;
 if(!cur)return toast("Сначала создайте кейс","bad");const b=$("#add");b.classList.add("loading");let n=0;
 for(const u of list){try{const r=await api("add",{case:cur.id,url:u});n++;toast(n+"/"+list.length+": "+r.status,r.status.startsWith("OK")?"ok":"bad")}catch(e){toast(e.message,"bad")}await refresh()}
 b.classList.remove("loading");$("#url").value=""}
$("#add").onclick=addUrls;$("#url").onkeydown=e=>{if(e.key==="Enter")addUrls()};
$("#ver").onclick=async()=>{if(!cur)return;await refresh();const i=st.integrity;
 toast("Снимки: "+i.snap_ok+" целы, "+i.snap_bad+" нарушены. Журнал: "+(i.chain?"цел":"НАРУШЕН"),i.snap_bad||!i.chain?"bad":"ok")};
$("#rep").onclick=()=>{if(cur){window.open("/report?case="+cur.id+"&t="+T,"_blank");setTimeout(refresh,600)}};
window.addEventListener("load",()=>{renderTools();moveInk();sizeCv();loadCases()});
</script></body></html>
"""

if __name__ == "__main__":
    main()
