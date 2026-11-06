// Cloudflare Worker: приём и хранение технических отчётов dpi-bypass.
//
// Настройка (один раз, бесплатно) - подробно в report-worker/README.md:
//   1. Storage & Databases -> D1 -> Create database "dpi-reports".
//   2. Workers & Pages -> Create -> Worker "dpi-reports" -> Deploy -> Edit code -> вставить этот файл -> Deploy.
//   3. Worker -> Settings -> Bindings -> Add -> D1 database: имя переменной DB, база dpi-reports.
//   4. Worker -> Settings -> Variables and Secrets -> Add -> тип Secret, имя ADMIN_KEY, значение - длинный пароль.
//   5. Адрес вида https://dpi-reports.<аккаунт>.workers.dev вписать в update/update.json -> "report_url".
//
// Программа шлёт POST /report (JSON). Просмотр: https://<адрес>/?key=ADMIN_KEY

const MAX_BODY = 256 * 1024;      // самый большой отчёт
const KEEP_DAYS = 90;             // сколько хранить
const PER_IP_PER_HOUR = 30;       // защита от спама

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS reports (
     id TEXT PRIMARY KEY, ts INTEGER NOT NULL, ip TEXT, country TEXT, city TEXT, asn INTEGER, isp TEXT,
     platform TEXT, version TEXT, trigger TEXT, sites_ok INTEGER, sites_total INTEGER, errors INTEGER,
     summary TEXT, body TEXT NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS reports_ts ON reports(ts)`,
  `CREATE INDEX IF NOT EXISTS reports_ip_ts ON reports(ip, ts)`,
];

let schemaReady = false;
async function ensureSchema(db) {
  if (schemaReady) return;
  await db.batch(SCHEMA.map((s) => db.prepare(s)));
  schemaReady = true;
}

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8" } });

function newId() {
  const b = new Uint8Array(5);
  crypto.getRandomValues(b);
  return [...b].map((x) => x.toString(36).padStart(2, "0")).join("").slice(0, 8).toUpperCase();
}

function summarize(r) {
  const sites = Array.isArray(r.sites) ? r.sites : [];
  const ok = sites.filter((s) => s && s.ok).length;
  const bad = sites.filter((s) => s && !s.ok).map((s) => s.name);
  const st = r.strategy && (r.strategy.current || (r.strategy.groups || []).map((g) => g.id).join("+"));
  const vpn = r.vpn && r.vpn.detected ? "VPN " + ((r.vpn.clients || [])[0] || r.vpn.name || "да") : "";
  const tg = r.telegram && r.telegram.connections ? `TG ${r.telegram.connections.total - r.telegram.connections.failed}/${r.telegram.connections.total}` : "";
  return { ok, total: sites.length, text: [st && "стратегия " + st, bad.length && "none: " + bad.join(", "), vpn, tg].filter(Boolean).join(" · ") };
}

async function handleReport(req, env) {
  const len = Number(req.headers.get("content-length") || 0);
  if (len > MAX_BODY) return json({ error: "too large" }, 413);
  const text = await req.text();
  if (text.length > MAX_BODY) return json({ error: "too large" }, 413);
  let r;
  try { r = JSON.parse(text); } catch { return json({ error: "bad json" }, 400); }
  if (!r || typeof r !== "object" || !r.app || typeof r.app.platform !== "string") return json({ error: "bad report" }, 400);

  const ip = req.headers.get("CF-Connecting-IP") || "";
  const cf = req.cf || {};
  const now = Date.now();
  await ensureSchema(env.DB);
  const recent = await env.DB.prepare("SELECT COUNT(*) AS n FROM reports WHERE ip = ? AND ts > ?").bind(ip, now - 3600e3).first();
  if (recent && recent.n >= PER_IP_PER_HOUR) return json({ error: "rate limited" }, 429);

  const id = newId();
  r.server = { received: new Date(now).toISOString(), ip, country: cf.country || "", city: cf.city || "", region: cf.region || "", asn: cf.asn || 0, isp: cf.asOrganization || "" };
  const s = summarize(r);
  await env.DB.prepare(
    `INSERT INTO reports (id, ts, ip, country, city, asn, isp, platform, version, trigger, sites_ok, sites_total, errors, summary, body)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(id, now, ip, cf.country || "", cf.city || "", cf.asn || 0, cf.asOrganization || "",
    String(r.app.platform).slice(0, 20), String(r.app.version || "").slice(0, 20), String(r.trigger || "").slice(0, 20),
    s.ok, s.total, Array.isArray(r.errors) ? r.errors.length : 0, s.text.slice(0, 500), JSON.stringify(r)).run();

  if (Math.random() < 0.02) {
    await env.DB.prepare("DELETE FROM reports WHERE ts < ?").bind(now - KEEP_DAYS * 86400e3).run();
  }
  return json({ id });
}

function authorized(url, env) {
  return env.ADMIN_KEY && url.searchParams.get("key") === env.ADMIN_KEY;
}

async function handleList(url, env) {
  await ensureSchema(env.DB);
  const where = [], args = [];
  const p = url.searchParams;
  if (p.get("platform")) { where.push("platform = ?"); args.push(p.get("platform")); }
  if (p.get("trigger")) { where.push("trigger = ?"); args.push(p.get("trigger")); }
  if (p.get("q")) { where.push("(ip LIKE ? OR isp LIKE ? OR summary LIKE ? OR id = ?)"); const q = "%" + p.get("q") + "%"; args.push(q, q, q, p.get("q").toUpperCase()); }
  if (p.get("before")) { where.push("ts < ?"); args.push(Number(p.get("before"))); }
  const sql = `SELECT id, ts, ip, country, city, asn, isp, platform, version, trigger, sites_ok, sites_total, errors, summary
               FROM reports ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY ts DESC LIMIT 100`;
  const { results } = await env.DB.prepare(sql).bind(...args).all();
  const stats = await env.DB.prepare(
    "SELECT platform, COUNT(*) AS n, SUM(errors > 0) AS with_errors FROM reports WHERE ts > ? GROUP BY platform"
  ).bind(Date.now() - 86400e3).all();
  return json({ reports: results, last24h: stats.results });
}

async function handleOne(id, env) {
  await ensureSchema(env.DB);
  const row = await env.DB.prepare("SELECT body FROM reports WHERE id = ?").bind(id).first();
  if (!row) return json({ error: "not found" }, 404);
  return new Response(row.body, { headers: { "content-type": "application/json; charset=utf-8" } });
}

async function handleDelete(id, env) {
  await ensureSchema(env.DB);
  await env.DB.prepare("DELETE FROM reports WHERE id = ?").bind(id).run();
  return json({ deleted: id });
}

const PAGE = `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>dpi-bypass reports</title><style>
:root{color-scheme:dark;--bg:#0b0e1f;--card:#151a36;--line:#262d55;--text:#e8eaf8;--dim:#9aa0c4;--ok:#6ee7b7;--bad:#fca5a5;--acc:#6f8cff}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 system-ui,Segoe UI,Roboto,sans-serif}
header{padding:16px;display:flex;gap:10px;flex-wrap:wrap;align-items:center;border-bottom:1px solid var(--line)}
header b{font-size:17px;margin-right:auto}input,select,button{background:var(--card);color:var(--text);border:1px solid var(--line);border-radius:10px;padding:8px 10px;font:inherit}
button{cursor:pointer}main{padding:12px 16px}#stats{color:var(--dim);margin-bottom:10px}
table{width:100%;border-collapse:collapse}td,th{padding:8px 6px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{color:var(--dim);font-weight:600;font-size:12px}tr.r{cursor:pointer}tr.r:hover{background:#1b2146}
.ok{color:var(--ok)}.bad{color:var(--bad)}.dim{color:var(--dim)}pre{white-space:pre-wrap;word-break:break-word;background:#0f1330;border:1px solid var(--line);border-radius:10px;padding:12px;font:12px/1.5 ui-monospace,Consolas,monospace;max-height:70vh;overflow:auto}
@media(max-width:700px){.h{display:none}}
</style></head><body><header><b>dpi-bypass · отчёты</b>
<input id="q" placeholder="IP, провайдер, номер, сайт"><select id="pf"><option value="">все</option><option>windows</option><option>android</option></select>
<select id="tr"><option value="">любой повод</option><option>launch</option><option>connect</option><option>error</option><option>manual</option></select><button id="go">Найти</button></header>
<main><div id="stats"></div><table><thead><tr><th>Время</th><th>Номер</th><th>Платформа</th><th class="h">IP / провайдер</th><th>Сайты</th><th>Итог</th></tr></thead><tbody id="rows"></tbody></table><button id="more" style="margin-top:12px">Ещё</button></main>
<script>
const key=new URLSearchParams(location.search).get("key");let last=0;
const esc=s=>String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
async function load(append){
  const p=new URLSearchParams({key,platform:pf.value,trigger:tr.value,q:q.value});if(append&&last)p.set("before",last);
  const d=await (await fetch("/api/reports?"+p)).json();
  stats.textContent="За сутки: "+(d.last24h||[]).map(x=>x.platform+" "+x.n+" (с ошибками "+x.with_errors+")").join(", ");
  if(!append)rows.innerHTML="";
  for(const r of d.reports){last=r.ts;const tr=document.createElement("tr");tr.className="r";
    tr.innerHTML="<td>"+new Date(r.ts).toLocaleString()+"</td><td>"+esc(r.id)+"<div class=dim>"+esc(r.trigger)+"</div></td><td>"+esc(r.platform)+" "+esc(r.version)+"</td><td class=h>"+esc(r.ip)+"<div class=dim>"+esc(r.isp)+" · AS"+esc(r.asn)+" · "+esc(r.country)+" "+esc(r.city)+"</div></td><td class="+(r.sites_ok<r.sites_total?"bad":"ok")+">"+r.sites_ok+"/"+r.sites_total+(r.errors?" <span class=bad>⚠"+r.errors+"</span>":"")+"</td><td>"+esc(r.summary)+"</td>";
    tr.onclick=async()=>{const n=tr.nextSibling;if(n&&n.className==="x"){n.remove();return}
      const b=await (await fetch("/api/report/"+r.id+"?key="+encodeURIComponent(key))).json();
      const x=document.createElement("tr");x.className="x";x.innerHTML="<td colspan=6><pre>"+esc(JSON.stringify(b,null,2))+"</pre></td>";tr.after(x)};
    rows.appendChild(tr)}
}
go.onclick=()=>{last=0;load(false)};more.onclick=()=>load(true);q.onkeydown=e=>{if(e.key==="Enter")go.onclick()};load(false);
</script></body></html>`;

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    try {
      if (req.method === "POST" && url.pathname === "/report") return await handleReport(req, env);
      if (req.method === "GET" && url.pathname === "/") {
        if (!authorized(url, env)) return new Response("dpi-bypass reports: ok");
        return new Response(PAGE, { headers: { "content-type": "text/html; charset=utf-8" } });
      }
      if (!authorized(url, env)) return json({ error: "forbidden" }, 403);
      if (req.method === "GET" && url.pathname === "/api/reports") return await handleList(url, env);
      const m = url.pathname.match(/^\/api\/report\/([A-Z0-9]{4,12})$/);
      if (m && req.method === "GET") return await handleOne(m[1], env);
      if (m && req.method === "DELETE") return await handleDelete(m[1], env);
      return json({ error: "not found" }, 404);
    } catch (e) {
      return json({ error: String(e && e.message || e) }, 500);
    }
  },
};
