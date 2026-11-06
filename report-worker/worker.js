// Cloudflare Worker: приём и хранение технических отчётов dpi-bypass (версия сервера 2).
//
// Настройка (один раз, бесплатно) - подробно в report-worker/README.md:
//   1. Storage & Databases -> D1 -> Create database "dpi-reports".
//   2. Workers & Pages -> Create -> Worker "dpi-reports" -> Edit code -> вставить этот файл -> Deploy.
//   3. Worker -> Settings -> Bindings -> Add -> D1 database: имя переменной DB, база dpi-reports.
//   4. Worker -> Settings -> Variables and Secrets -> Add -> Secret, имя ADMIN_KEY, значение - длинный пароль.
//   5. Адрес https://dpi-reports.<аккаунт>.workers.dev вписать в update/update.json -> "report_url".
//
// Программа шлёт POST /report (JSON). Просмотр: https://<адрес>/?key=ADMIN_KEY
// Обновление этого файла безопасно: новые столбцы добавляются в старую базу сами.

const MAX_BODY = 512 * 1024;      // самый большой отчёт
const KEEP_DAYS = 90;             // сколько хранить
const PER_IP_PER_HOUR = 60;       // защита от спама

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS reports (
     id TEXT PRIMARY KEY, ts INTEGER NOT NULL, ip TEXT, country TEXT, city TEXT, asn INTEGER, isp TEXT,
     platform TEXT, version TEXT, trigger TEXT, sites_ok INTEGER, sites_total INTEGER, errors INTEGER,
     summary TEXT, body TEXT NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS reports_ts ON reports(ts)`,
  `CREATE INDEX IF NOT EXISTS reports_ip_ts ON reports(ip, ts)`,
];
// столбцы версии 2 (добавляются к старой таблице; ошибка "duplicate column" - значит уже есть)
const COLUMNS = [
  "device TEXT", "model TEXT", "cts INTEGER", "nip TEXT", "nisp TEXT", "nasn TEXT", "ncity TEXT",
  "net TEXT", "strat TEXT", "bad TEXT", "err TEXT", "mode TEXT",
];

let schemaReady = false;
async function ensureSchema(db) {
  if (schemaReady) return;
  await db.batch(SCHEMA.map((s) => db.prepare(s)));
  for (const c of COLUMNS) {
    try { await db.prepare("ALTER TABLE reports ADD COLUMN " + c).run(); } catch (e) { /* уже есть */ }
  }
  try { await db.prepare("CREATE INDEX IF NOT EXISTS reports_dev_ts ON reports(device, ts)").run(); } catch (e) {}
  // отчёты, сохранённые до версии 2: заполнить новые столбцы из тела отчёта
  try {
    const { results } = await db.prepare("SELECT id, body FROM reports WHERE cts IS NULL LIMIT 300").all();
    for (const row of results) {
      let x;
      try { x = extract(JSON.parse(row.body)); } catch { x = extract({}); }
      await db.prepare("UPDATE reports SET device=?, model=?, cts=?, nip=?, nisp=?, nasn=?, ncity=?, net=?, strat=?, bad=?, err=?, mode=? WHERE id=?")
        .bind(x.device, x.model, x.cts, x.nip, x.nisp, x.nasn, x.ncity, x.net, x.strat, x.bad, x.err, x.mode, row.id).run();
    }
  } catch (e) {}
  schemaReady = true;
}

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8" } });

function newId() {
  const b = new Uint8Array(5);
  crypto.getRandomValues(b);
  return [...b].map((x) => x.toString(36).padStart(2, "0")).join("").slice(0, 8).toUpperCase();
}

const str = (v, n) => String(v == null ? "" : v).slice(0, n);

// поля для списка и сводки из тела отчёта (форматы Windows и Android немного различаются)
function extract(r) {
  const sites = Array.isArray(r.sites) ? r.sites : [];
  const ok = sites.filter((s) => s && s.ok).length;
  const bad = sites.filter((s) => s && !s.ok).map((s) => s.name);
  const st = r.strategy || {};
  let strat = st.current || (st.groups || []).map((g) => g.id).join("+") || "";
  if (!strat && r.plan && r.plan.default) strat = [r.plan.default].concat((r.plan.groups || []).map((g) => g.strategy)).join("+");
  const dev = r.device || {};
  let model = "";
  if (r.app && r.app.platform === "android") {
    model = [dev.marketing_name || "", (dev.manufacturer || "") + " " + (dev.model || "")].filter((x) => x.trim()).join(" · ");
    if (dev.release) model += " · Android " + dev.release;
  } else {
    model = [dev.edition || "Windows", dev.build ? "build " + dev.build : "", dev.cpu || ""].filter(Boolean).join(" · ");
  }
  const n = r.network || {};
  const vpn = r.vpn && r.vpn.detected ? "VPN " + ((r.vpn.clients || [])[0] || r.vpn.name || "да") : "";
  const tgc = r.telegram && r.telegram.connections;
  const tg = tgc && tgc.total ? `TG ${tgc.total - tgc.failed}/${tgc.total}` : "";
  const errs = Array.isArray(r.errors) ? r.errors : [];
  const crash = r.crash ? String(r.crash).split("\n")[0] : "";
  return {
    ok, total: sites.length, bad: bad.join(","), strat: str(strat, 100), model: str(model, 120),
    device: /^[a-zA-Z0-9-]{4,64}$/.test(r.device_id || "") ? r.device_id : "",
    cts: Date.parse(r.time) || 0,
    nip: str(n.ip, 45), nisp: str(n.isp, 80), nasn: str(n.asn, 20), ncity: str([n.city, n.country].filter(Boolean).join(", "), 60),
    net: str([n.type, n.operator].filter(Boolean).join(" "), 40),
    err: str(crash || errs[errs.length - 1] || "", 300), mode: str(r.app && r.app.mode, 20),
    text: [strat && "стратегия " + strat, bad.length && "none: " + bad.join(", "), vpn, tg, crash && "ПАДЕНИЕ"].filter(Boolean).join(" · "),
  };
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
  const x = extract(r);
  await env.DB.prepare(
    `INSERT INTO reports (id, ts, ip, country, city, asn, isp, platform, version, trigger, sites_ok, sites_total, errors, summary, body,
       device, model, cts, nip, nisp, nasn, ncity, net, strat, bad, err, mode)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(id, now, ip, cf.country || "", cf.city || "", cf.asn || 0, cf.asOrganization || "",
    str(r.app.platform, 20), str(r.app.version, 20), str(r.trigger, 20),
    x.ok, x.total, Array.isArray(r.errors) ? r.errors.length : 0, str(x.text, 500), JSON.stringify(r),
    x.device, x.model, x.cts, x.nip, x.nisp, x.nasn, x.ncity, x.net, x.strat, x.bad, x.err, x.mode).run();

  if (Math.random() < 0.02) {
    await env.DB.prepare("DELETE FROM reports WHERE ts < ?").bind(now - KEEP_DAYS * 86400e3).run();
  }
  return json({ id });
}

function authorized(url, env) {
  return env.ADMIN_KEY && url.searchParams.get("key") === env.ADMIN_KEY;
}

const LIST_COLS = `id, ts, cts, ip, country, city, asn, isp, platform, version, trigger, sites_ok, sites_total, errors, summary,
  device, model, nip, nisp, nasn, ncity, net, strat, bad, err, mode`;

async function handleList(url, env) {
  await ensureSchema(env.DB);
  const where = [], args = [];
  const p = url.searchParams;
  if (p.get("platform")) { where.push("platform = ?"); args.push(p.get("platform")); }
  if (p.get("trigger")) { where.push("trigger = ?"); args.push(p.get("trigger")); }
  if (p.get("device")) { where.push("device = ?"); args.push(p.get("device")); }
  if (p.get("q")) {
    where.push("(ip LIKE ? OR isp LIKE ? OR nip LIKE ? OR nisp LIKE ? OR model LIKE ? OR summary LIKE ? OR err LIKE ? OR id = ?)");
    const q = "%" + p.get("q") + "%";
    args.push(q, q, q, q, q, q, q, p.get("q").toUpperCase());
  }
  if (p.get("before")) { where.push("ts < ?"); args.push(Number(p.get("before"))); }
  const sql = `SELECT ${LIST_COLS} FROM reports ${where.length ? "WHERE " + where.join(" AND ") : ""} ORDER BY ts DESC LIMIT 100`;
  const { results } = await env.DB.prepare(sql).bind(...args).all();
  return json({ reports: results });
}

// устройства: последний отчёт каждого + счётчики
async function handleDevices(env) {
  await ensureSchema(env.DB);
  const { results } = await env.DB.prepare(
    `SELECT r.device, r.platform, r.model, r.version, r.ts, r.nisp, r.nasn, r.ncity, r.net, r.sites_ok, r.sites_total, r.summary, r.strat,
            a.n, a.first, a.crashes, a.with_errors
     FROM reports r JOIN (
       SELECT device, COUNT(*) AS n, MIN(ts) AS first, MAX(ts) AS last,
              SUM(trigger = 'crash') AS crashes, SUM(errors > 0) AS with_errors
       FROM reports WHERE device IS NOT NULL AND device != '' GROUP BY device
     ) a ON a.device = r.device AND a.last = r.ts
     ORDER BY r.ts DESC LIMIT 300`
  ).all();
  const old = await env.DB.prepare("SELECT COUNT(*) AS n FROM reports WHERE device IS NULL OR device = ''").first();
  return json({ devices: results, without_id: old ? old.n : 0 });
}

// сводка за N дней
async function handleSummary(url, env) {
  await ensureSchema(env.DB);
  const days = Math.min(90, Math.max(1, Number(url.searchParams.get("days")) || 7));
  const since = Date.now() - days * 86400e3;
  const q = (sql, ...a) => env.DB.prepare(sql).bind(since, ...a).all().then((x) => x.results);
  const [tot, plat, ver, isps, strats, trig, errs, rows] = await Promise.all([
    q(`SELECT COUNT(*) AS reports, COUNT(DISTINCT NULLIF(device,'')) AS devices, SUM(trigger='crash') AS crashes,
              SUM(errors > 0) AS with_errors, SUM(sites_total > 0 AND sites_ok = sites_total) AS all_ok FROM reports WHERE ts > ?`),
    q(`SELECT platform, COUNT(*) AS n, COUNT(DISTINCT NULLIF(device,'')) AS devices FROM reports WHERE ts > ? GROUP BY platform ORDER BY n DESC`),
    q(`SELECT platform, version, COUNT(*) AS n FROM reports WHERE ts > ? GROUP BY platform, version ORDER BY n DESC LIMIT 12`),
    q(`SELECT COALESCE(NULLIF(nisp,''), isp) AS isp, COALESCE(NULLIF(nasn,''), 'AS' || asn) AS asn, COUNT(*) AS n,
              COUNT(DISTINCT NULLIF(device,'')) AS devices, SUM(sites_ok) AS ok, SUM(sites_total) AS total
       FROM reports WHERE ts > ? GROUP BY 1, 2 ORDER BY n DESC LIMIT 15`),
    q(`SELECT platform, strat, COUNT(*) AS n, SUM(sites_ok) AS ok, SUM(sites_total) AS total
       FROM reports WHERE ts > ? AND strat IS NOT NULL AND strat != '' GROUP BY platform, strat ORDER BY n DESC LIMIT 15`),
    q(`SELECT trigger, COUNT(*) AS n FROM reports WHERE ts > ? GROUP BY trigger ORDER BY n DESC`),
    q(`SELECT err, platform, COUNT(*) AS n, MAX(ts) AS last, MAX(id) AS id FROM reports WHERE ts > ? AND err IS NOT NULL AND err != ''
       GROUP BY substr(err, 1, 80), platform ORDER BY n DESC LIMIT 15`),
    q(`SELECT bad FROM reports WHERE ts > ? AND bad IS NOT NULL AND bad != '' LIMIT 5000`),
  ]);
  const sites = {};
  for (const r of rows) for (const s of r.bad.split(",")) if (s) sites[s] = (sites[s] || 0) + 1;
  const badSites = Object.entries(sites).sort((a, b) => b[1] - a[1]).slice(0, 15).map(([name, n]) => ({ name, n }));
  return json({ days, total: tot[0] || {}, platforms: plat, versions: ver, isps, strategies: strats, triggers: trig, errors: errs, bad_sites: badSites });
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
:root{color-scheme:dark;--bg:#0b0e1f;--card:#151a36;--line:#262d55;--text:#e8eaf8;--dim:#9aa0c4;--ok:#6ee7b7;--bad:#fca5a5;--warn:#fcd34d;--acc:#6f8cff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 system-ui,Segoe UI,Roboto,sans-serif}
header{padding:12px 16px;display:flex;gap:8px;flex-wrap:wrap;align-items:center;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--bg);z-index:2}
header b{font-size:17px;margin-right:8px}.tabs{display:flex;gap:4px;margin-right:auto}
input,select,button{background:var(--card);color:var(--text);border:1px solid var(--line);border-radius:10px;padding:7px 10px;font:inherit}
button{cursor:pointer}.tab.on{background:var(--acc);border-color:var(--acc);color:#fff}
main{padding:12px 16px;max-width:1400px}.dim{color:var(--dim)}.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}
table{width:100%;border-collapse:collapse}td,th{padding:7px 6px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{color:var(--dim);font-weight:600;font-size:12px}tr.r{cursor:pointer}tr.r:hover{background:#1b2146}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:12px 14px}.card h3{margin:0 0 8px;font-size:14px;color:var(--dim);font-weight:600}
.kpis{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px}.kpi{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:10px 14px;min-width:120px}
.kpi b{display:block;font-size:22px}.kpi span{color:var(--dim);font-size:12px}
.bar{height:6px;border-radius:9px;background:#262d55;overflow:hidden;margin-top:3px}.bar i{display:block;height:100%;background:var(--ok)}
.tag{display:inline-block;padding:1px 7px;border-radius:999px;border:1px solid var(--line);font-size:11.5px;color:var(--dim);margin-right:4px}
pre{white-space:pre-wrap;word-break:break-word;background:#0f1330;border:1px solid var(--line);border-radius:10px;padding:12px;font:12px/1.5 ui-monospace,Consolas,monospace;max-height:70vh;overflow:auto}
#filter{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;align-items:center}
@media(max-width:760px){.h{display:none}}
</style></head><body><header><b>dpi-bypass</b><div class="tabs"><button class="tab" data-t="sum">Сводка</button><button class="tab" data-t="dev">Устройства</button><button class="tab" data-t="rep">Отчёты</button></div>
<select id="days"><option value="1">сутки</option><option value="7" selected>7 дней</option><option value="30">30 дней</option><option value="90">90 дней</option></select></header>
<main id="m"></main>
<script>
const key=new URLSearchParams(location.search).get("key");const m=document.getElementById("m");
const esc=s=>String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const api=(p,o)=>fetch(p+(p.includes("?")?"&":"?")+"key="+encodeURIComponent(key),o).then(r=>r.json());
const dt=t=>t?new Date(t).toLocaleString():"";
const ago=t=>{const s=(Date.now()-t)/1e3;return s<90?"только что":s<5400?Math.round(s/60)+" мин назад":s<172800?Math.round(s/3600)+" ч назад":Math.round(s/86400)+" дн назад"};
const pct=(a,b)=>b?Math.round(100*a/b):0;
const bar=(a,b)=>'<div class="bar"><i style="width:'+pct(a,b)+'%"></i></div>';
let tab="sum",devF="",last=0;
document.querySelectorAll(".tab").forEach(b=>b.onclick=()=>show(b.dataset.t));
days.onchange=()=>show(tab);
function show(t,dev){tab=t;if(dev!==undefined)devF=dev;document.querySelectorAll(".tab").forEach(b=>b.classList.toggle("on",b.dataset.t===t));
  m.innerHTML='<p class="dim">Загрузка…</p>';({sum:sum,dev:devs,rep:reps})[t]()}
function table(head,rows){return "<table><thead><tr>"+head.map(h=>"<th>"+h+"</th>").join("")+"</tr></thead><tbody>"+rows.join("")+"</tbody></table>"}
async function sum(){const d=await api("/api/summary?days="+days.value);const t=d.total||{};
  let h='<div class="kpis">'+[["Отчётов",t.reports],["Устройств",t.devices],["Всё открылось",t.all_ok],["С ошибками",t.with_errors],["Падений",t.crashes]].map(([a,b])=>'<div class="kpi"><b class="'+(a==="Падений"&&b?"bad":"")+'">'+(b||0)+'</b><span>'+a+'</span></div>').join("")+'</div><div class="grid">';
  h+='<div class="card"><h3>Платформы и версии</h3>'+table(["","отчётов","устройств"],(d.platforms||[]).map(x=>"<tr><td>"+esc(x.platform)+"</td><td>"+x.n+"</td><td>"+x.devices+"</td></tr>"))+'<div style="margin-top:8px">'+(d.versions||[]).map(v=>'<span class="tag">'+esc(v.platform+" "+v.version)+" · "+v.n+"</span>").join("")+'</div></div>';
  h+='<div class="card"><h3>Провайдеры (доля открытых сайтов)</h3>'+table(["провайдер","отчётов","сайты"],(d.isps||[]).map(x=>"<tr><td>"+esc(x.isp||"?")+'<div class="dim">'+esc(x.asn||"")+" · устройств "+x.devices+"</div></td><td>"+x.n+"</td><td>"+pct(x.ok,x.total)+"%"+bar(x.ok,x.total)+"</td></tr>"))+'</div>';
  h+='<div class="card"><h3>Стратегии</h3>'+table(["стратегия","отчётов","сайты"],(d.strategies||[]).map(x=>"<tr><td>"+esc(x.strat)+'<div class="dim">'+esc(x.platform)+"</div></td><td>"+x.n+"</td><td>"+pct(x.ok,x.total)+"%"+bar(x.ok,x.total)+"</td></tr>"))+'</div>';
  h+='<div class="card"><h3>Чаще всего не открываются</h3>'+table(["сайт","раз"],(d.bad_sites||[]).map(x=>"<tr><td>"+esc(x.name)+"</td><td>"+x.n+"</td></tr>"))+'</div>';
  h+='<div class="card" style="grid-column:1/-1"><h3>Ошибки и падения</h3>'+table(["ошибка","платформа","раз","последняя"],(d.errors||[]).map(x=>'<tr class="r" data-id="'+esc(x.id)+'"><td class="bad">'+esc(x.err)+"</td><td>"+esc(x.platform)+"</td><td>"+x.n+"</td><td>"+ago(x.last)+"</td></tr>"))+'</div>';
  h+='<div class="card"><h3>Поводы отчётов</h3>'+(d.triggers||[]).map(x=>'<span class="tag">'+esc(x.trigger)+" · "+x.n+"</span>").join("")+'</div></div>';
  m.innerHTML=h;m.querySelectorAll("tr.r").forEach(tr=>tr.onclick=()=>openRep(tr,tr.dataset.id,4))}
async function devs(){const d=await api("/api/devices");
  m.innerHTML=table(["Устройство","Последний отчёт","Сеть","Сайты","Итог","Отчётов"],(d.devices||[]).map(x=>'<tr class="r" data-d="'+esc(x.device)+'"><td><b>'+esc(x.model||"?")+'</b><div class="dim">'+esc(x.platform+" "+x.version)+" · id "+esc(x.device.slice(0,10))+"</div></td><td>"+ago(x.ts)+'<div class="dim">первый '+dt(x.first).split(",")[0]+"</div></td><td>"+esc(x.nisp||"")+'<div class="dim">'+esc([x.nasn,x.ncity,x.net].filter(Boolean).join(" · "))+'</div></td><td class="'+(x.sites_ok<x.sites_total?"bad":"ok")+'">'+(x.sites_total?x.sites_ok+"/"+x.sites_total:"")+"</td><td>"+esc(x.summary)+(x.crashes?' <span class="bad">падений '+x.crashes+"</span>":"")+"</td><td>"+x.n+"</td></tr>"))
   +(d.without_id?'<p class="dim">Отчётов без ключа устройства (старые версии программы): '+d.without_id+" - они во вкладке «Отчёты».</p>":"");
  m.querySelectorAll("tr.r").forEach(tr=>tr.onclick=()=>show("rep",tr.dataset.d))}
async function reps(){last=0;m.innerHTML='<div id="filter">'+(devF?'<span class="tag">устройство '+esc(devF.slice(0,10))+'</span><button id="clr">все устройства</button>':"")+
  '<input id="q" placeholder="IP, провайдер, модель, номер, ошибка"><select id="pf"><option value="">все</option><option>windows</option><option>android</option></select><select id="tr"><option value="">любой повод</option><option>launch</option><option>connect</option><option>error</option><option>crash</option><option>manual</option></select><button id="go">Найти</button></div><div id="list"></div><button id="more" style="margin-top:12px">Ещё</button>';
  if(devF)clr.onclick=()=>show("rep","");go.onclick=()=>{last=0;load(false)};more.onclick=()=>load(true);q.onkeydown=e=>{if(e.key==="Enter")go.onclick()};load(false)}
async function load(append){const p=new URLSearchParams({platform:pf.value,trigger:tr.value,q:q.value,device:devF});if(append&&last)p.set("before",last);
  const d=await api("/api/reports?"+p);const L=document.getElementById("list");
  const rows=(d.reports||[]).map(r=>{last=r.ts;const late=r.cts&&r.ts-r.cts>15*60e3;
    return '<tr class="r" data-id="'+esc(r.id)+'"><td>'+dt(r.cts||r.ts)+(late?'<div class="warn">доставлен '+dt(r.ts)+"</div>":"")+"</td><td>"+esc(r.id)+'<div class="dim">'+esc(r.trigger)+"</div></td><td>"+esc(r.model||r.platform)+'<div class="dim">'+esc(r.platform+" "+r.version+(r.mode?" · "+r.mode:""))+'</div></td><td class="h">'+esc(r.nip||r.ip)+'<div class="dim">'+esc([r.nisp||r.isp,r.nasn||(r.asn?"AS"+r.asn:""),r.ncity||[r.country,r.city].filter(Boolean).join(" "),r.net].filter(Boolean).join(" · "))+'</div></td><td class="'+(r.sites_ok<r.sites_total?"bad":"ok")+'">'+(r.sites_total?r.sites_ok+"/"+r.sites_total:"")+(r.errors?' <span class="bad">⚠'+r.errors+"</span>":"")+"</td><td>"+esc(r.summary)+(r.err?'<div class="bad">'+esc(r.err)+"</div>":"")+"</td></tr>"});
  const html=rows.join("");
  if(!append)L.innerHTML=table(["Время","Номер","Устройство","Сеть (с устройства)","Сайты","Итог"],[html]);else L.querySelector("tbody").insertAdjacentHTML("beforeend",html);
  L.querySelectorAll("tr.r:not([data-b])").forEach(tr=>{tr.dataset.b=1;tr.onclick=()=>openRep(tr,tr.dataset.id,6)})}
async function openRep(tr,id,cols){const n=tr.nextSibling;if(n&&n.className==="x"){n.remove();return}
  const b=await api("/api/report/"+id);const x=document.createElement("tr");x.className="x";
  x.innerHTML="<td colspan="+cols+"><pre>"+esc(JSON.stringify(b,null,2))+"</pre></td>";tr.after(x)}
show("sum");
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
      if (req.method === "GET" && url.pathname === "/api/devices") return await handleDevices(env);
      if (req.method === "GET" && url.pathname === "/api/summary") return await handleSummary(url, env);
      const m = url.pathname.match(/^\/api\/report\/([A-Z0-9]{4,12})$/);
      if (m && req.method === "GET") return await handleOne(m[1], env);
      if (m && req.method === "DELETE") return await handleDelete(m[1], env);
      return json({ error: "not found" }, 404);
    } catch (e) {
      return json({ error: String(e && e.message || e) }, 500);
    }
  },
};
