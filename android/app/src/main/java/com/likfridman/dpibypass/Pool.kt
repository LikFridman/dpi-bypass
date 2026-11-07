package com.likfridman.dpibypass

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.util.concurrent.TimeUnit

/** Группа сайтов со своей стратегией. */
data class PlanGroup(val strategy: String, val sites: List<String>)

/**
 * План обхода: стратегия по умолчанию (для всего трафика) и отдельные стратегии для
 * сайтов, которым нужна другая. ytKBps - скорость видео YouTube при выборе.
 */
data class Plan(val default: String, val groups: List<PlanGroup>, val ytKBps: Int = 0, val backup: String = "") {
    fun toJson(): JSONObject = JSONObject().put("default", default).put("yt_kbps", ytKBps).put("backup", backup)
        .put("groups", JSONArray(groups.map { JSONObject().put("strategy", it.strategy).put("sites", JSONArray(it.sites)) }))

    /** Какая стратегия отвечает за сайт */
    fun strategyFor(site: String) = groups.firstOrNull { site in it.sites }?.strategy ?: default

    companion object {
        fun fromJson(s: String?): Plan? = runCatching {
            val o = JSONObject(s!!)
            val g = o.getJSONArray("groups")
            Plan(o.getString("default"), (0 until g.length()).map { i ->
                val x = g.getJSONObject(i)
                val a = x.getJSONArray("sites")
                PlanGroup(x.getString("strategy"), (0 until a.length()).map { a.getString(it) })
            }, o.optInt("yt_kbps"), o.optString("backup"))
        }.getOrNull()
    }
}

/**
 * Процессы обхода: byedpi со стратегией по умолчанию, копии byedpi для отдельных сайтов,
 * byedpi для UDP и маршрутизатор (libtgproxy.so -router), который раскладывает трафик туннеля.
 */
object Pool {
    /** args - что запускаем (с запасной стратегией), base - без неё (если byedpi не примет) */
    private data class Proc(val args: List<String>, var p: Process?, val base: List<String> = args)

    private val procs = LinkedHashMap<Int, Proc>() // порт -> процесс
    @Volatile private var router: Process? = null
    @Volatile var routerReady = false
    @Volatile var routerStats = "{}"
    @Volatile var plan: Plan? = null

    /** Куда подключать туннель: маршрутизатор, а если он не поднялся - сразу byedpi */
    fun tunnelPort() = if (routerReady) Engine.ROUTER_PORT else Engine.PORT

    @Synchronized
    fun start(ctx: Context, pl: Plan): Boolean {
        stopAll()
        plan = pl
        val def = Engine.strategyById(pl.default) ?: Engine.strategies.first()
        val backup = Engine.strategyById(pl.backup)
        procs[Engine.PORT] = Proc(withBackup(def, backup), null, def.args)
        pl.groups.forEachIndexed { i, g ->
            if (g.strategy != Engine.NONE) Engine.strategyById(g.strategy)?.let { procs[Engine.GROUP_PORT + i] = Proc(withBackup(it, backup), null, it.args) }
        }
        if (Store.discordUdp(ctx)) procs[Engine.UDP_PORT] = Proc(Engine.udpArgs, null)
        for ((port, pr) in procs) {
            pr.p = Engine.startProxyArgs(ctx, pr.args, port)
            // эта сборка byedpi не приняла параметры запасной стратегии - запускаем без неё
            if (pr.p?.isAlive != true && pr.base != pr.args) {
                Engine.dbg("byedpi:$port не принял запасную стратегию - без неё")
                pr.p = Engine.startProxyArgs(ctx, pr.base, port)
            }
        }
        if (procs[Engine.PORT]?.p?.isAlive != true) return false
        startRouter(ctx, pl)
        return true
    }

    /**
     * Стратегия + запасная на каждое соединение: если сервер не ответил за 3 с или соединение сбросили
     * (часть видеосерверов YouTube режут по-другому), byedpi сам повторяет его запасной стратегией -
     * вместо зависания на 20-30 с.
     */
    private fun withBackup(s: Strategy, backup: Strategy?): List<String> {
        if (backup == null || backup.id == s.id) return s.args
        // у запасной берём только основную часть (без её собственных --auto-групп)
        val i = backup.args.indexOf("--auto")
        val b = if (i >= 0) backup.args.subList(0, i) else backup.args
        return listOf("--tls-timeout", "3") + s.args + listOf("--auto", "torst,ssl_err") + b
    }

    /** Диапазоны адресов Telegram (как в ядре): соединения приложения Telegram без имени сайта */
    val TG_CIDRS = listOf("149.154.160.0/20", "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22",
        "91.108.20.0/22", "91.108.56.0/22", "91.105.192.0/23", "95.161.64.0/20", "185.76.151.0/24",
        "2001:67c:4e8::/48", "2001:b28:f23c::/46", "2a0a:f280::/32")

    /** Способ обхода сервиса по плану: адрес копии byedpi или direct (None / не выбран) */
    fun bypassUp(pl: Plan, site: String): String {
        val gi = pl.groups.indexOfFirst { site in it.sites }
        if (gi >= 0) return if (pl.groups[gi].strategy == Engine.NONE) "direct" else "127.0.0.1:${Engine.GROUP_PORT + gi}"
        return "127.0.0.1:${Engine.PORT}"
    }

    /** Отправить маршрутизатору свежий список MTProto-прокси (после поиска или добавления своего) */
    fun pushTgProxies(ctx: Context) {
        if (!routerReady) return
        runCatching {
            val c = java.net.URL("http://127.0.0.1:${Engine.CONTROL_PORT}/tgproxies").openConnection(java.net.Proxy.NO_PROXY) as java.net.HttpURLConnection
            c.connectTimeout = 2000; c.readTimeout = 5000; c.requestMethod = "POST"; c.doOutput = true
            c.setRequestProperty("Content-Type", "application/json")
            c.outputStream.use { it.write(JSONArray(tgProxyLinks(ctx)).toString().toByteArray()) }
            val n = runCatching { JSONObject(c.inputStream.bufferedReader().readText()).optInt("proxies") }.getOrDefault(0)
            c.disconnect()
            Engine.dbg("маршрутизатор: MTProto-прокси для Telegram - $n")
        }.onFailure { Engine.dbg("маршрутизатор: список прокси не передан (${it.message})") }
    }

    /** Пул VPN, с которым запущен маршрутизатор */
    @Volatile private var startedVpn: List<Pair<String, Int>> = emptyList()

    /** Серверы VPN поменялись (после проверки): перезапустить маршрутизатор, только если пул другой */
    fun refreshVpn(ctx: Context) {
        val pl = plan ?: return
        if (!Engine.running || Vpn.pool(ctx) == startedVpn) return
        restartRouter(ctx, pl)
    }

    /** Ссылки MTProto-прокси для Telegram (свои и найденные) */
    private fun tgProxyLinks(ctx: Context): List<String> {
        val l = Store.tgProxies(ctx).filter { it.startsWith("tg://") || it.startsWith("https://t.me/proxy") }.toMutableList()
        val f = TgProxy.found
        for (i in 0 until f.length()) f.optJSONObject(i)?.optString("link")?.takeIf { it.isNotEmpty() }?.let { l += it }
        return l.distinct()
    }

    /**
     * Способы для каждого сервиса по порядку (основной, затем запасные):
     *  - обход стратегией (копия byedpi), VPN (лучшие серверы пула), напрямую;
     *  - Telegram: самый быстрый из обхода, WebSocket, VPN и MTProto-прокси;
     *  - выбранный вручную способ - первым, остальные остаются запасными;
     *  - None - только напрямую.
     */
    fun siteUpstreams(ctx: Context, pl: Plan, site: String): Pair<List<String>, Boolean> {
        val bp = bypassUp(pl, site)
        if (bp == "direct") return listOf("direct") to false
        val isTG = site == "Telegram"
        val vps = Vpn.ports(ctx, isTG).map { "127.0.0.1:$it" }
        // tg-proxy - всегда: список прокси обновляется в маршрутизаторе на ходу (пустой - способ пропускается)
        val tgx = if (isTG) listOf("tg-ws", "tg-proxy") else emptyList()
        val r = Store.routes(ctx)[site] ?: ""
        val ups = mutableListOf<String>()
        var fastest = false
        when {
            r == "vpn" -> { ups += vps; ups += bp; ups += tgx }
            r.startsWith("vpn:") -> { Vpn.portOf(ctx, r.removePrefix("vpn:"))?.let { ups += "127.0.0.1:$it" }; ups += vps; ups += bp; ups += tgx }
            isTG && (r == "tg-ws" || r == "tg-proxy") -> { ups += r; ups += bp; ups += tgx; ups += vps }
            r == "bypass" -> { ups += bp; ups += tgx; ups += vps }
            isTG -> { ups += bp; ups += tgx; ups += vps; fastest = true }
            // стратегией не исправить (блок по IP) - сначала VPN
            site in Store.unfixable(ctx) && vps.isNotEmpty() -> { ups += vps; ups += bp }
            else -> { ups += bp; ups += vps }
        }
        return ups.distinct() to fastest
    }

    /** Понятные имена способов (для журнала маршрутизатора и страницы) */
    fun upName(ctx: Context, pl: Plan, up: String): String = when {
        up == "direct" -> "напрямую"
        up == "tg-ws" -> "WebSocket"
        up == "tg-proxy" -> "MTProto-прокси"
        up.startsWith("127.0.0.1:") -> {
            val port = up.removePrefix("127.0.0.1:").toIntOrNull() ?: 0
            when {
                port >= Vpn.PORT_BASE -> Vpn.nameOf(ctx, port)
                port == Engine.PORT -> "обход · " + Engine.strategyName(pl.default)
                else -> pl.groups.getOrNull(port - Engine.GROUP_PORT)?.let { "обход · " + Engine.strategyName(it.strategy) } ?: "обход"
            }
        }
        else -> up
    }

    private fun routerConfig(ctx: Context, pl: Plan): JSONObject {
        val groups = JSONArray()
        val names = JSONObject()
        for (s in Engine.sites) {
            val (ups, fastest) = siteUpstreams(ctx, pl, s.name)
            ups.forEach { names.put(it, upName(ctx, pl, it)) }
            val g = JSONObject().put("name", s.name).put("upstreams", JSONArray(ups)).put("domains", JSONArray(s.domains))
                .put("check", if (s.name == "Telegram") "tg" else s.host).put("fastest", fastest)
            if (s.name == "Telegram") g.put("cidrs", JSONArray(TG_CIDRS))
            groups.put(g)
        }
        val vpn = JSONArray()
        val vp = Vpn.pool(ctx)
        startedVpn = vp
        vp.forEach { (l, port) -> vpn.put(JSONObject().put("link", l).put("port", port)) }
        val o = JSONObject()
            .put("listen", "127.0.0.1:${Engine.ROUTER_PORT}")
            .put("default", "127.0.0.1:${Engine.PORT}")
            .put("groups", groups)
            .put("names", names)
            .put("block_quic", Store.blockQuic(ctx))
            .put("telegram_mode", Store.tgMode(ctx))
            .put("doh", Store.doh(ctx))
            .put("doh_provider", Store.dnsProvider(ctx))
            .put("doh_custom", Store.dnsCustom(ctx))
            .put("tg_proxies", JSONArray(tgProxyLinks(ctx)))
            .put("control", "127.0.0.1:${Engine.CONTROL_PORT}")
            .apply {
                Engine.dnsSelected(ctx)?.let { sel -> put("doh_url", sel.optString("url")).put("doh_ips", sel.optJSONArray("ips") ?: JSONArray()) }
                if (vpn.length() > 0) put("vpn", vpn).put("xray", Vpn.xray(ctx).absolutePath)
            }
        if (procs.containsKey(Engine.UDP_PORT)) {
            // голос Discord: UDP 50000-65535
            // только к серверам голоса Discord: игры (Roblox и др.) используют те же порты, и подмена пакетов их ломает
            o.put("udp_upstream", "127.0.0.1:${Engine.UDP_PORT}").put("udp_ports", JSONArray().put(JSONArray().put(50000).put(65535)))
                .put("udp_cidrs", JSONArray(listOf("66.22.192.0/18", "138.128.136.0/21")))
        }
        return o
    }

    /** Xray работает (null - VPN не используется) */
    val vpnAlive: Any? get() = runCatching { JSONObject(routerStats).opt("vpn") }.getOrNull().takeIf { it != JSONObject.NULL }

    /** Состояние маршрутов из маршрутизатора: сервис -> {active, ping, ok, ups[]} */
    fun routes(): Map<String, JSONObject> {
        val a = runCatching { JSONObject(routerStats).optJSONArray("routes") }.getOrNull() ?: return emptyMap()
        return (0 until a.length()).mapNotNull { a.optJSONObject(it) }.associateBy { it.optString("name") }
    }

    /** Проверить способы сейчас (через маршрутизатор): name - сервис, пусто - все. Возвращает routes. */
    fun checkNow(name: String = ""): Map<String, JSONObject> {
        if (!routerReady) return emptyMap()
        val q = if (name.isEmpty()) "" else "?name=" + java.net.URLEncoder.encode(name, "UTF-8")
        val body = runCatching {
            val c = java.net.URL("http://127.0.0.1:${Engine.CONTROL_PORT}/check$q").openConnection(java.net.Proxy.NO_PROXY) as java.net.HttpURLConnection
            c.connectTimeout = 2000; c.readTimeout = 30000
            c.inputStream.bufferedReader().readText().also { c.disconnect() }
        }.getOrNull() ?: return emptyMap()
        val a = runCatching { JSONObject(body).optJSONArray("routes") }.getOrNull() ?: return emptyMap()
        val m = (0 until a.length()).mapNotNull { a.optJSONObject(it) }.associateBy { it.optString("name") }
        // свежее состояние сразу в статистику, чтобы страница его увидела
        runCatching {
            val st = JSONObject(routerStats)
            val all = st.optJSONArray("routes") ?: JSONArray()
            val merged = JSONArray()
            for (i in 0 until all.length()) all.optJSONObject(i)?.let { merged.put(m[it.optString("name")] ?: it) }
            if (all.length() == 0) m.values.forEach { merged.put(it) }
            routerStats = st.put("routes", merged).toString()
        }
        return m
    }

    private fun startRouter(ctx: Context, pl: Plan) {
        routerReady = false
        routerStats = "{}" // состояние прежнего маршрутизатора (способы, VPN) больше не верно
        val bin = File(ctx.applicationInfo.nativeLibraryDir, "libtgproxy.so")
        val cfg = File(ctx.filesDir, "router.json")
        cfg.writeText(routerConfig(ctx, pl).toString())
        val p = try {
            ProcessBuilder(bin.absolutePath, "-router", cfg.absolutePath).redirectErrorStream(true).start()
        } catch (e: IOException) {
            Engine.log("Маршрутизатор не запустился (${e.message}) - трафик пойдёт сразу в byedpi")
            return
        }
        router = p
        Thread {
            try {
                p.inputStream.bufferedReader().forEachLine { line ->
                    when {
                        line.startsWith("READY ") -> routerReady = true
                        line.startsWith("RSTATS ") -> routerStats = line.removePrefix("RSTATS ")
                        line.startsWith("LOG ") -> line.removePrefix("LOG ").let {
                            if ("перевожу" in it || "снова работает" in it || "теперь через" in it || it.startsWith("VPN")) Engine.log(it) else Engine.dbg(it)
                        }
                        line.startsWith("ERR ") -> Engine.err("Маршрутизатор: ${line.removePrefix("ERR ")}")
                    }
                }
            } catch (_: IOException) {
            }
        }.apply { isDaemon = true }.start()
        for (i in 0 until 30) { if (routerReady) break; Thread.sleep(100) }
        if (!routerReady) Engine.log("Маршрутизатор не ответил - трафик пойдёт сразу в byedpi")
    }

    /** Перезапустить только маршрутизатор (новые способы или серверы VPN), byedpi не трогая */
    @Synchronized
    fun restartRouter(ctx: Context, pl: Plan) {
        if (procs[Engine.PORT]?.p?.isAlive != true) return
        plan = pl
        router?.let { it.destroy(); it.waitFor(2, TimeUnit.SECONDS) }
        router = null
        killStray("libxray.so")
        startRouter(ctx, pl)
    }

    /** Свои процессы с этим именем, оставшиеся без родителя (Xray после падения маршрутизатора) */
    private fun killStray(name: String) {
        val me = android.os.Process.myPid()
        File("/proc").listFiles()?.forEach { d ->
            val pid = d.name.toIntOrNull() ?: return@forEach
            if (pid == me) return@forEach
            val cmd = runCatching { File(d, "cmdline").readText() }.getOrNull() ?: return@forEach
            if (cmd.substringBefore('\u0000').endsWith(name)) runCatching { android.os.Process.killProcess(pid) }
        }
    }

    /** Перезапуск упавших процессов (вызывается сторожем) */
    @Synchronized
    fun ensureAlive(ctx: Context) {
        for ((port, pr) in procs) {
            if (pr.p?.isAlive != true) {
                Engine.err("byedpi на порту $port завершился - перезапускаю")
                Report.error("byedpi на порту $port завершился")
                pr.p = Engine.startProxyArgs(ctx, pr.args, port)
            }
        }
        val pl = plan
        if (routerReady && router?.isAlive != true && pl != null) {
            Engine.err("Маршрутизатор завершился - перезапускаю")
            Report.error("маршрутизатор завершился")
            startRouter(ctx, pl)
        }
    }

    @Synchronized
    fun stopAll() {
        router?.let { it.destroy(); it.waitFor(2, TimeUnit.SECONDS) }
        router = null
        routerReady = false
        killStray("libxray.so")
        for (pr in procs.values) Engine.stopProxy(pr.p)
        procs.clear()
    }

    /** Описание для журнала */
    fun describe(): String {
        val pl = plan ?: return ""
        val def = Engine.strategyById(pl.default)?.name ?: pl.default
        val g = pl.groups.joinToString("; ") { "${it.sites.joinToString(", ")} → ${Engine.strategyName(it.strategy)}" }
        return "по умолчанию: $def" + (if (g.isNotEmpty()) "; $g" else "")
    }
}
