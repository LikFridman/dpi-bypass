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
        return listOf("--timeout", "3") + s.args + listOf("--auto", "torst,ssl_err") + b
    }

    private fun routerConfig(ctx: Context, pl: Plan): JSONObject {
        val groups = JSONArray()
        pl.groups.forEachIndexed { i, g ->
            val domains = g.sites.flatMap { n -> Engine.sites.firstOrNull { it.name == n }?.domains ?: emptyList() }
            val up = if (g.strategy == Engine.NONE) "direct" else "127.0.0.1:${Engine.GROUP_PORT + i}"
            groups.put(JSONObject().put("upstream", up).put("domains", JSONArray(domains)))
        }
        val o = JSONObject()
            .put("listen", "127.0.0.1:${Engine.ROUTER_PORT}")
            .put("default", "127.0.0.1:${Engine.PORT}")
            .put("groups", groups)
            .put("block_quic", Store.blockQuic(ctx))
            .put("telegram_mode", Store.tgMode(ctx))
            .put("doh", Store.doh(ctx))
            .put("doh_provider", Store.dnsProvider(ctx))
            .put("doh_custom", Store.dnsCustom(ctx))
            .apply {
                Engine.dnsSelected(ctx)?.let { sel -> put("doh_url", sel.optString("url")).put("doh_ips", sel.optJSONArray("ips") ?: JSONArray()) }
            }
        if (procs.containsKey(Engine.UDP_PORT)) {
            // голос Discord: UDP 50000-65535
            // только к серверам голоса Discord: игры (Roblox и др.) используют те же порты, и подмена пакетов их ломает
            o.put("udp_upstream", "127.0.0.1:${Engine.UDP_PORT}").put("udp_ports", JSONArray().put(JSONArray().put(50000).put(65535)))
                .put("udp_cidrs", JSONArray(listOf("66.22.192.0/18", "138.128.136.0/21")))
        }
        return o
    }

    private fun startRouter(ctx: Context, pl: Plan) {
        routerReady = false
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
                        line.startsWith("LOG ") -> line.removePrefix("LOG ").let { if ("перевожу" in it) Engine.log(it) else Engine.dbg(it) }
                        line.startsWith("ERR ") -> Engine.err("Маршрутизатор: ${line.removePrefix("ERR ")}")
                    }
                }
            } catch (_: IOException) {
            }
        }.apply { isDaemon = true }.start()
        for (i in 0 until 30) { if (routerReady) break; Thread.sleep(100) }
        if (!routerReady) Engine.log("Маршрутизатор не ответил - трафик пойдёт сразу в byedpi")
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
