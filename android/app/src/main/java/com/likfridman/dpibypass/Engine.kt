package com.likfridman.dpibypass

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit

/** Стратегия обхода = параметры byedpi (ciadpi). */
data class Strategy(val id: String, val name: String, val args: List<String>)

/** Сайт: что проверять и какие домены к нему относятся (для маршрутизации по стратегиям). */
data class Site(val name: String, val host: String, val domains: List<String> = emptyList())

/**
 * Результат проверки сервиса. kind: ok | dns | ip | dpi (для решений),
 * stage: ok | dns | tcp | tls | data | throttle | http (что именно сломалось).
 */
data class Probe(
    val ok: Boolean, val kind: String, val reason: String, val ms: Int = 0,
    val stage: String = "", val kbps: Int = 0, val what: String = "",
) {
    /** Подпись для списка: "42 ms" или "none", если сервис не работает. */
    val label: String get() = if (ok && ms > 0) "$ms ms" else "none"

    /** Одна строка: что работает и как быстро, или что сломалось */
    val detail: String get() = when {
        ok && kbps > 0 -> "${speedText(kbps)} · $what"
        ok -> what
        else -> "$stage: $reason"
    }
}

fun speedText(kbps: Int) = if (kbps >= 1024) String.format(Locale.US, "%.1f MB/s", kbps / 1024.0) else "$kbps KB/s"

/**
 * Движок: проверка сервисов, подбор стратегий, ручной выбор.
 * Проверки делает Go-ядро (libtgproxy.so -check-sites): сервис считается рабочим,
 * только если реально тянет данные (видео YouTube, файлы с CDN, шлюз Discord,
 * MTProto Telegram), а не просто отвечает на первый запрос.
 */
object Engine {
    const val PORT = 1080        // byedpi со стратегией по умолчанию
    const val GROUP_PORT = 1081  // 1081, 1082... - стратегии для отдельных сайтов
    const val UDP_PORT = 1089    // byedpi для UDP (голос Discord)
    const val ROUTER_PORT = 1090 // маршрутизатор: сюда идёт весь трафик туннеля
    const val TEST_PORT = 10801

    val strategies = listOf(
        Strategy("b1", "disorder 1 + tlsrec по SNI", listOf("--disorder", "1", "--tlsrec", "1+s")),
        Strategy("b3", "split + disorder по SNI", listOf("--split", "1", "--disorder", "3+s", "--mod-http", "h,d", "--tlsrec", "1+s")),
        Strategy("b4", "disorder + авто при сбросе", listOf("--disorder", "1", "--auto", "torst", "--tlsrec", "1+s")),
        Strategy("b6", "oob 1 + tlsrec", listOf("--oob", "1", "--tlsrec", "1+s")),
        Strategy("b8", "disoob 1 + tlsrec 3", listOf("--disoob", "1", "--tlsrec", "3+s")),
        Strategy("b10", "tlsrec в середине SNI + split", listOf("--split", "2", "--tlsrec", "0+sm")),
        Strategy("b12", "split по SNI + oob", listOf("--split", "1+s", "--oob", "3+s", "--tlsrec", "1+s")),
        Strategy("b13", "split 1 + tlsrec", listOf("--split", "1", "--tlsrec", "1+s")),
        Strategy("b14", "disorder по SNI + tlsrec", listOf("--disorder", "1+s", "--tlsrec", "1+s")),
        Strategy("b15", "split 2+s + disorder 4+s", listOf("--split", "2+s", "--disorder", "4+s")),
        Strategy("b16", "oob по SNI + tlsrec", listOf("--oob", "1+s", "--tlsrec", "1+s")),
        Strategy("b17", "disoob по SNI", listOf("--disoob", "1+s")),
        Strategy("b18", "disorder 1 + split по SNI + tlsrec в середине", listOf("--disorder", "1", "--split", "1+s", "--tlsrec", "0+sm")),
        Strategy("b20", "disorder 1 + tlsrec + mod-http", listOf("--disorder", "1", "--tlsrec", "1+s", "--mod-http", "h,d")),
        Strategy("b21", "split 1 + oob 2+s", listOf("--split", "1", "--oob", "2+s")),
        Strategy("b22", "disorder 2 + авто disorder по SNI", listOf("--disorder", "2", "--tlsrec", "1+s", "--auto", "torst", "--disorder", "1+s")),
        Strategy("b27", "oob 1 + disorder 3+s", listOf("--oob", "1", "--disorder", "3+s")),
        Strategy("b28", "split 3 + disorder 7", listOf("--split", "3", "--disorder", "7")),
        Strategy("b30", "tlsrec 3+s + split 1", listOf("--tlsrec", "3+s", "--split", "1")),
        Strategy("b32", "split по SNI + авто при ошибке TLS", listOf("--split", "1+s", "--auto", "ssl_err", "--disorder", "1")),
        Strategy("b33", "disoob 1 + split 3+s", listOf("--disoob", "1", "--split", "3+s")),
        Strategy("b34", "oob 2 + tlsrec + mod-http", listOf("--oob", "2", "--tlsrec", "1+s", "--mod-http", "h,d,r")),
        Strategy("b35", "disorder 5 + tlsrec 2+s", listOf("--disorder", "5", "--tlsrec", "2+s")),
        Strategy("b39", "двойной split", listOf("--split", "2", "--split", "1+s")),
        Strategy("b40", "oob + disorder + tlsrec по SNI", listOf("--oob", "1+s", "--disorder", "3+s", "--tlsrec", "1+s")),
        // с фейковыми пакетами (TTL)
        Strategy("b2", "fake + ttl 8, подмена SNI", listOf("--fake", "-1", "--ttl", "8", "--fake-sni", "www.google.com")),
        Strategy("b5", "fake 1 + ttl 6 + tlsrec", listOf("--fake", "1", "--ttl", "6", "--tlsrec", "1+s")),
        Strategy("b7", "split + disorder + fake, случайный фейк", listOf("--split", "1+s", "--disorder", "3+s", "--fake", "-1", "--ttl", "8", "--fake-tls-mod", "rand")),
        Strategy("b9", "fake + ttl 5 + tlsrec", listOf("--fake", "-1", "--ttl", "5", "--tlsrec", "1+s")),
        Strategy("b11", "disorder 3 + fake ttl 4", listOf("--disorder", "3", "--fake", "-1", "--ttl", "4")),
        Strategy("b23", "fake + ttl 3 + tlsrec", listOf("--fake", "-1", "--ttl", "3", "--tlsrec", "1+s")),
        Strategy("b24", "fake + ttl 10, случайный фейк", listOf("--fake", "-1", "--ttl", "10", "--fake-tls-mod", "rand")),
        Strategy("b25", "fake по SNI + ttl 6 + split", listOf("--fake", "1+s", "--ttl", "6", "--split", "1")),
        Strategy("b26", "disorder 1 + fake ttl 6, SNI yandex", listOf("--disorder", "1", "--fake", "-1", "--ttl", "6", "--fake-sni", "ya.ru")),
        Strategy("b31", "disorder по SNI + авто fake", listOf("--disorder", "1+s", "--auto", "torst", "--fake", "-1", "--ttl", "8")),
        Strategy("b37", "fake ttl 7 + disorder по SNI", listOf("--fake", "-1", "--ttl", "7", "--fake-sni", "www.google.com", "--disorder", "1+s")),
    )


    /** Отдельная копия byedpi для UDP (голос Discord): фейковые UDP-пакеты перед настоящими. */
    val udpArgs = listOf("--udp-fake", "6")

    val sites = listOf(
        Site("YouTube", "www.youtube.com", listOf("youtube.com", "googlevideo.com", "ytimg.com", "ggpht.com", "youtu.be", "youtubei.googleapis.com", "youtube-nocookie.com", "yt3.googleusercontent.com", "jnn-pa.googleapis.com")),
        Site("Discord", "discord.com", listOf("discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media", "discordcdn.com", "discord.dev", "discord.app", "discordstatus.com", "dis.gd")),
        Site("Instagram", "www.instagram.com", listOf("instagram.com", "cdninstagram.com", "igcdn.com")),
        Site("X/Twitter", "x.com", listOf("x.com", "twitter.com", "twimg.com", "t.co")),
        Site("Rutracker", "rutracker.org", listOf("rutracker.org", "rutracker.cc", "rutracker.net")),
        Site("LinkedIn", "www.linkedin.com", listOf("linkedin.com", "licdn.com")),
        Site("Roblox", "www.roblox.com", listOf("roblox.com", "rbxcdn.com", "rbx.com", "robloxlabs.com", "robloxcdn.com", "rbxinfra.com", "rbxtrk.com")),
        Site("Telegram", "web.telegram.org", listOf("telegram.org", "t.me", "telegram.me", "telesco.pe", "tdesktop.com", "cdn-telegram.org")),
    )


    // ---------- журнал и состояние для окна ----------
    // строка журнала: "<уровень>\t<время>  <текст>"; уровни: i - главное, e - ошибка, d - подробности
    private val logLock = Any()
    private val logLines = ArrayList<String>()
    private var logSeq = 0L
    @Volatile var status = "Bypass off"
    @Volatile var running = false
    @Volatile var starting = false
    @Volatile var busy = false
    @Volatile var cancel = false
    @Volatile var results: Map<String, Probe> = emptyMap()
    @Volatile var checkedAt = 0L
    /** Ключ текущей сети: мобильный оператор (cell:25002) или провайдер Wi-Fi/кабеля (asn:AS12389) */
    @Volatile var netKey = ""
    @Volatile var netTitle = ""
    @Volatile var netAsn = ""

    /** Стратегии, которые чаще всего работают у этого провайдера по отчётам других пользователей */
    fun crowdPreset(ctx: Context): List<String> {
        val asn = netAsn
        val base = Store.reportUrl(ctx)
        if (asn.isEmpty() || !base.startsWith("https://")) return emptyList()
        return runCatching {
            val j = JSONObject(Net.get("$base/presets?platform=android&asn=$asn", 4000).body)
            val a = j.optJSONArray("strategies") ?: JSONArray()
            val ids = (0 until a.length()).map { a.getJSONObject(it).optString("id") }.filter { strategyById(it) != null }
            if (ids.isNotEmpty()) log("У других пользователей $asn чаще всего работают: ${ids.joinToString()} (по ${j.optInt("reports")} отчётам) - пробую их первыми")
            ids
        }.getOrDefault(emptyList())
    }

    /** Определить сеть под VPN (наш туннель не учитывается). Вызывать не из главного потока. */
    fun networkKey(ctx: Context): Pair<String, String> = runCatching {
        val cm = ctx.getSystemService(android.net.ConnectivityManager::class.java)
        @Suppress("DEPRECATION")
        val nets = cm.allNetworks.mapNotNull { n -> cm.getNetworkCapabilities(n)?.let { n to it } }
            .filter { (_, c) -> !c.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN) && c.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET) }
        val wifi = nets.firstOrNull { it.second.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI) || it.second.hasTransport(android.net.NetworkCapabilities.TRANSPORT_ETHERNET) }
        val cell = nets.firstOrNull { it.second.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR) }
        when {
            wifi != null -> {
                // провайдер Wi-Fi: AS-номер по внешнему IP (запрос именно через эту сеть)
                val c = wifi.first.openConnection(java.net.URL("https://ipinfo.io/json")) as java.net.HttpURLConnection
                c.connectTimeout = 4000; c.readTimeout = 4000
                val j = JSONObject(c.inputStream.bufferedReader().readText())
                c.disconnect()
                val org = j.optString("org")
                val asn = org.substringBefore(" ")
                if (asn.startsWith("AS")) netAsn = asn
                if (asn.startsWith("AS")) ("asn:$asn" to "Wi-Fi · ${org.substringAfter(" ", asn)}") else ("" to "Wi-Fi")
            }
            cell != null -> {
                val tm = ctx.getSystemService(android.telephony.TelephonyManager::class.java)
                val op = tm.networkOperator ?: ""
                runCatching {
                    val c = cell.first.openConnection(java.net.URL("https://ipinfo.io/json")) as java.net.HttpURLConnection
                    c.connectTimeout = 4000; c.readTimeout = 4000
                    netAsn = JSONObject(c.inputStream.bufferedReader().readText()).optString("org").substringBefore(" ").takeIf { it.startsWith("AS") } ?: ""
                    c.disconnect()
                }
                if (op.isNotEmpty()) ("cell:$op" to "мобильная сеть · ${tm.networkOperatorName}") else ("" to "мобильная сеть")
            }
            else -> "" to ""
        }
    }.getOrDefault("" to "")
    /** Проверки через зашифрованный DNS - как трафик при включённом обходе (настройка Encrypted DNS) */
    @Volatile var useDoH = true
    @Volatile var dnsArgsCache: List<String> = emptyList()
    @Volatile var progCur = 0
    @Volatile var progTotal = 0
    @Volatile var pinging = false

    fun log(line: String, level: Char = 'i') {
        val t = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
        synchronized(logLock) {
            logLines.add("$level\t$t  $line")
            logSeq++
            if (logLines.size > 3000) logLines.subList(0, 600).clear()
        }
        android.util.Log.i("dpi-bypass", line)
    }
    fun err(line: String) = log(line, 'e')
    fun dbg(line: String) = log(line, 'd')

    /** Строки журнала после номера [after]; возвращает (новый номер, строки). */
    fun logsSince(after: Long): Pair<Long, List<String>> = synchronized(logLock) {
        val n = (logSeq - after).coerceAtMost(logLines.size.toLong()).toInt()
        if (n <= 0) logSeq to emptyList() else logSeq to logLines.takeLast(n)
    }

    // ---------- byedpi ----------

    fun binary(ctx: Context) = File(ctx.applicationInfo.nativeLibraryDir, "libciadpi.so")

    fun startProxy(ctx: Context, s: Strategy, port: Int): Process = startProxyArgs(ctx, s.args, port)

    fun startProxyArgs(ctx: Context, args: List<String>, port: Int): Process {
        val cmd = listOf(binary(ctx).absolutePath, "-i", "127.0.0.1", "-p", port.toString()) + args
        val p = ProcessBuilder(cmd).redirectErrorStream(true).start()
        Thread {
            try {
                p.inputStream.bufferedReader().forEachLine { if (it.isNotBlank()) dbg("byedpi:$port: $it") }
            } catch (_: IOException) {
            }
        }.apply { isDaemon = true }.start()
        Thread.sleep(400)
        return p
    }

    fun stopProxy(p: Process?) {
        if (p == null) return
        p.destroy()
        if (!p.waitFor(2, TimeUnit.SECONDS)) p.destroyForcibly()
    }

    // ---------- проверка сервисов (Go-ядро) ----------

    /** Папка с libtgproxy.so (задаётся при запуске приложения и службы). */
    @Volatile var nativeDir = ""

    private fun kindOf(stage: String) = when (stage) {
        "ok" -> "ok"
        "dns" -> "dns"
        "tcp" -> "ip"
        else -> "dpi"
    }

    /**
     * Проверить сервисы через SOCKS на порту port (null - напрямую).
     * light - быстрее и меньше данных (для перебора стратегий).
     */
    fun probeAll(port: Int?, list: List<Site> = sites, light: Boolean = false, quick: Boolean = false): Map<String, Probe> {
        val bin = File(nativeDir, "libtgproxy.so")
        if (list.isEmpty()) return emptyMap()
        val res = HashMap<String, Probe>()
        if (nativeDir.isEmpty() || !bin.exists()) {
            list.forEach { res[it.name] = Probe(false, "dpi", "нет проверочного модуля") }
            return res
        }
        val f = File.createTempFile("sites", ".json")
        f.writeText(JSONArray(list.map { s -> JSONObject().put("name", s.name).put("host", s.host).put("domains", JSONArray(s.domains)) }).toString())
        try {
            val cmd = mutableListOf(bin.absolutePath, "-check-sites", f.absolutePath)
            if (port != null) cmd += listOf("-socks", "127.0.0.1:$port")
            if (light) cmd += "-light"
            if (quick) cmd += "-quick"
            if (useDoH) { cmd += "-doh"; cmd += dnsArgsCache }
            val p = ProcessBuilder(cmd).redirectErrorStream(true).start()
            // сторож: зависшую проверку - убить через 60 с. Прерывание сторожа (проверка закончилась раньше)
            // бросает InterruptedException - без перехвата оно роняло всё приложение (краш после Ping all / Test)
            val killer = Thread {
                try {
                    if (!p.waitFor(60, TimeUnit.SECONDS)) p.destroyForcibly()
                } catch (_: InterruptedException) {
                }
            }.apply { isDaemon = true; start() }
            p.inputStream.bufferedReader().forEachLine { line ->
                if (line.startsWith("SITE ")) runCatching {
                    val j = JSONObject(line.removePrefix("SITE "))
                    val st = j.optString("stage")
                    res[j.getString("name")] = Probe(j.optBoolean("ok"), kindOf(st), j.optString("reason"), j.optInt("ping"),
                        st, j.optInt("kbps"), j.optString("what"))
                }
            }
            killer.interrupt()
        } catch (e: Exception) {
            dbg("проверка: ${e.message}")
        } finally {
            f.delete()
        }
        list.forEach { if (it.name !in res) res[it.name] = Probe(false, "dpi", "проверка не завершилась", stage = "data") }
        return res
    }

    /** Средний пинг ответивших сайтов (0 - никто не ответил). */
    fun avgPing(res: Map<String, Probe>): Int {
        val v = res.values.filter { it.ok && it.ms > 0 }.map { it.ms }
        return if (v.isEmpty()) 0 else v.sum() / v.size
    }

    fun probeLine(name: String, p: Probe) =
        if (p.ok) "✓ $name · ${p.ms} ms · ${p.detail}" else "✗ $name · ${p.detail}"

    /** Скорость видео YouTube через byedpi на порту port (null - без обхода), КБ/с; -1 - не вышло. */
    fun speedTest(port: Int?): Int {
        val bin = File(nativeDir, "libtgproxy.so")
        if (nativeDir.isEmpty() || !bin.exists()) return -1
        val cmd = mutableListOf(bin.absolutePath, "-speed")
        if (port != null) cmd += listOf("-socks", "127.0.0.1:$port")
        return runCatching {
            val p = ProcessBuilder(cmd).redirectErrorStream(true).start()
            val out = p.inputStream.bufferedReader().readText()
            p.waitFor(30, TimeUnit.SECONDS)
            val line = out.lines().lastOrNull { it.startsWith("SPEED ") } ?: return@runCatching -1
            if (line.startsWith("SPEED FAIL")) return@runCatching -1
            val j = JSONObject(line.removePrefix("SPEED "))
            lastSpeedMethod = j.optString("method")
            j.optInt("kbps", -1)
        }.getOrDefault(-1)
    }

    @Volatile var lastSpeedMethod = ""
    @Volatile var lastSpeeds = JSONObject()

    /** YouTube считается замедленным, если видео грузится медленнее этого (КБ/с) */
    private const val YT_SLOW_KBPS = 600

    // ---------- стратегии: встроенные + найденные глубоким поиском ----------

    @Volatile private var customCache: List<Strategy> = emptyList()

    fun allStrategies(ctx: Context): List<Strategy> {
        customCache = Store.custom(ctx).map { (id, a) -> Strategy(id, a.joinToString(" "), a) }
        return strategies + customCache
    }

    fun strategyById(id: String?) = strategies.firstOrNull { it.id == id } ?: customCache.firstOrNull { it.id == id }

    /** Сначала стратегии, которые уже срабатывали на этом телефоне. */
    fun orderedStrategies(ctx: Context): List<Strategy> {
        val worked = Store.worked(ctx)
        return allStrategies(ctx).sortedByDescending { worked[it.id] ?: 0 }
    }

    // ---------- результаты проверок стратегий (для ручного выбора) ----------

    private fun saveResult(m: JSONObject, id: String, site: String, p: Probe, full: Boolean) {
        val o = m.optJSONObject(id) ?: JSONObject().also { m.put(id, it) }
        o.put(site, JSONObject().put("ok", p.ok).put("stage", p.stage).put("ping", p.ms).put("kbps", p.kbps)
            .put("reason", p.reason).put("full", full).put("at", System.currentTimeMillis()))
    }

    private fun testStrategy(ctx: Context, s: Strategy, list: List<Site>, light: Boolean): Map<String, Probe>? {
        val p = runCatching { startProxy(ctx, s, TEST_PORT) }.getOrNull()
        if (p == null || !p.isAlive) {
            stopProxy(p)
            return null
        }
        val r = probeAll(TEST_PORT, list, light)
        stopProxy(p)
        return r
    }

    // ---------- подбор ----------

    /** Простые приёмы для глубокого поиска: какие вообще пробивают DPI этой сети */
    private fun primitives(): List<List<String>> {
        val pos = listOf("1", "2", "1+s", "3+s", "0+sm")
        val out = ArrayList<List<String>>()
        for (x in pos) {
            out += listOf("--split", x)
            out += listOf("--disorder", x)
            out += listOf("--oob", x)
            out += listOf("--disoob", x)
            out += listOf("--tlsrec", x)
        }
        for (t in listOf(2, 3, 4, 5, 6, 8, 10, 12)) out += listOf("--fake", "-1", "--ttl", t.toString())
        return out
    }

    private fun customId(args: List<String>) = "g" + Integer.toHexString(args.joinToString(" ").hashCode())

    /**
     * Подбор:
     *  1) проверка без обхода (что и как сломано),
     *  2) быстрый прогон встроенных стратегий по сломанным сервисам,
     *  3) если что-то не покрыто - глубокий поиск: простые приёмы и их сочетания,
     *  4) полная проверка 3 лучших стратегий для каждого сервиса и выбор по скорости,
     *  5) план: стратегия по умолчанию + отдельные для сервисов, кому нужна другая
     *     (с учётом закреплённых вручную).
     */
    fun select(ctx: Context): Plan {
        val t0 = System.currentTimeMillis()
        log("━━ Подбор стратегий ━━")
        status = "Checking without bypass…"
        // только выбранные пользователем сервисы (и не те, где выбран None)
        val sites = activeSites(ctx)
        val off = offSites(ctx)
        if (off.isNotEmpty()) log("Без обхода (не выбраны или None): ${off.joinToString()}")
        if (sites.isEmpty()) {
            log("Не выбрано ни одного сервиса - обход только стратегией по умолчанию", 'e')
            return finishPlan(ctx, emptyMap(), emptyList(), Store.matrix(ctx))
        }
        val base = probeAll(null, sites)
        Report.setBaseline(base)
        log("Без обхода:")
        sites.forEach { s -> base[s.name]?.let { log("  " + probeLine(s.name, it), if (it.ok) 'i' else 'e') } }

        val cands = sites.filter { base[it.name]?.kind == "dpi" }.toMutableList()
        val ipBlocked = sites.filter { base[it.name]?.kind == "ip" || base[it.name]?.kind == "dns" }.map { it.name }
        Store.setUnfixable(ctx, ipBlocked)
        sites.firstOrNull { it.name == "YouTube" }?.let { yt ->
            base[yt.name]?.let { if (it.ok && it.kbps in 1 until YT_SLOW_KBPS) { log("YouTube замедлен (${speedText(it.kbps)}) - подбираю и для него"); cands.add(yt) } }
        }
        lastSpeeds = JSONObject().put("direct", base["YouTube"]?.kbps ?: -1)
        if (ipBlocked.isNotEmpty()) log("Блок по IP, обход DPI не поможет: ${ipBlocked.joinToString()}", 'e')

        val m = Store.matrix(ctx)
        if (cands.isEmpty()) {
            log("Все сервисы работают без обхода - включаю стратегию по умолчанию")
            return finishPlan(ctx, emptyMap(), emptyList(), m)
        }
        log("Нужен обход: ${cands.joinToString { it.name }}")

        // 2) быстрый прогон
        val light = LinkedHashMap<String, Map<String, Probe>>()
        // что работает у других пользователей этого провайдера (сервер отчётов) - первыми
        val crowd = crowdPreset(ctx)
        val order = orderedStrategies(ctx).filter { !it.id.startsWith("g") }
            .sortedBy { s -> crowd.indexOf(s.id).let { if (it < 0) Int.MAX_VALUE else it } }
        progTotal = order.size
        for ((i, s) in order.withIndex()) {
            if (cancel) break
            progCur = i + 1
            status = "Testing strategies: ${i + 1}/${order.size}"
            val r = testStrategy(ctx, s, cands, true)
            if (r == null) {
                Report.recordStrategy(s, cands, null); err("[${s.id}] ${s.name}: byedpi не запустился"); continue
            }
            light[s.id] = r
            r.forEach { (site, p) -> saveResult(m, s.id, site, p, false) }
            Report.recordStrategy(s, cands, r)
            dbg("[${s.id}] ${s.name}: " + cands.joinToString("  ") { (if (r[it.name]?.ok == true) "✓" else "✗") + it.name })
            // быстрый подбор: хватит, если одна стратегия открыла всё, или после 4 лучших у каждого
            // сервиса есть рабочая; иначе - перебор дальше (обычный режим)
            val covered = cands.all { c -> light.values.any { it[c.name]?.ok == true } }
            if (covered && (cands.all { r[it.name]?.ok == true } || i + 1 >= 4)) {
                log("Быстрый подбор: хватило ${i + 1} из ${order.size} стратегий")
                break
            }
            if (i + 1 == 4) log("Быстрый подбор открыл не всё - перебираю остальные стратегии")
        }
        progTotal = 0

        // 3) глубокий поиск для непокрытых
        var uncovered = cands.filter { c -> light.values.none { it[c.name]?.ok == true } }
        if (uncovered.isNotEmpty() && !cancel) {
            log("Встроенные стратегии не помогли: ${uncovered.joinToString { it.name }} - глубокий поиск")
            val prims = primitives()
            val passing = ArrayList<Pair<List<String>, Int>>()
            progTotal = prims.size
            for ((i, a) in prims.withIndex()) {
                if (cancel) break
                progCur = i + 1
                status = "Deep search: ${i + 1}/${prims.size}"
                val s = Strategy(customId(a), a.joinToString(" "), a)
                val r = testStrategy(ctx, s, uncovered, true) ?: continue
                val n = uncovered.count { r[it.name]?.ok == true }
                // приём «почти работает»: хотя бы TLS прошёл (обрыв позже) - тоже кандидат для сочетаний
                val partial = uncovered.count { r[it.name]?.stage == "throttle" || r[it.name]?.stage == "data" }
                if (n > 0 || partial > 0) passing += a to (n * 10 + partial)
                if (n > 0) { Store.addCustom(ctx, s.id, a); light[s.id] = r; r.forEach { (site, p) -> saveResult(m, s.id, site, p, false) } }
                dbg("[глубокий] ${s.name}: $n из ${uncovered.size}")
            }
            // сочетания лучших приёмов
            val top = passing.sortedByDescending { it.second }.take(6).map { it.first }
            val combos = ArrayList<List<String>>()
            for (i in top.indices) for (j in i + 1 until top.size) {
                if (top[i][0] != top[j][0]) combos += top[i] + top[j]
            }
            for ((i, a) in combos.take(12).withIndex()) {
                if (cancel) break
                status = "Deep search: combo ${i + 1}"
                val s = Strategy(customId(a), a.joinToString(" "), a)
                val r = testStrategy(ctx, s, uncovered, true) ?: continue
                if (uncovered.any { r[it.name]?.ok == true }) {
                    Store.addCustom(ctx, s.id, a); light[s.id] = r; r.forEach { (site, p) -> saveResult(m, s.id, site, p, false) }
                    log("Глубокий поиск нашёл: ${s.name} → " + uncovered.filter { r[it.name]?.ok == true }.joinToString { it.name })
                }
            }
            progTotal = 0
            allStrategies(ctx)
            uncovered = cands.filter { c -> light.values.none { it[c.name]?.ok == true } }
        }

        // 4) полная проверка с нагрузкой. Сначала одна общая стратегия для всех (если такая есть) -
        //    одним прогоном; сервисы, которым она не подошла, - по очереди до 3 лучших кандидатов
        val best = LinkedHashMap<String, Pair<String, Int>>() // сайт -> (стратегия, КБ/с)
        val speeds = lastSpeeds
        fun verify(s: Strategy, list: List<Site>) {
            val res = testStrategy(ctx, s, list, false) ?: return
            for (c in list) {
                val r = res[c.name] ?: continue
                saveResult(m, s.id, c.name, r, true)
                if (c.name == "YouTube") speeds.put(s.id, r.kbps)
                dbg("[проверка] ${c.name} + ${s.name}: ${if (r.ok) speedText(r.kbps) else r.detail}")
                if (r.ok && r.kbps > (best[c.name]?.second ?: -1)) best[c.name] = s.id to r.kbps
            }
        }
        val common = light.entries.filter { e -> cands.all { e.value[it.name]?.ok == true } }
            .maxByOrNull { e -> cands.sumOf { e.value[it.name]?.kbps ?: 0 } }
        if (common != null && !cancel) {
            status = "Verifying ${strategyById(common.key)?.name ?: common.key}"
            strategyById(common.key)?.let { verify(it, cands) }
        }
        for (c in cands) {
            if (cancel) break
            // YouTube: если видео быстрое - дальше не ищем, иначе пробуем ещё кандидатов
            if (best[c.name]?.let { c.name != "YouTube" || it.second >= YT_SLOW_KBPS * 3 } == true) continue
            val top = light.entries.filter { it.value[c.name]?.ok == true && it.key != common?.key }
                .sortedByDescending { it.value[c.name]?.kbps ?: 0 }.take(if (best[c.name] == null) 3 else 2)
            for ((k, e) in top.withIndex()) {
                if (cancel) break
                status = "Verifying ${c.name}: ${k + 1}/${top.size}"
                strategyById(e.key)?.let { verify(it, listOf(c)) }
                if (best[c.name]?.let { c.name != "YouTube" || it.second >= YT_SLOW_KBPS * 3 } == true) break
            }
        }
        Store.setMatrix(ctx, m)
        lastSpeeds = speeds
        for (c in cands) {
            val b = best[c.name]
            if (b != null) log("  ${c.name}: ${strategyById(b.first)?.name} · ${speedText(b.second)}")
            else err("  ${c.name}: рабочей стратегии не нашлось" + (base[c.name]?.let { " (${it.detail})" } ?: ""))
        }
        val pl = finishPlan(ctx, best.mapValues { it.value.first }, cands.map { it.name }, m)
        log("Подбор занял ${(System.currentTimeMillis() - t0) / 1000} с")
        return pl
    }

    /**
     * План из выбранных стратегий: закреплённые вручную важнее, сервисы с близкой скоростью
     * (не хуже 70%) объединяются в стратегию по умолчанию, чтобы держать меньше процессов.
     */
    fun finishPlan(ctx: Context, chosen: Map<String, String>, cands: List<String>, m: JSONObject): Plan {
        val assign = LinkedHashMap(chosen)
        Store.pins(ctx).forEach { (site, id) -> if (strategyById(id) != null || id == NONE) assign[site] = id }
        offSites(ctx).forEach { assign[it] = NONE }
        val def = assign.values.filter { it != NONE }.groupingBy { it }.eachCount().maxByOrNull { it.value }?.key ?: strategies.first().id
        val pins = Store.pins(ctx)
        val groups = LinkedHashMap<String, MutableList<String>>()
        for ((site, id) in assign) {
            if (id == def) continue
            if (site !in pins) {
                val mine = m.optJSONObject(id)?.optJSONObject(site)?.optInt("kbps") ?: 0
                val viaDef = m.optJSONObject(def)?.optJSONObject(site)
                if (viaDef?.optBoolean("ok") == true && viaDef.optInt("kbps") * 10 >= mine * 7) continue
            }
            groups.getOrPut(id) { mutableListOf() }.add(site)
        }
        val ytK = m.optJSONObject(assign["YouTube"] ?: def)?.optJSONObject("YouTube")?.optInt("kbps") ?: 0
        val none = groups.remove(NONE)
        val pl = Plan(def, groups.map { PlanGroup(it.key, it.value) }.take(5) + listOfNotNull(none?.let { PlanGroup(NONE, it) }), ytK)
        Store.setPlan(ctx, pl)
        assign.values.toSet().forEach { Store.recordWorked(ctx, it) }
        // после подбора - отчёт с полной таблицей проверенных стратегий
        if (cands.isNotEmpty()) Report.send(ctx, "select")
        log("План: по умолчанию ${strategyById(def)?.name}" + pl.groups.joinToString("") { "; ${it.sites.joinToString()} → ${strategyName(it.strategy)}" })
        return pl
    }

    // ---------- зашифрованный DNS ----------

    private const val DNS_BUILTIN = "[{\"id\": \"cloudflare\", \"name\": \"Cloudflare\", \"note\": \"быстрый, без фильтрации\", \"url\": \"https://cloudflare-dns.com/dns-query\", \"ips\": [\"1.1.1.1\", \"1.0.0.1\"]}, {\"id\": \"google\", \"name\": \"Google\", \"note\": \"надёжный, без фильтрации\", \"url\": \"https://dns.google/dns-query\", \"ips\": [\"8.8.8.8\", \"8.8.4.4\"]}, {\"id\": \"quad9\", \"name\": \"Quad9\", \"note\": \"блокирует вредоносные сайты\", \"url\": \"https://dns.quad9.net/dns-query\", \"ips\": [\"9.9.9.9\", \"149.112.112.112\"]}, {\"id\": \"adguard\", \"name\": \"AdGuard\", \"note\": \"блокирует рекламу и трекеры\", \"url\": \"https://dns.adguard-dns.com/dns-query\", \"ips\": [\"94.140.14.14\", \"94.140.15.15\"]}, {\"id\": \"adguard-family\", \"name\": \"AdGuard Family\", \"note\": \"реклама + сайты для взрослых, безопасный поиск\", \"url\": \"https://family.adguard-dns.com/dns-query\", \"ips\": [\"94.140.14.15\", \"94.140.15.16\"]}, {\"id\": \"cloudflare-family\", \"name\": \"Cloudflare Family\", \"note\": \"без вредоносных и взрослых сайтов\", \"url\": \"https://family.cloudflare-dns.com/dns-query\", \"ips\": [\"1.1.1.3\", \"1.0.0.3\"]}, {\"id\": \"mullvad\", \"name\": \"Mullvad\", \"note\": \"без логов, без фильтрации\", \"url\": \"https://dns.mullvad.net/dns-query\", \"ips\": [\"194.242.2.2\"]}, {\"id\": \"comss\", \"name\": \"Comss.one\", \"note\": \"РФ: открывает часть сервисов, недоступных из России (ИИ, игры)\", \"url\": \"https://dns.comss.one/dns-query\", \"ips\": [\"195.133.25.16\"]}]"

    /** Серверы DoH: из update.json (обновляются без переустановки) или встроенные */
    fun dnsProviders(ctx: Context): JSONArray =
        runCatching { JSONArray(Store.dnsProviders(ctx)).takeIf { it.length() > 0 } }.getOrNull() ?: JSONArray(DNS_BUILTIN)

    /** Выбранный сервер (null - Auto или свой адрес) */
    fun dnsSelected(ctx: Context): JSONObject? {
        val id = Store.dnsProvider(ctx)
        val l = dnsProviders(ctx)
        return (0 until l.length()).map { l.getJSONObject(it) }.firstOrNull { it.optString("id") == id }
    }

    /** Аргументы helper для DNS проверок (как у маршрутизатора) */
    fun dnsArgs(ctx: Context): List<String> {
        val sel = dnsSelected(ctx)
        val ips = sel?.optJSONArray("ips")?.let { a -> (0 until a.length()).joinToString(",") { a.getString(it) } } ?: ""
        return when {
            sel != null -> listOf("-dns", sel.optString("id"), "-dns-url", sel.optString("url"), "-dns-ips", ips)
            Store.dnsProvider(ctx) == "custom" -> listOf("-dns", "custom", "-dns-custom", Store.dnsCustom(ctx))
            else -> listOf("-dns", "auto")
        }
    }

    /** Задержка до всех серверов DoH (через helper), JSON-массив [{id, ms, error}] */
    fun dnsPing(ctx: Context): JSONArray {
        val bin = File(nativeDir, "libtgproxy.so")
        val f = File.createTempFile("dns", ".json").apply { writeText(dnsProviders(ctx).toString()) }
        return try {
            val cmd = mutableListOf(bin.absolutePath, "-dns-ping", "-dns-list", f.absolutePath)
            if (Store.dnsCustom(ctx).startsWith("https://")) cmd += listOf("-dns-custom", Store.dnsCustom(ctx))
            val p = ProcessBuilder(cmd).redirectErrorStream(true).start()
            val out = p.inputStream.bufferedReader().readText()
            runCatching { p.waitFor(5, TimeUnit.SECONDS) }
            val line = out.lines().lastOrNull { it.startsWith("DNSPING ") } ?: return JSONArray()
            JSONArray(line.removePrefix("DNSPING "))
        } catch (e: Exception) {
            dbg("проверка DNS: ${e.message}"); JSONArray()
        } finally {
            f.delete()
        }
    }

    /** Стратегия «без обхода» для сервиса (выбор None) */
    const val NONE = "none"

    /** Сервисы, выбранные для обхода (Sites → галочки); null в настройках - ещё не выбирали (все) */
    fun chosen(ctx: Context): Set<String> = Store.chosenSites(ctx) ?: sites.map { it.name }.toSet()
    fun activeSites(ctx: Context) = sites.filter { it.name in chosen(ctx) && it.name !in noneSites(ctx) }
    fun offSites(ctx: Context) = sites.map { it.name }.filter { it !in chosen(ctx) || it in noneSites(ctx) }

    fun strategyName(id: String) = if (id == NONE) "без обхода (None)" else strategyById(id)?.name ?: id

    /** Сервисы, для которых пользователь выбрал None - их не подбираем */
    fun noneSites(ctx: Context) = Store.pins(ctx).filterValues { it == NONE }.keys

    // ---------- ручной выбор ----------

    /** Все стратегии для сервиса с результатами последних проверок (для окна выбора) */
    fun siteStrategies(ctx: Context, site: String): JSONObject {
        val m = Store.matrix(ctx)
        val pl = Pool.plan ?: Store.plan(ctx)
        val pin = Store.pins(ctx)[site]
        val arr = JSONArray()
        for (s in allStrategies(ctx)) {
            val r = m.optJSONObject(s.id)?.optJSONObject(site)
            arr.put(JSONObject().put("id", s.id).put("name", s.name).put("args", s.args.joinToString(" "))
                .put("tested", r != null).put("ok", r?.optBoolean("ok") ?: false).put("kbps", r?.optInt("kbps") ?: 0)
                .put("ping", r?.optInt("ping") ?: 0).put("stage", r?.optString("stage") ?: "").put("reason", r?.optString("reason") ?: "")
                .put("full", r?.optBoolean("full") ?: false))
        }
        return JSONObject().put("site", site).put("current", pl?.strategyFor(site) ?: "").put("pinned", pin ?: "").put("list", arr)
    }

    /** Проверить одну стратегию на одном сервисе (полная проверка) */
    fun testOne(ctx: Context, site: String, id: String): Probe? {
        val s = strategyById(id) ?: allStrategies(ctx).firstOrNull { it.id == id } ?: return null
        val st = sites.firstOrNull { it.name == site } ?: return null
        val r = testStrategy(ctx, s, listOf(st), false)?.get(site) ?: return null
        val m = Store.matrix(ctx)
        saveResult(m, id, site, r, true)
        Store.setMatrix(ctx, m)
        log("Проверка ${s.name} для $site: " + if (r.ok) "${r.ms} ms · ${r.detail}" else r.detail, if (r.ok) 'i' else 'e')
        return r
    }

    /** Закрепить стратегию за сервисом (id = null - снова автоматически) и пересобрать план */
    fun pin(ctx: Context, site: String, id: String?): Plan {
        Store.setPin(ctx, site, id)
        val old = Store.plan(ctx)
        val chosen = LinkedHashMap<String, String>()
        old?.let { pl -> sites.forEach { s -> chosen[s.name] = pl.strategyFor(s.name) } }
        chosen.entries.removeAll { it.value == NONE && it.key != site }
        if (id == null) chosen.remove(site)
        log(when (id) {
            null -> "$site: снова автоматический выбор"
            NONE -> "$site: без обхода (None) - напрямую, как без программы"
            else -> "$site: закреплена ${strategyById(id)?.name}"
        })
        return finishPlan(ctx, chosen.filterKeys { it !in Store.unfixable(ctx) }, emptyList(), Store.matrix(ctx))
    }

    // ---------- проверить все сервисы сейчас ----------

    /** Ping all: полная проверка всех сервисов через текущие настройки (маршрутизатор) */
    fun pingAll(ctx: Context): Map<String, Probe> {
        pinging = true
        try {
            val port = if (running) Pool.tunnelPort() else null
            log("━━ Ping all ${if (port == null) "(без обхода)" else "(через обход)"} ━━")
            val sites = activeSites(ctx)
            val r = probeAll(port, sites)
            sites.forEach { s -> r[s.name]?.let { log("  " + probeLine(s.name, it), if (it.ok) 'i' else 'e') } }
            results = r; checkedAt = System.currentTimeMillis() // показывать и без обхода (что открывается напрямую)
            log("Работают ${r.values.count { it.ok }} из ${r.size}" + (avgPing(r).takeIf { it > 0 }?.let { " · ping ~$it ms" } ?: ""))
            return r
        } finally {
            pinging = false
        }
    }

    // ---------- состояние для страницы ----------

    fun stateJson(ctx: Context): JSONObject {
        val o = JSONObject()
        o.put("version", BuildConfigVersion.name(ctx))
        o.put("running", running)
        o.put("starting", starting)
        o.put("busy", busy || pinging)
        o.put("pinging", pinging)
        o.put("status", status)
        val plan = Pool.plan ?: Store.plan(ctx)
        val st = strategyById(plan?.default ?: Store.strategy(ctx))
        o.put("strategy", (st?.name ?: "") + (if ((plan?.groups?.size ?: 0) > 0) " + ${plan!!.groups.size} per-site" else ""))
        o.put("boot", Store.boot(ctx))
        val unfix = Store.unfixable(ctx)
        val pins = Store.pins(ctx)
        val rows = JSONArray()
        var ok = 0
        var total = 0
        val chosenSet = Store.chosenSites(ctx) != null
        val ch = chosen(ctx)
        for (s in sites) {
            val sid = plan?.strategyFor(s.name) ?: ""
            val isNone = pins[s.name] == NONE
            val r = JSONObject().put("name", s.name).put("strategy", if (isNone) "None" else sid + (if (s.name in pins) " 📌" else ""))
                .put("chosen", s.name in ch).put("none", isNone)
            val p = results[s.name]
            when {
                // не выбран или None - серым «none»: обход его не трогает и не проверяет
                s.name !in ch || isNone -> r.put("kind", "idle").put("label", "none").put("detail", if (isNone) "без обхода (None)" else "не выбран - без обхода")
                // результат проверки (Ping all или фоновая проверка) - пинг зелёным или ошибка красным
                p != null && checkedAt > 0 -> {
                    total++
                    if (p.ok) ok++
                    r.put("kind", if (p.ok) "ok" else "bad").put("label", if (p.ok) p.label else "none").put("detail", p.detail)
                }
                unfix.contains(s.name) -> r.put("kind", "bad").put("label", "none").put("detail", "блок по IP: нужен VPN")
                // обход включён, проверки ещё не было - зелёным «on»
                running -> r.put("kind", "ok").put("label", "on").put("detail", "обход включён · Ping all - проверить")
                starting || busy -> r.put("kind", "idle").put("label", "…").put("detail", "подбор стратегий")
                else -> r.put("kind", "idle").put("label", "off")
            }
            rows.put(r)
        }
        o.put("sites", rows)
        o.put("chosenSet", chosenSet)
        o.put("sitesOk", ok)
        o.put("sitesTotal", total)
        o.put("checked", if (checkedAt > 0) ago(checkedAt) else "")
        o.put("progress", JSONObject().put("cur", progCur).put("total", progTotal))
        o.put("tgRunning", TgProxy.ready)
        o.put("tgLink", if (TgProxy.ready) TgProxy.link(ctx) else "")
        o.put("tgStats", TgProxy.stats)
        o.put("tgError", TgProxy.lastError)
        o.put("tgProxies", JSONArray(Store.tgProxies(ctx)))
        o.put("tgWorker", Store.tgWorker(ctx))
        o.put("needConsent", !Store.consentOK(ctx))
        o.put("blockQuic", Store.blockQuic(ctx))
        o.put("doh", Store.doh(ctx))
        o.put("dnsInfo", JSONObject().put("provider", Store.dnsProvider(ctx)).put("custom", Store.dnsCustom(ctx)).put("providers", dnsProviders(ctx)))
        o.put("network", netTitle)
        o.put("dns", runCatching { JSONObject(Pool.routerStats).optJSONObject("doh") }.getOrNull() ?: JSONObject())
        o.put("discordUdp", Store.discordUdp(ctx))
        o.put("tgMode", Store.tgMode(ctx))
        o.put("ytKBps", plan?.ytKBps ?: 0)
        o.put("tgFound", TgProxy.found)
        o.put("tgSearching", TgProxy.isSearching)
        o.put("tgFoundAt", if (TgProxy.foundAt > 0) ago(TgProxy.foundAt) else "")
        return o
    }

    private fun ago(t: Long): String {
        val s = (System.currentTimeMillis() - t) / 1000
        return when {
            s < 20 -> "just now"
            s < 90 -> "1 min ago"
            else -> "${s / 60} min ago"
        }
    }
}

object BuildConfigVersion {
    fun name(ctx: Context): String = runCatching {
        ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionName ?: ""
    }.getOrDefault("")
}
