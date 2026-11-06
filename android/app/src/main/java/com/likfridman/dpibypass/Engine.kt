package com.likfridman.dpibypass

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.net.ConnectException
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.SocketTimeoutException
import java.net.URL
import java.net.UnknownHostException
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLException

/** Стратегия обхода = параметры byedpi (ciadpi). */
data class Strategy(val id: String, val name: String, val args: List<String>)

/** Сайт: что проверять и какие домены к нему относятся (для маршрутизации по стратегиям). */
data class Site(val name: String, val host: String, val domains: List<String> = emptyList())

/** Результат проверки сайта. */
data class Probe(val ok: Boolean, val kind: String, val reason: String, val ms: Int = 0) {
    /** Подпись для списка: "42 мс" или "none", если сайт не ответил. */
    val label: String get() = if (ok && ms > 0) "$ms ms" else "none"
}

/**
 * Движок: локальный SOCKS-прокси byedpi, проверка сайтов и подбор стратегии.
 * Само приложение исключено из своего VPN, поэтому проверки идут мимо туннеля -
 * так видно настоящее состояние блокировок.
 */
object Engine {
    const val PORT = 1080        // byedpi со стратегией по умолчанию
    const val GROUP_PORT = 1081  // 1081, 1082... - стратегии для отдельных сайтов
    const val UDP_PORT = 1089    // byedpi для UDP (голос Discord)
    const val ROUTER_PORT = 1090 // маршрутизатор: сюда идёт весь трафик туннеля
    const val TEST_PORT = 10801

    /**
     * Стратегии byedpi. Сначала - без подмены TTL: у мобильных операторов
     * (Yota, МегаФон, МТС) фейковые пакеты с малым TTL часто не доходят до DPI.
     */
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
        Site("Roblox", "www.roblox.com", listOf("roblox.com", "rbxcdn.com", "rbx.com", "robloxlabs.com")),
        Site("Telegram", "web.telegram.org", listOf("telegram.org", "t.me", "telegram.me", "telesco.pe", "tdesktop.com", "cdn-telegram.org")),
    )

    // ---------- журнал и состояние для окна ----------
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
    @Volatile var progCur = 0
    @Volatile var progTotal = 0

    fun log(line: String) {
        val t = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
        synchronized(logLock) {
            logLines.add("$t  $line")
            logSeq++
            if (logLines.size > 1500) logLines.subList(0, 300).clear()
        }
        android.util.Log.i("dpi-bypass", line)
    }

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
                p.inputStream.bufferedReader().forEachLine { if (it.isNotBlank()) log("byedpi: $it") }
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

    // ---------- проверка сайтов ----------

    fun probe(host: String, socksPort: Int?): Probe {
        val proxy = if (socksPort == null) Proxy.NO_PROXY
                    else Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", socksPort))
        var conn: HttpURLConnection? = null
        return try {
            conn = URL("https://$host/").openConnection(proxy) as HttpsURLConnection
            conn.connectTimeout = 6000
            conn.readTimeout = 7000
            conn.instanceFollowRedirects = false
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/130.0 Mobile Safari/537.36")
            val code = conn.responseCode
            val stream = if (code >= 400) conn.errorStream else conn.inputStream
            var total = 0
            if (stream != null) {
                val buf = ByteArray(16 * 1024)
                while (total < 96 * 1024) {
                    val n = stream.read(buf)
                    if (n < 0) break
                    total += n
                }
                stream.close()
            }
            Probe(true, "ok", "HTTP $code", ping(host))
        } catch (e: UnknownHostException) {
            Probe(false, "dns", "DNS не отвечает")
        } catch (e: ConnectException) {
            Probe(false, "ip", "нет соединения: блокировка по IP")
        } catch (e: SocketTimeoutException) {
            if (conn != null && e.message?.contains("connect", true) == true)
                Probe(false, "ip", "нет соединения: блокировка по IP")
            else Probe(false, "dpi", "DPI: соединение зависло")
        } catch (e: SSLException) {
            Probe(false, "dpi", "DPI: сброс на TLS")
        } catch (e: IOException) {
            val m = e.message ?: ""
            if (m.contains("reset", true) || m.contains("closed", true) || m.contains("EOF", true))
                Probe(false, "dpi", "DPI: соединение сброшено")
            else Probe(false, "dpi", "ошибка: ${m.take(60)}")
        } finally {
            conn?.disconnect()
        }
    }

    /** Пинг: время TCP-соединения с сервером напрямую (на него DPI не влияет), мс. */
    fun ping(host: String): Int = try {
        val ip = java.net.InetAddress.getByName(host)
        java.net.Socket().use { sock ->
            val t0 = System.nanoTime()
            sock.connect(InetSocketAddress(ip, 443), 3000)
            ((System.nanoTime() - t0) / 1_000_000).toInt().coerceAtLeast(1)
        }
    } catch (e: Exception) { 0 }

    /** Средний пинг ответивших сайтов (0 - никто не ответил). */
    fun avgPing(res: Map<String, Probe>): Int {
        val v = res.values.filter { it.ok && it.ms > 0 }.map { it.ms }
        return if (v.isEmpty()) 0 else v.sum() / v.size
    }

    fun probeLine(name: String, p: Probe) =
        if (p.ok) "+ $name: ping ${p.label}" else "- $name: ping none · ${p.reason}"

    /** Папка с libtgproxy.so (задаётся при запуске приложения и службы). */
    @Volatile var nativeDir = ""

    /**
     * Telegram: приложение ходит не на сайт, а по MTProto прямо к серверам DC.
     * Проверяем так же (req_pq к DC2 через тот же путь, что и трафик Telegram);
     * если не вышло - результат проверки сайта web.telegram.org.
     */
    private fun probeTelegram(host: String, socksPort: Int?): Probe {
        val bin = File(nativeDir, "libtgproxy.so")
        if (nativeDir.isEmpty() || !bin.exists()) return probe(host, socksPort)
        val cmd = mutableListOf(bin.absolutePath, "-check-dc")
        if (socksPort != null) cmd += listOf("-socks", "127.0.0.1:$socksPort")
        val line = runCatching {
            val p = ProcessBuilder(cmd).redirectErrorStream(true).start()
            val out = p.inputStream.bufferedReader().readText()
            p.waitFor(15, TimeUnit.SECONDS)
            out.lines().lastOrNull { it.startsWith("CHECK ") } ?: ""
        }.getOrDefault("")
        if (line.startsWith("CHECK OK ")) {
            val ms = line.removePrefix("CHECK OK ").trim().toIntOrNull() ?: 0
            return Probe(true, "ok", "MTProto DC2", ms.coerceAtLeast(1))
        }
        val web = probe(host, socksPort)
        return if (web.ok) web else web.copy(reason = web.reason + "; MTProto: " + line.removePrefix("CHECK FAIL ").ifEmpty { "нет ответа" })
    }

    fun probeAll(socksPort: Int?, list: List<Site> = sites): Map<String, Probe> {
        val pool = Executors.newFixedThreadPool(8)
        val fut = list.associate { s ->
            s.name to pool.submit<Probe> { if (s.name == "Telegram") probeTelegram(s.host, socksPort) else probe(s.host, socksPort) }
        }
        val res = fut.mapValues { (_, f) -> runCatching { f.get(35, TimeUnit.SECONDS) }.getOrElse { Probe(false, "dpi", "нет ответа") } }
        pool.shutdownNow()
        return res
    }

    // ---------- подбор стратегии ----------

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
            if (line.startsWith("SPEED FAIL")) { log("Скорость YouTube: ${line.removePrefix("SPEED FAIL ").take(120)}"); return@runCatching -1 }
            val j = JSONObject(line.removePrefix("SPEED "))
            lastSpeedMethod = j.optString("method")
            j.optInt("kbps", -1)
        }.getOrDefault(-1)
    }

    @Volatile var lastSpeedMethod = ""
    /** Результаты последнего подбора - для отчёта */
    @Volatile var lastSpeeds = JSONObject()

    /** YouTube считается замедленным, если видео грузится медленнее этого (КБ/с) */
    private const val YT_SLOW_KBPS = 600

    /**
     * Подбор: проверка без обхода, перебор стратегий по каждому сайту, замер скорости
     * видео YouTube для подходящих стратегий, затем план: стратегия по умолчанию +
     * отдельные стратегии для сайтов, которым нужна другая.
     */
    fun select(ctx: Context): Plan {
        log("== Проверка без обхода ==")
        status = "Checking sites…"
        val base = probeAll(null)
        sites.forEach { s -> base[s.name]?.let { log(probeLine(s.name, it)) } }
        Report.setBaseline(base)
        val cands = sites.filter { base[it.name]?.kind == "dpi" }.toMutableList()
        val ipBlocked = sites.filter { base[it.name]?.kind == "ip" || base[it.name]?.kind == "dns" }.map { it.name }
        Store.setUnfixable(ctx, ipBlocked)
        val speeds = JSONObject()
        // YouTube часто не блокируют, а замедляют: страница открывается, видео - нет
        val yt = sites.first { it.name == "YouTube" }
        if (base[yt.name]?.ok == true) {
            status = "Measuring YouTube speed…"
            val sp = speedTest(null)
            speeds.put("direct", sp)
            log("Скорость видео YouTube без обхода: ${if (sp >= 0) "$sp КБ/с" else "не измерить"} ($lastSpeedMethod)")
            if (sp in 0 until YT_SLOW_KBPS) {
                log("YouTube замедлен - подбираю стратегию и для него")
                cands.add(yt)
            }
        }
        if (cands.isEmpty()) {
            log("Блокировок DPI не найдено - включаю стратегию по умолчанию.")
            val pl = Plan(strategies.first().id, emptyList())
            Store.setPlan(ctx, pl)
            lastSpeeds = speeds
            return pl
        }
        val order = orderedStrategies(ctx)
        log("== Перебор стратегий (до ${order.size}) для: ${cands.joinToString { it.name }} ==")
        val matrix = LinkedHashMap<String, Map<String, Probe>>()
        progTotal = order.size
        for ((i, s) in order.withIndex()) {
            if (cancel) break
            progCur = i + 1
            status = "Testing strategies: ${i + 1}/${order.size}"
            val p = runCatching { startProxy(ctx, s, TEST_PORT) }.getOrNull()
            if (p == null || !p.isAlive) {
                Report.recordStrategy(s, cands, null)
                log("[${i + 1}] ${s.name}: не запустилась")
                stopProxy(p)
                continue
            }
            val r = probeAll(TEST_PORT, cands)
            stopProxy(p)
            matrix[s.id] = r
            Report.recordStrategy(s, cands, r)
            log("[${i + 1}] ${s.name}: " + cands.joinToString("  ") { (if (r[it.name]?.ok == true) "+" else "-") + it.name })
            val covered = cands.all { c -> matrix.values.any { it[c.name]?.ok == true } }
            val ytCands = matrix.values.count { it[yt.name]?.ok == true }
            // достаточно: всё покрыто, проверено не меньше 10, и для YouTube есть из чего выбрать
            if (covered && i + 1 >= 10 && (yt !in cands || ytCands >= 3)) break
        }
        progTotal = 0

        val assign = LinkedHashMap<String, String>() // сайт -> стратегия
        var ytKBps = 0
        if (yt in cands) {
            val ytOk = matrix.entries.filter { it.value[yt.name]?.ok == true }
                .sortedBy { it.value[yt.name]?.ms ?: 9999 }.take(4)
            var best = ""
            for ((i, e) in ytOk.withIndex()) {
                if (cancel) break
                status = "Measuring YouTube speed: ${i + 1}/${ytOk.size}"
                val s = strategyById(e.key) ?: continue
                val p = runCatching { startProxy(ctx, s, TEST_PORT) }.getOrNull()
                val sp = speedTest(TEST_PORT)
                stopProxy(p)
                speeds.put(s.id, sp)
                log("Скорость видео YouTube, ${s.name}: ${if (sp >= 0) "$sp КБ/с" else "не измерить"}")
                if (sp > ytKBps) { ytKBps = sp; best = s.id }
            }
            if (best.isEmpty()) best = ytOk.firstOrNull()?.key ?: ""
            if (best.isNotEmpty()) assign[yt.name] = best
        }
        // остальные сайты - жадно минимальным числом стратегий
        val remaining = cands.filter { it.name !in assign }.map { it.name }.toMutableSet()
        while (remaining.isNotEmpty()) {
            val used = assign.values.toSet()
            val best = matrix.entries.maxByOrNull { e ->
                remaining.count { e.value[it]?.ok == true } * 10 + (if (e.key in used) 5 else 0)
            } ?: break
            val got = remaining.filter { best.value[it]?.ok == true }
            if (got.isEmpty()) break
            got.forEach { assign[it] = best.key; remaining.remove(it) }
        }
        if (remaining.isNotEmpty()) log("Не помогла ни одна стратегия: ${remaining.joinToString()}")
        // по умолчанию - стратегия, которая нужна большему числу сайтов
        val counts = assign.values.groupingBy { it }.eachCount()
        val def = counts.maxByOrNull { it.value }?.key ?: matrix.entries.maxByOrNull { e -> cands.count { e.value[it.name]?.ok == true } }?.key ?: strategies.first().id
        val groups = assign.entries.filter { it.value != def }.groupBy({ it.value }, { it.key })
            .map { (st, ss) -> PlanGroup(st, ss) }
        val pl = Plan(def, groups, ytKBps)
        Store.setPlan(ctx, pl)
        assign.values.toSet().forEach { Store.recordWorked(ctx, it) }
        lastSpeeds = speeds
        log("Итог: по умолчанию ${strategyById(def)?.name}" + groups.joinToString("") { "; ${it.sites.joinToString()} → ${strategyById(it.strategy)?.name}" } +
            (if (ytKBps > 0) "; видео YouTube $ytKBps КБ/с" else ""))
        if (ipBlocked.isNotEmpty()) log("Заблокированы по IP (нужен VPN): ${ipBlocked.joinToString()}")
        return pl
    }

    /** Сначала стратегии, которые уже срабатывали на этом телефоне. */
    fun orderedStrategies(ctx: Context): List<Strategy> {
        val worked = Store.worked(ctx)
        return strategies.sortedByDescending { worked[it.id] ?: 0 }
    }

    fun strategyById(id: String?) = strategies.firstOrNull { it.id == id }

    // ---------- состояние для страницы ----------

    fun stateJson(ctx: Context): JSONObject {
        val o = JSONObject()
        o.put("version", BuildConfigVersion.name(ctx))
        o.put("running", running)
        o.put("starting", starting)
        o.put("busy", busy)
        o.put("status", status)
        val plan = Pool.plan ?: Store.plan(ctx)
        val st = strategyById(plan?.default ?: Store.strategy(ctx))
        o.put("strategy", (st?.name ?: "") + (if ((plan?.groups?.size ?: 0) > 0) " + ${plan!!.groups.size} per-site" else ""))
        o.put("boot", Store.boot(ctx))
        val unfix = Store.unfixable(ctx)
        val rows = JSONArray()
        var ok = 0
        var total = 0
        for (s in sites) {
            val r = JSONObject().put("name", s.name)
            val p = results[s.name]
            when {
                unfix.contains(s.name) -> r.put("kind", "bad").put("label", "none").put("strategy", "IP blocked · needs VPN")
                running && p != null -> {
                    total++
                    if (p.ok) ok++
                    r.put("kind", if (p.ok) "ok" else "bad").put("label", p.label)
                    r.put("strategy", plan?.strategyFor(s.name) ?: st?.id ?: "")
                }
                running -> r.put("kind", "idle").put("label", "checking…").put("strategy", plan?.strategyFor(s.name) ?: "")
                else -> r.put("kind", "idle").put("label", "off").put("strategy", plan?.strategyFor(s.name) ?: "—")
            }
            rows.put(r)
        }
        o.put("sites", rows)
        o.put("sitesOk", ok)
        o.put("sitesTotal", total)
        o.put("checked", if (running && checkedAt > 0) ago(checkedAt) else "")
        o.put("progress", JSONObject().put("cur", progCur).put("total", progTotal))
        o.put("tgRunning", TgProxy.ready)
        o.put("tgLink", if (TgProxy.ready) TgProxy.link(ctx) else "")
        o.put("tgStats", TgProxy.stats)
        o.put("tgError", TgProxy.lastError)
        o.put("tgProxies", JSONArray(Store.tgProxies(ctx)))
        o.put("tgWorker", Store.tgWorker(ctx))
        o.put("needConsent", !Store.consentOK(ctx))
        o.put("blockQuic", Store.blockQuic(ctx))
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
