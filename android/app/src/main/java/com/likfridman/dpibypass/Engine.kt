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

/** Сайт для проверки. */
data class Site(val name: String, val host: String)

/** Результат проверки сайта. */
data class Probe(val ok: Boolean, val kind: String, val reason: String)

/**
 * Движок: локальный SOCKS-прокси byedpi, проверка сайтов и подбор стратегии.
 * Само приложение исключено из своего VPN, поэтому проверки идут мимо туннеля -
 * так видно настоящее состояние блокировок.
 */
object Engine {
    const val PORT = 1080
    const val TEST_PORT = 10801

    val strategies = listOf(
        Strategy("b1", "disorder 1 + tlsrec по SNI", listOf("--disorder", "1", "--tlsrec", "1+s")),
        Strategy("b2", "fake + ttl 8, подмена SNI", listOf("--fake", "-1", "--ttl", "8", "--fake-sni", "www.google.com")),
        Strategy("b3", "split + disorder по SNI", listOf("--split", "1", "--disorder", "3+s", "--mod-http", "h,d", "--tlsrec", "1+s")),
        Strategy("b4", "disorder + авто при сбросе", listOf("--disorder", "1", "--auto", "torst", "--tlsrec", "1+s")),
        Strategy("b5", "fake 1 + ttl 6 + tlsrec", listOf("--fake", "1", "--ttl", "6", "--tlsrec", "1+s")),
        Strategy("b6", "oob 1 + tlsrec", listOf("--oob", "1", "--tlsrec", "1+s")),
        Strategy("b7", "split + disorder + fake, случайный фейк", listOf("--split", "1+s", "--disorder", "3+s", "--fake", "-1", "--ttl", "8", "--fake-tls-mod", "rand")),
        Strategy("b8", "disoob 1 + tlsrec 3", listOf("--disoob", "1", "--tlsrec", "3+s")),
        Strategy("b9", "fake + ttl 5 + tlsrec", listOf("--fake", "-1", "--ttl", "5", "--tlsrec", "1+s")),
        Strategy("b10", "tlsrec в середине SNI + split", listOf("--split", "2", "--tlsrec", "0+sm")),
        Strategy("b11", "disorder 3 + fake ttl 4", listOf("--disorder", "3", "--fake", "-1", "--ttl", "4")),
        Strategy("b12", "split по SNI + oob", listOf("--split", "1+s", "--oob", "3+s", "--tlsrec", "1+s")),
    )

    val sites = listOf(
        Site("YouTube", "www.youtube.com"),
        Site("Discord", "discord.com"),
        Site("Instagram", "www.instagram.com"),
        Site("X/Twitter", "x.com"),
        Site("Rutracker", "rutracker.org"),
        Site("LinkedIn", "www.linkedin.com"),
        Site("Roblox", "www.roblox.com"),
        Site("Telegram", "web.telegram.org"),
    )

    // ---------- журнал и состояние для окна ----------
    private val logLock = Any()
    private val logLines = ArrayList<String>()
    private var logSeq = 0L
    @Volatile var status = "Обход выключен"
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

    fun startProxy(ctx: Context, s: Strategy, port: Int): Process {
        val cmd = listOf(binary(ctx).absolutePath, "-i", "127.0.0.1", "-p", port.toString()) + s.args
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
            Probe(true, "ok", "HTTP $code")
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

    fun probeAll(socksPort: Int?, list: List<Site> = sites): Map<String, Probe> {
        val pool = Executors.newFixedThreadPool(8)
        val fut = list.associate { s -> s.name to pool.submit<Probe> { probe(s.host, socksPort) } }
        val res = fut.mapValues { (_, f) -> runCatching { f.get(20, TimeUnit.SECONDS) }.getOrElse { Probe(false, "dpi", "нет ответа") } }
        pool.shutdownNow()
        return res
    }

    // ---------- подбор стратегии ----------

    /** Перебирает стратегии; возвращает лучшую и сохраняет её. */
    fun select(ctx: Context): Strategy {
        log("== Проверка без обхода ==")
        status = "Проверяю сайты..."
        val base = probeAll(null)
        sites.forEach { s -> base[s.name]?.let { log("${if (it.ok) "+" else "-"} ${s.name}: ${if (it.ok) "доступен" else it.reason}") } }
        val cands = sites.filter { base[it.name]?.kind == "dpi" }
        val ipBlocked = sites.filter { base[it.name]?.kind == "ip" || base[it.name]?.kind == "dns" }.map { it.name }
        Store.setUnfixable(ctx, ipBlocked)
        if (cands.isEmpty()) {
            log("DPI-блокировок не найдено - включаю стратегию по умолчанию.")
            val s = strategies.first()
            Store.setStrategy(ctx, s.id)
            return s
        }
        log("== Перебор стратегий (${strategies.size}) ==")
        var best = strategies.first()
        var bestN = -1
        progTotal = strategies.size
        for ((i, s) in orderedStrategies(ctx).withIndex()) {
            if (cancel) break
            progCur = i + 1
            status = "Подбор стратегий: ${i + 1} из ${strategies.size}"
            val p = runCatching { startProxy(ctx, s, TEST_PORT) }.getOrNull()
            if (p == null || !p.isAlive) {
                log("[${i + 1}/${strategies.size}] ${s.name}: не запустилась")
                stopProxy(p)
                continue
            }
            val r = probeAll(TEST_PORT, cands)
            stopProxy(p)
            val n = cands.count { r[it.name]?.ok == true }
            log("[${i + 1}/${strategies.size}] ${s.name}: открыто $n из ${cands.size}")
            if (n > bestN) { best = s; bestN = n }
            if (n == cands.size) break
        }
        progTotal = 0
        Store.setStrategy(ctx, best.id)
        Store.recordWorked(ctx, best.id)
        log("Итог: ${best.name} (открыто $bestN из ${cands.size})")
        if (ipBlocked.isNotEmpty()) log("Заблокированы по IP (нужен VPN): ${ipBlocked.joinToString()}")
        return best
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
        val st = strategyById(Store.strategy(ctx))
        o.put("strategy", st?.name ?: "")
        o.put("boot", Store.boot(ctx))
        val unfix = Store.unfixable(ctx)
        val rows = JSONArray()
        var ok = 0
        var total = 0
        for (s in sites) {
            val r = JSONObject().put("name", s.name)
            val p = results[s.name]
            when {
                unfix.contains(s.name) -> r.put("kind", "bad").put("label", "блок по IP").put("strategy", "нужен VPN")
                running && p != null -> {
                    total++
                    if (p.ok) { ok++; r.put("kind", "ok").put("label", "открывается") }
                    else r.put("kind", "bad").put("label", "не открывается")
                    r.put("strategy", st?.id ?: "")
                }
                running -> r.put("kind", "idle").put("label", "проверяю...").put("strategy", st?.id ?: "")
                else -> r.put("kind", "idle").put("label", "обход выключен").put("strategy", st?.id ?: "—")
            }
            rows.put(r)
        }
        o.put("sites", rows)
        o.put("sitesOk", ok)
        o.put("sitesTotal", total)
        o.put("checked", if (running && checkedAt > 0) ago(checkedAt) else "")
        o.put("progress", JSONObject().put("cur", progCur).put("total", progTotal))
        return o
    }

    private fun ago(t: Long): String {
        val s = (System.currentTimeMillis() - t) / 1000
        return when {
            s < 20 -> "только что"
            s < 90 -> "минуту назад"
            else -> "${s / 60} мин назад"
        }
    }
}

object BuildConfigVersion {
    fun name(ctx: Context): String = runCatching {
        ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionName ?: ""
    }.getOrDefault("")
}
