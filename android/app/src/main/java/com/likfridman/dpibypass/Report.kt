package com.likfridman.dpibypass

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.telephony.TelephonyManager
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * Технические отчёты для разработчика (см. AGREEMENT.md): при каждом подключении и при
 * ошибках уходят на Cloudflare Worker (адрес - report_url в update/update.json).
 * Неотправленные копятся в очереди (не больше 20) и уходят при следующей возможности.
 */
object Report {
    private val updateUrls = listOf(
        "https://raw.githubusercontent.com/LikFridman/dpi-bypass/main/update/update.json",
        "https://cdn.jsdelivr.net/gh/LikFridman/dpi-bypass@main/update/update.json",
    )

    private val lock = Any()
    private var baseline = JSONArray()
    private val tested = JSONArray()
    private val errors = ArrayList<String>()
    @Volatile var otherVpnBeforeStart = false

    private fun siteJson(name: String, p: Probe) = JSONObject().put("name", name).put("ok", p.ok)
        .put("ping_ms", p.ms).put("stage", if (p.ok) "" else p.kind).put("reason", if (p.ok) "" else p.reason)

    private fun sitesJson(res: Map<String, Probe>) = JSONArray().also { a ->
        res.toSortedMap().forEach { (n, p) -> a.put(siteJson(n, p)) }
    }

    fun setBaseline(res: Map<String, Probe>) = synchronized(lock) {
        baseline = sitesJson(res)
        while (tested.length() > 0) tested.remove(0)
    }

    fun recordStrategy(s: Strategy, cands: List<Site>, res: Map<String, Probe>?) = synchronized(lock) {
        val opens = JSONArray()
        val fails = JSONArray()
        cands.forEach { c -> if (res?.get(c.name)?.ok == true) opens.put(c.name) else if (res != null) fails.put(c.name) }
        val o = JSONObject().put("id", s.id).put("name", s.name).put("opens", opens).put("fails", fails)
        if (res == null) o.put("start_error", "byedpi не запустился")
        tested.put(o)
    }

    fun error(msg: String) = synchronized(lock) {
        errors.add(SimpleDateFormat("HH:mm:ss", Locale.US).format(Date()) + " " + msg)
        while (errors.size > 30) errors.removeAt(0)
    }

    // ---------- сбор ----------

    private fun network(ctx: Context): JSONObject {
        val o = JSONObject()
        runCatching {
            val cm = ctx.getSystemService(ConnectivityManager::class.java)
            val caps = cm.getNetworkCapabilities(cm.activeNetwork)
            o.put("type", when {
                caps == null -> "none"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
                else -> "other"
            })
        }
        runCatching {
            val tm = ctx.getSystemService(TelephonyManager::class.java)
            o.put("operator", tm.networkOperatorName).put("sim_operator", tm.simOperatorName)
        }
        // внешний IP и провайдер (приложение исключено из своего VPN - это настоящий провайдер)
        runCatching {
            val c = URL("https://ipinfo.io/json").openConnection() as HttpURLConnection
            c.connectTimeout = 5000; c.readTimeout = 5000
            val j = JSONObject(c.inputStream.bufferedReader().readText())
            c.disconnect()
            val org = j.optString("org")
            o.put("ip", j.optString("ip")).put("city", j.optString("city")).put("region", j.optString("region"))
                .put("country", j.optString("country")).put("asn", org.substringBefore(" ")).put("isp", org.substringAfter(" ", ""))
        }
        return o
    }

    private fun device() = JSONObject()
        .put("os", "Android").put("release", Build.VERSION.RELEASE).put("sdk", Build.VERSION.SDK_INT)
        .put("manufacturer", Build.MANUFACTURER).put("model", Build.MODEL)
        .put("abi", JSONArray(Build.SUPPORTED_ABIS.toList()))

    fun build(ctx: Context, trigger: String): JSONObject {
        val st = Engine.strategyById(Store.strategy(ctx))
        val (_, lines) = Engine.logsSince(0)
        val r = JSONObject()
            .put("schema", 1).put("trigger", trigger)
            .put("time", SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.US).apply { timeZone = TimeZone.getDefault() }.format(Date()))
            .put("app", JSONObject().put("platform", "android").put("version", BuildConfigVersion.name(ctx))
                .put("running", Engine.running).put("boot", Store.boot(ctx)))
            .put("device", device())
            .put("network", network(ctx))
            .put("vpn", JSONObject().put("detected", otherVpnBeforeStart).put("note", "на Android обход сам является VPN; detected - был ли другой VPN до включения"))
            .put("strategy", JSONObject().put("current", st?.id ?: "").put("name", st?.name ?: "")
                .put("args", JSONArray(st?.args ?: emptyList<String>()))
                .put("unfixable", JSONArray(Store.unfixable(ctx).toList())))
            .put("sites", sitesJson(Engine.results))
            .put("telegram", JSONObject().put("running", TgProxy.ready).put("stats", TgProxy.stats)
                .put("routes", runCatching { JSONObject(TgProxy.routes) }.getOrElse { JSONObject() })
                .put("backup_proxies", Store.tgProxies(ctx).size).put("worker", Store.tgWorker(ctx).isNotBlank())
                .put("error", TgProxy.lastError))
            .put("log", JSONArray(lines.takeLast(200).map { it.take(400) }))
        synchronized(lock) {
            r.put("baseline", JSONArray(baseline.toString())).put("tested", JSONArray(tested.toString()))
                .put("errors", JSONArray(errors))
        }
        // счётчики для сводки на сервере: total = connections, failed
        TgProxy.stats.let { s ->
            Regex("""connections (\d+).*failed (\d+)""").find(s)?.let { m ->
                r.getJSONObject("telegram").put("connections", JSONObject().put("total", m.groupValues[1].toInt()).put("failed", m.groupValues[2].toInt()))
            }
        }
        return r
    }

    // ---------- отправка ----------

    private fun queueDir(ctx: Context) = File(ctx.filesDir, "reports").apply { mkdirs() }

    private fun reportUrl(ctx: Context): String {
        for (u in updateUrls) {
            runCatching {
                val c = URL(u).openConnection() as HttpURLConnection
                c.connectTimeout = 5000; c.readTimeout = 5000
                val j = JSONObject(c.inputStream.bufferedReader().readText())
                c.disconnect()
                val r = j.optString("report_url").trimEnd('/')
                Store.setReportUrl(ctx, r)
                return r
            }
        }
        return Store.reportUrl(ctx)
    }

    /** Собирает отчёт, ставит в очередь и отправляет всё накопленное. done - сообщение для пользователя. */
    fun send(ctx: Context, trigger: String, done: ((String) -> Unit)? = null) {
        if (!Store.consentOK(ctx)) return
        val app = ctx.applicationContext
        Thread {
            runCatching {
                val dir = queueDir(app)
                File(dir, "${System.currentTimeMillis()}-${(1000..9999).random()}.json").writeText(build(app, trigger).toString())
                flush(app, done)
            }.onFailure { done?.invoke("Отчёт не собран: ${it.message}") }
        }.start()
    }

    @Synchronized
    private fun flush(ctx: Context, done: ((String) -> Unit)?) {
        val files = queueDir(ctx).listFiles { f -> f.name.endsWith(".json") }?.sortedBy { it.name } ?: return
        files.dropLast(20).forEach { it.delete() }
        val url = reportUrl(ctx)
        if (!url.startsWith("https://")) {
            done?.invoke("Отчёт сохранён, но адрес для отчётов ещё не настроен разработчиком")
            return
        }
        for (f in files.takeLast(20)) {
            val code: Int
            val body: String
            try {
                val c = URL("$url/report").openConnection() as HttpURLConnection
                c.connectTimeout = 8000; c.readTimeout = 15000
                c.requestMethod = "POST"; c.doOutput = true
                c.setRequestProperty("Content-Type", "application/json")
                c.outputStream.use { it.write(f.readBytes()) }
                code = c.responseCode
                body = runCatching { (if (code < 400) c.inputStream else c.errorStream).bufferedReader().readText() }.getOrDefault("")
                c.disconnect()
            } catch (e: Exception) {
                done?.invoke("Отчёт не отправился (${e.message}), попробую позже")
                return
            }
            when (code) {
                200 -> {
                    f.delete()
                    val id = runCatching { JSONObject(body).optString("id") }.getOrDefault("")
                    Engine.log("Отчёт для разработчика отправлен, номер $id")
                    done?.invoke("Отчёт отправлен, номер $id")
                }
                400, 413 -> f.delete()
                else -> return
            }
        }
    }
}
