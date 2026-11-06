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
            val net = cm.activeNetwork
            val caps = cm.getNetworkCapabilities(net)
            caps?.let { c ->
                o.put("metered", !c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED))
                    .put("validated", c.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED))
                    .put("down_kbps", c.linkDownstreamBandwidthKbps).put("up_kbps", c.linkUpstreamBandwidthKbps)
                    .put("vpn_transport", c.hasTransport(NetworkCapabilities.TRANSPORT_VPN))
            }
            cm.getLinkProperties(net)?.let { lp ->
                o.put("interface", lp.interfaceName ?: "")
                    .put("dns", JSONArray(lp.dnsServers.map { it.hostAddress }))
                    .put("private_dns_active", if (Build.VERSION.SDK_INT >= 28) lp.isPrivateDnsActive else false)
                    .put("private_dns_server", if (Build.VERSION.SDK_INT >= 28) lp.privateDnsServerName ?: "" else "")
                    .put("mtu", if (Build.VERSION.SDK_INT >= 29) lp.mtu else 0)
                    .put("local_ips", JSONArray(lp.linkAddresses.map { it.toString() }))
            }
            @Suppress("DEPRECATION")
            o.put("networks", JSONArray(cm.allNetworks.mapNotNull { n ->
                cm.getNetworkCapabilities(n)?.let { c ->
                    listOf("wifi" to NetworkCapabilities.TRANSPORT_WIFI, "cellular" to NetworkCapabilities.TRANSPORT_CELLULAR,
                        "vpn" to NetworkCapabilities.TRANSPORT_VPN, "ethernet" to NetworkCapabilities.TRANSPORT_ETHERNET)
                        .filter { c.hasTransport(it.second) }.joinToString("+") { it.first }
                }
            }))
        }
        runCatching {
            o.put("private_dns_mode", android.provider.Settings.Global.getString(ctx.contentResolver, "private_dns_mode") ?: "")
        }
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
                .put("mcc_mnc", tm.networkOperator).put("roaming", tm.isNetworkRoaming)
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

    private fun device(ctx: Context): JSONObject {
        val o = JSONObject()
            .put("os", "Android").put("release", Build.VERSION.RELEASE).put("sdk", Build.VERSION.SDK_INT)
            .put("security_patch", Build.VERSION.SECURITY_PATCH).put("incremental", Build.VERSION.INCREMENTAL)
            .put("manufacturer", Build.MANUFACTURER).put("brand", Build.BRAND).put("model", Build.MODEL)
            .put("device", Build.DEVICE).put("product", Build.PRODUCT).put("hardware", Build.HARDWARE).put("board", Build.BOARD)
            .put("abi", JSONArray(Build.SUPPORTED_ABIS.toList()))
            .put("kernel", System.getProperty("os.version") ?: "")
            .put("locale", Locale.getDefault().toString()).put("timezone", TimeZone.getDefault().id)
        if (Build.VERSION.SDK_INT >= 31) o.put("soc", Build.SOC_MANUFACTURER + " " + Build.SOC_MODEL)
        runCatching {
            val am = ctx.getSystemService(android.app.ActivityManager::class.java)
            val mi = android.app.ActivityManager.MemoryInfo().also { am.getMemoryInfo(it) }
            o.put("ram_mb", mi.totalMem shr 20).put("ram_free_mb", mi.availMem shr 20).put("low_memory", mi.lowMemory)
        }
        runCatching {
            if (Build.VERSION.SDK_INT >= 26) android.webkit.WebView.getCurrentWebViewPackage()?.let { o.put("webview", it.packageName + " " + it.versionName) }
        }
        return o
    }

    private fun appState(ctx: Context): JSONObject {
        val o = JSONObject()
        runCatching {
            val pm = ctx.getSystemService(android.os.PowerManager::class.java)
            o.put("battery_optimization_ignored", pm.isIgnoringBatteryOptimizations(ctx.packageName)).put("power_save", pm.isPowerSaveMode)
        }
        runCatching { o.put("notifications", ctx.getSystemService(android.app.NotificationManager::class.java).areNotificationsEnabled()) }
        runCatching { o.put("vpn_permission", android.net.VpnService.prepare(ctx) == null) }
        runCatching {
            val rt = Runtime.getRuntime()
            o.put("heap_mb", (rt.totalMemory() - rt.freeMemory()) shr 20)
        }
        runCatching {
            // статистику туннеля спрашиваем только у работающего туннеля
            val st = if (Engine.running && TProxyService.TProxyIsRunning()) TProxyService.TProxyGetStats() else null
            if (st != null && st.size >= 4) o.put("tunnel", JSONObject().put("tx_packets", st[0]).put("tx_bytes", st[1]).put("rx_packets", st[2]).put("rx_bytes", st[3]))
        }
        o.put("uptime_s", if (startedAt > 0) (System.currentTimeMillis() - startedAt) / 1000 else 0)
            .put("worked", JSONObject(Store.worked(ctx)))
            .put("strategies", JSONArray(Engine.strategies.map { JSONObject().put("id", it.id).put("args", JSONArray(it.args)) }))
        return o
    }

    @Volatile var startedAt = 0L

    // ---------- падения приложения ----------

    private fun crashFile(ctx: Context) = File(ctx.filesDir, "crash.txt")

    /** Перехват падений: стек сохраняется и уходит отчётом при следующем запуске. */
    fun installCrashHandler(ctx: Context) {
        val app = ctx.applicationContext
        val prev = Thread.getDefaultUncaughtExceptionHandler()
        if (prev is CrashHandler) return
        Thread.setDefaultUncaughtExceptionHandler(CrashHandler(app, prev))
    }

    private class CrashHandler(val ctx: Context, val prev: Thread.UncaughtExceptionHandler?) : Thread.UncaughtExceptionHandler {
        override fun uncaughtException(t: Thread, e: Throwable) {
            runCatching { crashFile(ctx).writeText("поток ${t.name}: " + android.util.Log.getStackTraceString(e).take(6000)) }
            prev?.uncaughtException(t, e)
        }
    }

    /** Если в прошлый раз приложение упало - отправить отчёт о падении. */
    fun sendPendingCrash(ctx: Context) {
        val f = crashFile(ctx)
        if (!f.exists()) return
        val text = runCatching { f.readText() }.getOrDefault("")
        f.delete()
        error("падение приложения: $text")
        send(ctx, "crash")
    }

    fun build(ctx: Context, trigger: String): JSONObject {
        val st = Engine.strategyById(Store.strategy(ctx))
        val (_, lines) = Engine.logsSince(0)
        val r = JSONObject()
            .put("schema", 1).put("trigger", trigger)
            .put("time", SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.US).apply { timeZone = TimeZone.getDefault() }.format(Date()))
            .put("app", JSONObject().put("platform", "android").put("version", BuildConfigVersion.name(ctx))
                .put("running", Engine.running).put("boot", Store.boot(ctx)))
            .put("device", device(ctx))
            .put("program", appState(ctx))
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
