package com.likfridman.dpibypass

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Итог проверки сервера VPN */
data class VRes(
    val link: String, val id: String, val name: String, val proto: String, val source: String,
    val ok: Boolean, val ping: Int, val tg: Int, val kbps: Int, val err: String,
) {
    fun toJson(): JSONObject = JSONObject().put("link", link).put("id", id).put("name", name).put("proto", proto)
        .put("source", source).put("ok", ok).put("ping", ping).put("tg", tg).put("kbps", kbps).put("err", err)

    companion object {
        fun from(o: JSONObject) = VRes(o.optString("link"), o.optString("id").ifEmpty { Vpn.idOf(o.optString("link")) },
            o.optString("name"), o.optString("proto"), o.optString("source"), o.optBoolean("ok"), o.optInt("ping"),
            o.optInt("tg"), o.optInt("kbps"), o.optString("err"))
    }
}

/**
 * Встроенный VPN (ядро Xray, libxray.so): свои ключи и подписки, бесплатный Cloudflare WARP и
 * бесплатные серверы из публичных списков. Серверы проверяются по-настоящему (запрос к сайту и к
 * Telegram через каждый), лучшие попадают в «пул» - маршрутизатор держит их на локальных портах
 * SOCKS и использует для сервисов, которым нужен VPN, и как запасной путь.
 */
object Vpn {
    const val PORT_BASE = 2081
    const val POOL = 4

    /** Списки бесплатных серверов по умолчанию (обновляются из update.json: vpn_sources) */
    val DEFAULT_SOURCES = listOf(
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt",
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS+All_RUS.txt",
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    )
    private val SCHEMES = listOf("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "wireguard://", "wg://")

    private val testing = AtomicBoolean(false)
    val isTesting get() = testing.get()
    @Volatile var progress = ""

    private fun p(ctx: Context) = ctx.getSharedPreferences("vpn", Context.MODE_PRIVATE)
    fun xray(ctx: Context) = File(ctx.applicationInfo.nativeLibraryDir, "libxray.so")
    fun available(ctx: Context) = xray(ctx).exists()

    /** Тот же номер, что у ядра (sha1 ссылки без названия, 10 знаков) */
    fun idOf(link: String): String {
        val l = link.substringBefore('#').trim()
        return MessageDigest.getInstance("SHA-1").digest(l.toByteArray()).take(5).joinToString("") { "%02x".format(it) }
    }

    // ---------- настройки ----------

    private fun list(ctx: Context, key: String): List<String> =
        (p(ctx).getString(key, "") ?: "").lines().map { it.trim() }.filter { it.isNotEmpty() }
    private fun setList(ctx: Context, key: String, v: List<String>) = p(ctx).edit().putString(key, v.distinct().joinToString("\n")).apply()

    fun own(ctx: Context) = list(ctx, "own")
    fun subs(ctx: Context) = list(ctx, "subs")
    fun useFree(ctx: Context) = p(ctx).getBoolean("free", true)
    fun setUseFree(ctx: Context, v: Boolean) = p(ctx).edit().putBoolean("free", v).apply()
    // 2.7.0-2.7.1 хранили под тем же ключом ссылки WARP (строку) - такое значение сбрасывается
    fun useWarp(ctx: Context) = runCatching { p(ctx).getBoolean("warp", true) }
        .getOrElse { p(ctx).edit().remove("warp").apply(); true }
    fun setUseWarp(ctx: Context, v: Boolean) = p(ctx).edit().putBoolean("warp", v).apply()
    fun sources(ctx: Context) = list(ctx, "sources").filter { it.startsWith("https://") }.ifEmpty { DEFAULT_SOURCES }
    fun setSources(ctx: Context, v: List<String>) = setList(ctx, "sources", v)
    private fun warpLinks(ctx: Context) = list(ctx, "warp_links")

    /** Добавить свои ключи или ссылки на подписки (по одной в строке). Возвращает итог для пользователя. */
    fun addOwn(ctx: Context, text: String): String {
        val lines = text.split('\n', ' ', '\r', '\t').map { it.trim() }.filter { it.isNotEmpty() }
        val keys = lines.filter { l -> SCHEMES.any { l.startsWith(it, ignoreCase = true) } }
        val subs = lines.filter { it.startsWith("https://") || it.startsWith("http://") }
        if (keys.isEmpty() && subs.isEmpty()) return "Не нашёл ключей (vless://, vmess://, trojan://, ss://, hysteria2://, wireguard://) или ссылок на подписку"
        if (keys.isNotEmpty()) setList(ctx, "own", own(ctx) + keys)
        if (subs.isNotEmpty()) setList(ctx, "subs", subs(ctx) + subs)
        return listOfNotNull(keys.size.takeIf { it > 0 }?.let { "ключей: $it" }, subs.size.takeIf { it > 0 }?.let { "подписок: $it" })
            .joinToString(", ", "Добавлено ") + " - проверяю"
    }

    fun removeOwn(ctx: Context, id: String) {
        setList(ctx, "own", own(ctx).filter { idOf(it) != id && it != id })
        setList(ctx, "subs", subs(ctx).filter { it != id })
        p(ctx).edit().putString("results", JSONArray(results(ctx).filter { it.id != id }.map { it.toJson() }).toString()).apply()
    }

    // ---------- результаты и пул ----------

    @Volatile private var cache: Pair<String, List<VRes>> = "" to emptyList()

    /** Результаты проверки (разбор кешируется: страница спрашивает состояние 3 раза в секунду) */
    fun results(ctx: Context): List<VRes> {
        val raw = p(ctx).getString("results", "[]") ?: "[]"
        cache.let { if (it.first == raw) return it.second }
        val l = runCatching {
            val a = JSONArray(raw)
            (0 until a.length()).map { VRes.from(a.getJSONObject(it)) }
        }.getOrElse { emptyList() }
        cache = raw to l
        return l
    }
    fun testedAt(ctx: Context) = p(ctx).getLong("testedAt", 0)

    /** Лучшие рабочие (свои выше при близком пинге); forTG - по ответу Telegram */
    fun best(ctx: Context, forTG: Boolean = false): List<VRes> {
        fun score(r: VRes): Double {
            var v = (if (forTG) r.tg else r.ping).toDouble()
            if (r.kbps in 1..299) v += 400
            if (r.source == "own" || r.source == "sub") v *= 0.6
            return v
        }
        return results(ctx).filter { it.ok && (!forTG || it.tg > 0) && usable(ctx, it) }.sortedBy { score(it) }
    }

    /** Сервер ещё в настройках (бесплатные не выключены, свой не удалён) */
    private fun usable(ctx: Context, r: VRes) = when (r.source) {
        "free" -> useFree(ctx)
        "warp" -> useWarp(ctx)
        "own" -> own(ctx).any { idOf(it) == r.id }
        else -> true
    }

    /** Пул для маршрутизатора: ссылка -> порт (лучшие для сайтов и для Telegram, без повторов) */
    fun pool(ctx: Context): List<Pair<String, Int>> {
        if (!available(ctx)) return emptyList()
        val pick = LinkedHashSet<String>()
        // серверы, выбранные вручную для сервисов, - всегда в пуле
        val manual = Store.routes(ctx).values.filter { it.startsWith("vpn:") }.map { it.removePrefix("vpn:") }.toSet()
        if (manual.isNotEmpty()) results(ctx).filter { it.id in manual && usable(ctx, it) }.take(2).forEach { pick += it.link }
        best(ctx).take(2).forEach { pick += it.link }
        best(ctx, true).take(2).forEach { pick += it.link }
        best(ctx).forEach { if (pick.size < POOL) pick += it.link }
        return pick.take(POOL + manual.size.coerceAtMost(2)).mapIndexed { i, l -> l to PORT_BASE + i }
    }

    /** Порты пула по порядку для сайтов или для Telegram */
    fun ports(ctx: Context, forTG: Boolean): List<Int> {
        val pool = pool(ctx)
        val order = best(ctx, forTG).map { it.link }
        return order.mapNotNull { l -> pool.firstOrNull { it.first == l }?.second }.take(2)
    }

    /** Порт конкретного сервера (если он в пуле) */
    fun portOf(ctx: Context, id: String) = pool(ctx).firstOrNull { idOf(it.first) == id }?.second

    fun nameOf(ctx: Context, port: Int): String {
        val l = pool(ctx).firstOrNull { it.second == port }?.first ?: return "VPN"
        val r = results(ctx).firstOrNull { it.link == l }
        return "VPN · " + (r?.name?.takeIf { it.isNotBlank() } ?: r?.proto ?: "сервер")
    }

    // ---------- списки серверов ----------

    /** Ссылки из текста подписки (по строке или целиком в base64) */
    fun parseLinks(text: String): List<String> {
        var t = text.trim()
        if (!t.contains("://")) {
            val d = runCatching { String(android.util.Base64.decode(t.replace("\\s".toRegex(), ""), android.util.Base64.DEFAULT)) }.getOrNull()
            if (d != null && d.contains("://")) t = d
        }
        return t.lines().map { it.trim() }.filter { l -> SCHEMES.any { l.startsWith(it, ignoreCase = true) } }.distinct()
    }

    private fun fetch(url: String): String? {
        val tries = listOf(url) + (jsdelivr(url)?.let { listOf(it) } ?: emptyList())
        for (u in tries) {
            val r = runCatching { Net.get(u, 10000) { x -> x.code == 200 && x.body.contains("://") || x.code == 200 && x.body.length > 64 } }.getOrNull()
            if (r != null && r.code == 200) return r.body
        }
        return null
    }

    /** raw.githubusercontent.com/u/r/branch/path -> cdn.jsdelivr.net/gh/u/r@branch/path */
    private fun jsdelivr(u: String): String? {
        val m = Regex("^https://raw\\.githubusercontent\\.com/([^/]+)/([^/]+)/([^/]+)/(.+)$").find(u) ?: return null
        val (a, b, c, d) = m.destructured
        return "https://cdn.jsdelivr.net/gh/$a/$b@$c/$d"
    }

    /** Бесплатный WARP: зарегистрировать один раз (через обход, если он включён) */
    private fun ensureWarp(ctx: Context) {
        if (!useWarp(ctx) || warpLinks(ctx).isNotEmpty()) return
        val bin = File(ctx.applicationInfo.nativeLibraryDir, "libtgproxy.so")
        val cmd = mutableListOf(bin.absolutePath, "-warp")
        if (Engine.running) cmd += listOf("-socks", "127.0.0.1:${Engine.PORT}")
        runCatching {
            val pr = ProcessBuilder(cmd).redirectErrorStream(true).start()
            val out = pr.inputStream.bufferedReader().readText()
            pr.waitFor(45, TimeUnit.SECONDS)
            val line = out.lines().firstOrNull { it.startsWith("WARP ") }
            if (line == null) {
                Engine.dbg("WARP: ${out.lines().lastOrNull { it.isNotBlank() } ?: "нет ответа"}")
                return
            }
            val a = JSONObject(line.removePrefix("WARP ")).getJSONArray("links")
            setList(ctx, "warp_links", (0 until a.length()).map { a.getString(it) })
            Engine.log("VPN: бесплатный Cloudflare WARP зарегистрирован")
        }.onFailure { Engine.dbg("WARP: ${it.message}") }
    }

    /**
     * Проверить серверы: свои и из подписок - все, WARP, бесплатные - до 80 (сначала те, что работали
     * в прошлый раз). quick - только свои и прежние рабочие (быстро, при включении обхода).
     */
    fun testAsync(ctx: Context, quick: Boolean = false, done: ((String) -> Unit)? = null) {
        if (!available(ctx)) { done?.invoke("VPN недоступен в этой сборке"); return }
        if (!testing.compareAndSet(false, true)) { done?.invoke("Проверка серверов уже идёт"); return }
        val app = ctx.applicationContext
        Thread {
            try {
                done?.invoke(test(app, quick))
            } catch (e: Exception) {
                Engine.err("VPN: проверка не удалась (${e.message})")
                done?.invoke("Проверка не удалась: ${e.message}")
            } finally {
                testing.set(false)
                progress = ""
            }
        }.start()
    }

    private fun test(ctx: Context, quick: Boolean): String {
        val links = LinkedHashMap<String, String>() // ссылка -> источник
        own(ctx).forEach { links[it] = "own" }
        progress = "загружаю списки серверов"
        for (s in subs(ctx)) fetch(s)?.let { t -> parseLinks(t).take(100).forEach { links.putIfAbsent(it, "sub") } }
            ?: Engine.log("VPN: подписка не загрузилась - ${s.take(60)}")
        if (!quick) ensureWarp(ctx)
        if (useWarp(ctx)) warpLinks(ctx).forEach { links.putIfAbsent(it, "warp") }
        val prev = results(ctx)
        if (useFree(ctx)) {
            // прежние рабочие бесплатные - первыми, затем свежие из списков
            prev.filter { it.ok && it.source == "free" }.forEach { links.putIfAbsent(it.link, "free") }
            if (!quick) {
                val fresh = LinkedHashSet<String>()
                for (s in sources(ctx)) fetch(s)?.let { fresh += parseLinks(it).take(60) }
                var n = links.values.count { it == "free" }
                for (l in fresh.shuffled()) { if (n >= 80) break; if (links.putIfAbsent(l, "free") == null) n++ }
            }
        }
        if (links.isEmpty()) return "Нет серверов: добавь свой ключ или включи бесплатные"
        progress = "проверяю ${links.size} серверов"
        Engine.log("VPN: проверяю серверов ${links.size}…")
        val req = JSONObject().put("xray", xray(ctx).absolutePath).put("links", JSONArray(links.keys.toList()))
            .put("sources", JSONArray(links.values.toList())).put("telegram", true).put("speed", 4)
        val f = File(ctx.cacheDir, "vpn-test.json").apply { writeText(req.toString()) }
        val bin = File(ctx.applicationInfo.nativeLibraryDir, "libtgproxy.so")
        val pr = ProcessBuilder(bin.absolutePath, "-vpn-test", f.absolutePath).redirectErrorStream(true).start()
        val killer = Thread {
            try { if (!pr.waitFor(5, TimeUnit.MINUTES)) pr.destroyForcibly() } catch (_: InterruptedException) {}
        }.apply { isDaemon = true; start() }
        var res: List<VRes>? = null
        pr.inputStream.bufferedReader().forEachLine { line ->
            if (line.startsWith("VPNTEST ")) runCatching {
                val a = JSONArray(line.removePrefix("VPNTEST "))
                res = (0 until a.length()).map { VRes.from(a.getJSONObject(it)) }
            }
        }
        killer.interrupt()
        f.delete()
        val r = res ?: return "Проверка не завершилась"
        // свои и прежние результаты, которых не было в этой проверке, не теряем
        val merged = r + prev.filter { p -> r.none { it.id == p.id } && p.source != "free" && links.containsKey(p.link) }
        p(ctx).edit().putString("results", JSONArray(merged.map { it.toJson() }).toString())
            .putLong("testedAt", System.currentTimeMillis()).apply()
        val ok = r.count { it.ok }
        val tg = r.count { it.tg > 0 }
        val b = best(ctx).firstOrNull()
        val msg = "VPN: работают $ok из ${r.size} (Telegram через $tg)" + (b?.let { " · лучший ${it.name.take(30)} ${it.ping} ms" } ?: "")
        Engine.log(msg)
        return msg.removePrefix("VPN: ")
    }

    // ---------- для страницы ----------

    fun stateJson(ctx: Context): JSONObject {
        val pool = pool(ctx).map { it.first }.toSet()
        val res = results(ctx)
        val ownIds = own(ctx).map { idOf(it) }.toSet()
        val list = JSONArray()
        // свои - все (даже не проверенные), остальные - рабочие, лучшие сверху
        own(ctx).forEach { l ->
            val r = res.firstOrNull { it.id == idOf(l) }
            list.put((r ?: VRes(l, idOf(l), l.substringAfter('#', "").let { runCatching { java.net.URLDecoder.decode(it, "UTF-8") }.getOrDefault(it) }
                .ifBlank { l.substringBefore("://") }, l.substringBefore("://"), "own", false, 0, 0, 0, "не проверен")).toJson()
                .put("pool", l in pool).put("own", true))
        }
        res.filter { it.id !in ownIds && it.ok && usable(ctx, it) }
            .sortedBy { it.ping }.take(30).forEach { list.put(it.toJson().put("pool", it.link in pool).put("own", false)) }
        return JSONObject().put("available", available(ctx)).put("testing", isTesting).put("progress", progress)
            .put("free", useFree(ctx)).put("warp", useWarp(ctx)).put("subs", JSONArray(subs(ctx)))
            .put("testedAt", testedAt(ctx)).put("list", list)
            .put("tested", testedAt(ctx).let { t -> if (t <= 0) "" else ((System.currentTimeMillis() - t) / 60000).let { m -> if (m < 1) "just now" else if (m < 90) "$m min ago" else "${m / 60} h ago" } })
            .put("ok", res.count { it.ok && usable(ctx, it) }).put("total", res.size)
            .put("xray", Pool.vpnAlive)
    }
}
