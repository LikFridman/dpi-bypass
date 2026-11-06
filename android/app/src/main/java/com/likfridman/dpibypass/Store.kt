package com.likfridman.dpibypass

import android.content.Context
import org.json.JSONObject

/** Настройки приложения. */
object Store {
    private fun p(ctx: Context) = ctx.getSharedPreferences("dpi", Context.MODE_PRIVATE)

    fun strategy(ctx: Context): String? = p(ctx).getString("strategy", null)
    fun setStrategy(ctx: Context, id: String) = p(ctx).edit().putString("strategy", id).apply()

    fun unfixable(ctx: Context): Set<String> = p(ctx).getStringSet("unfixable", emptySet()) ?: emptySet()
    fun setUnfixable(ctx: Context, names: List<String>) = p(ctx).edit().putStringSet("unfixable", names.toSet()).apply()

    fun boot(ctx: Context) = p(ctx).getBoolean("boot", false)
    fun setBoot(ctx: Context, v: Boolean) = p(ctx).edit().putBoolean("boot", v).apply()

    fun bgDim(ctx: Context) = p(ctx).getInt("bgDim", 45)
    fun bgBlur(ctx: Context) = p(ctx).getInt("bgBlur", 0)
    fun setBgOpts(ctx: Context, dim: Int, blur: Int) =
        p(ctx).edit().putInt("bgDim", dim.coerceIn(0, 90)).putInt("bgBlur", blur.coerceIn(0, 30)).apply()

    /** План обхода (стратегии по сайтам) */
    fun plan(ctx: Context): Plan? = Plan.fromJson(p(ctx).getString("plan", null))
    fun setPlan(ctx: Context, pl: Plan) = p(ctx).edit().putString("plan", pl.toJson().toString()).putString("strategy", pl.default).apply()

    /** Отбрасывать QUIC (UDP 443), чтобы YouTube шёл по TCP через обход */
    fun blockQuic(ctx: Context) = p(ctx).getBoolean("blockQuic", true)
    fun setBlockQuic(ctx: Context, v: Boolean) = p(ctx).edit().putBoolean("blockQuic", v).apply()

    /** UDP голоса Discord через byedpi с фейковыми пакетами */
    fun discordUdp(ctx: Context) = p(ctx).getBoolean("discordUdp", true)
    fun setDiscordUdp(ctx: Context, v: Boolean) = p(ctx).edit().putBoolean("discordUdp", v).apply()

    /** Telegram: auto (WebSocket при сбоях) | ws (всегда WebSocket) | direct */
    fun tgMode(ctx: Context): String = p(ctx).getString("tgMode", "auto") ?: "auto"
    fun setTgMode(ctx: Context, v: String) = p(ctx).edit().putString("tgMode", v).apply()

    /** Принятая версия пользовательского соглашения (0 - не принято). */
    const val AGREEMENT_VERSION = 2
    fun consentOK(ctx: Context) = p(ctx).getInt("consent", 0) >= AGREEMENT_VERSION
    fun setConsent(ctx: Context, ok: Boolean) =
        p(ctx).edit().putInt("consent", if (ok) AGREEMENT_VERSION else 0).putLong("consentAt", System.currentTimeMillis()).apply()

    /** Адрес для отчётов (из update.json в репозитории). */
    fun reportUrl(ctx: Context): String = p(ctx).getString("reportUrl", "") ?: ""
    fun setReportUrl(ctx: Context, u: String) = p(ctx).edit().putString("reportUrl", u).apply()

    /** Списки публичных прокси Telegram из update.json (пусто - встроенные). */
    fun tgSources(ctx: Context): List<String> =
        (p(ctx).getString("tgSources", "") ?: "").lines().filter { it.startsWith("https://") }
    fun setTgSources(ctx: Context, l: List<String>) = p(ctx).edit().putString("tgSources", l.joinToString("\n")).apply()

    /** Постоянный секрет локального прокси Telegram (чтобы прокси не добавлять заново). */
    fun tgSecret(ctx: Context): String {
        p(ctx).getString("tgSecret", null)?.let { if (it.length == 32) return it }
        val b = ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }
        val hex = b.joinToString("") { "%02x".format(it) }
        p(ctx).edit().putString("tgSecret", hex).apply()
        return hex
    }

    /** Запасные прокси для Telegram (tg://proxy?... или socks5://...). */
    fun tgProxies(ctx: Context): List<String> =
        (p(ctx).getString("tgProxies", "") ?: "").lines().map { it.trim() }.filter { it.isNotEmpty() }
    fun setTgProxies(ctx: Context, list: List<String>) = p(ctx).edit().putString("tgProxies", list.joinToString("\n")).apply()

    fun tgWorker(ctx: Context): String = p(ctx).getString("tgWorker", "") ?: ""
    fun setTgWorker(ctx: Context, host: String) = p(ctx).edit().putString("tgWorker", host).apply()

    /** Свои (сгенерированные при глубоком поиске) стратегии: id -> аргументы byedpi */
    fun custom(ctx: Context): Map<String, List<String>> {
        val o = runCatching { JSONObject(p(ctx).getString("custom", "{}")!!) }.getOrElse { JSONObject() }
        return o.keys().asSequence().associateWith { k -> o.getJSONArray(k).let { a -> (0 until a.length()).map { a.getString(it) } } }
    }
    fun addCustom(ctx: Context, id: String, args: List<String>) {
        val o = runCatching { JSONObject(p(ctx).getString("custom", "{}")!!) }.getOrElse { JSONObject() }
        o.put(id, org.json.JSONArray(args))
        p(ctx).edit().putString("custom", o.toString()).apply()
    }

    /** Закреплённые вручную стратегии: сайт -> id */
    fun pins(ctx: Context): Map<String, String> {
        val o = runCatching { JSONObject(p(ctx).getString("pins", "{}")!!) }.getOrElse { JSONObject() }
        return o.keys().asSequence().associateWith { o.getString(it) }
    }
    fun setPin(ctx: Context, site: String, id: String?) {
        val o = runCatching { JSONObject(p(ctx).getString("pins", "{}")!!) }.getOrElse { JSONObject() }
        if (id == null) o.remove(site) else o.put(site, id)
        p(ctx).edit().putString("pins", o.toString()).apply()
    }

    /** Результаты проверок стратегий: id -> сайт -> {ok, stage, ping, kbps, full, at} */
    fun matrix(ctx: Context): JSONObject =
        runCatching { JSONObject(p(ctx).getString("matrix", "{}")!!) }.getOrElse { JSONObject() }
    fun setMatrix(ctx: Context, m: JSONObject) = p(ctx).edit().putString("matrix", m.toString()).apply()

    /** Сколько раз каждая стратегия срабатывала - пробуем их первыми. */
    fun worked(ctx: Context): Map<String, Int> {
        val o = runCatching { JSONObject(p(ctx).getString("worked", "{}")!!) }.getOrElse { JSONObject() }
        return o.keys().asSequence().associateWith { o.optInt(it) }
    }

    fun recordWorked(ctx: Context, id: String) {
        val o = runCatching { JSONObject(p(ctx).getString("worked", "{}")!!) }.getOrElse { JSONObject() }
        o.put(id, o.optInt(id) + 1)
        p(ctx).edit().putString("worked", o.toString()).apply()
    }
}
