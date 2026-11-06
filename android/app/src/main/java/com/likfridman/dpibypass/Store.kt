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
