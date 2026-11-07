package com.likfridman.dpibypass

import android.content.Context
import android.content.Intent
import android.net.Uri
import java.net.HttpURLConnection
import java.net.URL

/** Проверка новой версии приложения на GitHub (как на ПК): номер версии и ссылка на APK. */
object Updater {
    private val versionUrls = listOf(
        "https://raw.githubusercontent.com/LikFridman/dpi-bypass/main/dpi-bypass-android.version",
        "https://cdn.jsdelivr.net/gh/LikFridman/dpi-bypass@main/dpi-bypass-android.version",
    )
    const val APK_URL = "https://github.com/LikFridman/dpi-bypass/raw/main/dpi-bypass.apk"

    @Volatile var latest = ""
    @Volatile var checkedAt = 0L

    /** Последняя версия на GitHub ("" - не узнать) */
    fun fetch(): String {
        for (u in versionUrls) {
            runCatching {
                val v = Net.get(u) { x -> x.code == 200 && Regex("""\s*\d+(\.\d+){0,3}\s*""").matches(x.body) }.takeIf { it.code == 200 }?.body?.trim() ?: return@runCatching
                if (Regex("""\d+(\.\d+){0,3}""").matches(v)) {
                    latest = v; checkedAt = System.currentTimeMillis()
                    return v
                }
            }
        }
        return ""
    }

    private val configUrls = listOf(
        "https://raw.githubusercontent.com/LikFridman/dpi-bypass/main/update/update.json",
        "https://cdn.jsdelivr.net/gh/LikFridman/dpi-bypass@main/update/update.json",
    )

    /** Настройки с GitHub (update.json): адрес отчётов, списки прокси Telegram, серверы DNS */
    fun refreshConfig(ctx: Context) {
        for (u in configUrls) {
            runCatching {
                val r = Net.get(u) { x -> x.code == 200 && x.body.trimStart().startsWith("{") }
                if (r.code != 200) return@runCatching
                val j = org.json.JSONObject(r.body)
                j.optString("report_url").trimEnd('/').takeIf { it.startsWith("https://") }?.let { Store.setReportUrl(ctx, it) }
                j.optJSONArray("tg_proxy_sources")?.let { a -> Store.setTgSources(ctx, (0 until a.length()).map { a.getString(it) }) }
                j.optJSONArray("dns_providers")?.takeIf { it.length() > 0 }?.let { Store.setDnsProviders(ctx, it.toString()) }
                return
            }
        }
    }

    /** a > b для версий вида 2.3.1 */
    fun newer(a: String, b: String): Boolean {
        val x = a.split(".").map { it.toIntOrNull() ?: 0 }
        val y = b.split(".").map { it.toIntOrNull() ?: 0 }
        for (i in 0 until maxOf(x.size, y.size)) {
            val p = x.getOrElse(i) { 0 }
            val q = y.getOrElse(i) { 0 }
            if (p != q) return p > q
        }
        return false
    }

    fun available(ctx: Context) = latest.isNotEmpty() && newer(latest, BuildConfigVersion.name(ctx))

    fun openDownload(ctx: Context) {
        ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(APK_URL)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }
}
