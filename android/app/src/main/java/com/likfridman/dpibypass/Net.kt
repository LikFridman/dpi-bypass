package com.likfridman.dpibypass

import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL

/**
 * Запросы самого приложения (отчёты, обновления, стратегии по провайдеру). Приложение не идёт через
 * свой VPN-туннель, поэтому заблокированные у оператора адреса (например, *.workers.dev) напрямую
 * недоступны: тогда запрос повторяется через обход (byedpi на 127.0.0.1, SOCKS5).
 */
object Net {
    data class Resp(val code: Int, val body: String)

    fun get(url: String, timeoutMs: Int = 6000, accept: (Resp) -> Boolean = { it.code == 200 }) = request(url, "GET", null, timeoutMs, accept)

    /**
     * accept - похож ли ответ на настоящий (оператор вместо заблокированного адреса часто отдаёт свою
     * страницу-заглушку с кодом 200 или 302); если нет - тот же запрос через обход.
     */
    fun request(url: String, method: String, body: ByteArray?, timeoutMs: Int = 8000, accept: (Resp) -> Boolean = { it.code in 200..499 && it.code != 403 && it.code != 451 }): Resp {
        var last: Exception? = null
        val routes = mutableListOf<Proxy>(Proxy.NO_PROXY)
        if (Engine.running) routes += Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", Engine.PORT))
        for ((i, px) in routes.withIndex()) {
            try {
                val r = once(url, method, body, timeoutMs, px)
                if (!accept(r) && i < routes.size - 1) { last = Exception("HTTP ${r.code}: не тот ответ (заглушка?)"); continue }
                if (i > 0) Engine.dbg("запрос $url прошёл через обход")
                return r
            } catch (e: Exception) {
                last = e
            }
        }
        throw last ?: Exception("нет соединения")
    }

    private fun once(url: String, method: String, body: ByteArray?, timeoutMs: Int, px: Proxy): Resp {
        val c = URL(url).openConnection(px) as HttpURLConnection
        c.connectTimeout = timeoutMs; c.readTimeout = timeoutMs
        c.instanceFollowRedirects = false // редирект на страницу оператора - не ответ сервера
        c.requestMethod = method
        c.setRequestProperty("Cache-Control", "no-cache")
        if (body != null) {
            c.doOutput = true
            c.setRequestProperty("Content-Type", "application/json")
            c.outputStream.use { it.write(body) }
        }
        val code = c.responseCode
        val text = runCatching { (if (code < 400) c.inputStream else c.errorStream)?.bufferedReader()?.readText() ?: "" }.getOrDefault("")
        c.disconnect()
        return Resp(code, text)
    }
}
