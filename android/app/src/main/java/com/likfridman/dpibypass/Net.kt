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

    fun get(url: String, timeoutMs: Int = 6000) = request(url, "GET", null, timeoutMs)

    fun request(url: String, method: String, body: ByteArray?, timeoutMs: Int = 8000): Resp {
        var last: Exception? = null
        val routes = mutableListOf<Proxy>(Proxy.NO_PROXY)
        if (Engine.running) routes += Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", Engine.PORT))
        for ((i, px) in routes.withIndex()) {
            try {
                val r = once(url, method, body, timeoutMs, px)
                // 403/451 напрямую часто означает заглушку оператора - пробуем через обход
                if (i == 0 && routes.size > 1 && (r.code == 403 || r.code == 451)) { last = Exception("HTTP ${r.code}"); continue }
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
