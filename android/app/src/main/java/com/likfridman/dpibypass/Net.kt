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
        val errs = mutableListOf<String>()
        val routes = mutableListOf<Proxy>(Proxy.NO_PROXY)
        if (Engine.running) routes += Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", Engine.PORT))
        for ((i, px) in routes.withIndex()) {
            try {
                val r = once(url, method, body, timeoutMs, px)
                if (!accept(r) && i < routes.size - 1) { errs += "напрямую HTTP ${r.code} - не тот ответ (заглушка оператора?)"; continue }
                if (i > 0) Engine.dbg("запрос $url прошёл через обход")
                return r
            } catch (e: Exception) {
                errs += (if (i == 0) "напрямую: " else "через обход: ") + (e.message ?: e.javaClass.simpleName)
            }
        }
        throw Exception(errs.joinToString("; ").ifEmpty { "нет соединения" })
    }

    /**
     * Один запрос с жёстким пределом времени: у HttpURLConnection нет тайм-аута на запись тела и на
     * рукопожатие SOCKS, и при «чёрной дыре» у оператора запрос мог висеть бесконечно (и держать
     * очередь отчётов). Здесь запрос идёт в отдельном потоке и обрывается по сроку.
     */
    private fun once(url: String, method: String, body: ByteArray?, timeoutMs: Int, px: Proxy): Resp {
        val conn = java.util.concurrent.atomic.AtomicReference<HttpURLConnection?>()
        val task = java.util.concurrent.FutureTask<Resp>(java.util.concurrent.Callable { exec(url, method, body, timeoutMs, px, conn) })
        Thread(task, "net").apply { isDaemon = true }.start()
        return try {
            task.get(timeoutMs * 2L + 2000, java.util.concurrent.TimeUnit.MILLISECONDS)
        } catch (e: java.util.concurrent.TimeoutException) {
            runCatching { conn.get()?.disconnect() }
            task.cancel(true)
            throw Exception("нет ответа за ${(timeoutMs * 2 + 2000) / 1000} с" + if (px != Proxy.NO_PROXY) " (через обход)" else "")
        } catch (e: java.util.concurrent.ExecutionException) {
            val c = e.cause ?: e
            throw Exception("${c.javaClass.simpleName}: ${c.message}" + if (px != Proxy.NO_PROXY) " (через обход)" else "")
        }
    }

    private fun exec(url: String, method: String, body: ByteArray?, timeoutMs: Int, px: Proxy,
                     ref: java.util.concurrent.atomic.AtomicReference<HttpURLConnection?>): Resp {
        val c = URL(url).openConnection(px) as HttpURLConnection
        ref.set(c)
        c.connectTimeout = timeoutMs; c.readTimeout = timeoutMs
        c.instanceFollowRedirects = false // редирект на страницу оператора - не ответ сервера
        c.requestMethod = method
        c.setRequestProperty("Cache-Control", "no-cache")
        if (body != null) {
            c.doOutput = true
            c.setRequestProperty("Content-Type", "application/json")
            c.setFixedLengthStreamingMode(body.size)
            c.outputStream.use { it.write(body) }
        }
        val code = c.responseCode
        val text = runCatching { (if (code < 400) c.inputStream else c.errorStream)?.bufferedReader()?.readText() ?: "" }.getOrDefault("")
        c.disconnect()
        return Resp(code, text)
    }
}
