package com.likfridman.dpibypass

import android.content.Context
import java.io.File
import java.io.IOException
import java.util.concurrent.TimeUnit

/**
 * Локальный MTProto-прокси для Telegram (libtgproxy.so - та же реализация на Go, что и в
 * Windows-версии). Telegram подключается к 127.0.0.1:PORT, а прокси ведёт трафик
 * WebSocket'ом к web.telegram.org через byedpi, напрямую, через Worker или запасной прокси.
 * Приложение исключено из своего VPN, поэтому прокси выходит в сеть напрямую.
 */
object TgProxy {
    const val PORT = 1443

    @Volatile private var proc: Process? = null
    @Volatile var ready = false
    @Volatile var stats = ""
    @Volatile var lastError = ""

    fun binary(ctx: Context) = File(ctx.applicationInfo.nativeLibraryDir, "libtgproxy.so")

    fun link(ctx: Context) = "tg://proxy?server=127.0.0.1&port=$PORT&secret=dd${Store.tgSecret(ctx)}"

    val running get() = proc?.isAlive == true

    @Synchronized
    fun start(ctx: Context, socksPort: Int?) {
        stop()
        val bin = binary(ctx)
        if (!bin.exists()) {
            lastError = "нет libtgproxy.so"
            Engine.log("Telegram: прокси не найден в приложении")
            return
        }
        val cmd = mutableListOf(bin.absolutePath, "-listen", "127.0.0.1:$PORT", "-secret", Store.tgSecret(ctx))
        if (socksPort != null) cmd += listOf("-socks", "127.0.0.1:$socksPort")
        Store.tgWorker(ctx).takeIf { it.isNotBlank() }?.let { cmd += listOf("-worker", it) }
        Store.tgProxies(ctx).forEach { cmd += listOf("-up", it) }
        ready = false
        stats = ""
        lastError = ""
        val p = try {
            ProcessBuilder(cmd).redirectErrorStream(true).start()
        } catch (e: IOException) {
            lastError = e.message ?: "не запустился"
            Engine.log("Telegram: прокси не запустился (${e.message})")
            return
        }
        proc = p
        Thread {
            try {
                p.inputStream.bufferedReader().forEachLine { line ->
                    when {
                        line.startsWith("READY ") -> {
                            ready = true
                            Engine.log("Telegram: прокси работает на 127.0.0.1:$PORT")
                        }
                        line.startsWith("STATS ") -> {
                            val n = line.removePrefix("STATS ").split(" ").mapNotNull { it.toLongOrNull() }
                            if (n.size == 5 && n[1] > 0)
                                stats = "connections ${n[1]} (active ${n[0]}) · WebSocket ${n[2]} · TCP ${n[3]} · failed ${n[4]}"
                        }
                        line.startsWith("LOG ") -> Engine.log(line.removePrefix("LOG "))
                        line.startsWith("ERR ") -> {
                            lastError = line.removePrefix("ERR ")
                            Engine.log("Telegram: ошибка прокси - $lastError")
                        }
                        line.isNotBlank() -> Engine.log("tgproxy: $line")
                    }
                }
            } catch (_: IOException) {
            }
            ready = false
        }.apply { isDaemon = true }.start()
    }

    @Synchronized
    fun stop() {
        val p = proc ?: return
        proc = null
        ready = false
        p.destroy()
        if (!p.waitFor(2, TimeUnit.SECONDS)) p.destroyForcibly()
    }

    /** Настоящий запрос к Telegram через запущенный прокси: время ответа в мс или текст ошибки. */
    fun check(ctx: Context): Pair<Long?, String> {
        if (!ready) return null to "прокси не запущен"
        return try {
            val p = ProcessBuilder(binary(ctx).absolutePath, "-check", "127.0.0.1:$PORT", "-secret", Store.tgSecret(ctx))
                .redirectErrorStream(true).start()
            val out = p.inputStream.bufferedReader().readText().trim()
            p.waitFor(25, TimeUnit.SECONDS)
            val line = out.lines().lastOrNull { it.startsWith("CHECK ") } ?: out
            if (line.startsWith("CHECK OK ")) line.removePrefix("CHECK OK ").toLongOrNull() to ""
            else null to line.removePrefix("CHECK FAIL ")
        } catch (e: Exception) {
            null to (e.message ?: "ошибка")
        }
    }

    /** Перезапуск после смены настроек (если обход включён). */
    fun restartIfRunning(ctx: Context) {
        if (running) Thread { start(ctx, Engine.PORT) }.start()
    }
}
