package com.likfridman.dpibypass

import android.app.Activity
import android.net.VpnService
import android.util.Log
import java.io.File

/**
 * Самопроверка для эмулятора на GitHub Actions (запуск с флагом selftest):
 * byedpi запускается со всеми стратегиями, через него открывается сайт,
 * поднимается VPN-туннель. Результаты - в logcat с меткой DPI_SELFTEST.
 */
object SelfTest {
    private const val TAG = "DPI_SELFTEST"
    @Volatile private var page: String? = null

    fun pageReport(json: String) { page = json }

    private val started = java.util.concurrent.atomic.AtomicBoolean(false)

    fun run(a: Activity) {
        if (!started.compareAndSet(false, true)) return // окно могло пересоздаться - проверка одна
        thread(a)
    }

    private fun thread(a: Activity) = Thread {
        val out = StringBuilder()
        var failed = 0
        fun check(name: String, ok: Boolean, detail: String = "") {
            val line = "${if (ok) "OK  " else "FAIL"} $name $detail"
            if (!ok) failed++
            out.appendLine(line)
            Log.i(TAG, line)
        }
        val bin = Engine.binary(a)
        check("byedpi на месте", bin.exists() && bin.canExecute(), bin.absolutePath)
        for (s in Engine.strategies) {
            val p = runCatching { Engine.startProxy(a, s, Engine.TEST_PORT) }.getOrNull()
            Thread.sleep(300)
            check("стратегия ${s.id}", p?.isAlive == true)
            Engine.stopProxy(p)
        }
        val p = Engine.startProxy(a, Engine.strategies.first(), Engine.TEST_PORT)
        val r = Engine.probe("www.google.com", Engine.TEST_PORT)
        check("сайт через byedpi", r.ok, r.reason)
        TgProxy.start(a, Engine.TEST_PORT)
        for (i in 0 until 20) { if (TgProxy.ready) break; Thread.sleep(250) }
        check("прокси Telegram запустился", TgProxy.ready, TgProxy.lastError)
        val (tgMs, tgErr) = TgProxy.check(a)
        // настоящий запрос к Telegram - не критично, сеть эмулятора в CI может не пустить
        out.appendLine(if (tgMs != null) "INFO Telegram ответил через прокси за $tgMs мс" else "INFO Telegram через прокси: $tgErr")
        Log.i(TAG, if (tgMs != null) "INFO Telegram ok $tgMs ms" else "INFO Telegram fail $tgErr")
        TgProxy.stop()
        Engine.stopProxy(p)
        val direct = Engine.probe("www.google.com", null)
        check("сайт напрямую", direct.ok, direct.reason)
        check("пинг измеряется", direct.ms > 0, direct.label)

        val rj = runCatching { Report.build(a, "test") }
        check("отчёт собирается", rj.getOrNull()?.has("device") == true, rj.exceptionOrNull()?.toString() ?: "${rj.getOrNull()?.toString()?.length} байт")
        rj.getOrNull()?.let { Log.i(TAG, "INFO report " + it.toString().take(3000)) }

        for (i in 0 until 40) { if (page != null) break; Thread.sleep(250) }
        check("страница", page == "[]", page ?: "нет ответа")

        if (VpnService.prepare(a) == null) {
            Store.setStrategy(a, Engine.strategies.first().id)
            BypassVpnService.start(a)
            var up = false
            for (i in 0 until 60) { if (Engine.running) { up = true; break }; Thread.sleep(500) }
            check("VPN-туннель поднялся", up, Engine.status)
        } else {
            check("VPN-туннель (нет разрешения - пропущено)", true)
        }
        out.appendLine(if (failed == 0) "RESULT OK" else "RESULT FAIL $failed")
        Log.i(TAG, if (failed == 0) "RESULT OK" else "RESULT FAIL $failed")
        File(a.filesDir, "selftest.txt").writeText(out.toString())
    }.start()
}
