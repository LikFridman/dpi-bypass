package com.likfridman.dpibypass

import android.app.Activity
import android.util.Log
import java.io.File

/**
 * Автотест интерфейса на эмуляторе: нажимает кнопки на странице так же, как человек
 * (при включённом обходе), и проверяет, что приложение не упало и страница отвечает.
 */
object UiTest {
    private const val TAG = "DPI_SELFTEST"

    fun run(a: Activity, check: (String, Boolean, String) -> Unit) {
        val m = a as? MainActivity ?: run { check("автотест интерфейса", false, "нет окна"); return }
        fun js(code: String) = m.evalJs(code, 8000)
        fun click(sel: String, what: String): Boolean {
            val r = js("(function(){const e=document.querySelector(${q(sel)});if(!e)return 'none';e.click();return 'ok'})()")
            val ok = r == "\"ok\""
            check("нажатие: $what", ok, r ?: "страница не ответила")
            return ok
        }
        fun alive(step: String) {
            val r = js("1+1")
            val crash = File(a.filesDir, "crash.txt")
            check("после «$step» приложение живо", r == "2" && !crash.exists(),
                if (crash.exists()) crash.readText().take(400) else (r ?: "страница не отвечает"))
        }
        fun waitIdle(sec: Int) {
            for (i in 0 until sec * 2) { if (!Engine.busy && !Engine.pinging) break; Thread.sleep(500) }
        }
        val logStart = Engine.logsSince(0).first

        // вкладки
        for (p in listOf("home", "sites", "tg", "log", "set", "home")) {
            click(".tab[data-p=$p]", "вкладка $p"); Thread.sleep(700)
        }
        alive("переключение вкладок")

        // Ping all
        click("#pingBtn", "Ping all"); Thread.sleep(1500); waitIdle(120)
        alive("Ping all")

        // окно стратегий для сервиса: Test, Use, Auto
        click(".tab[data-p=sites]", "вкладка Sites"); Thread.sleep(800)
        click("#allSites .r.click", "сервис в списке"); Thread.sleep(2000)
        val rows = js("document.querySelectorAll('#shList .r').length")?.toIntOrNull() ?: 0
        check("окно стратегий открылось", rows > 0, "строк $rows")
        val tested = js("(function(){const b=[...document.querySelectorAll('#shList button')].find(x=>x.textContent==='Test');if(!b)return 'none';b.click();return 'ok'})()")
        check("нажатие: Test у стратегии", tested == "\"ok\"", tested ?: "")
        Thread.sleep(1500); waitIdle(90)
        alive("Test стратегии")
        val used = js("(function(){const b=[...document.querySelectorAll('#shList button')].filter(x=>x.textContent==='Use')[1];if(!b)return 'none';b.click();return 'ok'})()")
        check("нажатие: Use у стратегии", used == "\"ok\"", used ?: "")
        Thread.sleep(8000)
        alive("Use стратегии")
        click("#shAuto", "Auto (снять закрепление)"); Thread.sleep(8000)
        alive("Auto")
        click("#shClose", "закрыть окно стратегий"); Thread.sleep(500)

        // диагностика, Telegram, настройки, журнал, отчёт
        click("[data-a=diag]", "Diagnostics"); Thread.sleep(1500); waitIdle(90)
        alive("Diagnostics")
        click(".tab[data-p=tg]", "вкладка Telegram"); Thread.sleep(600)
        click("[data-a=tgFind]", "поиск прокси Telegram"); Thread.sleep(15000)
        click("[data-a=tgTest]", "проверка Telegram"); Thread.sleep(10000)
        alive("Telegram")
        click(".tab[data-p=set]", "вкладка Settings"); Thread.sleep(600)
        for (t in listOf("#togDoh", "#togQuic", "#togUdp")) { click(t, "переключатель $t"); Thread.sleep(4000); click(t, "переключатель $t обратно"); Thread.sleep(4000) }
        alive("переключатели настроек")
        click("[data-a=report]", "отправить отчёт"); Thread.sleep(3000)
        click(".tab[data-p=log]", "вкладка Log"); Thread.sleep(600)
        js("document.querySelectorAll('.chip').forEach(c=>c.click())"); Thread.sleep(600)
        click("[data-a=reselect]", "Re-tune"); Thread.sleep(3000); waitIdle(240)
        alive("Re-tune")

        val bad = Engine.logsSince(0).second.filter { "Ошибка команды" in it || "Страница перезапущена" in it }
        check("ошибок команд нет", bad.isEmpty(), bad.joinToString(" / ").take(500))
        Log.i(TAG, "INFO ui log lines since start: ${Engine.logsSince(logStart).second.size}")
    }

    private fun q(s: String) = "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"
}
