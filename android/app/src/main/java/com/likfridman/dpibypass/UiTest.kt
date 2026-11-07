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
        for (p in listOf("home", "sites", "dns", "tg", "log", "set", "home")) {
            click(".tab[data-p=$p]", "вкладка $p"); Thread.sleep(700)
        }
        alive("переключение вкладок")

        // DNS: проверка серверов и выбор
        click(".tab[data-p=dns]", "вкладка DNS"); Thread.sleep(600)
        val dn = js("document.querySelectorAll('#dnsList .dnsr').length")?.toIntOrNull() ?: 0
        check("список серверов DNS", dn > 3, "серверов $dn")
        click("#dnsTest", "DNS Test all"); Thread.sleep(16000)
        js("(function(){const r=document.querySelectorAll('#dnsList .dnsr');r[2]&&r[2].click()})()"); Thread.sleep(4000)
        js("(function(){const r=document.querySelectorAll('#dnsList .dnsr');r[0]&&r[0].click()})()"); Thread.sleep(4000)
        alive("DNS")

        // выбор сервисов (Sites → Choose → Save)
        click(".tab[data-p=sites]", "вкладка Sites"); Thread.sleep(600)
        click("#chooseBtn", "Choose"); Thread.sleep(800)
        val n = js("document.querySelectorAll('#chList input').length")?.toIntOrNull() ?: 0
        check("окно выбора сервисов", n > 0, "сервисов $n")
        js("document.querySelectorAll('#chList input').forEach(c=>c.checked=true)")
        click("#chSave", "Save"); Thread.sleep(2000)
        alive("выбор сервисов")

        // Ping all
        click(".tab[data-p=home]", "вкладка Bypass"); Thread.sleep(600)
        click("#pingBtn", "Ping all"); Thread.sleep(1500); waitIdle(120)
        alive("Ping all")

        // окно стратегий для сервиса: Test, Use, Auto
        click(".tab[data-p=sites]", "вкладка Sites"); Thread.sleep(800)
        click("#allSites .r.click", "сервис в списке"); Thread.sleep(2000)
        val rows = js("document.querySelectorAll('#shList .st').length")?.toIntOrNull() ?: 0
        check("окно стратегий открылось", rows > 0, "строк $rows")
        val tested = js("(function(){const b=[...document.querySelectorAll('#shList button')].find(x=>x.textContent==='Test');if(!b)return 'none';b.click();return 'ok'})()")
        check("нажатие: Test у стратегии", tested == "\"ok\"", tested ?: "")
        Thread.sleep(1500); waitIdle(90)
        alive("Test стратегии")
        val used = js("(function(){const b=[...document.querySelectorAll('#shList button')].filter(x=>x.textContent==='Use')[1];if(!b)return 'none';b.click();return 'ok'})()")
        check("нажатие: Use у стратегии", used == "\"ok\"", used ?: "")
        Thread.sleep(8000)
        alive("Use стратегии")
        val none = js("(function(){const b=document.querySelector('#shList .st button');if(!b)return 'none';b.click();return 'ok'})()")
        check("нажатие: None (без обхода)", none == "\"ok\"", none ?: "")
        Thread.sleep(8000)
        alive("None")
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

        // DNS приложений (запросы из оболочки эмулятора во время теста) должен идти через DoH маршрутизатора
        val rs = runCatching { org.json.JSONObject(Pool.routerStats) }.getOrNull()
        val dnsQ = rs?.optLong("dns") ?: 0
        val dnsFail = rs?.optLong("dns_fail") ?: 0
        val doh = rs?.optJSONObject("doh")
        check("DNS из туннеля идёт через зашифрованный DNS", dnsQ > 0 && dnsFail < dnsQ,
            "запросов $dnsQ, ошибок $dnsFail, сервер ${doh?.optString("current")}, кеш ${doh?.optLong("cache_hits")}")
        val noBackup = Engine.logsSince(0).second.count { "не принял запасную" in it }
        check("byedpi принял запасную стратегию", noBackup == 0, "отказов $noBackup")
        val bad = Engine.logsSince(0).second.filter { "Ошибка команды" in it || "Страница перезапущена" in it }
        check("ошибок команд нет", bad.isEmpty(), bad.joinToString(" / ").take(500))
        Log.i(TAG, "INFO ui log lines since start: ${Engine.logsSince(logStart).second.size}")
    }

    private fun q(s: String) = "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"
}
