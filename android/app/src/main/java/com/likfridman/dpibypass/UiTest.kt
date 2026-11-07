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
        for (p in listOf("home", "sites", "vpn", "dns", "log", "set", "home")) {
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
        // кнопка Use в строке, где заголовок начинается с prefix (способ, None) или в строке с Test (стратегия)
        fun useIn(prefix: String?, what: String) {
            val cond = if (prefix == null) "r.querySelector('button')&&[...r.querySelectorAll('button')].some(x=>x.textContent==='Test')"
                else "(r.querySelector('.nm b')||{}).textContent&&r.querySelector('.nm b').textContent.startsWith(${q(prefix)})"
            val r = js("(function(){const r=[...document.querySelectorAll('#shList .st')].find(r=>$cond);if(!r)return 'none';const b=[...r.querySelectorAll('button')].find(x=>x.textContent==='Use');if(!b)return 'nobtn';b.click();return 'ok'})()")
            check("нажатие: Use - $what", r == "\"ok\"", r ?: "")
        }
        useIn(null, "стратегия"); Thread.sleep(8000)
        alive("Use стратегии")
        useIn("None", "None (без обхода)"); Thread.sleep(8000)
        alive("None")
        useIn("Обход", "способ «обход»"); Thread.sleep(6000)
        alive("способ обход")
        click("#shAuto", "Auto (снять закрепление)"); Thread.sleep(8000)
        alive("Auto")
        click("#shCheck", "Check now (проверка способов)"); Thread.sleep(12000)
        val ups = js("document.querySelectorAll('#shList .st .bd.ok').length")?.toIntOrNull() ?: 0
        check("способы сервиса проверены (есть рабочие)", ups > 0, "рабочих строк $ups")
        click("#shClose", "закрыть окно стратегий"); Thread.sleep(500)

        // диагностика, Telegram, настройки, журнал, отчёт
        click("[data-a=diag]", "Diagnostics"); Thread.sleep(1500); waitIdle(90)
        alive("Diagnostics")
        // Telegram - в общем списке сервисов: способы WebSocket, MTProto-прокси, поиск прокси
        click(".tab[data-p=sites]", "вкладка Sites"); Thread.sleep(600)
        val tgOpen = js("(function(){const r=[...document.querySelectorAll('#allSites .r.click')].find(x=>x.querySelector('.nm').firstChild.textContent==='Telegram');if(!r)return 'none';r.click();return 'ok'})()")
        check("окно Telegram открылось", tgOpen == "\"ok\"", tgOpen ?: ""); Thread.sleep(2000)
        val tgRows = js("[...document.querySelectorAll('#shList .st .nm b')].map(b=>b.textContent).join('|')") ?: ""
        check("у Telegram есть WebSocket и MTProto", "WebSocket" in tgRows && "MTProto" in tgRows, tgRows.take(200))
        js("(function(){const b=[...document.querySelectorAll('#shList button')].find(x=>x.textContent==='Find');b&&b.click()})()"); Thread.sleep(20000)
        useIn("WebSocket", "Telegram через WebSocket"); Thread.sleep(8000)
        alive("Telegram WebSocket")
        click("#shCheck", "Check now у Telegram"); Thread.sleep(2000)
        val tgAct = Pool.checkNow("Telegram")["Telegram"]
        val tgWs = tgAct?.optJSONArray("ups")?.let { a -> (0 until a.length()).map { a.getJSONObject(it) }.firstOrNull { it.optString("up") == "tg-ws" } }
        check("Telegram: WebSocket выбран, проверен и отвечает", tgAct?.optString("active") == "tg-ws" && tgWs?.optBoolean("ok") == true,
            tgAct?.toString()?.take(500) ?: "нет данных маршрутизатора")
        click("#shAuto", "Telegram - Auto"); Thread.sleep(8000)
        click("#shClose", "закрыть окно Telegram"); Thread.sleep(500)
        alive("Telegram")

        // VPN: свой ключ (разбор, удаление), проверка серверов, сервис через VPN
        click(".tab[data-p=vpn]", "вкладка VPN"); Thread.sleep(600)
        js("document.querySelector('#vpnIn').value='vless://00000000-0000-0000-0000-000000000000@127.0.0.1:9?security=none&type=tcp#selftest'")
        click("#vpnAdd", "добавить свой ключ"); Thread.sleep(3000)
        for (i in 0 until 60) { if (!Vpn.isTesting) break; Thread.sleep(1000) }
        Thread.sleep(1000)
        val own = js("document.querySelectorAll('#vpnOwn .fr').length")?.toIntOrNull() ?: 0
        check("свой ключ появился в списке", own > 0, "строк $own")
        for (i in 0 until 60) { if (!Vpn.isTesting) break; Thread.sleep(1000) }
        js("(function(){const b=[...document.querySelectorAll('#vpnOwn button')].find(x=>x.textContent==='Remove');b&&b.click()})()"); Thread.sleep(1500)
        check("свой ключ удаляется", Vpn.own(m).isEmpty(), Vpn.own(m).joinToString())
        for (i in 0 until 60) { if (!Vpn.isTesting) break; Thread.sleep(1000) }
        click("#vpnTest", "VPN Test all")
        for (i in 0 until 20) { if (Vpn.isTesting) break; Thread.sleep(300) }
        check("VPN: проверка серверов началась", Vpn.isTesting, Vpn.progress)
        for (i in 0 until 300) { if (!Vpn.isTesting) break; Thread.sleep(1000) }
        val vok = Vpn.best(m).size
        check("VPN: рабочие серверы найдены", vok > 0, js("document.querySelector('#vpnStat').textContent") ?: "")
        alive("VPN Test")
        if (vok > 0) {
            for (i in 0 until 20) { if (Pool.vpnAlive == true) break; Thread.sleep(1000) }
            check("VPN: Xray запущен маршрутизатором", Pool.vpnAlive == true, "vpn=${Pool.vpnAlive}")
            js("dpiCall('route','X/Twitter|vpn');1"); Thread.sleep(8000)
            val ri = Pool.checkNow("X/Twitter")["X/Twitter"]
            val act = ri?.optString("active") ?: ""
            val actOk = (0 until (ri?.optJSONArray("ups")?.length() ?: 0)).map { ri!!.getJSONArray("ups").getJSONObject(it) }.firstOrNull { it.optBoolean("active") }
            check("VPN: X/Twitter идёт через VPN и отвечает", Engine.kindOfUp(act) == "vpn" && actOk?.optBoolean("ok") == true, ri?.toString()?.take(500) ?: "нет данных")
            val probe = Engine.probeAll(Pool.tunnelPort(), Engine.sites.filter { it.name == "X/Twitter" })["X/Twitter"]
            check("VPN: проверка X/Twitter через туннель", probe?.ok == true, probe?.detail ?: "")
            js("dpiCall('route','X/Twitter|');1"); Thread.sleep(6000)
            alive("сервис через VPN")
        }

        click(".tab[data-p=set]", "вкладка Settings"); Thread.sleep(600)
        for (t in listOf("#togDoh", "#togQuic", "#togUdp")) { click(t, "переключатель $t"); Thread.sleep(4000); click(t, "переключатель $t обратно"); Thread.sleep(4000) }
        alive("переключатели настроек")
        click("[data-a=report]", "отправить отчёт"); Thread.sleep(3000)
        click(".tab[data-p=log]", "вкладка Log"); Thread.sleep(600)
        js("document.querySelectorAll('.chip').forEach(c=>c.click())"); Thread.sleep(600)
        click("[data-a=reselect]", "Re-tune"); Thread.sleep(3000); waitIdle(240)
        alive("Re-tune")

        // DNS приложений (запросы из оболочки эмулятора во время теста) должен идти через DoH маршрутизатора
        // после «Re-tune» маршрутизатор перезапущен и счётчики с нуля: ждём запросов оболочки (до 60 с)
        var rs = runCatching { org.json.JSONObject(Pool.routerStats) }.getOrNull()
        for (i in 0 until 30) {
            if ((rs?.optLong("dns") ?: 0) > 0) break
            Thread.sleep(2000)
            rs = runCatching { org.json.JSONObject(Pool.routerStats) }.getOrNull()
        }
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
