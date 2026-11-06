package com.likfridman.dpibypass

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Base64
import android.view.WindowInsets
import android.webkit.JavascriptInterface
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebView
import android.webkit.WebViewClient
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** Окно «Ночь» - та же страница, что и в Windows-версии, но под телефон. */
class MainActivity : Activity() {

    private lateinit var web: WebView
    private val ui = Handler(Looper.getMainLooper())
    private var logSeq = 0L
    private var lastState = ""
    private var ready = false
    private val events = JSONArray()
    private var fileCb: ValueCallback<Array<Uri>>? = null
    private var pendingStart = false

    companion object {
        private const val REQ_VPN = 1
        private const val REQ_FILE = 2
        private const val REQ_NOTIF = 3
    }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Report.installCrashHandler(this)
        Engine.nativeDir = applicationInfo.nativeLibraryDir
        Engine.useDoH = Store.doh(this)
        safeThread {
            val v = Updater.fetch()
            if (v.isNotEmpty() && Updater.newer(v, BuildConfigVersion.name(this))) {
                Engine.log("Доступна новая версия $v - Settings → Updates")
                event(JSONObject().put("t", "update").put("v", v))
            }
        }.start()
        if (Store.consentOK(this)) {
            Report.sendPendingCrash(this)
            Report.sendExitReasons(this)
            // отчёт при каждом запуске (не при повороте экрана)
            if (savedInstanceState == null) Report.send(this, "launch")
        }
        window.setDecorFitsSystemWindowsCompat()
        web = WebView(this)
        web.setBackgroundColor(Color.parseColor("#070A1C"))
        web.settings.javaScriptEnabled = true
        web.settings.domStorageEnabled = true
        web.settings.allowFileAccess = false
        web.addJavascriptInterface(Bridge(), "Android")
        web.webViewClient = object : WebViewClient() {
            // упал процесс отрисовки страницы (нехватка памяти, сбой WebView) - без этого Android закрывает приложение
            override fun onRenderProcessGone(view: WebView?, detail: android.webkit.RenderProcessGoneDetail?): Boolean {
                val why = if (Build.VERSION.SDK_INT >= 26 && detail?.didCrash() == true) "сбой" else "нехватка памяти"
                Engine.err("Страница перезапущена: процесс WebView завершился ($why)")
                Report.error("WebView renderer gone: $why")
                (view?.parent as? android.view.ViewGroup)?.removeView(view)
                view?.destroy()
                ui.post { recreate() }
                return true
            }
        }
        web.webChromeClient = object : WebChromeClient() {
            override fun onShowFileChooser(view: WebView?, cb: ValueCallback<Array<Uri>>?, params: FileChooserParams?): Boolean {
                fileCb?.onReceiveValue(null)
                fileCb = cb
                val i = Intent(Intent.ACTION_GET_CONTENT).setType("image/*").addCategory(Intent.CATEGORY_OPENABLE)
                startActivityForResult(Intent.createChooser(i, "Картинка для фона"), REQ_FILE)
                return true
            }
        }
        web.setOnApplyWindowInsetsListener { v, insets ->
            val d = resources.displayMetrics.density
            val top: Int
            val bottom: Int
            if (Build.VERSION.SDK_INT >= 30) {
                val b = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout())
                top = b.top; bottom = b.bottom
            } else {
                @Suppress("DEPRECATION")
                top = insets.systemWindowInsetTop
                @Suppress("DEPRECATION")
                bottom = insets.systemWindowInsetBottom
            }
            js("window.__insets&&window.__insets(${(top / d).toInt()},${(bottom / d).toInt()})")
            insets
        }
        setContentView(web)
        web.loadUrl("file:///android_asset/ui/index.html")
        ui.post(pusher)

        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIF)
        }
        if (intent?.getBooleanExtra("selftest", false) == true) SelfTest.run(this)
        if (intent?.getStringExtra("page") != null) event(JSONObject().put("t", "go").put("p", intent.getStringExtra("page")))
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        intent.getStringExtra("page")?.let { event(JSONObject().put("t", "go").put("p", it)) }
    }

    private fun android.view.Window.setDecorFitsSystemWindowsCompat() {
        if (Build.VERSION.SDK_INT >= 30) setDecorFitsSystemWindows(false)
        else {
            @Suppress("DEPRECATION")
            decorView.systemUiVisibility = android.view.View.SYSTEM_UI_FLAG_LAYOUT_STABLE or
                android.view.View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN or android.view.View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
        }
    }

    /** Ошибка команды из страницы: не роняем приложение, а пишем в журнал, отчёт и показываем сообщение */
    private fun commandFailed(cmd: String, e: Throwable) {
        val st = android.util.Log.getStackTraceString(e).lines().take(8).joinToString(" | ")
        Engine.err("Ошибка команды $cmd: ${e.javaClass.simpleName}: ${e.message}")
        Report.error("команда $cmd: $st")
        toast("Ошибка: ${e.message ?: e.javaClass.simpleName} - отчёт отправлен")
        Report.send(this, "error")
    }

    /** Фоновый поток для команды: исключение внутри не завершает приложение */
    private fun safeThread(body: () -> Unit) = Thread {
        try {
            body()
        } catch (e: Throwable) {
            Engine.busy = false
            Engine.pinging = false
            commandFailed("фон", e)
        }
    }

    /** Выполнить JS на странице и дождаться результата (для автотеста интерфейса). null - страница не ответила */
    fun evalJs(code: String, timeoutMs: Long = 5000): String? {
        if (isFinishing || isDestroyed) return null
        val latch = java.util.concurrent.CountDownLatch(1)
        var r: String? = null
        ui.post { runCatching { web.evaluateJavascript(code) { r = it; latch.countDown() } }.onFailure { latch.countDown() } }
        latch.await(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS)
        return r
    }

    private fun js(code: String) = ui.post { web.evaluateJavascript(code, null) }

    private fun event(e: JSONObject) = synchronized(events) { events.put(e) }

    fun toast(text: String) = event(JSONObject().put("t", "toast").put("text", text))

    /** Раз в 300 мс отправляет в страницу состояние и новые строки журнала. */
    private val pusher = object : Runnable {
        override fun run() {
            try {
                push()
            } catch (e: Throwable) {
                Engine.dbg("обновление страницы: ${e.javaClass.simpleName}: ${e.message}")
            }
            ui.postDelayed(this, 300)
        }

        private fun push() {
            if (ready) {
                val st = Engine.stateJson(this@MainActivity).toString()
                val (seq, lines) = Engine.logsSince(logSeq)
                logSeq = seq
                val evs = synchronized(events) { val c = JSONArray(events.toString()); while (events.length() > 0) events.remove(0); c }
                if (st != lastState || lines.isNotEmpty() || evs.length() > 0) {
                    val m = JSONObject()
                    if (st != lastState) { m.put("state", JSONObject(st)); lastState = st }
                    if (lines.isNotEmpty()) m.put("logs", JSONArray(lines))
                    if (evs.length() > 0) m.put("events", evs)
                    web.evaluateJavascript("window.__push&&window.__push($m)", null)
                }
            }
        }
    }

    // ---------- включение (нужно разрешение на VPN) ----------

    fun startBypass(reselect: Boolean) {
        if (!Store.consentOK(this)) {
            event(JSONObject().put("t", "consent"))
            return
        }
        val prep = VpnService.prepare(this)
        if (prep != null) {
            pendingStart = reselect
            startActivityForResult(prep, REQ_VPN)
            return
        }
        Engine.starting = true
        BypassVpnService.start(this, reselect)
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        when (requestCode) {
            REQ_VPN -> if (resultCode == RESULT_OK) {
                Engine.starting = true
                BypassVpnService.start(this, pendingStart)
            } else toast("Без разрешения на VPN обход не включится")
            REQ_FILE -> {
                val uri = data?.data
                fileCb?.onReceiveValue(if (resultCode == RESULT_OK && uri != null) arrayOf(uri) else null)
                fileCb = null
            }
        }
    }

    // ---------- фон ----------

    private fun bgFile() = File(filesDir, "background")

    private fun bgInfo(): JSONObject {
        val o = JSONObject().put("dim", Store.bgDim(this)).put("blur", Store.bgBlur(this)).put("url", "")
        val f = bgFile()
        if (f.exists()) {
            val mime = File(filesDir, "background.mime").takeIf { it.exists() }?.readText() ?: "image/jpeg"
            o.put("url", "data:$mime;base64," + Base64.encodeToString(f.readBytes(), Base64.NO_WRAP))
        }
        return o
    }

    private fun bgSet(dataUrl: String): JSONObject {
        val head = dataUrl.substringBefore(",")
        val mime = head.removePrefix("data:").removeSuffix(";base64")
        if (!head.startsWith("data:image/") || !head.endsWith(";base64")) { toast("Это не картинка"); return bgInfo() }
        val raw = Base64.decode(dataUrl.substringAfter(","), Base64.DEFAULT)
        if (raw.size > 15 * 1024 * 1024) { toast("Картинка больше 15 МБ"); return bgInfo() }
        bgFile().writeBytes(raw)
        File(filesDir, "background.mime").writeText(mime)
        toast("Фон обновлён")
        return bgInfo()
    }

    // ---------- команды из страницы ----------

    inner class Bridge {
        @JavascriptInterface
        fun call(cmd: String, arg: String): String = try {
            callUnsafe(cmd, arg)
        } catch (e: Throwable) {
            commandFailed(cmd, e)
            "null"
        }

        private fun callUnsafe(cmd: String, arg: String): String {
            if (cmd != "ready" && cmd != "logs") Report.action(if (cmd.startsWith("bg")) cmd else "$cmd ${arg.take(80)}".trim())
            val res: Any? = when (cmd) {
                "ready" -> {
                    ready = true
                    lastState = ""
                    val (seq, lines) = Engine.logsSince(0)
                    logSeq = seq
                    JSONObject().put("state", Engine.stateJson(this@MainActivity)).put("logs", JSONArray(lines))
                }
                "on" -> { ui.post { startBypass(false) }; null }
                "off" -> { BypassVpnService.stop(this@MainActivity); null }
                "reselect" -> { ui.post { startBypass(true) }; null }
                "stop" -> { Engine.cancel = true; toast("Останавливаю..."); null }
                "diag" -> {
                    if (!Engine.busy) safeThread {
                        Engine.busy = true
                        try {
                            Engine.log("━━ Диагностика: без обхода ━━")
                            val r = Engine.probeAll(null)
                            Engine.sites.forEach { s -> r[s.name]?.let { Engine.log("  " + Engine.probeLine(s.name, it), if (it.ok) 'i' else 'e') } }
                        } finally { Engine.busy = false }
                    }.start()
                    null
                }
                "pingAll" -> {
                    if (!Engine.pinging && !Engine.busy) safeThread {
                        val r = Engine.pingAll(this@MainActivity)
                        toast("Ping all: ${r.values.count { it.ok }}/${r.size} work")
                    }.start()
                    null
                }
                "siteStrategies" -> Engine.siteStrategies(this@MainActivity, arg)
                "testStrategy" -> {
                    val (site, id) = arg.split("|").let { (it.getOrNull(0) ?: "") to (it.getOrNull(1) ?: "") }
                    if (Engine.busy) toast("Сейчас идёт подбор - подожди")
                    else safeThread {
                        Engine.busy = true
                        try {
                            val r = Engine.testOne(this@MainActivity, site, id)
                            toast(if (r == null) "byedpi не запустился" else if (r.ok) "$site: ${r.ms} ms · ${r.detail}" else "$site: ${r.detail}")
                            event(JSONObject().put("t", "stratUpdated").put("site", site))
                        } finally { Engine.busy = false }
                    }.start()
                    null
                }
                "chooseSites" -> {
                    val list = runCatching { JSONArray(arg) }.getOrNull()
                    val v = (0 until (list?.length() ?: 0)).map { list!!.getString(it) }.toSet()
                    Store.setChosenSites(this@MainActivity, v)
                    Engine.log("Сервисы для обхода: ${v.joinToString()}")
                    safeThread {
                        val pl = Store.plan(this@MainActivity)
                        if (pl != null) {
                            // невыбранные - напрямую, выбранные - по прежнему плану (новые подберутся при Re-tune)
                            val chosen = LinkedHashMap<String, String>()
                            Engine.sites.forEach { s -> chosen[s.name] = pl.strategyFor(s.name) }
                            chosen.entries.removeAll { it.value == Engine.NONE }
                            val np = Engine.finishPlan(this@MainActivity, chosen.filterKeys { it !in Store.unfixable(this@MainActivity) }, emptyList(), Store.matrix(this@MainActivity))
                            if (Engine.running) Pool.start(this@MainActivity, np)
                        }
                    }.start()
                    toast("Сохранено: ${v.size} сервисов")
                    null
                }
                "pin" -> {
                    val (site, id) = arg.split("|").let { (it.getOrNull(0) ?: "") to (it.getOrNull(1) ?: "") }
                    safeThread {
                        val pl = Engine.pin(this@MainActivity, site, id.ifEmpty { null })
                        if (Engine.running) Pool.start(this@MainActivity, pl)
                        toast(when (id) { "" -> "$site: автоматический выбор"; Engine.NONE -> "$site: без обхода"; else -> "$site: стратегия закреплена" })
                        event(JSONObject().put("t", "stratUpdated").put("site", site))
                    }.start()
                    null
                }
                "boot" -> { Store.setBoot(this@MainActivity, arg == "1"); null }
                "bgGet" -> bgInfo()
                "bgSet" -> bgSet(arg)
                "bgClear" -> { bgFile().delete(); bgInfo() }
                "bgOpts" -> {
                    val p = arg.split(":")
                    Store.setBgOpts(this@MainActivity, p.getOrNull(0)?.toIntOrNull() ?: 45, p.getOrNull(1)?.toIntOrNull() ?: 0)
                    null
                }
                "tgOpen" -> {
                    if (!TgProxy.ready) toast("Прокси Telegram запускается вместе с обходом - сначала включи обход")
                    else ui.post {
                        try {
                            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(TgProxy.link(this@MainActivity))))
                        } catch (e: Exception) {
                            toast("Telegram не установлен")
                        }
                    }
                    null
                }
                "tgCopy" -> {
                    val cm = getSystemService(android.content.ClipboardManager::class.java)
                    cm.setPrimaryClip(android.content.ClipData.newPlainText("Telegram proxy", TgProxy.link(this@MainActivity)))
                    toast("Link copied")
                    null
                }
                "tgAddProxy" -> {
                    val l = arg.trim()
                    val okLink = listOf("tg://proxy?", "tg://socks?", "https://t.me/proxy?", "https://t.me/socks?", "socks5://").any { l.startsWith(it, true) }
                    if (!okLink) toast("Нужна ссылка tg://proxy?... или socks5://адрес:порт")
                    else {
                        Store.setTgProxies(this@MainActivity, (Store.tgProxies(this@MainActivity) + l).distinct())
                        toast("Запасной прокси добавлен")
                        TgProxy.restartIfRunning(this@MainActivity)
                    }
                    null
                }
                "update" -> {
                    safeThread {
                        val v = Updater.fetch()
                        val cur = BuildConfigVersion.name(this@MainActivity)
                        when {
                            v.isEmpty() -> toast("GitHub не ответил - проверь интернет")
                            Updater.newer(v, cur) -> {
                                Engine.log("Доступна версия $v (сейчас $cur) - открываю загрузку APK")
                                toast("Новая версия $v - скачай и установи APK")
                                ui.post { runCatching { Updater.openDownload(this@MainActivity) } }
                            }
                            else -> toast("Установлена последняя версия ($cur)")
                        }
                    }.start()
                    null
                }
                "reset" -> {
                    safeThread {
                        if (Engine.running) BypassVpnService.stop(this@MainActivity)
                        Store.resetStrategies(this@MainActivity)
                        Engine.log("Настройки обхода сброшены: при следующем включении - подбор заново")
                        toast("Сброшено: при включении стратегии подберутся заново")
                    }.start()
                    null
                }
                "tgTest" -> {
                    safeThread {
                        val (ms, err) = TgProxy.check(this@MainActivity)
                        val msg = if (ms != null) "Telegram отвечает: ping $ms ms" else "Telegram не ответил: $err"
                        Engine.log(msg)
                        toast(msg)
                    }.start()
                    null
                }
                "blockQuic", "discordUdp", "tgMode", "doh" -> {
                    when (cmd) {
                        "doh" -> { Store.setDoh(this@MainActivity, arg == "1"); Engine.useDoH = arg == "1" }
                        "blockQuic" -> Store.setBlockQuic(this@MainActivity, arg == "1")
                        "discordUdp" -> Store.setDiscordUdp(this@MainActivity, arg == "1")
                        else -> if (arg in listOf("auto", "ws", "direct")) Store.setTgMode(this@MainActivity, arg)
                    }
                    // перезапустить процессы обхода с новыми настройками (план тот же)
                    if (Engine.running) safeThread { Pool.plan?.let { Pool.start(this@MainActivity, it) } }.start()
                    null
                }
                "tgFind" -> { TgProxy.discoverAsync(this@MainActivity, true) { toast(it) }; null }
                "tgUse" -> {
                    if (arg.startsWith("tg://proxy?")) {
                        Store.setTgProxies(this@MainActivity, (Store.tgProxies(this@MainActivity) + arg).distinct())
                        toast("Добавлен в запасные прокси")
                        TgProxy.restartIfRunning(this@MainActivity)
                    }
                    null
                }
                "tgOpenLink" -> {
                    if (arg.startsWith("tg://proxy?")) ui.post {
                        try { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(arg))) } catch (e: Exception) { toast("Telegram не установлен") }
                    }
                    null
                }
                "tgClearProxies" -> {
                    Store.setTgProxies(this@MainActivity, emptyList())
                    toast("Запасные прокси удалены")
                    TgProxy.restartIfRunning(this@MainActivity)
                    null
                }
                "tgWorker" -> {
                    val h = arg.trim().removePrefix("https://").removePrefix("wss://").substringBefore("/")
                    Store.setTgWorker(this@MainActivity, h)
                    toast(if (h.isEmpty()) "Worker убран" else "Worker сохранён: $h")
                    TgProxy.restartIfRunning(this@MainActivity)
                    null
                }
                "consent" -> {
                    if (arg == "1") {
                        Store.setConsent(this@MainActivity, true)
                        Engine.log("Пользовательское соглашение принято")
                        Report.send(this@MainActivity, "launch")
                    } else {
                        Store.setConsent(this@MainActivity, false)
                        ui.post { BypassVpnService.stop(this@MainActivity); finishAndRemoveTask() }
                    }
                    null
                }
                // строка в кавычках JSON: страница делает JSON.parse
                "agreement" -> JSONObject.quote(runCatching { assets.open("AGREEMENT.md").bufferedReader().readText() }.getOrDefault(""))
                "report" -> {
                    Report.send(this@MainActivity, "manual", done = { msg -> toast(msg) })
                    toast("Собираю отчёт…")
                    null
                }
                "vpnSettings" -> { ui.post { startActivity(Intent("android.settings.VPN_SETTINGS")) }; null }
                "github" -> { ui.post { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/LikFridman/dpi-bypass"))) }; null }
                "selftestDone" -> { SelfTest.pageReport(arg); null }
                "jsError" -> { Engine.log("[js] $arg"); null }
                else -> null
            }
            return res?.toString() ?: "null"
        }
    }

    override fun onDestroy() {
        ui.removeCallbacks(pusher)
        web.destroy()
        super.onDestroy()
    }
}
