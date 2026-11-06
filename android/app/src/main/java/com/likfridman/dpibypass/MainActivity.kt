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
        window.setDecorFitsSystemWindowsCompat()
        web = WebView(this)
        web.setBackgroundColor(Color.parseColor("#070A1C"))
        web.settings.javaScriptEnabled = true
        web.settings.domStorageEnabled = true
        web.settings.allowFileAccess = false
        web.addJavascriptInterface(Bridge(), "Android")
        web.webViewClient = WebViewClient()
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

    private fun js(code: String) = ui.post { web.evaluateJavascript(code, null) }

    private fun event(e: JSONObject) = synchronized(events) { events.put(e) }

    fun toast(text: String) = event(JSONObject().put("t", "toast").put("text", text))

    /** Раз в 300 мс отправляет в страницу состояние и новые строки журнала. */
    private val pusher = object : Runnable {
        override fun run() {
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
            ui.postDelayed(this, 300)
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
        fun call(cmd: String, arg: String): String {
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
                    if (!Engine.busy) Thread {
                        Engine.busy = true
                        try {
                            Engine.log("== Диагностика: проверка без обхода ==")
                            val r = Engine.probeAll(null)
                            Engine.sites.forEach { s -> r[s.name]?.let { Engine.log(Engine.probeLine(s.name, it)) } }
                        } finally { Engine.busy = false }
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
                "tgTest" -> {
                    Thread {
                        val (ms, err) = TgProxy.check(this@MainActivity)
                        val msg = if (ms != null) "Telegram отвечает: ping $ms ms" else "Telegram не ответил: $err"
                        Engine.log(msg)
                        toast(msg)
                    }.start()
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
                    } else {
                        Store.setConsent(this@MainActivity, false)
                        ui.post { BypassVpnService.stop(this@MainActivity); finishAndRemoveTask() }
                    }
                    null
                }
                // строка в кавычках JSON: страница делает JSON.parse
                "agreement" -> JSONObject.quote(runCatching { assets.open("AGREEMENT.md").bufferedReader().readText() }.getOrDefault(""))
                "report" -> {
                    Report.send(this@MainActivity, "manual") { msg -> toast(msg) }
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
