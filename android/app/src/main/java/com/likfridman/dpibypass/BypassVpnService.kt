package com.likfridman.dpibypass

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import java.io.File

/**
 * Локальный VPN: весь трафик телефона идёт в туннель, оттуда через hev-socks5-tunnel
 * в byedpi на 127.0.0.1, а byedpi отправляет его в интернет напрямую, «разрезав» так,
 * чтобы DPI провайдера не узнал сайт. Само приложение исключено из туннеля.
 */
class BypassVpnService : VpnService() {

    companion object {
        const val ACTION_START = "start"
        const val ACTION_STOP = "stop"
        const val ACTION_RESELECT = "reselect"
        private const val CHANNEL = "bypass"

        fun start(ctx: Context, reselect: Boolean = false) {
            val i = Intent(ctx, BypassVpnService::class.java).setAction(if (reselect) ACTION_RESELECT else ACTION_START)
            if (Build.VERSION.SDK_INT >= 26) ctx.startForegroundService(i) else ctx.startService(i)
        }

        fun stop(ctx: Context) {
            ctx.startService(Intent(ctx, BypassVpnService::class.java).setAction(ACTION_STOP))
        }
    }

    private var tun: ParcelFileDescriptor? = null
    private var worker: Thread? = null
    @Volatile private var stopping = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                shutdown()
                return START_NOT_STICKY
            }
            else -> {
                foreground()
                val reselect = intent?.action == ACTION_RESELECT
                val old = worker
                if (old?.isAlive == true && !reselect) return START_STICKY
                worker = Thread {
                    // старый запуск (если был) сначала останавливаем
                    if (old?.isAlive == true) {
                        stopping = true
                        Engine.cancel = true
                        old.join(30_000)
                    }
                    shutdownTunnel()
                    stopping = false
                    run(reselect)
                }.apply { start() }
            }
        }
        return START_STICKY
    }

    private fun foreground() {
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= 26) {
            nm.createNotificationChannel(NotificationChannel(CHANNEL, getString(R.string.notif_channel), NotificationManager.IMPORTANCE_LOW))
        }
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(this, 1, Intent(this, BypassVpnService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE)
        val n = Notification.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_stat)
            .setContentTitle(getString(R.string.notif_on))
            .setContentText(Engine.status)
            .setContentIntent(open)
            .setOngoing(true)
            .addAction(Notification.Action.Builder(null, getString(R.string.notif_stop), stop).build())
            .build()
        if (Build.VERSION.SDK_INT >= 34) startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        else startForeground(1, n)
    }

    private fun run(reselect: Boolean) {
        Report.installCrashHandler(this)
        Engine.nativeDir = applicationInfo.nativeLibraryDir
        Engine.useDoH = Store.doh(this)
        Report.startedAt = System.currentTimeMillis()
        Engine.starting = true
        Engine.cancel = false
        // был ли включён другой VPN до нас (для отчёта)
        Report.otherVpnBeforeStart = runCatching {
            val cm = getSystemService(android.net.ConnectivityManager::class.java)
            @Suppress("DEPRECATION")
            cm.allNetworks.any { cm.getNetworkCapabilities(it)?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN) == true }
        }.getOrDefault(false) && tun == null
        try {
            var plan = Store.plan(this)
            if (plan == null || reselect) plan = Engine.select(this)
            if (stopping) return
            Engine.status = "Starting…"
            if (!Pool.start(this, plan)) {
                Engine.log("byedpi не запустился - подбираю другую стратегию")
                plan = Engine.select(this)
                Pool.start(this, plan)
            }
            if (!startTunnel()) {
                Report.error("VPN-туннель не создан")
                Report.send(this, "error")
                Engine.log("Не удалось создать VPN-туннель. Возможно, включён другой VPN с «постоянным» режимом.")
                Engine.status = "Ошибка: VPN-туннель не создан"
                shutdown()
                return
            }
            Engine.running = true
            Engine.starting = false
            Engine.log("Обход работает: ${Pool.describe()}" + (if (Pool.routerReady) "" else " (без маршрутизатора)"))
            TgProxy.start(this, Engine.PORT)
            TgProxy.discoverAsync(this, false)
            watch()
        } catch (e: Exception) {
            Report.error("сбой: ${e.javaClass.simpleName}: ${e.message}")
            Report.send(this, "error")
            Engine.log("Ошибка: ${e.message}")
            Engine.status = "Ошибка: ${e.message}"
            shutdown()
        } finally {
            Engine.starting = false
        }
    }

    private fun startTunnel(): Boolean {
        val b = Builder()
            .setSession("dpi-bypass")
            .setMtu(8500)
            .addAddress("198.18.0.1", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")
            .addDnsServer("8.8.8.8")
        runCatching { b.addAddress("fc00::1", 128).addRoute("::", 0) }
        // само приложение (и byedpi внутри него) идёт мимо туннеля, иначе трафик зациклится
        runCatching { b.addDisallowedApplication(packageName) }
        if (Build.VERSION.SDK_INT >= 29) b.setMetered(false)
        tun = b.establish() ?: return false
        val cfg = File(filesDir, "hev.yml")
        cfg.writeText(
            """
            tunnel:
              mtu: 8500
              ipv4: 198.18.0.1
              ipv6: 'fc00::1'
            socks5:
              port: ${Pool.tunnelPort()}
              address: 127.0.0.1
              udp: 'udp'
            misc:
              task-stack-size: 81920
              log-level: warn
            """.trimIndent()
        )
        return TProxyService.TProxyStartService(cfg.absolutePath, tun!!.fd)
    }

    /** Сторож: раз в минуту проверяет сайты через обход и перезапускает byedpi, если упал. */
    private fun watch() {
        var fails = 0
        var reported = false
        while (!stopping) {
            // проверка тем же путём, что и трафик: через маршрутизатор (стратегии по сайтам)
            // фоновая проверка - лёгкая (начало страниц), чтобы не тратить мобильный трафик;
            // полная, с видео и файлами, - при подборе и по кнопке Ping all
            if (!Engine.pinging) Engine.results = Engine.probeAll(Pool.tunnelPort(), Engine.sites.filter { !Store.unfixable(this).contains(it.name) }, quick = true)
            Engine.checkedAt = System.currentTimeMillis()
            val ok = Engine.results.values.count { it.ok }
            val total = Engine.results.size
            val avg = Engine.avgPing(Engine.results)
            val bad = Engine.results.filter { !it.value.ok }.keys
            Engine.status = "Running: $ok/$total up" +
                (if (avg > 0) " · ping ~$avg ms" else "") +
                (if (bad.isNotEmpty()) " · none: " + bad.joinToString(", ") else "")
            foreground()
            fails = if (total > 0 && ok * 2 < total) fails + 1 else 0
            if (!reported) {
                reported = true
                // отчёт о подключении - когда Telegram успеет поработать
                Thread { Thread.sleep(20_000); Report.send(this, "connect") }.start()
            }
            if (fails >= 2 && !stopping) {
                Engine.log("Сайты перестали открываться - подбираю стратегию заново")
                Report.error("сайты перестали открываться: $ok из $total")
                Report.send(this, "error")
                Pool.stopAll()
                val pl = Engine.select(this)
                Pool.start(this, pl)
                fails = 0
                continue
            }
            if (System.currentTimeMillis() - TgProxy.foundAt > 30 * 60_000L) TgProxy.discoverAsync(this, false)
            for (i in 0 until 300) {
                if (stopping) return
                if (i % 5 == 0) Pool.ensureAlive(this)
                Thread.sleep(1000)
            }
        }
    }

    private fun shutdownTunnel() {
        TgProxy.stop()
        runCatching { if (TProxyService.TProxyIsRunning()) TProxyService.TProxyStopService() }
        runCatching { tun?.close() }
        tun = null
        Pool.stopAll()
    }

    private fun shutdown() {
        stopping = true
        Engine.cancel = true
        shutdownTunnel()
        Engine.running = false
        Engine.starting = false
        Engine.results = emptyMap()
        Engine.status = "Bypass off"
        Engine.log("Обход выключен")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onRevoke() {
        Engine.log("VPN отключён системой (включили другой VPN?)")
        shutdown()
    }

    override fun onDestroy() {
        if (!stopping) shutdown()
        super.onDestroy()
    }
}
