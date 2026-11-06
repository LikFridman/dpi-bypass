package com.likfridman.dpibypass

/**
 * Мост к hev-socks5-tunnel (libhev-socks5-tunnel.so): переводит трафик из VPN-туннеля
 * в локальный SOCKS-прокси byedpi. Библиотека собрана с PKGNAME=com/likfridman/dpibypass,
 * CLSNAME=TProxyService и регистрирует эти методы при загрузке.
 */
class TProxyService {
    companion object {
        init {
            System.loadLibrary("hev-socks5-tunnel")
        }

        @JvmStatic external fun TProxyStartService(configPath: String, fd: Int): Boolean
        @JvmStatic external fun TProxyStopService(): Boolean
        @JvmStatic external fun TProxyIsRunning(): Boolean
        @JvmStatic external fun TProxyGetStats(): LongArray?
    }
}
