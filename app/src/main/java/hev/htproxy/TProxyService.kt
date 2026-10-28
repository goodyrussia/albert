package hev.htproxy

/**
 * Pure Kotlin stub so no native .so library is ever dlopen'd by JNI.
 * All TUN-to-SOCKS5 packet forwarding is handled in pure Kotlin by Tun2Socks.kt.
 */
class TProxyService {
    companion object {
        @JvmStatic
        fun TProxyStartService(configPath: String, fd: Int) {}

        @JvmStatic
        fun TProxyStopService() {}

        @JvmStatic
        fun TProxyGetStats(): LongArray = LongArray(4)

        fun start(configPath: String, fd: Int): Boolean = true
        fun stop(): Boolean = true
        fun stats(): LongArray = LongArray(4)
    }
}
