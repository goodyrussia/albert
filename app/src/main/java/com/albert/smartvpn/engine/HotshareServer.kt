package com.albert.smartvpn.engine

import android.util.Log
import com.albert.smartvpn.ui.viewmodel.VpnStateBridge
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.PushbackInputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors
import kotlin.concurrent.thread

object HotshareServer {
    private const val TAG = "HotshareServer"
    private var serverSocket: ServerSocket? = null
    private val workerPool = Executors.newFixedThreadPool(24)
    @Volatile private var isRunning = false

    fun detectHotspotIp(): String {
        return try {
            var fallbackIp = "192.168.43.1"
            val interfaces = NetworkInterface.getNetworkInterfaces()
            while (interfaces.hasMoreElements()) {
                val iface = interfaces.nextElement()
                if (!iface.isUp || iface.isLoopback) continue
                val name = iface.name.lowercase()
                val addrs = iface.inetAddresses
                while (addrs.hasMoreElements()) {
                    val addr = addrs.nextElement()
                    if (addr is Inet4Address && !addr.isLoopbackAddress) {
                        val ip = addr.hostAddress ?: continue
                        if (name.contains("ap") || name.contains("wlan") || name.contains("rndis") || ip.startsWith("192.168.")) {
                            if (ip.startsWith("192.168.43.") || ip.startsWith("192.168.42.") || name.contains("ap")) {
                                return ip
                            }
                            fallbackIp = ip
                        }
                    }
                }
            }
            fallbackIp
        } catch (_: Throwable) {
            "192.168.43.1"
        }
    }

    fun isDeviceRooted(): Boolean {
        return try {
            val proc = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
            val output = proc.inputStream.bufferedReader().readText()
            proc.waitFor() == 0 && output.contains("uid=0")
        } catch (_: Throwable) {
            false
        }
    }

    fun startHotshare(
        upstreamSocksPort: Int = VpnStateBridge.localSocksPort.value,
        listenPort: Int = VpnStateBridge.shareNetPort.value
    ): Boolean {
        stopHotshare()
        return try {
            val detectedIp = detectHotspotIp()
            VpnStateBridge.hotshareIp.value = detectedIp

            serverSocket = ServerSocket().apply {
                reuseAddress = true
                bind(InetSocketAddress("0.0.0.0", listenPort), 128)
            }
            isRunning = true
            VpnStateBridge.hotshareEnabled.value = true
            VpnStateBridge.addLog("ShareNet HTTP/SOCKS5 Proxy active on $detectedIp:$listenPort")

            thread(start = true, name = "ShareNet-Proxy-Listener") {
                while (isRunning) {
                    try {
                        val client = serverSocket?.accept() ?: break
                        client.tcpNoDelay = true
                        workerPool.execute {
                            handleTetheredClient(client, upstreamSocksPort)
                        }
                    } catch (_: Throwable) {
                        if (!isRunning) break
                    }
                }
            }
            true
        } catch (t: Throwable) {
            Log.e(TAG, "ShareNet start failed: ${t.message}")
            VpnStateBridge.hotshareEnabled.value = false
            false
        }
    }

    private fun handleTetheredClient(client: Socket, upstreamSocksPort: Int) {
        var upstream: Socket? = null
        try {
            val pushIn = PushbackInputStream(client.getInputStream(), 8192)
            val clientOut = client.getOutputStream()

            val firstByte = pushIn.read()
            if (firstByte == -1) {
                client.close()
                return
            }
            pushIn.unread(firstByte)

            // If client speaks SOCKS5 (0x05), pipe directly to local VPN SOCKS5 inbound
            if (firstByte == 0x05) {
                upstream = Socket().apply {
                    tcpNoDelay = true
                    connect(InetSocketAddress("127.0.0.1", upstreamSocksPort), 6000)
                }
                pipeBidirectional(pushIn, clientOut, upstream.getInputStream(), upstream.getOutputStream(), client, upstream)
                return
            }

            // Otherwise handle HTTP Proxy (CONNECT host:port or HTTP GET/POST)
            val headerBytes = ByteArray(8192)
            var hLen = 0
            while (hLen < headerBytes.size) {
                val b = pushIn.read()
                if (b == -1) break
                headerBytes[hLen++] = b.toByte()
                if (hLen >= 4 &&
                    headerBytes[hLen - 4] == '\r'.code.toByte() &&
                    headerBytes[hLen - 3] == '\n'.code.toByte() &&
                    headerBytes[hLen - 2] == '\r'.code.toByte() &&
                    headerBytes[hLen - 1] == '\n'.code.toByte()
                ) {
                    break
                }
            }
            val headerStr = String(headerBytes, 0, hLen, Charsets.ISO_8859_1)
            val lines = headerStr.split("\r\n")
            val firstLine = lines.firstOrNull() ?: ""
            val parts = firstLine.split(" ")
            if (parts.size < 2) {
                client.close()
                return
            }

            val method = parts[0].uppercase()
            var targetHost = ""
            var targetPort = if (method == "CONNECT") 443 else 80

            if (method == "CONNECT") {
                val hp = parts[1]
                targetHost = hp.substringBeforeLast(":")
                targetPort = hp.substringAfterLast(":", "443").toIntOrNull() ?: 443
            } else {
                val uriPart = parts[1]
                if (uriPart.startsWith("http://", true)) {
                    val stripped = uriPart.substring(7).substringBefore("/")
                    targetHost = stripped.substringBefore(":")
                    targetPort = stripped.substringAfter(":", "80").toIntOrNull() ?: 80
                } else {
                    val hostHeader = lines.firstOrNull { it.startsWith("Host:", true) }
                        ?.substringAfter(":")?.trim() ?: ""
                    targetHost = hostHeader.substringBefore(":")
                    targetPort = hostHeader.substringAfter(":", "80").toIntOrNull() ?: 80
                }
            }

            if (targetHost.isEmpty()) {
                client.close()
                return
            }

            upstream = connectViaLocalSocks5("127.0.0.1", upstreamSocksPort, targetHost, targetPort)
            if (upstream == null) {
                client.close()
                return
            }

            val upIn = upstream.getInputStream()
            val upOut = upstream.getOutputStream()

            if (method == "CONNECT") {
                clientOut.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray(Charsets.ISO_8859_1))
                clientOut.flush()
            } else {
                // Forward the HTTP request header to the destination through SOCKS5
                upOut.write(headerBytes, 0, hLen)
                upOut.flush()
            }

            pipeBidirectional(pushIn, clientOut, upIn, upOut, client, upstream)
        } catch (_: Throwable) {
            try { client.close() } catch (_: Throwable) {}
            try { upstream?.close() } catch (_: Throwable) {}
        }
    }

    private fun connectViaLocalSocks5(socksHost: String, socksPort: Int, dstHost: String, dstPort: Int): Socket? {
        return try {
            val s = Socket().apply {
                tcpNoDelay = true
                connect(InetSocketAddress(socksHost, socksPort), 6000)
            }
            val ins = s.getInputStream()
            val outs = s.getOutputStream()

            // SOCKS5 Greeting
            outs.write(byteArrayOf(0x05, 0x01, 0x00))
            outs.flush()
            if (ins.read() != 0x05 || ins.read() != 0x00) {
                s.close()
                return null
            }

            // SOCKS5 CONNECT with domain name (0x03)
            val hostBytes = dstHost.toByteArray(Charsets.UTF_8)
            val req = ByteArray(4 + 1 + hostBytes.size + 2)
            req[0] = 0x05
            req[1] = 0x01
            req[2] = 0x00
            req[3] = 0x03
            req[4] = hostBytes.size.toByte()
            System.arraycopy(hostBytes, 0, req, 5, hostBytes.size)
            req[5 + hostBytes.size] = ((dstPort shr 8) and 0xFF).toByte()
            req[6 + hostBytes.size] = (dstPort and 0xFF).toByte()
            outs.write(req)
            outs.flush()

            val respVer = ins.read()
            val respRep = ins.read()
            ins.read() // RSV
            val atyp = ins.read()
            if (respVer != 0x05 || respRep != 0x00) {
                s.close()
                return null
            }
            val skipBytes = when (atyp) {
                1 -> 4 + 2
                3 -> (ins.read() and 0xFF) + 2
                4 -> 16 + 2
                else -> 6
            }
            val dummy = ByteArray(skipBytes)
            var readCount = 0
            while (readCount < skipBytes) {
                val r = ins.read(dummy, readCount, skipBytes - readCount)
                if (r == -1) break
                readCount += r
            }
            s
        } catch (_: Throwable) {
            null
        }
    }

    private fun pipeBidirectional(
        cIn: InputStream,
        cOut: OutputStream,
        uIn: InputStream,
        uOut: OutputStream,
        client: Socket,
        upstream: Socket
    ) {
        val bcIn = BufferedInputStream(cIn, 32768)
        val bcOut = BufferedOutputStream(cOut, 32768)
        val buIn = BufferedInputStream(uIn, 32768)
        val buOut = BufferedOutputStream(uOut, 32768)

        val upTask = workerPool.submit {
            try {
                val buf = ByteArray(32768)
                while (isRunning) {
                    val n = bcIn.read(buf)
                    if (n == -1) break
                    buOut.write(buf, 0, n)
                    buOut.flush()
                }
            } catch (_: Throwable) {
            } finally {
                try { upstream.close() } catch (_: Throwable) {}
            }
        }

        try {
            val buf = ByteArray(32768)
            while (isRunning) {
                val n = buIn.read(buf)
                if (n == -1) break
                bcOut.write(buf, 0, n)
                bcOut.flush()
            }
        } catch (_: Throwable) {
        } finally {
            upTask.cancel(true)
            try { client.close() } catch (_: Throwable) {}
            try { upstream.close() } catch (_: Throwable) {}
        }
    }

    fun stopHotshare() {
        isRunning = false
        try { serverSocket?.close() } catch (_: Throwable) {}
        serverSocket = null
    }
}
