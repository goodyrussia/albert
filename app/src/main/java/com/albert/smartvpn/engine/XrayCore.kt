package com.albert.smartvpn.engine

import android.content.Context
import android.net.VpnService
import android.os.Build
import android.util.Base64
import android.util.Log
import com.albert.smartvpn.ui.viewmodel.VpnStateBridge
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.BufferedReader
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.EOFException
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.zip.ZipFile
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlin.math.min
import kotlin.random.Random

object XrayCore {
    private const val TAG = "XrayCore"
    private const val SS_MAX_PAYLOAD = 0x3FFF

    private val isRunning = AtomicBoolean(false)
    private val nativeXrayRunning = AtomicBoolean(false)
    private var xrayProcess: Process? = null
    private var activeXrayConfigFile: File? = null
    private var fallbackServer: ServerSocket? = null
    private var fallbackUdpSocket: DatagramSocket? = null
    private val ioPool = Executors.newCachedThreadPool()
    private val outboundPool = CopyOnWriteArrayList<ParsedOutbound>()
    private val roundRobinCursor = AtomicInteger(0)
    private val secureRng = SecureRandom()

    private data class DnsCacheEntry(val payload: ByteArray, val expiresAtMs: Long)
    private val dnsMemoryCache = ConcurrentHashMap<String, DnsCacheEntry>()
    private val verifiedSsCipherCache = ConcurrentHashMap<String, String>()

    @Volatile var activeVpnService: VpnService? = null
    @Volatile private var appContextRef: Context? = null
    @Volatile private var appFilesDir: File? = null
    @Volatile private var nativeBackendPort: Int = 0

    fun initContext(context: Context) {
        appContextRef = context.applicationContext
        appFilesDir = context.filesDir
        SlowDnsSpeedBooster.initContext(context)
    }

    private fun protectSocket(sock: Socket) {
        try { activeVpnService?.protect(sock) } catch (_: Throwable) {}
    }

    private fun protectDatagram(ds: DatagramSocket) {
        try { activeVpnService?.protect(ds) } catch (_: Throwable) {}
    }

    private fun socketBufSize(): Int =
        if (VpnStateBridge.turboSpeedEnabled.value) 1048576 else 524288

    private fun resolveXrayBinary(): File? {
        val ctx = appContextRef ?: return null
        val nativeDir = File(ctx.applicationInfo.nativeLibraryDir)
        for (name in listOf("libxray.so", "xray")) {
            val f = File(nativeDir, name)
            if (f.exists() && f.length() > 1_000_000L) {
                try { f.setExecutable(true, false) } catch (_: Throwable) {}
                return f
            }
        }

        val apkPaths = buildList {
            add(ctx.applicationInfo.sourceDir)
            ctx.applicationInfo.splitSourceDirs?.let { addAll(it) }
        }.filter { !it.isNullOrBlank() }

        val abis = Build.SUPPORTED_ABIS?.toList() ?: listOf("arm64-v8a", "armeabi-v7a")
        for (apkPath in apkPaths) {
            try {
                ZipFile(File(apkPath)).use { zip ->
                    for (abi in abis) {
                        val entry = zip.getEntry("lib/$abi/libxray.so") ?: continue
                        val outFile = File(ctx.filesDir, "libxray.so")
                        zip.getInputStream(entry).use { input ->
                            FileOutputStream(outFile).use { output -> input.copyTo(output) }
                        }
                        outFile.setReadable(true, false)
                        outFile.setExecutable(true, false)
                        try {
                            Runtime.getRuntime().exec(arrayOf("chmod", "755", outFile.absolutePath)).waitFor()
                        } catch (_: Throwable) {}
                        if (outFile.exists() && outFile.length() > 1_000_000L) return outFile
                    }
                }
            } catch (_: Throwable) {}
        }
        return null
    }

    fun verifyServerReachable(host: String, port: Int): Boolean {
        val cleanHost = host.trim()
        if (cleanHost.isEmpty()) return false
        return try {
            Socket().use { s ->
                protectSocket(s)
                s.tcpNoDelay = true
                s.connect(InetSocketAddress(cleanHost, port.coerceIn(1, 65535)), 6000)
            }
            true
        } catch (t: Throwable) {
            VpnStateBridge.addLog("Server unreachable ($cleanHost:$port): ${t.message}")
            false
        }
    }

    private fun isLocalPortOpen(port: Int): Boolean {
        return try {
            Socket().use { s ->
                s.connect(InetSocketAddress("127.0.0.1", port), 250)
            }
            true
        } catch (_: Throwable) {
            false
        }
    }

    private fun waitForLocalPort(port: Int, timeoutMs: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (isLocalPortOpen(port)) return true
            Thread.sleep(80)
        }
        return isLocalPortOpen(port)
    }

    /**
     * Normalizes the JSON config for official Xray-core (`libxray.so`) so that:
     * 1. Shadowsocks outbounds have normalized `(method, password)` and resolved IP addresses (no DNS loop).
     * 2. Native Xray listens on `internalXrayPort` (`socksPort + 10`) while our front bridge on `socksPort`
     *    handles both standard SOCKS5 TCP/UDP and `hev-socks5-tunnel` `CMD = 0x05` UDP-in-TCP seamlessly!
     */
    private fun startNativeXrayProcess(jsonConfig: String, internalPort: Int): Boolean {
        val xrayBin = resolveXrayBinary() ?: return false
        val ctx = appContextRef ?: return false

        return try {
            val root = JsonParser.parseString(jsonConfig).asJsonObject
            val inbounds = root.getAsJsonArray("inbounds")
            if (inbounds != null && inbounds.size() > 0) {
                val firstIn = inbounds[0].asJsonObject
                firstIn.addProperty("port", internalPort)
                firstIn.addProperty("listen", "127.0.0.1")
            }

            // Normalize Shadowsocks credentials & resolve server hostnames to IPs so Xray never loops on DNS
            val outbounds = root.getAsJsonArray("outbounds")
            if (outbounds != null) {
                for (elem in outbounds) {
                    if (!elem.isJsonObject) continue
                    val outObj = elem.asJsonObject
                    val proto = outObj.get("protocol")?.asString?.lowercase()?.trim() ?: ""
                    val settings = outObj.getAsJsonObject("settings") ?: continue

                    if (proto == "shadowsocks" || proto == "ss") {
                        outObj.addProperty("protocol", "shadowsocks")
                        val servers = settings.getAsJsonArray("servers")
                        if (servers != null && servers.size() > 0) {
                            val srv = servers[0].asJsonObject
                            val rawHost = srv.get("address")?.asString?.trim() ?: ""
                            val resolvedIp = try {
                                InetAddress.getByName(rawHost).hostAddress ?: rawHost
                            } catch (_: Throwable) {
                                rawHost
                            }
                            if (resolvedIp.isNotEmpty()) srv.addProperty("address", resolvedIp)

                            val rawMethod = srv.get("method")?.asString ?: "chacha20-ietf-poly1305"
                            val rawPass = srv.get("password")?.asString ?: ""
                            val (cleanMethod, cleanPass) = normalizeShadowsocksCredentials(rawMethod, rawPass)
                            srv.addProperty("method", cleanMethod)
                            srv.addProperty("password", cleanPass)
                            srv.addProperty("uot", false)
                        }
                    } else if (settings.has("vnext")) {
                        val vnext = settings.getAsJsonArray("vnext")
                        if (vnext != null && vnext.size() > 0) {
                            val vn = vnext[0].asJsonObject
                            val rawHost = vn.get("address")?.asString?.trim() ?: ""
                            val resolvedIp = try {
                                InetAddress.getByName(rawHost).hostAddress ?: rawHost
                            } catch (_: Throwable) {
                                rawHost
                            }
                            if (resolvedIp.isNotEmpty()) vn.addProperty("address", resolvedIp)
                        }
                    } else if (settings.has("servers")) {
                        val servers = settings.getAsJsonArray("servers")
                        if (servers != null && servers.size() > 0) {
                            val srv = servers[0].asJsonObject
                            val rawHost = srv.get("address")?.asString?.trim() ?: ""
                            val resolvedIp = try {
                                InetAddress.getByName(rawHost).hostAddress ?: rawHost
                            } catch (_: Throwable) {
                                rawHost
                            }
                            if (resolvedIp.isNotEmpty()) srv.addProperty("address", resolvedIp)
                        }
                    }
                }
            }

            val cfgFile = File(ctx.cacheDir, "techfeeds_xray_live.json")
            cfgFile.writeText(root.toString())
            activeXrayConfigFile = cfgFile

            val proc = ProcessBuilder(xrayBin.absolutePath, "run", "-c", cfgFile.absolutePath)
                .directory(ctx.filesDir)
                .redirectErrorStream(true)
                .start()
            xrayProcess = proc

            ioPool.execute {
                try {
                    BufferedReader(InputStreamReader(proc.inputStream)).use { reader ->
                        while (proc.isAlive) {
                            val line = reader.readLine() ?: break
                            Log.d(TAG, "libxray: $line")
                        }
                    }
                } catch (_: Throwable) {}
            }

            val ready = waitForLocalPort(internalPort, 2200L)
            if (proc.isAlive && ready) {
                nativeBackendPort = internalPort
                nativeXrayRunning.set(true)
                true
            } else {
                try { proc.destroyForcibly() } catch (_: Throwable) {}
                xrayProcess = null
                false
            }
        } catch (t: Throwable) {
            Log.e(TAG, "Native libxray start failed: ${t.message}")
            false
        }
    }

    fun RunXrayFromJSON(jsonConfig: String): Boolean {
        if (isRunning.get()) StopXray()

        return try {
            val root = JsonParser.parseString(jsonConfig).asJsonObject
            val socksPort = root.getAsJsonArray("inbounds")
                ?.firstOrNull()?.asJsonObject
                ?.get("port")?.asInt ?: VpnStateBridge.localSocksPort.value

            isRunning.set(true)
            val parsedList = parseOutboundPool(jsonConfig)
            val primaryProto = parsedList.firstOrNull()?.protocol?.lowercase() ?: "vless"

            // Start native official Xray-core process on internalPort (if protocol is supported by Xray-core)
            nativeBackendPort = 0
            if (primaryProto in listOf("shadowsocks", "ss", "vless", "vmess", "trojan")) {
                val internalPort = if (socksPort < 60000) socksPort + 11 else socksPort - 11
                startNativeXrayProcess(jsonConfig, internalPort)
            }

            val startedBuiltIn = startBuiltInProtocolEngine(jsonConfig, socksPort)
            if (startedBuiltIn && waitForLocalPort(socksPort, 1500)) {
                val primary = outboundPool.firstOrNull()
                val activeProto = primary?.protocol?.uppercase() ?: "STEALTH"
                val rrStatus = if (VpnStateBridge.roundRobinEnabled.value) "Round-Robin ON" else "Single/Primary Mode"
                if (activeProto == "SHADOWSOCKS" || activeProto == "SS") {
                    val engineMode = if (nativeBackendPort > 0) "Native Xray-Core" else "AEAD Core"
                    VpnStateBridge.addLog("Shadowsocks ($engineMode): ${primary?.cipherMethod} -> ${primary?.server}:${primary?.port}")
                }
                VpnStateBridge.addLog("Techfeeds-VPN V1.2 Turbo $activeProto Engine active on port $socksPort ($rrStatus)")
                return true
            }

            StopXray()
            false
        } catch (t: Throwable) {
            Log.e(TAG, "RunXrayFromJSON error: ${t.message}", t)
            VpnStateBridge.addLog("Engine start error: ${t.message}")
            StopXray()
            false
        }
    }

    private data class ParsedOutbound(
        val protocol: String,
        val server: String,
        val port: Int,
        val uuidOrPass: String,
        val cipherMethod: String,
        val network: String,
        val security: String,
        val sni: String,
        val wsPath: String,
        val wsHost: String,
        val proxyHost: String = "",
        val proxyPort: Int = 8080,
        val proxyUser: String = "",
        val proxyPass: String = "",
        val payloadTemplate: String = ""
    )

    private fun parseSingleOutboundObject(out: JsonObject): ParsedOutbound? {
        return try {
            val protocol = out.get("protocol")?.asString?.lowercase()?.trim() ?: "vless"
            val settings = out.getAsJsonObject("settings")
            var server = ""
            var port = 443
            var uuidOrPass = ""
            var cipherMethod = "chacha20-ietf-poly1305"
            var proxyHost = ""
            var proxyPort = 8080
            var proxyUser = ""
            var proxyPass = ""
            var payloadTemplate = ""

            if (settings?.has("vnext") == true) {
                val vnext = settings.getAsJsonArray("vnext").firstOrNull()?.asJsonObject
                server = vnext?.get("address")?.asString ?: ""
                port = vnext?.get("port")?.asInt ?: 443
                val user = vnext?.getAsJsonArray("users")?.firstOrNull()?.asJsonObject
                uuidOrPass = user?.get("id")?.asString
                    ?: user?.get("password")?.asString
                    ?: ""
                cipherMethod = user?.get("method")?.asString
                    ?: user?.get("cipher")?.asString
                    ?: user?.get("security")?.asString
                    ?: "aes-256-gcm"
            } else if (settings?.has("servers") == true) {
                val srv = settings.getAsJsonArray("servers").firstOrNull()?.asJsonObject
                server = srv?.get("address")?.asString ?: ""
                port = srv?.get("port")?.asInt ?: 443
                uuidOrPass = srv?.get("password")?.asString
                    ?: srv?.get("id")?.asString
                    ?: ""
                cipherMethod = srv?.get("method")?.asString
                    ?: srv?.get("cipher")?.asString
                    ?: srv?.get("security")?.asString
                    ?: "chacha20-ietf-poly1305"
                proxyHost = srv?.get("proxyHost")?.asString ?: ""
                proxyPort = srv?.get("proxyPort")?.asInt ?: 8080
                proxyUser = srv?.get("proxyUser")?.asString ?: ""
                proxyPass = srv?.get("proxyPass")?.asString ?: ""
                payloadTemplate = srv?.get("payload")?.asString ?: ""
            } else if (settings?.has("peers") == true) {
                val peer = settings.getAsJsonArray("peers").firstOrNull()?.asJsonObject
                val ep = peer?.get("endpoint")?.asString ?: ""
                server = ep.substringBeforeLast(":")
                port = ep.substringAfterLast(":", "51820").toIntOrNull() ?: 51820
                uuidOrPass = settings.get("secretKey")?.asString ?: ""
            } else if (settings != null) {
                server = settings.get("address")?.asString ?: ""
                port = settings.get("port")?.asInt ?: 1194
                uuidOrPass = settings.get("password")?.asString ?: ""
                cipherMethod = settings.get("method")?.asString
                    ?: settings.get("cipher")?.asString
                    ?: "chacha20-ietf-poly1305"
                proxyHost = settings.get("proxyHost")?.asString ?: ""
                proxyPort = settings.get("proxyPort")?.asInt ?: 8080
                proxyUser = settings.get("proxyUser")?.asString ?: ""
                proxyPass = settings.get("proxyPass")?.asString ?: ""
                payloadTemplate = settings.get("payload")?.asString ?: ""
            }

            if (protocol == "shadowsocks" || protocol == "ss") {
                val extracted = normalizeShadowsocksCredentials(cipherMethod, uuidOrPass)
                cipherMethod = extracted.first
                uuidOrPass = extracted.second
            }

            val stream = out.getAsJsonObject("streamSettings")
            val network = stream?.get("network")?.asString?.lowercase() ?: "tcp"
            val security = stream?.get("security")?.asString?.lowercase() ?: "none"
            val tlsObj = stream?.getAsJsonObject("tlsSettings") ?: stream?.getAsJsonObject("realitySettings")
            val sni = tlsObj?.get("serverName")?.asString?.takeIf { it.isNotBlank() } ?: server
            val wsObj = stream?.getAsJsonObject("wsSettings")
            val wsPath = wsObj?.get("path")?.asString?.takeIf { it.isNotBlank() } ?: "/"
            val wsHost = wsObj?.getAsJsonObject("headers")?.get("Host")?.asString
                ?: wsObj?.get("host")?.asString
                ?: sni

            if (server.isEmpty()) null else ParsedOutbound(
                protocol = protocol,
                server = server.trim(),
                port = port.coerceIn(1, 65535),
                uuidOrPass = uuidOrPass,
                cipherMethod = cipherMethod.lowercase().trim(),
                network = network,
                security = security,
                sni = sni.trim(),
                wsPath = wsPath,
                wsHost = wsHost.trim(),
                proxyHost = proxyHost.trim(),
                proxyPort = proxyPort,
                proxyUser = proxyUser,
                proxyPass = proxyPass,
                payloadTemplate = payloadTemplate
            )
        } catch (_: Throwable) {
            null
        }
    }

    private fun normalizeShadowsocksCredentials(rawMethod: String, rawPass: String): Pair<String, String> {
        var method = rawMethod.trim().lowercase()
        var pass = rawPass.trim()

        if (pass.startsWith("ss://", ignoreCase = true)) {
            pass = pass.removePrefix("ss://").removePrefix("SS://").substringBefore("#").substringBefore("?")
            if (pass.contains("@")) {
                pass = pass.substringBefore("@")
            }
        }

        if (!pass.contains(":") && pass.length >= 8) {
            for (flags in intArrayOf(Base64.DEFAULT, Base64.URL_SAFE or Base64.NO_WRAP, Base64.NO_WRAP)) {
                try {
                    val decoded = String(Base64.decode(pass, flags), Charsets.UTF_8).trim()
                    if (decoded.contains(":")) {
                        val m = decoded.substringBefore(":").trim().lowercase()
                        val p = decoded.substringAfter(":").substringBefore("@")
                        if (isKnownShadowsocksCipher(m) && p.isNotEmpty()) {
                            return m to p
                        }
                    }
                } catch (_: Throwable) {}
            }
        }

        if (pass.contains(":")) {
            val prefix = pass.substringBefore(":").trim().lowercase()
            val remainder = pass.substringAfter(":").substringBefore("@")
            if (isKnownShadowsocksCipher(prefix) && remainder.isNotEmpty()) {
                method = prefix
                pass = remainder
            }
        }

        if (!isKnownShadowsocksCipher(method)) {
            method = "chacha20-ietf-poly1305"
        }
        return method to pass
    }

    private fun isKnownShadowsocksCipher(m: String): Boolean {
        val clean = m.trim().lowercase()
        return clean.startsWith("aes-") ||
            clean.contains("chacha20") ||
            clean.contains("xchacha20") ||
            clean.contains("blake3") ||
            clean.contains("gcm") ||
            clean.contains("cfb") ||
            clean.contains("ctr") ||
            clean == "rc4-md5" ||
            clean == "none" ||
            clean == "plain"
    }

    private fun parseOutboundPool(jsonConfig: String): List<ParsedOutbound> {
        val list = ArrayList<ParsedOutbound>()
        try {
            val root = JsonParser.parseString(jsonConfig).asJsonObject
            val arr = root.getAsJsonArray("outbounds") ?: return emptyList()
            for (elem in arr) {
                if (elem.isJsonObject) {
                    val parsed = parseSingleOutboundObject(elem.asJsonObject)
                    if (parsed != null) {
                        list.add(parsed)
                    }
                }
            }
        } catch (_: Throwable) {}
        return list
    }

    private fun pickOutbound(): ParsedOutbound? {
        val pool = outboundPool
        if (pool.isEmpty()) return null
        if (!VpnStateBridge.roundRobinEnabled.value || pool.size == 1) {
            return pool[0]
        }
        val idx = (roundRobinCursor.getAndIncrement() and Int.MAX_VALUE) % pool.size
        return pool[idx]
    }

    private fun startBuiltInProtocolEngine(jsonConfig: String, socksPort: Int): Boolean {
        val parsedList = parseOutboundPool(jsonConfig)
        if (parsedList.isEmpty()) return false

        outboundPool.clear()
        outboundPool.addAll(parsedList)

        if (outboundPool.size == 1) {
            val primary = outboundPool[0]
            val sniParts = primary.sni.split(",").map { it.trim() }.filter { it.isNotEmpty() }
            if (sniParts.size > 1) {
                outboundPool.clear()
                for (sniCandidate in sniParts) {
                    outboundPool.add(primary.copy(sni = sniCandidate, wsHost = primary.wsHost.ifBlank { sniCandidate }))
                }
            }
        }

        val firstNode = outboundPool.firstOrNull()
        if (firstNode != null && (firstNode.protocol == "shadowsocks" || firstNode.protocol == "ss")) {
            ioPool.execute {
                autoProbeShadowsocksCipher(firstNode)
            }
        }

        return try {
            val srv = ServerSocket()
            srv.reuseAddress = true
            srv.receiveBufferSize = socketBufSize()
            srv.bind(InetSocketAddress("127.0.0.1", socksPort), 1024)
            fallbackServer = srv

            ioPool.execute {
                while (isRunning.get() && !srv.isClosed) {
                    try {
                        val client = srv.accept()
                        val selectedOutbound = pickOutbound() ?: parsedList[0]
                        ioPool.execute { handleSocksClient(client, selectedOutbound) }
                    } catch (_: Throwable) {
                        if (!isRunning.get()) break
                    }
                }
            }
            true
        } catch (t: Throwable) {
            Log.e(TAG, "Built-in SOCKS engine error: ${t.message}")
            false
        }
    }

    private fun autoProbeShadowsocksCipher(outbound: ParsedOutbound) {
        val serverKey = "${outbound.server}:${outbound.port}"
        if (verifiedSsCipherCache.containsKey(serverKey)) return

        val candidateCiphers = listOf(
            outbound.cipherMethod,
            "chacha20-ietf-poly1305",
            "aes-256-gcm",
            "aes-128-gcm",
            "aes-256-cfb"
        ).map { it.lowercase().trim() }.distinct()

        val dnsProbe = byteArrayOf(
            0x00, 0x1d,
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, 0x6f, 0x6e, 0x65, 0x03, 0x6f, 0x6e, 0x65, 0x03, 0x6f, 0x6e, 0x65, 0x00,
            0x00, 0x01, 0x00, 0x01
        )

        for (cipherCandidate in candidateCiphers) {
            if (!isRunning.get()) return
            var testSock: Socket? = null
            try {
                val testNode = outbound.copy(cipherMethod = cipherCandidate)
                val (s, rIn, rOut) = openShadowsocksStream(testNode, "1.1.1.1", 53, ignoreCache = true)
                testSock = s
                s.soTimeout = 2200
                rOut.write(dnsProbe)
                rOut.flush()
                val b0 = rIn.read()
                val b1 = rIn.read()
                if (b0 >= 0 && b1 > 0) {
                    verifiedSsCipherCache[serverKey] = cipherCandidate
                    return
                }
            } catch (_: Throwable) {
            } finally {
                try { testSock?.close() } catch (_: Throwable) {}
            }
        }
    }

    /**
     * Opens a stream through the native `libxray.so` SOCKS5 listener on `127.0.0.1:nativeBackendPort`.
     */
    private fun openViaNativeXrayBackend(dstHost: String, dstPort: Int): Triple<Socket, InputStream, OutputStream>? {
        val backendPort = nativeBackendPort
        if (backendPort <= 0 || xrayProcess?.isAlive != true) return null
        return try {
            val bufSz = socketBufSize()
            val s = Socket().apply {
                tcpNoDelay = true
                keepAlive = true
                sendBufferSize = bufSz
                receiveBufferSize = bufSz
                connect(InetSocketAddress("127.0.0.1", backendPort), 3500)
            }
            val sIn = DataInputStream(BufferedInputStream(s.getInputStream(), 65536))
            val sOut = BufferedOutputStream(s.getOutputStream(), 65536)

            // SOCKS5 greeting
            sOut.write(byteArrayOf(0x05, 0x01, 0x00))
            sOut.flush()
            val v = sIn.read()
            val m = sIn.read()
            if (v != 5 || m != 0) {
                s.close()
                return null
            }

            // SOCKS5 CONNECT
            val req = ByteArrayOutputStream(32)
            req.write(byteArrayOf(0x05, 0x01, 0x00))
            req.write(buildSocksTargetAddressBytes(dstHost, dstPort))
            sOut.write(req.toByteArray())
            sOut.flush()

            val rv = sIn.read()
            val rep = sIn.read()
            sIn.read() // RSV
            val atyp = sIn.read()
            if (rv != 5 || rep != 0) {
                s.close()
                return null
            }
            when (atyp) {
                1 -> sIn.readFully(ByteArray(4))
                3 -> {
                    val l = sIn.read()
                    if (l > 0) sIn.readFully(ByteArray(l))
                }
                4 -> sIn.readFully(ByteArray(16))
            }
            sIn.readUnsignedShort() // BND.PORT

            Triple(s, sIn, sOut)
        } catch (_: Throwable) {
            null
        }
    }

    private fun openRemoteTransport(outbound: ParsedOutbound): Triple<Socket, InputStream, OutputStream> {
        val bufSz = socketBufSize()
        val raw = Socket().apply {
            protectSocket(this)
            tcpNoDelay = true
            keepAlive = true
            sendBufferSize = bufSz
            receiveBufferSize = bufSz
            connect(InetSocketAddress(outbound.server, outbound.port), 10000)
        }

        val useTls = when (outbound.protocol) {
            "shadowsocks", "ss" -> (outbound.network == "ws" && outbound.security == "tls")
            "openvpn", "wireguard" -> outbound.security == "tls"
            else -> outbound.security == "tls" || outbound.security == "reality" ||
                outbound.port in listOf(443, 8443, 2053, 2083, 2087, 2096)
        }

        val transportSocket: Socket = if (useTls) {
            val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
                override fun checkClientTrusted(c: Array<out X509Certificate>?, a: String?) {}
                override fun checkServerTrusted(c: Array<out X509Certificate>?, a: String?) {}
                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            })
            val ctx = SSLContext.getInstance("TLS").apply { init(null, trustAll, secureRng) }
            (ctx.socketFactory.createSocket(raw, outbound.sni, outbound.port, true) as SSLSocket).apply {
                tcpNoDelay = true
                sendBufferSize = bufSz
                receiveBufferSize = bufSz
                val params = sslParameters
                params.serverNames = listOf(SNIHostName(outbound.sni.ifBlank { outbound.server }))
                if (outbound.network == "ws" && Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    params.applicationProtocols = arrayOf("http/1.1")
                }
                sslParameters = params
                startHandshake()
            }
        } else {
            raw
        }

        if (outbound.network == "ws") {
            val rawIn = BufferedInputStream(transportSocket.getInputStream(), 65536)
            val rawOut = BufferedOutputStream(transportSocket.getOutputStream(), 65536)
            val wsKey = Base64.encodeToString(Random.nextBytes(16), Base64.NO_WRAP)
            val path = if (outbound.wsPath.startsWith("/")) outbound.wsPath else "/${outbound.wsPath}"
            val req = "GET $path HTTP/1.1\r\n" +
                "Host: ${outbound.wsHost}\r\n" +
                "Upgrade: websocket\r\n" +
                "Connection: Upgrade\r\n" +
                "Sec-WebSocket-Key: $wsKey\r\n" +
                "Sec-WebSocket-Version: 13\r\n" +
                "User-Agent: Mozilla/5.0\r\n\r\n"
            rawOut.write(req.toByteArray(Charsets.UTF_8))
            rawOut.flush()

            val hdr = ByteArray(2048)
            var hLen = 0
            while (hLen < hdr.size) {
                val b = rawIn.read()
                if (b == -1) throw IllegalStateException("WS EOF during handshake")
                hdr[hLen++] = b.toByte()
                if (hLen >= 4 &&
                    hdr[hLen - 4] == '\r'.code.toByte() &&
                    hdr[hLen - 3] == '\n'.code.toByte() &&
                    hdr[hLen - 2] == '\r'.code.toByte() &&
                    hdr[hLen - 1] == '\n'.code.toByte()
                ) {
                    break
                }
            }
            return Triple(transportSocket, WebSocketFrameInputStream(rawIn), WebSocketFrameOutputStream(rawOut))
        }

        return Triple(
            transportSocket,
            BufferedInputStream(transportSocket.getInputStream(), 65536),
            BufferedOutputStream(transportSocket.getOutputStream(), 65536)
        )
    }

    private fun openOpenVpnOrDirectTurboStream(
        outbound: ParsedOutbound,
        dstHost: String,
        dstPort: Int
    ): Triple<Socket, InputStream, OutputStream> {
        val bufSz = socketBufSize()
        if (outbound.proxyHost.isNotBlank()) {
            val proxySock = Socket().apply {
                protectSocket(this)
                tcpNoDelay = true
                keepAlive = true
                sendBufferSize = bufSz
                receiveBufferSize = bufSz
                connect(InetSocketAddress(outbound.proxyHost, outbound.proxyPort.coerceIn(1, 65535)), 10000)
            }
            val pIn = BufferedInputStream(proxySock.getInputStream(), 65536)
            val pOut = BufferedOutputStream(proxySock.getOutputStream(), 65536)
            val authHdr = if (outbound.proxyUser.isNotBlank()) {
                val creds = Base64.encodeToString(
                    "${outbound.proxyUser}:${outbound.proxyPass}".toByteArray(),
                    Base64.NO_WRAP
                )
                "Proxy-Authorization: Basic $creds\r\n"
            } else ""
            val connectReq = "CONNECT $dstHost:$dstPort HTTP/1.1\r\nHost: $dstHost:$dstPort\r\n$authHdr\r\n"
            pOut.write(connectReq.toByteArray(Charsets.UTF_8))
            pOut.flush()

            val hdr = ByteArray(1024)
            var len = 0
            while (len < hdr.size) {
                val b = pIn.read()
                if (b == -1) break
                hdr[len++] = b.toByte()
                if (len >= 4 &&
                    hdr[len - 4] == '\r'.code.toByte() &&
                    hdr[len - 3] == '\n'.code.toByte() &&
                    hdr[len - 2] == '\r'.code.toByte() &&
                    hdr[len - 1] == '\n'.code.toByte()
                ) {
                    break
                }
            }
            return Triple(proxySock, pIn, pOut)
        }

        val directSock = Socket().apply {
            protectSocket(this)
            tcpNoDelay = true
            keepAlive = true
            sendBufferSize = bufSz
            receiveBufferSize = bufSz
            connect(InetSocketAddress(dstHost, dstPort), 10000)
        }
        return Triple(
            directSock,
            BufferedInputStream(directSock.getInputStream(), 65536),
            BufferedOutputStream(directSock.getOutputStream(), 65536)
        )
    }

    private fun uuidToBytes(uuidStr: String): ByteArray {
        return try {
            val u = UUID.fromString(uuidStr.trim())
            val bb = ByteBuffer.wrap(ByteArray(16))
            bb.putLong(u.mostSignificantBits)
            bb.putLong(u.leastSignificantBits)
            bb.array()
        } catch (_: Throwable) {
            ByteArray(16)
        }
    }

    private fun buildSocksTargetAddressBytes(dstHost: String, dstPort: Int): ByteArray {
        val out = ByteArrayOutputStream(32)
        val ipv4Parts = dstHost.split(".")
        if (ipv4Parts.size == 4 && ipv4Parts.all { it.toIntOrNull() in 0..255 }) {
            out.write(0x01)
            for (p in ipv4Parts) out.write(p.toInt())
        } else if (dstHost.contains(":")) {
            val addrBytes = try {
                InetAddress.getByName(dstHost).address
            } catch (_: Throwable) {
                null
            }
            if (addrBytes != null && addrBytes.size == 16) {
                out.write(0x04)
                out.write(addrBytes)
            } else {
                val domainBytes = dstHost.toByteArray(Charsets.UTF_8)
                out.write(0x03)
                out.write(domainBytes.size and 0xFF)
                out.write(domainBytes)
            }
        } else {
            val domainBytes = dstHost.toByteArray(Charsets.UTF_8)
            out.write(0x03)
            out.write(domainBytes.size and 0xFF)
            out.write(domainBytes)
        }
        out.write((dstPort shr 8) and 0xFF)
        out.write(dstPort and 0xFF)
        return out.toByteArray()
    }

    private fun buildVlessHeader(uuidStr: String, cmd: Byte, dstHost: String, dstPort: Int): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(0x00)
        out.write(uuidToBytes(uuidStr))
        out.write(0x00)
        out.write(cmd.toInt())
        out.write((dstPort shr 8) and 0xFF)
        out.write(dstPort and 0xFF)
        val ipv4Parts = dstHost.split(".")
        if (ipv4Parts.size == 4 && ipv4Parts.all { it.toIntOrNull() in 0..255 }) {
            out.write(0x01)
            for (p in ipv4Parts) out.write(p.toInt())
        } else {
            val domainBytes = dstHost.toByteArray(Charsets.UTF_8)
            out.write(0x02)
            out.write(domainBytes.size and 0xFF)
            out.write(domainBytes)
        }
        return out.toByteArray()
    }

    private fun buildTrojanHeader(password: String, cmd: Byte, dstHost: String, dstPort: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val sha224Hex = MessageDigest.getInstance("SHA-224")
            .digest(password.trim().toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
        out.write(sha224Hex.toByteArray(Charsets.US_ASCII))
        out.write(byteArrayOf(0x0D, 0x0A))
        out.write(cmd.toInt())
        out.write(buildSocksTargetAddressBytes(dstHost, dstPort))
        out.write(byteArrayOf(0x0D, 0x0A))
        return out.toByteArray()
    }

    private fun evpBytesToKey(password: String, keyLen: Int, cipherMethod: String = ""): ByteArray {
        if (cipherMethod.contains("2022-blake3")) {
            try {
                val decodedPsk = Base64.decode(password.trim(), Base64.DEFAULT)
                if (decodedPsk.size == keyLen) return decodedPsk
            } catch (_: Throwable) {}
        }
        val passBytes = password.toByteArray(Charsets.UTF_8)
        val md5 = MessageDigest.getInstance("MD5")
        val result = ByteArray(keyLen)
        var offset = 0
        var prev = ByteArray(0)
        while (offset < keyLen) {
            md5.reset()
            if (prev.isNotEmpty()) md5.update(prev)
            md5.update(passBytes)
            prev = md5.digest()
            val toCopy = min(prev.size, keyLen - offset)
            System.arraycopy(prev, 0, result, offset, toCopy)
            offset += toCopy
        }
        return result
    }

    private fun hkdfSha1Subkey(masterKey: ByteArray, salt: ByteArray, keyLen: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(salt, "HmacSHA1"))
        val prk = mac.doFinal(masterKey)
        val info = "ss-subkey".toByteArray(Charsets.US_ASCII)
        val okm = ByteArray(keyLen)
        var offset = 0
        var t = ByteArray(0)
        var counter = 1
        mac.init(SecretKeySpec(prk, "HmacSHA1"))
        while (offset < keyLen) {
            mac.reset()
            if (t.isNotEmpty()) mac.update(t)
            mac.update(info)
            mac.update(counter.toByte())
            t = mac.doFinal()
            val copyLen = min(t.size, keyLen - offset)
            System.arraycopy(t, 0, okm, offset, copyLen)
            offset += copyLen
            counter++
        }
        return okm
    }

    private fun incrementLittleEndianNonce(nonce: ByteArray) {
        for (i in nonce.indices) {
            val v = (nonce[i].toInt() and 0xFF) + 1
            nonce[i] = (v and 0xFF).toByte()
            if (v <= 0xFF) break
        }
    }

    private fun createChaCha20Poly1305Cipher(): Cipher {
        val transforms = listOf(
            "ChaCha20-Poly1305",
            "ChaCha20-Poly1305/None/NoPadding",
            "ChaCha20/Poly1305/NoPadding"
        )
        for (t in transforms) {
            try { return Cipher.getInstance(t) } catch (_: Throwable) {}
            try { return Cipher.getInstance(t, "BC") } catch (_: Throwable) {}
        }
        return Cipher.getInstance("ChaCha20-Poly1305")
    }

    private fun aeadCipherEncrypt(
        isChaCha: Boolean,
        subkey: ByteArray,
        nonce: ByteArray,
        plain: ByteArray,
        off: Int = 0,
        len: Int = plain.size
    ): ByteArray {
        return if (isChaCha) {
            val cipher = createChaCha20Poly1305Cipher()
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(subkey, "ChaCha20"), IvParameterSpec(nonce))
            cipher.doFinal(plain, off, len)
        } else {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(subkey, "AES"), GCMParameterSpec(128, nonce))
            cipher.doFinal(plain, off, len)
        }
    }

    private fun aeadCipherDecrypt(
        isChaCha: Boolean,
        subkey: ByteArray,
        nonce: ByteArray,
        cipherText: ByteArray,
        off: Int = 0,
        len: Int = cipherText.size
    ): ByteArray {
        return if (isChaCha) {
            val cipher = createChaCha20Poly1305Cipher()
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(subkey, "ChaCha20"), IvParameterSpec(nonce))
            cipher.doFinal(cipherText, off, len)
        } else {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(subkey, "AES"), GCMParameterSpec(128, nonce))
            cipher.doFinal(cipherText, off, len)
        }
    }

    private class ShadowsocksAeadOutputStream(
        private val delegate: OutputStream,
        private val masterKey: ByteArray,
        private val keyLen: Int,
        private val isChaCha: Boolean,
        initialTargetHeader: ByteArray
    ) : OutputStream() {
        private var saltSent = false
        private lateinit var subkey: ByteArray
        private val nonce = ByteArray(12)
        private var pendingHeader: ByteArray? = initialTargetHeader

        private fun ensureSaltInitialized(outBuffer: ByteArrayOutputStream) {
            if (!saltSent) {
                saltSent = true
                val salt = ByteArray(keyLen).also { secureRng.nextBytes(it) }
                subkey = hkdfSha1Subkey(masterKey, salt, keyLen)
                outBuffer.write(salt)
            }
        }

        override fun write(b: Int) {
            write(byteArrayOf(b.toByte()), 0, 1)
        }

        @Synchronized
        override fun write(b: ByteArray, off: Int, len: Int) {
            if (len <= 0 && pendingHeader == null) return
            val combined: ByteArray
            val hdr = pendingHeader
            if (hdr != null) {
                pendingHeader = null
                combined = ByteArray(hdr.size + len)
                System.arraycopy(hdr, 0, combined, 0, hdr.size)
                if (len > 0) {
                    System.arraycopy(b, off, combined, hdr.size, len)
                }
            } else {
                combined = b.copyOfRange(off, off + len)
            }

            val wireOut = ByteArrayOutputStream(combined.size + 128)
            ensureSaltInitialized(wireOut)

            var pos = 0
            while (pos < combined.size) {
                val chunkLen = min(SS_MAX_PAYLOAD, combined.size - pos)
                val lenBytes = byteArrayOf(
                    ((chunkLen ushr 8) and 0x3F).toByte(),
                    (chunkLen and 0xFF).toByte()
                )
                val encLen = aeadCipherEncrypt(isChaCha, subkey, nonce, lenBytes)
                incrementLittleEndianNonce(nonce)

                val encPayload = aeadCipherEncrypt(isChaCha, subkey, nonce, combined, pos, chunkLen)
                incrementLittleEndianNonce(nonce)

                wireOut.write(encLen)
                wireOut.write(encPayload)
                pos += chunkLen
            }

            delegate.write(wireOut.toByteArray())
            delegate.flush()
        }

        @Synchronized
        override fun flush() {
            if (pendingHeader != null) {
                write(ByteArray(0), 0, 0)
            }
            delegate.flush()
        }

        override fun close() {
            try { flush() } catch (_: Throwable) {}
            delegate.close()
        }
    }

    private class ShadowsocksAeadInputStream(
        delegate: InputStream,
        private val masterKey: ByteArray,
        private val keyLen: Int,
        private val isChaCha: Boolean
    ) : InputStream() {
        private val dis = DataInputStream(delegate)
        private var saltRead = false
        private lateinit var subkey: ByteArray
        private val nonce = ByteArray(12)
        private var chunkBuf = ByteArray(0)
        private var chunkPos = 0

        private fun readNextChunk(): Boolean {
            if (!saltRead) {
                saltRead = true
                val serverSalt = ByteArray(keyLen)
                try {
                    dis.readFully(serverSalt)
                } catch (_: EOFException) {
                    return false
                }
                subkey = hkdfSha1Subkey(masterKey, serverSalt, keyLen)
            }

            val encLen = ByteArray(2 + 16)
            try {
                dis.readFully(encLen)
            } catch (_: EOFException) {
                return false
            }
            val decLenBytes = aeadCipherDecrypt(isChaCha, subkey, nonce, encLen)
            incrementLittleEndianNonce(nonce)

            val payloadLen = ((decLenBytes[0].toInt() and 0x3F) shl 8) or (decLenBytes[1].toInt() and 0xFF)
            if (payloadLen <= 0 || payloadLen > SS_MAX_PAYLOAD) return false

            val encPayload = ByteArray(payloadLen + 16)
            dis.readFully(encPayload)
            chunkBuf = aeadCipherDecrypt(isChaCha, subkey, nonce, encPayload)
            incrementLittleEndianNonce(nonce)
            chunkPos = 0
            return chunkBuf.isNotEmpty()
        }

        override fun read(): Int {
            if (chunkPos >= chunkBuf.size) {
                if (!readNextChunk()) return -1
            }
            return chunkBuf[chunkPos++].toInt() and 0xFF
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (len <= 0) return 0
            if (chunkPos >= chunkBuf.size) {
                if (!readNextChunk()) return -1
            }
            val n = min(len, chunkBuf.size - chunkPos)
            System.arraycopy(chunkBuf, chunkPos, b, off, n)
            chunkPos += n
            return n
        }

        override fun available(): Int = (chunkBuf.size - chunkPos).coerceAtLeast(0)
        override fun close() = dis.close()
    }

    private class ShadowsocksStreamCipherOutputStream(
        private val delegate: OutputStream,
        private val masterKey: ByteArray,
        private val transform: String,
        initialTargetHeader: ByteArray
    ) : OutputStream() {
        private var cipher: Cipher? = null
        private var pendingHeader: ByteArray? = initialTargetHeader

        private fun ensureInitialized() {
            if (cipher == null) {
                val iv = ByteArray(16).also { secureRng.nextBytes(it) }
                val c = Cipher.getInstance(transform)
                c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(masterKey, "AES"), IvParameterSpec(iv))
                cipher = c
                delegate.write(iv)
                val hdr = pendingHeader
                if (hdr != null) {
                    pendingHeader = null
                    val encHdr = c.update(hdr)
                    if (encHdr != null && encHdr.isNotEmpty()) {
                        delegate.write(encHdr)
                    }
                }
                delegate.flush()
            }
        }

        override fun write(b: Int) {
            write(byteArrayOf(b.toByte()), 0, 1)
        }

        @Synchronized
        override fun write(b: ByteArray, off: Int, len: Int) {
            ensureInitialized()
            if (len <= 0) return
            val enc = cipher?.update(b, off, len)
            if (enc != null && enc.isNotEmpty()) {
                delegate.write(enc)
                delegate.flush()
            }
        }

        @Synchronized
        override fun flush() {
            ensureInitialized()
            delegate.flush()
        }

        override fun close() = delegate.close()
    }

    private class ShadowsocksStreamCipherInputStream(
        delegate: InputStream,
        private val masterKey: ByteArray,
        private val transform: String
    ) : InputStream() {
        private val dis = DataInputStream(delegate)
        private var cipher: Cipher? = null

        private fun ensureInitialized(): Cipher {
            cipher?.let { return it }
            val iv = ByteArray(16)
            dis.readFully(iv)
            val initializedCipher = Cipher.getInstance(transform)
            initializedCipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(masterKey, "AES"),
                IvParameterSpec(iv)
            )
            cipher = initializedCipher
            return initializedCipher
        }

        override fun read(): Int {
            val one = ByteArray(1)
            val r = read(one, 0, 1)
            return if (r <= 0) -1 else (one[0].toInt() and 0xFF)
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            val c = try {
                ensureInitialized()
            } catch (_: Throwable) {
                return -1
            }
            val rawBuf = ByteArray(len)
            val n = dis.read(rawBuf, 0, len)
            if (n <= 0) return n
            val dec = c.update(rawBuf, 0, n) ?: return 0
            System.arraycopy(dec, 0, b, off, dec.size)
            return dec.size
        }

        override fun close() = dis.close()
    }

    private fun openShadowsocksStream(
        outbound: ParsedOutbound,
        dstHost: String,
        dstPort: Int,
        ignoreCache: Boolean = false
    ): Triple<Socket, InputStream, OutputStream> {
        val (sock, rawIn, rawOut) = openRemoteTransport(outbound)
        val targetHeader = buildSocksTargetAddressBytes(dstHost, dstPort)
        val serverKey = "${outbound.server}:${outbound.port}"
        val method = if (!ignoreCache) {
            verifiedSsCipherCache[serverKey] ?: outbound.cipherMethod.lowercase().trim()
        } else {
            outbound.cipherMethod.lowercase().trim()
        }

        if (method == "none" || method == "plain") {
            rawOut.write(targetHeader)
            rawOut.flush()
            return Triple(sock, rawIn, rawOut)
        }

        if (method.contains("cfb") || method.contains("ctr")) {
            val keyLen = when {
                method.contains("128") -> 16
                method.contains("192") -> 24
                else -> 32
            }
            val transform = if (method.contains("ctr")) "AES/CTR/NoPadding" else "AES/CFB/NoPadding"
            val masterKey = evpBytesToKey(outbound.uuidOrPass, keyLen, method)
            val ssIn = ShadowsocksStreamCipherInputStream(rawIn, masterKey, transform)
            val ssOut = ShadowsocksStreamCipherOutputStream(rawOut, masterKey, transform, targetHeader)
            return Triple(sock, ssIn, ssOut)
        }

        val isChaCha = method.contains("chacha20") || method.contains("poly1305")
        val keyLen = when {
            isChaCha -> 32
            method.contains("128") -> 16
            method.contains("192") -> 24
            else -> 32
        }
        val masterKey = evpBytesToKey(outbound.uuidOrPass, keyLen, method)
        val ssIn = ShadowsocksAeadInputStream(rawIn, masterKey, keyLen, isChaCha)
        val ssOut = ShadowsocksAeadOutputStream(rawOut, masterKey, keyLen, isChaCha, targetHeader)
        return Triple(sock, ssIn, ssOut)
    }

    private fun openProtocolStream(
        outbound: ParsedOutbound,
        dstHost: String,
        dstPort: Int
    ): Triple<Socket, InputStream, OutputStream> {
        // 1. Prefer the authentic native `libxray.so` backend if running
        openViaNativeXrayBackend(dstHost, dstPort)?.let { return it }

        // 2. Built-in fallback stream
        return when (outbound.protocol) {
            "shadowsocks", "ss" -> openShadowsocksStream(outbound, dstHost, dstPort)
            "openvpn", "wireguard" -> openOpenVpnOrDirectTurboStream(outbound, dstHost, dstPort)
            "vless", "vmess" -> {
                val (sock, rawIn, rawOut) = openRemoteTransport(outbound)
                val hdr = buildVlessHeader(outbound.uuidOrPass, 0x01, dstHost, dstPort)
                rawOut.write(hdr)
                rawOut.flush()
                val vlessIn = object : InputStream() {
                    private var headerRead = false
                    private fun ensureHeader() {
                        if (!headerRead) {
                            headerRead = true
                            val ver = rawIn.read()
                            val addonLen = rawIn.read()
                            if (ver >= 0 && addonLen > 0) {
                                var rem = addonLen
                                while (rem > 0) {
                                    val s = rawIn.skip(rem.toLong())
                                    if (s <= 0) {
                                        if (rawIn.read() == -1) break
                                        rem--
                                    } else {
                                        rem -= s.toInt()
                                    }
                                }
                            }
                        }
                    }
                    override fun read(): Int {
                        ensureHeader()
                        return rawIn.read()
                    }
                    override fun read(b: ByteArray, off: Int, len: Int): Int {
                        ensureHeader()
                        return rawIn.read(b, off, len)
                    }
                    override fun available(): Int = rawIn.available()
                }
                Triple(sock, vlessIn, rawOut)
            }
            "trojan" -> {
                val (sock, rawIn, rawOut) = openRemoteTransport(outbound)
                val hdr = buildTrojanHeader(outbound.uuidOrPass, 0x01, dstHost, dstPort)
                rawOut.write(hdr)
                rawOut.flush()
                Triple(sock, rawIn, rawOut)
            }
            else -> openOpenVpnOrDirectTurboStream(outbound, dstHost, dstPort)
        }
    }

    private fun openProtocolStreamWithFailover(
        primary: ParsedOutbound,
        dstHost: String,
        dstPort: Int
    ): Triple<Socket, InputStream, OutputStream> {
        return try {
            openProtocolStream(primary, dstHost, dstPort)
        } catch (t: Throwable) {
            val pool = outboundPool
            if (pool.size > 1) {
                for (candidate in pool) {
                    if (candidate !== primary) {
                        try {
                            return openProtocolStream(candidate, dstHost, dstPort)
                        } catch (_: Throwable) {}
                    }
                }
            }
            throw t
        }
    }

    private fun handleSocksClient(client: Socket, outbound: ParsedOutbound) {
        var remoteSocket: Socket? = null
        try {
            val bufSz = socketBufSize()
            client.tcpNoDelay = true
            client.sendBufferSize = bufSz
            client.receiveBufferSize = bufSz

            val rawClientOut = client.getOutputStream()
            val ins = DataInputStream(BufferedInputStream(client.getInputStream(), 65536))
            val outs = BufferedOutputStream(rawClientOut, 65536)

            val ver = ins.read()
            if (ver != 5) return
            val nMethods = ins.read()
            if (nMethods > 0) {
                val methods = ByteArray(nMethods)
                ins.readFully(methods)
            }
            outs.write(byteArrayOf(0x05, 0x00))
            outs.flush()

            val reqVer = ins.read()
            val cmd = ins.read()
            ins.read() // RSV
            val atyp = ins.read()
            if (reqVer != 5) return

            val dstHost = when (atyp) {
                1 -> {
                    val a = ByteArray(4)
                    ins.readFully(a)
                    InetAddress.getByAddress(a).hostAddress ?: ""
                }
                3 -> {
                    val l = ins.read()
                    val d = ByteArray(l)
                    ins.readFully(d)
                    String(d, Charsets.UTF_8)
                }
                4 -> {
                    val a = ByteArray(16)
                    ins.readFully(a)
                    InetAddress.getByAddress(a).hostAddress ?: ""
                }
                else -> return
            }
            val dstPort = ins.readUnsignedShort()

            if (cmd == 3) {
                handleSocksUdpDns(client, ins, outs, outbound)
                return
            }
            if (cmd == 5 || cmd == 4) {
                handleHevUdpInTcp(client, ins, outs, outbound)
                return
            }
            if (cmd != 1) return

            val (rSock, rIn, rOut) = openProtocolStreamWithFailover(outbound, dstHost, dstPort)
            remoteSocket = rSock

            outs.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            outs.flush()

            val upJob = ioPool.submit {
                try {
                    val buf = ByteArray(32768)
                    while (isRunning.get()) {
                        val n = ins.read(buf)
                        if (n == -1) break
                        rOut.write(buf, 0, n)
                        if (ins.available() == 0) {
                            rOut.flush()
                        }
                    }
                    rOut.flush()
                } catch (_: Throwable) {
                } finally {
                    try { rSock.shutdownOutput() } catch (_: Throwable) {}
                }
            }

            val downBuf = ByteArray(32768)
            while (isRunning.get()) {
                val n = rIn.read(downBuf)
                if (n == -1) break
                rawClientOut.write(downBuf, 0, n)
                rawClientOut.flush()
            }
            rawClientOut.flush()
            upJob.cancel(true)
        } catch (_: Throwable) {
        } finally {
            try { remoteSocket?.close() } catch (_: Throwable) {}
            try { client.close() } catch (_: Throwable) {}
        }
    }

    private fun handleHevUdpInTcp(
        client: Socket,
        ins: DataInputStream,
        outs: OutputStream,
        outbound: ParsedOutbound
    ) {
        try {
            outs.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            outs.flush()

            while (isRunning.get() && !client.isClosed) {
                val b0 = ins.read()
                val b1 = ins.read()
                val b2 = ins.read()
                if (b0 < 0 || b1 < 0 || b2 < 0) break

                val hdrLen = b2 and 0xFF
                if (hdrLen < 4 || hdrLen > 270) break

                val beLen = ((b0 and 0xFF) shl 8) or (b1 and 0xFF)
                val leLen = ((b1 and 0xFF) shl 8) or (b0 and 0xFF)
                val isLittleEndian = (beLen > 1500 && leLen in 1..1500)
                val datLen = if (isLittleEndian) leLen else beLen
                if (datLen <= 0 || datLen > 65535) break

                val addrBlockLen = hdrLen - 3
                val addrBlock = ByteArray(addrBlockLen)
                ins.readFully(addrBlock)
                val payload = ByteArray(datLen)
                ins.readFully(payload)

                val atyp = addrBlock[0].toInt() and 0xFF
                var dstHost = "1.1.1.1"
                var dstPort = 53
                try {
                    when (atyp) {
                        1 -> {
                            dstHost = InetAddress.getByAddress(addrBlock.copyOfRange(1, 5)).hostAddress ?: "1.1.1.1"
                            dstPort = ((addrBlock[5].toInt() and 0xFF) shl 8) or (addrBlock[6].toInt() and 0xFF)
                        }
                        3 -> {
                            val dLen = addrBlock[1].toInt() and 0xFF
                            dstHost = String(addrBlock, 2, dLen, Charsets.UTF_8)
                            dstPort = ((addrBlock[2 + dLen].toInt() and 0xFF) shl 8) or (addrBlock[3 + dLen].toInt() and 0xFF)
                        }
                        4 -> {
                            dstHost = InetAddress.getByAddress(addrBlock.copyOfRange(1, 17)).hostAddress ?: "1.1.1.1"
                            dstPort = ((addrBlock[17].toInt() and 0xFF) shl 8) or (addrBlock[18].toInt() and 0xFF)
                        }
                    }
                } catch (_: Throwable) {}

                val selectedNode = pickOutbound() ?: outbound
                ioPool.execute {
                    val udpReply = if (dstPort == 53 || dstPort == 5353) {
                        resolveDnsQuery(payload, selectedNode)
                    } else {
                        forwardProtectedUdpPacket(dstHost, dstPort, payload)
                    }

                    if (udpReply != null && udpReply.isNotEmpty()) {
                        val pktOut = ByteArrayOutputStream(3 + addrBlock.size + udpReply.size)
                        if (isLittleEndian) {
                            pktOut.write(udpReply.size and 0xFF)
                            pktOut.write((udpReply.size shr 8) and 0xFF)
                        } else {
                            pktOut.write((udpReply.size shr 8) and 0xFF)
                            pktOut.write(udpReply.size and 0xFF)
                        }
                        pktOut.write(hdrLen and 0xFF)
                        pktOut.write(addrBlock)
                        pktOut.write(udpReply)
                        val bytes = pktOut.toByteArray()
                        synchronized(outs) {
                            try {
                                outs.write(bytes)
                                outs.flush()
                            } catch (_: Throwable) {}
                        }
                    }
                }
            }
        } catch (_: Throwable) {
        } finally {
            try { client.close() } catch (_: Throwable) {}
        }
    }

    private fun forwardProtectedUdpPacket(dstHost: String, dstPort: Int, payload: ByteArray): ByteArray? {
        return try {
            DatagramSocket().use { ds ->
                protectDatagram(ds)
                ds.soTimeout = 1500
                val addr = InetAddress.getByName(dstHost)
                ds.send(DatagramPacket(payload, payload.size, addr, dstPort))
                val rBuf = ByteArray(4096)
                val rPkt = DatagramPacket(rBuf, rBuf.size)
                ds.receive(rPkt)
                if (rPkt.length > 0) rPkt.data.copyOfRange(0, rPkt.length) else null
            }
        } catch (_: Throwable) {
            null
        }
    }

    private fun handleSocksUdpDns(
        client: Socket,
        ins: InputStream,
        outs: OutputStream,
        outbound: ParsedOutbound
    ) {
        var udpRelay: DatagramSocket? = null
        try {
            udpRelay = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
            fallbackUdpSocket = udpRelay
            val port = udpRelay.localPort

            outs.write(
                byteArrayOf(
                    0x05, 0x00, 0x00, 0x01,
                    127, 0, 0, 1,
                    ((port shr 8) and 0xFF).toByte(),
                    (port and 0xFF).toByte()
                )
            )
            outs.flush()

            val relayRef = udpRelay
            ioPool.execute {
                val buf = ByteArray(4096)
                while (isRunning.get() && !relayRef.isClosed) {
                    try {
                        val pkt = DatagramPacket(buf, buf.size)
                        relayRef.receive(pkt)
                        val data = pkt.data.copyOfRange(0, pkt.length)
                        val sender = pkt.socketAddress
                        if (data.size <= 10) continue

                        val atyp = data[3].toInt() and 0xFF
                        val offset: Int
                        val dstHost = when (atyp) {
                            1 -> {
                                offset = 8
                                InetAddress.getByAddress(data.copyOfRange(4, 8)).hostAddress ?: "1.1.1.1"
                            }
                            3 -> {
                                val l = data[4].toInt() and 0xFF
                                offset = 5 + l
                                String(data, 5, l, Charsets.UTF_8)
                            }
                            4 -> {
                                offset = 20
                                InetAddress.getByAddress(data.copyOfRange(4, 20)).hostAddress ?: "1.1.1.1"
                            }
                            else -> continue
                        }
                        val dstPort = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
                        val payloadStart = offset + 2
                        val socksHeader = data.copyOfRange(0, payloadStart)
                        val payload = data.copyOfRange(payloadStart, data.size)
                        val selectedNode = pickOutbound() ?: outbound

                        ioPool.execute {
                            val reply = if (dstPort == 53 || dstPort == 5353) {
                                resolveDnsQuery(payload, selectedNode)
                            } else {
                                forwardProtectedUdpPacket(dstHost, dstPort, payload)
                            }
                            if (reply != null && reply.isNotEmpty()) {
                                val fullResp = socksHeader + reply
                                try {
                                    relayRef.send(DatagramPacket(fullResp, fullResp.size, sender))
                                } catch (_: Throwable) {}
                            }
                        }
                    } catch (_: Throwable) {
                        break
                    }
                }
            }

            while (isRunning.get() && ins.read() != -1) {}
        } catch (_: Throwable) {
        } finally {
            try { udpRelay?.close() } catch (_: Throwable) {}
            try { client.close() } catch (_: Throwable) {}
        }
    }

    private fun resolveDnsQuery(dnsQuery: ByteArray, outbound: ParsedOutbound): ByteArray? {
        if (dnsQuery.size < 12) return null

        val cacheKey = if (dnsQuery.size >= 17) {
            dnsQuery.copyOfRange(4, min(dnsQuery.size, 96)).joinToString(",") { "%02x".format(it) }
        } else null

        if (cacheKey != null) {
            val cached = dnsMemoryCache[cacheKey]
            if (cached != null && System.currentTimeMillis() < cached.expiresAtMs && cached.payload.size >= 2) {
                val clone = cached.payload.copyOf()
                clone[0] = dnsQuery[0]
                clone[1] = dnsQuery[1]
                return clone
            }
        }

        // 1. Try TCP DNS through the tunnel first so ISP DNS-blocking never poisons or drops queries
        try {
            val (rSock, rIn, rOut) = openProtocolStream(outbound, "1.1.1.1", 53)
            rSock.use {
                rSock.soTimeout = 2200
                val framedQuery = ByteArray(2 + dnsQuery.size)
                framedQuery[0] = ((dnsQuery.size ushr 8) and 0xFF).toByte()
                framedQuery[1] = (dnsQuery.size and 0xFF).toByte()
                System.arraycopy(dnsQuery, 0, framedQuery, 2, dnsQuery.size)
                rOut.write(framedQuery)
                rOut.flush()

                val dis = DataInputStream(rIn)
                val respLen = dis.readUnsignedShort()
                if (respLen in 2..4096) {
                    val resp = ByteArray(respLen)
                    dis.readFully(resp)
                    if (cacheKey != null) {
                        dnsMemoryCache[cacheKey] = DnsCacheEntry(resp.copyOf(), System.currentTimeMillis() + 300_000L)
                    }
                    return resp
                }
            }
        } catch (_: Throwable) {}

        // 2. Fallback: Direct protected UDP DNS
        val custom1 = VpnStateBridge.customDns1.value.trim().ifBlank { "1.1.1.1" }
        val custom2 = VpnStateBridge.customDns2.value.trim().ifBlank { "8.8.8.8" }
        for (dnsHost in listOf(custom1, "1.1.1.1", custom2, "8.8.8.8").distinct()) {
            try {
                DatagramSocket().use { ds ->
                    protectDatagram(ds)
                    ds.soTimeout = 900
                    val addr = InetAddress.getByName(dnsHost)
                    ds.send(DatagramPacket(dnsQuery, dnsQuery.size, addr, 53))
                    val rBuf = ByteArray(2048)
                    val rPkt = DatagramPacket(rBuf, rBuf.size)
                    ds.receive(rPkt)
                    if (rPkt.length >= 2) {
                        val ans = rPkt.data.copyOfRange(0, rPkt.length)
                        if (cacheKey != null) {
                            dnsMemoryCache[cacheKey] = DnsCacheEntry(ans.copyOf(), System.currentTimeMillis() + 300_000L)
                        }
                        return ans
                    }
                }
            } catch (_: Throwable) {}
        }

        return null
    }

    private class WebSocketFrameInputStream(delegate: InputStream) : InputStream() {
        private val dis = DataInputStream(delegate)
        private var frameBuf = ByteArray(0)
        private var framePos = 0

        private fun readNextFrame(): Boolean {
            while (true) {
                val b0 = dis.read()
                if (b0 == -1) return false
                val opcode = b0 and 0x0F
                val b1 = dis.read()
                if (b1 == -1) return false
                val masked = (b1 and 0x80) != 0
                var len = (b1 and 0x7F).toLong()
                if (len == 126L) {
                    len = dis.readUnsignedShort().toLong()
                } else if (len == 127L) {
                    len = dis.readLong()
                }
                val maskKey = if (masked) ByteArray(4).also { dis.readFully(it) } else null
                val payload = ByteArray(len.toInt())
                dis.readFully(payload)
                if (masked && maskKey != null) {
                    for (i in payload.indices) {
                        payload[i] = (payload[i].toInt() xor maskKey[i % 4].toInt()).toByte()
                    }
                }
                if (opcode == 0x8) return false
                if (opcode == 0x1 || opcode == 0x2 || opcode == 0x0) {
                    if (payload.isNotEmpty()) {
                        frameBuf = payload
                        framePos = 0
                        return true
                    }
                }
            }
        }

        override fun read(): Int {
            if (framePos >= frameBuf.size) {
                if (!readNextFrame()) return -1
            }
            return frameBuf[framePos++].toInt() and 0xFF
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (framePos >= frameBuf.size) {
                if (!readNextFrame()) return -1
            }
            val n = minOf(len, frameBuf.size - framePos)
            System.arraycopy(frameBuf, framePos, b, off, n)
            framePos += n
            return n
        }

        override fun available(): Int = (frameBuf.size - framePos).coerceAtLeast(0)
    }

    private class WebSocketFrameOutputStream(private val delegate: OutputStream) : OutputStream() {
        override fun write(b: Int) {
            write(byteArrayOf(b.toByte()), 0, 1)
        }

        override fun write(b: ByteArray, off: Int, len: Int) {
            if (len <= 0) return
            val mask = Random.nextBytes(4)
            val header = ByteArrayOutputStream(14)
            header.write(0x82)
            if (len <= 125) {
                header.write(0x80 or len)
            } else if (len <= 65535) {
                header.write(0x80 or 126)
                header.write((len shr 8) and 0xFF)
                header.write(len and 0xFF)
            } else {
                header.write(0x80 or 127)
                val l = len.toLong()
                for (sh in 56 downTo 0 step 8) {
                    header.write(((l shr sh) and 0xFF).toInt())
                }
            }
            header.write(mask)
            val maskedPayload = ByteArray(len)
            for (i in 0 until len) {
                maskedPayload[i] = (b[off + i].toInt() xor mask[i % 4].toInt()).toByte()
            }
            synchronized(delegate) {
                delegate.write(header.toByteArray())
                delegate.write(maskedPayload)
                delegate.flush()
            }
        }

        override fun flush() {
            synchronized(delegate) { delegate.flush() }
        }
    }

    fun startLocalPort80Relay(@Suppress("UNUSED_PARAMETER") remoteHost: String, remotePort: Int): Int = remotePort

    fun StopXray() {
        if (!isRunning.getAndSet(false)) return
        nativeBackendPort = 0
        outboundPool.clear()
        try { xrayProcess?.destroy() } catch (_: Throwable) {}
        try { xrayProcess?.destroyForcibly() } catch (_: Throwable) {}
        xrayProcess = null
        try { activeXrayConfigFile?.delete() } catch (_: Throwable) {}
        activeXrayConfigFile = null
        try { fallbackUdpSocket?.close() } catch (_: Throwable) {}
        fallbackUdpSocket = null
        try { fallbackServer?.close() } catch (_: Throwable) {}
        fallbackServer = null
        nativeXrayRunning.set(false)
    }
}
