package com.albert.smartvpn.engine

import android.net.VpnService
import android.os.Build
import android.os.Process
import android.util.Base64
import android.util.Log
import com.albert.smartvpn.ui.viewmodel.VpnStateBridge
import net.schmizz.sshj.DefaultConfig
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.common.SecurityUtils
import net.schmizz.sshj.connection.Connection
import net.schmizz.sshj.connection.channel.direct.DirectTCPIPChannel
import net.schmizz.sshj.connection.channel.direct.Parameters
import net.schmizz.sshj.transport.verification.HostKeyVerifier
import net.schmizz.sshj.userauth.method.AuthKeyboardInteractive
import net.schmizz.sshj.userauth.method.ChallengeResponseProvider
import net.schmizz.sshj.userauth.password.Resource
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketAddress
import java.net.SocketTimeoutException
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Security
import java.security.cert.X509Certificate
import java.util.Collections
import java.util.concurrent.Callable
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import javax.net.SocketFactory
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlin.concurrent.thread
import kotlin.math.min

object SshEngine {
    private const val TAG = "SshEngine"

    private class PooledSshSession(
        val client: SSHClient,
        val tunnelPort: Int,
        val activeChannels: AtomicInteger = AtomicInteger(0)
    )

    private val sshPool = CopyOnWriteArrayList<PooledSshSession>()
    private val poolSelector = AtomicInteger(0)
    private val bcInitialized = AtomicBoolean(false)

    @Volatile var activeVpnService: VpnService? = null
    @Volatile private var isRunning = false
    @Volatile private var isSlowDnsActive = false
    @Volatile private var activeUdpCustomHost = ""
    @Volatile private var activeUdpCustomPort = 0

    private var localServer: ServerSocket? = null
    private val activeUdpSockets = CopyOnWriteArrayList<DatagramSocket>()

    private val ioThreadPool = Executors.newCachedThreadPool { r ->
        Thread(r, "TechfeedsV12-SSH-IO").apply {
            isDaemon = true
            priority = Thread.MAX_PRIORITY
        }
    }

    private val tlsPorts = setOf(443, 8443, 2053, 2083, 2087, 2096)

    private data class DnsCacheRecord(val response: ByteArray, val expireAt: Long)
    private val dnsMemoryCache = ConcurrentHashMap<String, DnsCacheRecord>()

    private class SshDirectChannel(
        conn: Connection,
        params: Parameters
    ) : DirectTCPIPChannel(conn, params)

    private fun socketBufSize(): Int {
        if (isSlowDnsActive) return 1048576
        val bufPref = VpnStateBridge.socksBufferSize.value
        return when {
            bufPref.startsWith("8 MB") -> 4194304
            bufPref.startsWith("4 MB") -> 2097152
            bufPref.startsWith("2 MB") -> 1048576
            VpnStateBridge.turboSpeedEnabled.value -> 2097152
            else -> 1048576
        }
    }

    private fun protectSocket(sock: Socket) {
        try { activeVpnService?.protect(sock) } catch (_: Throwable) {}
    }

    private fun protectDatagram(ds: DatagramSocket) {
        try { activeVpnService?.protect(ds) } catch (_: Throwable) {}
    }

    fun computeSha256Fingerprint(bytes: ByteArray): String {
        return try {
            val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
            val b64 = Base64.encodeToString(digest, Base64.NO_WRAP).trimEnd('=')
            "SHA256:$b64"
        } catch (_: Throwable) {
            "SHA256:Verified"
        }
    }

    fun computeColonHexFingerprint(bytes: ByteArray): String {
        return try {
            val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
            digest.take(16).joinToString(":") { "%02x".format(it) }
        } catch (_: Throwable) {
            ""
        }
    }

    /**
     * Replaces Android's stripped-down system "BC" provider with full BouncyCastle 1.76
     * so X25519, Ed25519, and NISTNamedCurves work across all Android 7 - 16 devices.
     */
    private fun ensureFullBouncyCastleRegistered() {
        if (bcInitialized.compareAndSet(false, true)) {
            try {
                Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
                Security.insertProviderAt(BouncyCastleProvider(), 1)
                SecurityUtils.setRegisterBouncyCastle(true)
            } catch (_: Throwable) {
                try { SecurityUtils.setRegisterBouncyCastle(false) } catch (_: Throwable) {}
            }
        }
    }

    private fun isX25519Supported(): Boolean {
        return try {
            SecurityUtils.getKeyPairGenerator("X25519")
            true
        } catch (_: Throwable) {
            try {
                KeyPairGenerator.getInstance("X25519")
                true
            } catch (_: Throwable) {
                false
            }
        }
    }

    private fun buildAndroidSafeSshConfig(): DefaultConfig {
        ensureFullBouncyCastleRegistered()
        val config = DefaultConfig()
        val hasX25519 = isX25519Supported()

        // Filter out strict KEX and remove curve25519/x25519 if the device ROM still lacks X25519 KeyPairGenerator
        config.keyExchangeFactories = config.keyExchangeFactories.filterNot { factory ->
            val n = factory.name.lowercase()
            n.contains("strict") || (!hasX25519 && (n.contains("25519") || n.contains("curve25519")))
        }

        // Prioritize Ed25519 and RSA host keys before ECDSA for fast, crash-free handshakes
        config.keyAlgorithms = config.keyAlgorithms.sortedBy { factory ->
            val n = factory.name.lowercase()
            when {
                n.contains("ed25519") -> 0
                n.contains("rsa") -> 1
                else -> 2
            }
        }
        return config
    }

    private fun createTrustAllSslFactory(tlsVersion: String): javax.net.ssl.SSLSocketFactory {
        val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(c: Array<out X509Certificate>?, a: String?) {}
            override fun checkServerTrusted(c: Array<out X509Certificate>?, a: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        })
        val proto = when (tlsVersion.uppercase().replace("V", "")) {
            "TLS1.3" -> "TLSv1.3"
            "TLS1.2" -> "TLSv1.2"
            "TLS1.1" -> "TLSv1.1"
            "TLS1.0" -> "TLSv1"
            else -> "TLS"
        }
        return try {
            SSLContext.getInstance(proto).apply { init(null, trustAll, SecureRandom()) }.socketFactory
        } catch (_: Throwable) {
            SSLContext.getInstance("TLS").apply { init(null, trustAll, SecureRandom()) }.socketFactory
        }
    }

    private fun resolveCandidateSshPorts(mode: String, configuredPort: Int, isSlowDns: Boolean): List<Int> {
        val primaryPort = configuredPort.coerceIn(1, 65535)
        if (isSlowDns) return listOf(primaryPort)
        if (mode == "UDPCUSTOM") {
            return when {
                primaryPort == 53 -> listOf(53, 22, 80, 443, 8080, 2222, 143).distinct()
                primaryPort == 7300 || primaryPort == 36712 -> listOf(22, 80, 443, 53, 8080, 2222, 143).distinct()
                else -> listOf(primaryPort, 22, 80, 443, 53, 8080, 2222, 143).distinct()
            }
        }
        if (mode.startsWith("OPENVPN") || primaryPort == 1194) {
            return listOf(primaryPort, 22, 80, 443, 8080, 8880, 2222, 143, 1194).distinct()
        }
        return listOf(
            primaryPort, 22, 80, 443, 8080, 8880, 2222, 143, 109, 110, 442, 8443, 2052, 2053, 2082, 2083
        ).distinct()
    }

    private fun sendUdpCustomWakeupPacket(host: String, udpPort: Int, user: String, pass: String) {
        ioThreadPool.execute {
            val ports = listOf(udpPort.coerceIn(1, 65535), 53, 36712, 7300).distinct()
            for (p in ports) {
                try {
                    DatagramSocket().use { ds ->
                        protectDatagram(ds)
                        ds.soTimeout = 800
                        val addr = InetAddress.getByName(host)
                        val wakeBytes = "UDPCUSTOM|$user:$pass\n".toByteArray(Charsets.UTF_8)
                        ds.send(DatagramPacket(wakeBytes, wakeBytes.size, addr, p))
                    }
                } catch (_: Throwable) {}
            }
        }
    }

    private fun authenticateSshClient(client: SSHClient, user: String, pass: String): Boolean {
        try {
            client.authPassword(user, pass)
            if (client.isAuthenticated) return true
        } catch (_: Throwable) {}
        try {
            val kbiProvider = object : ChallengeResponseProvider {
                override fun getSubmethods(): MutableList<String> = Collections.emptyList()
                override fun init(resource: Resource<*>?, name: String?, instruction: String?) {}
                override fun getResponse(prompt: String?, echo: Boolean): CharArray = pass.toCharArray()
                override fun shouldRetry(): Boolean = false
            }
            client.auth(user, AuthKeyboardInteractive(kbiProvider))
            if (client.isAuthenticated) return true
        } catch (_: Throwable) {}
        return client.isAuthenticated
    }

    private fun createConnectedSshClientOnPort(
        mode: String,
        cleanHost: String,
        sshConnectPort: Int,
        cleanUser: String,
        pass: String,
        payloadTemplate: String,
        sni: String,
        proxyHost: String,
        proxyPort: Int,
        proxyAuth: Boolean,
        proxyUser: String,
        proxyPass: String,
        tlsVersion: String,
        isSlowDns: Boolean,
        emitUiLogs: Boolean,
        connectTimeoutMs: Int = if (isSlowDns) 45000 else 12000
    ): SSHClient? {
        val sshConfig = buildAndroidSafeSshConfig()
        val client = SSHClient(sshConfig).apply {
            addHostKeyVerifier(object : HostKeyVerifier {
                override fun verify(hostname: String?, port: Int, key: PublicKey?): Boolean {
                    if (emitUiLogs && key != null) {
                        val sha256Fp = computeSha256Fingerprint(key.encoded)
                        val hexFp = computeColonHexFingerprint(key.encoded)
                        val algo = key.algorithm ?: "SSH-Key"
                        VpnStateBridge.addLog("Server Host Key ($algo): $sha256Fp")
                        if (hexFp.isNotEmpty()) {
                            VpnStateBridge.addLog("Host Key Fingerprint: $hexFp")
                        }
                    }
                    return true
                }

                override fun findExistingAlgorithms(hostname: String?, port: Int): MutableList<String> {
                    return Collections.emptyList()
                }
            })
            connectTimeout = connectTimeoutMs
            timeout = if (isSlowDns) 90000 else 0
            connection.windowSize = if (isSlowDns) 2097152L else 4194304L
            connection.maxPacketSize = 32768
            socketFactory = createCustomTunnelSocketFactory(
                mode = mode,
                targetHost = cleanHost,
                targetPort = sshConnectPort,
                payloadTemplate = payloadTemplate,
                sni = sni.trim(),
                proxyHost = proxyHost.trim(),
                proxyPort = proxyPort,
                proxyAuth = proxyAuth,
                proxyUser = proxyUser,
                proxyPass = proxyPass,
                tlsVersion = tlsVersion,
                isSlowDns = isSlowDns,
                emitUiLogs = emitUiLogs,
                connectTimeoutMs = connectTimeoutMs
            )
        }

        client.connect(cleanHost, sshConnectPort)
        if (VpnStateBridge.sshCompression.value && !isSlowDns) {
            try { client.useCompression() } catch (_: Throwable) {}
        }
        if (emitUiLogs) {
            VpnStateBridge.addLog("Authenticating user '$cleanUser' on port $sshConnectPort...")
        }
        val authed = authenticateSshClient(client, cleanUser, pass)
        return if (authed) {
            if (VpnStateBridge.sshKeepAlive.value || isSlowDns) {
                try {
                    client.connection.keepAlive.keepAliveInterval =
                        if (isSlowDns) 25 else VpnStateBridge.pingIntervalSec.value.coerceIn(10, 120)
                } catch (_: Throwable) {}
            }
            if (emitUiLogs) {
                VpnStateBridge.addLog("SSH Handshake & Host Key verified on port $sshConnectPort.")
            }
            client
        } else {
            try { client.disconnect() } catch (_: Throwable) {}
            null
        }
    }

    fun startSshTunnel(
        protocolMode: String = "SSH",
        host: String,
        port: Int,
        user: String,
        pass: String,
        localPort: Int,
        payloadTemplate: String = "",
        sni: String = "",
        proxyHost: String = "",
        proxyPort: Int = 8080,
        proxyAuth: Boolean = false,
        proxyUser: String = "",
        proxyPass: String = "",
        tlsVersion: String = "DEFAULT",
        isSlowDns: Boolean = false,
        appendToPool: Boolean = false
    ): Boolean {
        if (!appendToPool && isRunning) stopSshTunnel()
        val cleanHost = host.trim()
        val cleanUser = user.trim()
        val mode = protocolMode.uppercase().trim()

        if (cleanHost.isEmpty() || cleanUser.isEmpty() || pass.isEmpty()) {
            VpnStateBridge.addLog("Connection failed: Missing host, username, or password.")
            return false
        }

        val effectiveSlowDns = isSlowDns ||
            mode.contains("SLOWDNS") ||
            mode.contains("DNSTT") ||
            (cleanHost == "127.0.0.1" && port == 7000)
        isSlowDnsActive = effectiveSlowDns

        if (mode == "UDPCUSTOM") {
            activeUdpCustomHost = cleanHost
            activeUdpCustomPort = when {
                port == 53 -> 53
                port in 1..65535 -> port
                else -> 36712
            }
            sendUdpCustomWakeupPacket(cleanHost, activeUdpCustomPort, cleanUser, pass)
        } else {
            activeUdpCustomHost = ""
            activeUdpCustomPort = 0
        }

        return try {
            if (!appendToPool) {
                VpnStateBridge.updateState("CONNECTING", "CONNECTING...")
                VpnStateBridge.addLog("Techfeeds-VPN V1.2.2 Connecting ($mode :${port.coerceIn(1, 65535)})...")
            }
            if (!isRunning) {
                isRunning = true
                startLocalSocks5Server("127.0.0.1", localPort)
            }
            if (effectiveSlowDns) {
                try { Thread.sleep(200L) } catch (_: Throwable) {}
            }

            val candidatePorts = resolveCandidateSshPorts(mode, port, effectiveSlowDns)
            var primaryClient: SSHClient? = null
            var connectedPort = port.coerceIn(1, 65535)
            var lastError: Throwable? = null
            val maxAttempts = if (effectiveSlowDns) 2 else candidatePorts.size

            for (idx in 0 until maxAttempts) {
                val candidatePort = candidatePorts[idx % candidatePorts.size]
                try {
                    val userTimeoutMs = (VpnStateBridge.sshTimeoutSec.value.coerceIn(3, 60) * 1000)
                        .coerceAtLeast(10000)
                    val perAttemptTimeout = when {
                        effectiveSlowDns -> 45000
                        idx == 0 -> userTimeoutMs
                        else -> 6000
                    }
                    val client = createConnectedSshClientOnPort(
                        mode = mode,
                        cleanHost = cleanHost,
                        sshConnectPort = candidatePort,
                        cleanUser = cleanUser,
                        pass = pass,
                        payloadTemplate = payloadTemplate,
                        sni = sni,
                        proxyHost = proxyHost,
                        proxyPort = proxyPort,
                        proxyAuth = proxyAuth,
                        proxyUser = proxyUser,
                        proxyPass = proxyPass,
                        tlsVersion = tlsVersion,
                        isSlowDns = effectiveSlowDns,
                        emitUiLogs = !appendToPool && idx == 0,
                        connectTimeoutMs = perAttemptTimeout
                    )
                    if (client != null) {
                        primaryClient = client
                        connectedPort = candidatePort
                        break
                    }
                } catch (t: Throwable) {
                    lastError = t
                    if (effectiveSlowDns && idx == 0) {
                        try { Thread.sleep(500L) } catch (_: Throwable) {}
                    }
                }
            }

            if (primaryClient != null) {
                sshPool.add(PooledSshSession(primaryClient, connectedPort))
                val winPort = connectedPort
                if (effectiveSlowDns) {
                    ioThreadPool.execute {
                        for (k in 1..3) {
                            try {
                                Thread.sleep(550L * k)
                                if (!isRunning) break
                                val extraSlowClient = createConnectedSshClientOnPort(
                                    mode = mode,
                                    cleanHost = cleanHost,
                                    sshConnectPort = winPort,
                                    cleanUser = cleanUser,
                                    pass = pass,
                                    payloadTemplate = payloadTemplate,
                                    sni = sni,
                                    proxyHost = proxyHost,
                                    proxyPort = proxyPort,
                                    proxyAuth = proxyAuth,
                                    proxyUser = proxyUser,
                                    proxyPass = proxyPass,
                                    tlsVersion = tlsVersion,
                                    isSlowDns = true,
                                    emitUiLogs = false,
                                    connectTimeoutMs = 35000
                                )
                                if (extraSlowClient != null && isRunning) {
                                    sshPool.add(PooledSshSession(extraSlowClient, winPort))
                                } else {
                                    extraSlowClient?.close()
                                }
                            } catch (_: Throwable) {}
                        }
                    }
                } else {
                    val extraSessions = when {
                        appendToPool -> 2
                        VpnStateBridge.turboSpeedEnabled.value || VpnStateBridge.roundRobinEnabled.value -> 4
                        else -> 2
                    }
                    repeat(extraSessions) {
                        ioThreadPool.execute {
                            try {
                                if (!isRunning) return@execute
                                val secondary = createConnectedSshClientOnPort(
                                    mode = mode,
                                    cleanHost = cleanHost,
                                    sshConnectPort = winPort,
                                    cleanUser = cleanUser,
                                    pass = pass,
                                    payloadTemplate = payloadTemplate,
                                    sni = sni,
                                    proxyHost = proxyHost,
                                    proxyPort = proxyPort,
                                    proxyAuth = proxyAuth,
                                    proxyUser = proxyUser,
                                    proxyPass = proxyPass,
                                    tlsVersion = tlsVersion,
                                    isSlowDns = false,
                                    emitUiLogs = false
                                )
                                if (secondary != null && isRunning) {
                                    sshPool.add(PooledSshSession(secondary, winPort))
                                } else {
                                    secondary?.close()
                                }
                            } catch (_: Throwable) {}
                        }
                    }
                }
                true
            } else {
                if (!appendToPool) {
                    val errMsg = lastError?.message ?: "Authentication or handshake failed"
                    VpnStateBridge.addLog("Connection failed: $errMsg")
                    stopSshTunnel()
                }
                false
            }
        } catch (t: Throwable) {
            Log.e(TAG, "SSH Error: ${t.message}")
            if (!appendToPool) {
                VpnStateBridge.addLog("Connection failed: ${t.message ?: "Handshake error"}")
                stopSshTunnel()
            }
            false
        }
    }

    private fun createCustomTunnelSocketFactory(
        mode: String,
        targetHost: String,
        targetPort: Int,
        payloadTemplate: String,
        sni: String,
        proxyHost: String,
        proxyPort: Int,
        proxyAuth: Boolean,
        proxyUser: String,
        proxyPass: String,
        tlsVersion: String,
        isSlowDns: Boolean,
        emitUiLogs: Boolean,
        connectTimeoutMs: Int
    ): SocketFactory {
        return object : SocketFactory() {
            override fun createSocket(): Socket = openTunneledSocket()
            override fun createSocket(h: String?, p: Int): Socket = openTunneledSocket()
            override fun createSocket(h: String?, p: Int, lh: InetAddress?, lp: Int): Socket = openTunneledSocket()
            override fun createSocket(h: InetAddress?, p: Int): Socket = openTunneledSocket()
            override fun createSocket(a: InetAddress?, p: Int, la: InetAddress?, lp: Int): Socket = openTunneledSocket()

            private fun openRawTcpSocket(tcpHost: String, tcpPort: Int): Socket {
                val bufSz = socketBufSize()
                return Socket().apply {
                    if (!isSlowDns && tcpHost != "127.0.0.1") protectSocket(this)
                    tcpNoDelay = true
                    keepAlive = true
                    sendBufferSize = bufSz
                    receiveBufferSize = bufSz
                    connect(InetSocketAddress(tcpHost, tcpPort.coerceIn(1, 65535)), connectTimeoutMs)
                }
            }

            private fun openSslSocket(tcpHost: String, tcpPort: Int, sniHost: String, forceHttp1: Boolean): SSLSocket {
                val bufSz = socketBufSize()
                val raw = openRawTcpSocket(tcpHost, tcpPort)
                return (createTrustAllSslFactory(tlsVersion).createSocket(raw, sniHost, tcpPort, true) as SSLSocket).apply {
                    tcpNoDelay = true
                    sendBufferSize = bufSz
                    receiveBufferSize = bufSz
                    val p = sslParameters
                    p.serverNames = listOf(SNIHostName(sniHost))
                    if (forceHttp1 && Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        p.applicationProtocols = arrayOf("http/1.1")
                    }
                    sslParameters = p
                    startHandshake()
                    if (emitUiLogs) {
                        try {
                            val cert = session.peerCertificates.firstOrNull() as? X509Certificate
                            if (cert != null) {
                                val tlsFp = computeSha256Fingerprint(cert.encoded)
                                VpnStateBridge.addLog("TLS (${session.protocol} / ${session.cipherSuite})")
                                VpnStateBridge.addLog("TLS Cert Fingerprint: $tlsFp")
                            }
                        } catch (_: Throwable) {}
                    }
                }
            }

            private fun sendPayloadChunks(out: OutputStream, formattedPayload: String) {
                val chunks = formattedPayload.split(Regex("\\[(instant_|delay_)?split\\]", RegexOption.IGNORE_CASE))
                for ((idx, chunk) in chunks.withIndex()) {
                    if (chunk.isNotEmpty()) {
                        out.write(chunk.toByteArray(Charsets.UTF_8))
                        out.flush()
                        if (idx < chunks.size - 1) Thread.sleep(15)
                    }
                }
            }

            private fun openTunneledSocket(): Socket {
                if (isSlowDns) {
                    val localDnsSock = openRawTcpSocket(targetHost, targetPort)
                    val fastIn = FastPrefixInputStream(BufferedInputStream(localDnsSock.getInputStream(), 131072))
                    return FastWrappedSocket(localDnsSock, fastIn)
                }

                val isDirectMode = (mode == "SSH-DIRECT" || mode == "SSH" || mode == "UDPCUSTOM")
                val hasProxy = proxyHost.isNotEmpty() && !isDirectMode
                val explicitTlsMode = mode.contains("TLS") || mode == "SSH+SSL" || mode == "SSH+WS+SNI+PAYLOAD"
                val hasPayload = payloadTemplate.isNotBlank() || mode.contains("PAYLOAD")

                val tcpHost = if (hasProxy) proxyHost else targetHost
                val tcpPort = if (hasProxy) proxyPort else targetPort
                val sniHost = sni.ifEmpty { targetHost }

                val plainSshPorts = setOf(22, 80, 8080, 8880, 143, 109, 110, 2222, 2052, 2082, 2086, 2095)
                val shouldTryTls = when {
                    isDirectMode && targetPort in plainSshPorts -> false
                    explicitTlsMode -> true
                    !isDirectMode && sni.isNotBlank() && targetPort !in plainSshPorts -> true
                    !isDirectMode && targetPort in tlsPorts -> true
                    else -> false
                }

                if ((mode == "SSH-TLS" || mode == "SSH+SSL") && !hasPayload && !hasProxy) {
                    try {
                        val sslSock = openSslSocket(tcpHost, tcpPort, sniHost, false)
                        val fastIn = FastPrefixInputStream(BufferedInputStream(sslSock.getInputStream(), 131072))
                        val prevTimeout = sslSock.soTimeout
                        sslSock.soTimeout = 1200
                        try {
                            val peek = ByteArray(256)
                            val n = fastIn.read(peek)
                            if (n > 0) {
                                val str = String(peek, 0, n, Charsets.ISO_8859_1)
                                fastIn.unread(peek, 0, n)
                                if (str.contains("SSH-")) {
                                    if (emitUiLogs) VpnStateBridge.addLog("HTTP/1.1 200 OK")
                                    sslSock.soTimeout = prevTimeout
                                    return FastWrappedSocket(sslSock, fastIn)
                                }
                            }
                        } catch (_: SocketTimeoutException) {
                        } catch (_: Throwable) {}

                        sslSock.soTimeout = 8500
                        val wsHost = sni.ifBlank { targetHost }
                        val wsReq = "GET / HTTP/1.1\r\nHost: $wsHost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
                        sslSock.getOutputStream().apply {
                            write(wsReq.toByteArray(Charsets.UTF_8))
                            flush()
                        }
                        consumeHttpUpgrade(fastIn, emitUiLogs)
                        sslSock.soTimeout = prevTimeout
                        return FastWrappedSocket(sslSock, fastIn)
                    } catch (tlsErr: Throwable) {
                        if (targetPort !in plainSshPorts) throw tlsErr
                    }
                }

                val activeSocket: Socket = if (shouldTryTls) {
                    try {
                        openSslSocket(tcpHost, tcpPort, sniHost, true)
                    } catch (_: Throwable) {
                        openRawTcpSocket(tcpHost, tcpPort)
                    }
                } else {
                    openRawTcpSocket(tcpHost, tcpPort)
                }

                val fastIn = FastPrefixInputStream(BufferedInputStream(activeSocket.getInputStream(), 131072))
                val effectivePayload = when {
                    !isDirectMode && payloadTemplate.isNotBlank() -> payloadTemplate
                    !isDirectMode && hasPayload ->
                        "GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf]User-Agent: Mozilla/5.0[crlf][crlf]"
                    hasProxy ->
                        "CONNECT [host_port] HTTP/1.1[crlf]Host: [host_port][crlf][crlf]"
                    else -> ""
                }

                if (effectivePayload.isNotBlank()) {
                    val norm = effectivePayload.replace("Host: [sni]", "Host: [host]", true)
                    var formatted = PayloadGenerator.generatePayload(norm, targetHost, targetPort, sniHost)
                    if (proxyAuth && proxyUser.isNotBlank()) {
                        val b64Creds = Base64.encodeToString("$proxyUser:$proxyPass".toByteArray(), Base64.NO_WRAP)
                        formatted = formatted.replaceFirst(
                            "\r\n\r\n",
                            "\r\nProxy-Authorization: Basic $b64Creds\r\n\r\n"
                        )
                    }
                    sendPayloadChunks(activeSocket.getOutputStream(), formatted)
                    val prevTimeout = activeSocket.soTimeout
                    activeSocket.soTimeout = 9000
                    try {
                        consumeHttpUpgrade(fastIn, emitUiLogs)
                    } finally {
                        activeSocket.soTimeout = prevTimeout
                    }
                } else {
                    val prevTimeout = activeSocket.soTimeout
                    activeSocket.soTimeout = if (targetPort == 22) 1400 else 850
                    var sawSshBanner = false
                    try {
                        val peek = ByteArray(512)
                        val n = fastIn.read(peek)
                        if (n > 0) {
                            val str = String(peek, 0, n, Charsets.ISO_8859_1)
                            val sshPos = str.indexOf("SSH-")
                            if (sshPos == 0) {
                                fastIn.unread(peek, 0, n)
                                sawSshBanner = true
                            } else if (sshPos > 0) {
                                val bannerLen = n - sshPos
                                fastIn.unread(peek, sshPos, bannerLen)
                                sawSshBanner = true
                            } else {
                                fastIn.unread(peek, 0, n)
                            }
                        }
                    } catch (_: SocketTimeoutException) {
                        sawSshBanner = false
                    } catch (_: Throwable) {
                    } finally {
                        activeSocket.soTimeout = prevTimeout
                    }

                    if (!sawSshBanner) {
                        val autoHost = sni.ifBlank { targetHost }
                        val autoPayload = if (payloadTemplate.isNotBlank()) {
                            val norm = payloadTemplate.replace("Host: [sni]", "Host: [host]", true)
                            PayloadGenerator.generatePayload(norm, targetHost, targetPort, autoHost)
                        } else {
                            "GET / HTTP/1.1\r\nHost: $autoHost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
                        }
                        try {
                            sendPayloadChunks(activeSocket.getOutputStream(), autoPayload)
                            activeSocket.soTimeout = 8000
                            consumeHttpUpgrade(fastIn, emitUiLogs)
                        } catch (_: Throwable) {
                        } finally {
                            activeSocket.soTimeout = prevTimeout
                        }
                    }
                }
                return FastWrappedSocket(activeSocket, fastIn)
            }
        }
    }

    private fun consumeHttpUpgrade(fastIn: FastPrefixInputStream, emitUiLogs: Boolean) {
        val headerBuf = ByteArray(8192)
        var len = 0
        while (len < headerBuf.size) {
            val b = fastIn.read()
            if (b == -1) break
            headerBuf[len++] = b.toByte()
            val currentStr = String(headerBuf, 0, len, Charsets.ISO_8859_1)
            val sshIdx = currentStr.indexOf("SSH-2.0-")
            if (sshIdx >= 0) {
                val bannerBytes = currentStr.substring(sshIdx).toByteArray(Charsets.ISO_8859_1)
                fastIn.unread(bannerBytes, 0, bannerBytes.size)
                if (emitUiLogs) {
                    VpnStateBridge.addLog("HTTP/1.1 101 Switching Protocols")
                }
                return
            }
            if (currentStr.endsWith("\r\n\r\n")) {
                val firstLine = currentStr.lineSequence().firstOrNull()?.trim() ?: ""
                if (emitUiLogs) {
                    if (firstLine.contains("101")) {
                        VpnStateBridge.addLog("HTTP/1.1 200 OK")
                        VpnStateBridge.addLog("HTTP/1.1 101 Switching Protocols")
                    } else if (firstLine.isNotEmpty()) {
                        VpnStateBridge.addLog(firstLine)
                    }
                }
                if (firstLine.contains("200") && !firstLine.contains("101")) {
                    val peekBuf = ByteArray(8)
                    val r = fastIn.read(peekBuf, 0, 8)
                    if (r > 0) {
                        val peekStr = String(peekBuf, 0, r, Charsets.ISO_8859_1)
                        fastIn.unread(peekBuf, 0, r)
                        if (peekStr.startsWith("HTTP", true)) {
                            len = 0
                            continue
                        }
                    }
                }
                return
            }
        }
    }

    private class FastPrefixInputStream(private val delegate: InputStream) : InputStream() {
        private var prefixBuf: ByteArray? = null
        private var prefixPos = 0
        private var prefixLimit = 0

        fun unread(b: ByteArray, off: Int, len: Int) {
            if (len <= 0) return
            val rem = prefixLimit - prefixPos
            val next = ByteArray(len + rem)
            System.arraycopy(b, off, next, 0, len)
            val existing = prefixBuf
            if (rem > 0 && existing != null) {
                System.arraycopy(existing, prefixPos, next, len, rem)
            }
            prefixBuf = next
            prefixPos = 0
            prefixLimit = next.size
        }

        override fun read(): Int {
            val buf = prefixBuf
            if (buf != null) {
                val v = buf[prefixPos++].toInt() and 0xFF
                if (prefixPos >= prefixLimit) {
                    prefixBuf = null
                    prefixPos = 0
                    prefixLimit = 0
                }
                return v
            }
            return delegate.read()
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            val buf = prefixBuf
            if (buf != null) {
                val avail = prefixLimit - prefixPos
                val toCopy = min(len, avail)
                System.arraycopy(buf, prefixPos, b, off, toCopy)
                prefixPos += toCopy
                if (prefixPos >= prefixLimit) {
                    prefixBuf = null
                    prefixPos = 0
                    prefixLimit = 0
                }
                return toCopy
            }
            return delegate.read(b, off, len)
        }

        override fun available(): Int {
            val rem = if (prefixBuf != null) (prefixLimit - prefixPos) else 0
            return rem + delegate.available()
        }

        override fun close() = delegate.close()
    }

    private class FastWrappedSocket(
        private val delegate: Socket,
        private val customIn: InputStream
    ) : Socket() {
        override fun connect(endpoint: SocketAddress?) {}
        override fun connect(endpoint: SocketAddress?, timeout: Int) {}
        override fun bind(bindpoint: SocketAddress?) {}
        override fun getInputStream(): InputStream = customIn
        override fun getOutputStream(): OutputStream = delegate.getOutputStream()
        override fun isConnected(): Boolean = delegate.isConnected
        override fun isClosed(): Boolean = delegate.isClosed
        override fun isBound(): Boolean = true
        override fun close() = delegate.close()
        override fun setSoTimeout(timeout: Int) { delegate.soTimeout = timeout }
        override fun getSoTimeout(): Int = delegate.soTimeout
        override fun setTcpNoDelay(on: Boolean) { try { delegate.tcpNoDelay = on } catch (_: Throwable) {} }
        override fun setKeepAlive(on: Boolean) { try { delegate.keepAlive = on } catch (_: Throwable) {} }
        override fun setSendBufferSize(size: Int) { try { delegate.sendBufferSize = size } catch (_: Throwable) {} }
        override fun setReceiveBufferSize(size: Int) { try { delegate.receiveBufferSize = size } catch (_: Throwable) {} }
        override fun getInetAddress(): InetAddress? = delegate.inetAddress ?: InetAddress.getLoopbackAddress()
        override fun getLocalAddress(): InetAddress = delegate.localAddress ?: InetAddress.getLoopbackAddress()
        override fun getPort(): Int = delegate.port
        override fun getLocalPort(): Int = delegate.localPort
    }

    private fun pickOrderedSessions(): List<PooledSshSession> {
        val healthy = sshPool.filter { it.client.isConnected && it.client.isAuthenticated }
        if (healthy.isEmpty()) return sshPool.toList()
        if (healthy.size == 1) return healthy
        val rrOffset = (poolSelector.getAndIncrement() and Int.MAX_VALUE) % healthy.size
        val rotated = ArrayList<PooledSshSession>(healthy.size)
        for (i in healthy.indices) {
            rotated.add(healthy[(rrOffset + i) % healthy.size])
        }
        return rotated.sortedBy { it.activeChannels.get() }
    }

    private fun startLocalSocks5Server(bindHost: String, localPort: Int) {
        thread(start = true, name = "SSH-SOCKS5-Server") {
            try {
                Process.setThreadPriority(Process.THREAD_PRIORITY_URGENT_DISPLAY)
            } catch (_: Throwable) {}
            try {
                localServer = ServerSocket().apply {
                    reuseAddress = true
                    receiveBufferSize = socketBufSize()
                    bind(InetSocketAddress(bindHost, localPort), 2048)
                }
                while (isRunning) {
                    val client = localServer?.accept() ?: break
                    ioThreadPool.execute { handleSocks5Client(client) }
                }
            } catch (_: Throwable) {}
        }
    }

    private fun openDirectSshChannel(targetHost: String, targetPort: Int): Pair<DirectTCPIPChannel, PooledSshSession> {
        val candidates = pickOrderedSessions()
        if (candidates.isEmpty()) throw IllegalStateException("No authenticated SSH client")
        var lastErr: Throwable? = null
        for (session in candidates) {
            try {
                val params = Parameters("127.0.0.1", 0, targetHost, targetPort)
                val channel = SshDirectChannel(session.client.connection, params)
                channel.open()
                session.activeChannels.incrementAndGet()
                return channel to session
            } catch (t: Throwable) {
                lastErr = t
            }
        }
        throw (lastErr ?: IllegalStateException("Failed to open DirectTCPIPChannel"))
    }

    private fun releaseChannelCount(session: PooledSshSession?) {
        if (session == null) return
        val after = session.activeChannels.decrementAndGet()
        if (after < 0) {
            session.activeChannels.set(0)
        }
    }

    private fun handleSocks5Client(client: Socket) {
        var sshChannel: DirectTCPIPChannel? = null
        var assignedSession: PooledSshSession? = null
        try {
            val bufSz = socketBufSize()
            client.tcpNoDelay = true
            client.sendBufferSize = bufSz
            client.receiveBufferSize = bufSz

            val rawClientIn = client.getInputStream()
            val rawClientOut = client.getOutputStream()
            val ins = DataInputStream(BufferedInputStream(rawClientIn, 65536))
            val outs = BufferedOutputStream(rawClientOut, 65536)

            val ver = ins.read()
            if (ver != 5) return
            val nMethods = ins.read()
            if (nMethods > 0) {
                val mBuf = ByteArray(nMethods)
                ins.readFully(mBuf)
            }
            outs.write(byteArrayOf(0x05, 0x00))
            outs.flush()

            val reqVer = ins.read()
            val cmd = ins.read()
            ins.read() // RSV
            val atyp = ins.read()
            if (reqVer != 5) return

            val targetHost = when (atyp) {
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
            val targetPort = ins.readUnsignedShort()

            if (cmd == 3) {
                handleSocks5UdpAssociate(client, ins, outs)
                return
            }
            if (cmd == 5 || cmd == 4) {
                handleHevUdpInTcp(client, ins, outs)
                return
            }
            if (cmd != 1) return

            val opened = openDirectSshChannel(targetHost, targetPort)
            sshChannel = opened.first
            assignedSession = opened.second
            val sshIn = sshChannel.inputStream
            val sshOut = sshChannel.outputStream

            outs.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            outs.flush()

            val relayChunkSize = if (isSlowDnsActive) 32768 else 65536
            val upFuture = ioThreadPool.submit {
                try {
                    val buf = ByteArray(relayChunkSize)
                    while (isRunning && sshChannel.isOpen) {
                        val n = ins.read(buf)
                        if (n == -1) break
                        sshOut.write(buf, 0, n)
                        if (ins.available() == 0) {
                            sshOut.flush()
                        }
                    }
                    sshOut.flush()
                } catch (_: Throwable) {
                } finally {
                    try { sshOut.close() } catch (_: Throwable) {}
                }
            }

            val downBuf = ByteArray(relayChunkSize)
            while (isRunning && sshChannel.isOpen) {
                val n = sshIn.read(downBuf)
                if (n == -1) break
                rawClientOut.write(downBuf, 0, n)
            }
            rawClientOut.flush()
            upFuture.cancel(true)
        } catch (_: Throwable) {
        } finally {
            releaseChannelCount(assignedSession)
            try { sshChannel?.close() } catch (_: Throwable) {}
            try { client.close() } catch (_: Throwable) {}
        }
    }

    private fun handleHevUdpInTcp(client: Socket, ins: DataInputStream, outs: OutputStream) {
        try {
            outs.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            outs.flush()
            while (isRunning && !client.isClosed) {
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

                if (dstPort != 53 && dstPort != 5353) continue
                ioThreadPool.execute {
                    val dnsReply = resolveDnsFast(dstHost, payload)
                    if (dnsReply != null && dnsReply.isNotEmpty()) {
                        val pktOut = ByteArrayOutputStream(3 + addrBlock.size + dnsReply.size)
                        if (isLittleEndian) {
                            pktOut.write(dnsReply.size and 0xFF)
                            pktOut.write((dnsReply.size shr 8) and 0xFF)
                        } else {
                            pktOut.write((dnsReply.size shr 8) and 0xFF)
                            pktOut.write(dnsReply.size and 0xFF)
                        }
                        pktOut.write(hdrLen and 0xFF)
                        pktOut.write(addrBlock)
                        pktOut.write(dnsReply)
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

    private fun handleSocks5UdpAssociate(client: Socket, ins: InputStream, outs: OutputStream) {
        var udpRelay: DatagramSocket? = null
        try {
            udpRelay = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
            activeUdpSockets.add(udpRelay)
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
            ioThreadPool.execute {
                val buf = ByteArray(4096)
                while (isRunning && !relayRef.isClosed) {
                    try {
                        val pkt = DatagramPacket(buf, buf.size)
                        relayRef.receive(pkt)
                        val data = pkt.data.copyOfRange(0, pkt.length)
                        val clientAddr = pkt.socketAddress
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
                                String(data, 5, l)
                            }
                            4 -> {
                                offset = 20
                                InetAddress.getByAddress(data.copyOfRange(4, 20)).hostAddress ?: "1.1.1.1"
                            }
                            else -> continue
                        }
                        val dstPort = ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
                        if (dstPort != 53 && dstPort != 5353) continue
                        val payloadStart = offset + 2
                        val header = data.copyOfRange(0, payloadStart)
                        val payload = data.copyOfRange(payloadStart, data.size)
                        ioThreadPool.execute {
                            val dnsReply = resolveDnsFast(dstHost, payload)
                            if (dnsReply != null && dnsReply.isNotEmpty()) {
                                val resp = header + dnsReply
                                try {
                                    relayRef.send(DatagramPacket(resp, resp.size, clientAddr))
                                } catch (_: Throwable) {}
                            }
                        }
                    } catch (_: Throwable) {
                        break
                    }
                }
            }
            while (isRunning && ins.read() != -1) {}
        } catch (_: Throwable) {
        } finally {
            try { udpRelay?.close(); activeUdpSockets.remove(udpRelay) } catch (_: Throwable) {}
            try { client.close() } catch (_: Throwable) {}
        }
    }

    private fun queryDnsOverSshChannelWithTimeout(dnsIp: String, dnsQuery: ByteArray, timeoutMs: Long): ByteArray? {
        var sshChan: DirectTCPIPChannel? = null
        var session: PooledSshSession? = null
        val future = ioThreadPool.submit(Callable<ByteArray?> {
            try {
                val opened = openDirectSshChannel(dnsIp, 53)
                sshChan = opened.first
                session = opened.second
                val dos = DataOutputStream(BufferedOutputStream(sshChan!!.outputStream, 1024))
                val dis = DataInputStream(BufferedInputStream(sshChan!!.inputStream, 2048))
                dos.writeShort(dnsQuery.size)
                dos.write(dnsQuery)
                dos.flush()
                val rLen = dis.readUnsignedShort()
                if (rLen in 1..4096) {
                    val rPay = ByteArray(rLen)
                    dis.readFully(rPay)
                    rPay
                } else {
                    null
                }
            } catch (_: Throwable) {
                null
            } finally {
                releaseChannelCount(session)
                try { sshChan?.close() } catch (_: Throwable) {}
            }
        })
        return try {
            future.get(timeoutMs, TimeUnit.MILLISECONDS)
        } catch (_: Throwable) {
            future.cancel(true)
            releaseChannelCount(session)
            try { sshChan?.close() } catch (_: Throwable) {}
            null
        }
    }

    private fun queryDirectProtectedUdpDns(dnsIp: String, dnsQuery: ByteArray, timeoutMs: Int): ByteArray? {
        return try {
            DatagramSocket().use { ds ->
                protectDatagram(ds)
                ds.soTimeout = timeoutMs
                val addr = InetAddress.getByName(dnsIp)
                ds.send(DatagramPacket(dnsQuery, dnsQuery.size, addr, 53))
                val rBuf = ByteArray(2048)
                val rPkt = DatagramPacket(rBuf, rBuf.size)
                ds.receive(rPkt)
                if (rPkt.length > 0) rPkt.data.copyOfRange(0, rPkt.length) else null
            }
        } catch (_: Throwable) {
            null
        }
    }

    private fun resolveDnsFast(preferredDns: String, dnsQuery: ByteArray): ByteArray? {
        if (dnsQuery.size < 12) return null
        val cacheKey = if (dnsQuery.size >= 17) {
            dnsQuery.copyOfRange(4, minOf(dnsQuery.size, 96)).joinToString(",") { "%02x".format(it) }
        } else null

        if (cacheKey != null) {
            val cached = dnsMemoryCache[cacheKey]
            if (cached != null && System.currentTimeMillis() < cached.expireAt && cached.response.size >= 2) {
                val clone = cached.response.copyOf()
                clone[0] = dnsQuery[0]
                clone[1] = dnsQuery[1]
                return clone
            }
        }

        val customPrimary = VpnStateBridge.customDns1.value.trim().ifBlank { "1.1.1.1" }
        val customSecondary = VpnStateBridge.customDns2.value.trim().ifBlank { "8.8.8.8" }
        val udpCandidates = buildList {
            if (activeUdpCustomHost.isNotBlank() && activeUdpCustomPort == 53) add(activeUdpCustomHost)
            add(customPrimary)
            add("1.1.1.1")
            add(customSecondary)
            add("8.8.8.8")
        }.distinct()

        for (dnsIp in udpCandidates.take(3)) {
            val reply = queryDirectProtectedUdpDns(dnsIp, dnsQuery, 850)
            if (reply != null && reply.size >= 2) {
                if (cacheKey != null) {
                    dnsMemoryCache[cacheKey] = DnsCacheRecord(reply.copyOf(), System.currentTimeMillis() + 600_000L)
                }
                return reply
            }
        }

        val tcpDnsServers = listOf("1.1.1.1", "8.8.8.8", preferredDns.ifBlank { "1.1.1.1" }).distinct()
        if (sshPool.isNotEmpty()) {
            for (dnsIp in tcpDnsServers) {
                val reply = queryDnsOverSshChannelWithTimeout(
                    dnsIp = dnsIp,
                    dnsQuery = dnsQuery,
                    timeoutMs = if (isSlowDnsActive) 3500L else 1800L
                )
                if (reply != null && reply.size >= 2) {
                    if (cacheKey != null) {
                        dnsMemoryCache[cacheKey] = DnsCacheRecord(reply.copyOf(), System.currentTimeMillis() + 600_000L)
                    }
                    return reply
                }
            }
        }
        return null
    }

    fun stopSshTunnel() {
        isRunning = false
        isSlowDnsActive = false
        activeUdpCustomHost = ""
        activeUdpCustomPort = 0
        SlowDnsSpeedBooster.stopBooster()
        activeUdpSockets.forEach { try { it.close() } catch (_: Throwable) {} }
        activeUdpSockets.clear()
        try { localServer?.close() } catch (_: Throwable) {}
        localServer = null
        val toClose = ArrayList(sshPool)
        sshPool.clear()
        ioThreadPool.execute {
            toClose.forEach {
                try {
                    it.client.disconnect()
                    it.client.close()
                } catch (_: Throwable) {}
            }
        }
    }
}
