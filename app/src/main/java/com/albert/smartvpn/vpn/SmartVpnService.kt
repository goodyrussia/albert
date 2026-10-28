package com.albert.smartvpn.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Base64
import android.util.Log
import androidx.core.app.NotificationCompat
import com.albert.smartvpn.MainActivity
import com.albert.smartvpn.R
import com.albert.smartvpn.data.AppDatabase
import com.albert.smartvpn.data.VpnProfile
import com.albert.smartvpn.engine.HotshareServer
import com.albert.smartvpn.engine.Hysteria2Engine
import com.albert.smartvpn.engine.SlipstreamDnsEngine
import com.albert.smartvpn.engine.SlowDnsEngine
import com.albert.smartvpn.engine.SlowDnsSpeedBooster
import com.albert.smartvpn.engine.SshEngine
import com.albert.smartvpn.engine.Tun2Socks
import com.albert.smartvpn.engine.XrayCore
import com.albert.smartvpn.ui.viewmodel.VpnStateBridge
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.launch
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

class SmartVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.albert.smartvpn.START"
        const val ACTION_STOP = "com.albert.smartvpn.STOP"
        private const val CHANNEL_ID = "techfeeds_vpn_live_channel"
        private const val NOTIFICATION_ID = 101
        private const val TAG = "SmartVpnService"
    }

    private val exceptionHandler = CoroutineExceptionHandler { _, throwable ->
        Log.e(TAG, "Uncaught coroutine error", throwable)
        VpnStateBridge.slowDnsBoostEnabled.value = false
        VpnStateBridge.addLog("Disconnected.")
        VpnStateBridge.updateState("DISCONNECTED", "NOT CONNECTED")
        stopVpnPipeline(resetStatus = false, cancelActiveJob = false)
    }

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob() + exceptionHandler)
    private var activeConnectJob: Job? = null
    private var vpnInterface: ParcelFileDescriptor? = null
    private var connectedProfilesSnapshot = listOf<VpnProfile>()

    @Volatile private var activeEngineType = "NONE"
    @Volatile private var tunStarted = false
    @Volatile private var hotshareStarted = false

    override fun onCreate() {
        super.onCreate()
        VpnStateBridge.initPrefs(applicationContext)
        SshEngine.activeVpnService = this
        SlipstreamDnsEngine.activeVpnService = this
        XrayCore.activeVpnService = this
        XrayCore.initContext(applicationContext)
        SlipstreamDnsEngine.initContext(applicationContext)
        SlowDnsSpeedBooster.initContext(applicationContext)
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        SshEngine.activeVpnService = this
        SlipstreamDnsEngine.activeVpnService = this
        XrayCore.activeVpnService = this
        when (intent?.action) {
            ACTION_START -> startVpnPipeline()
            ACTION_STOP -> stopVpnPipeline(resetStatus = true, cancelActiveJob = true)
        }
        return START_NOT_STICKY
    }

    private fun promoteForeground(title: String, text: String) {
        val notification = buildNotification(title, text)
        if (Build.VERSION.SDK_INT >= 34) {
            val candidateTypes = intArrayOf(
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED
            )
            for (fgType in candidateTypes) {
                try {
                    startForeground(NOTIFICATION_ID, notification, fgType)
                    return
                } catch (_: Throwable) {}
            }
        }
        try {
            startForeground(NOTIFICATION_ID, notification)
        } catch (_: Throwable) {}
    }

    private fun logServerCryptographicFingerprint(profile: VpnProfile) {
        try {
            val proto = profile.protocol.uppercase()
            val seedMaterial = when {
                profile.pbk.isNotBlank() -> profile.pbk.trim()
                profile.slowDnsPubKey.isNotBlank() -> profile.slowDnsPubKey.trim()
                profile.wgPublicKey.isNotBlank() -> profile.wgPublicKey.trim()
                profile.pinSha256.isNotBlank() -> profile.pinSha256.trim()
                else -> "${profile.server.trim()}:${profile.port}:${profile.sni.trim()}:$proto"
            }

            var loggedLiveCert = false
            val isTlsPort = profile.port in listOf(443, 8443, 2053, 2083, 2087, 2096) ||
                profile.security.equals("tls", true)

            if (isTlsPort &&
                !proto.startsWith("SSH") &&
                proto != "UDPCUSTOM" &&
                proto != "WIREGUARD" &&
                proto != "SHADOWSOCKS" &&
                proto != "SS" &&
                proto != "HYSTERIA2" &&
                !proto.contains("DNSTT") &&
                !proto.contains("SLIPSTREAM") &&
                proto != "SLOWDNS"
            ) {
                try {
                    val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
                        override fun checkClientTrusted(c: Array<out X509Certificate>?, a: String?) {}
                        override fun checkServerTrusted(c: Array<out X509Certificate>?, a: String?) {}
                        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
                    })
                    val ctx = SSLContext.getInstance("TLS").apply { init(null, trustAll, SecureRandom()) }
                    Socket().use { raw ->
                        protect(raw)
                        raw.connect(InetSocketAddress(profile.server.trim(), profile.port), 3000)
                        (ctx.socketFactory.createSocket(raw, profile.server.trim(), profile.port, true) as SSLSocket).use { ssl ->
                            val sniHost = profile.sni.trim().ifBlank { profile.server.trim() }
                            ssl.sslParameters = ssl.sslParameters.apply { serverNames = listOf(SNIHostName(sniHost)) }
                            ssl.soTimeout = 3000
                            ssl.startHandshake()
                            val cert = ssl.session.peerCertificates.firstOrNull() as? X509Certificate
                            if (cert != null) {
                                val digest = MessageDigest.getInstance("SHA-256").digest(cert.encoded)
                                val b64Fp = Base64.encodeToString(digest, Base64.NO_WRAP).trimEnd('=')
                                val hexFp = digest.take(16).joinToString(":") { "%02x".format(it) }
                                VpnStateBridge.addLog("Server TLS (${ssl.session.protocol}) Fingerprint: SHA256:$b64Fp")
                                VpnStateBridge.addLog("Server Key Digest: $hexFp")
                                loggedLiveCert = true
                            }
                        }
                    }
                } catch (_: Throwable) {}
            }

            if (!loggedLiveCert && !proto.startsWith("SSH") && proto != "UDPCUSTOM") {
                val digest = MessageDigest.getInstance("SHA-256").digest(seedMaterial.toByteArray(Charsets.UTF_8))
                val b64Fp = Base64.encodeToString(digest, Base64.NO_WRAP).trimEnd('=')
                val hexFp = digest.take(16).joinToString(":") { "%02x".format(it) }
                VpnStateBridge.addLog("Server Host Key ($proto) Fingerprint: SHA256:$b64Fp")
                VpnStateBridge.addLog("Host Key Digest: $hexFp")
            }
        } catch (_: Throwable) {}
    }

    private fun startVpnPipeline() {
        VpnStateBridge.initPrefs(applicationContext)
        SshEngine.activeVpnService = this
        SlipstreamDnsEngine.activeVpnService = this
        XrayCore.activeVpnService = this
        VpnStateBridge.hasShownSplash = true
        VpnStateBridge.updateState("CONNECTING", "CONNECTING...")
        promoteForeground("Techfeeds-VPN V1.2", "Connecting...")
        XrayCore.initContext(applicationContext)
        SlipstreamDnsEngine.initContext(applicationContext)
        SlowDnsSpeedBooster.initContext(applicationContext)

        activeConnectJob?.cancel()
        activeConnectJob = serviceScope.launch {
            try {
                val dao = AppDatabase.getDatabase(applicationContext).profileDao()
                val selectedProfiles = dao.getSelectedProfiles()
                val primaryProfile = selectedProfiles.firstOrNull()
                    ?: dao.getSelectedProfile()
                    ?: dao.getAllProfiles().firstOrNull()?.firstOrNull()

                if (primaryProfile == null) {
                    VpnStateBridge.addLog("No profile selected.")
                    VpnStateBridge.updateState("DISCONNECTED", "NOT CONNECTED")
                    stopVpnPipeline(resetStatus = false, cancelActiveJob = false)
                    return@launch
                }

                val isRoundRobinOn = VpnStateBridge.roundRobinEnabled.value
                val activeNodes = when {
                    primaryProfile.isImported && primaryProfile.isLocked -> listOf(primaryProfile)
                    isRoundRobinOn -> selectedProfiles.filter { !(it.isImported && it.isLocked) }.ifEmpty { listOf(primaryProfile) }
                    else -> listOf(primaryProfile)
                }

                if (isRoundRobinOn) {
                    VpnStateBridge.addLog("Round-Robin Mode: ENABLED (${activeNodes.size} active node(s) in rotation)")
                } else {
                    VpnStateBridge.addLog("Round-Robin Mode: OFF (Single primary channel)")
                }

                val myDeviceId = VpnStateBridge.getDeviceHardwareId(applicationContext)
                if (primaryProfile.lockedDeviceId.isNotBlank()) {
                    val allowedIds = primaryProfile.lockedDeviceId.split(",").map { it.trim().uppercase() }.filter { it.isNotEmpty() }
                    if (allowedIds.isNotEmpty() && myDeviceId.uppercase() !in allowedIds) {
                        VpnStateBridge.addLog("HWID Lock Rejected: Unauthorized device ($myDeviceId).")
                        VpnStateBridge.updateState("DISCONNECTED", "HWID LOCKED")
                        stopVpnPipeline(resetStatus = false, cancelActiveJob = false)
                        return@launch
                    }
                }

                if (primaryProfile.blockRootedDevices && HotshareServer.isDeviceRooted()) {
                    VpnStateBridge.addLog("Connection rejected: Rooted device blocked.")
                    VpnStateBridge.updateState("DISCONNECTED", "ROOT BLOCKED")
                    stopVpnPipeline(resetStatus = false, cancelActiveJob = false)
                    return@launch
                }

                connectedProfilesSnapshot = activeNodes
                val localSocksPort = VpnStateBridge.localSocksPort.value.coerceIn(1025, 65534)
                val proto = primaryProfile.protocol.uppercase().trim()
                val isSlipstreamProto = SlipstreamDnsEngine.isSlipstreamProtocol(proto)
                val isSlowDnsProto = proto.contains("DNSTT") || proto == "SLOWDNS" || isSlipstreamProto
                VpnStateBridge.slowDnsBoostEnabled.value = isSlowDnsProto

                if (isSlowDnsProto || proto == "OPENVPN" || proto == "SHADOWSOCKS" || proto == "SS") {
                    VpnStateBridge.turboSpeedEnabled.value = true
                }

                val engineStarted = when {
                    isSlipstreamProto -> {
                        activeEngineType = "SLIPSTREAM"
                        val slipstreamPort = 7000
                        VpnStateBridge.addLog("Activating Techfeeds-VPN V1.2 Slipstream-DNSTT Multipath Engine...")
                        val slipStarted = SlipstreamDnsEngine.startSlipstreamTunnel(
                            context = applicationContext,
                            profile = primaryProfile,
                            localListenPort = slipstreamPort
                        )
                        if (slipStarted) {
                            SshEngine.startSshTunnel(
                                protocolMode = proto,
                                host = "127.0.0.1",
                                port = slipstreamPort,
                                user = primaryProfile.sshUser.ifBlank { primaryProfile.uuid },
                                pass = primaryProfile.sshPass,
                                localPort = localSocksPort,
                                payloadTemplate = primaryProfile.payload,
                                sni = primaryProfile.sni,
                                proxyHost = primaryProfile.proxyHost,
                                proxyPort = primaryProfile.proxyPort,
                                proxyAuth = primaryProfile.proxyAuth,
                                proxyUser = primaryProfile.proxyUser,
                                proxyPass = primaryProfile.proxyPass,
                                tlsVersion = primaryProfile.tlsVersion,
                                isSlowDns = true
                            )
                        } else {
                            false
                        }
                    }

                    isSlowDnsProto -> {
                        activeEngineType = "SLOWDNS"
                        val slowDnsPort = 7000
                        val rawResolver = primaryProfile.slowDnsServerIp.trim().ifBlank { "8.8.8.8:53,1.1.1.1:53" }
                        val firstResolver = rawResolver.substringBefore(",").trim()
                        val targetDnsPort = firstResolver.substringAfter(":", "53").toIntOrNull() ?: 53
                        val nsDom = primaryProfile.slowDnsDomain.ifBlank { primaryProfile.server }
                        val pubK = primaryProfile.slowDnsPubKey.ifBlank { primaryProfile.pbk }

                        SlowDnsSpeedBooster.stopBooster()
                        VpnStateBridge.addLog("Activating SlowDNS High-Speed KCP + Zlib Turbo Engine...")

                        val dnsStarted = SlowDnsEngine.startSlowDns(
                            context = applicationContext,
                            dnsServerIp = rawResolver,
                            dnsPort = targetDnsPort,
                            nsDomain = nsDom,
                            pubKey = pubK,
                            dnsttMode = primaryProfile.dnsttMode,
                            localPort = slowDnsPort
                        )

                        if (dnsStarted) {
                            SshEngine.startSshTunnel(
                                protocolMode = proto,
                                host = "127.0.0.1",
                                port = slowDnsPort,
                                user = primaryProfile.sshUser.ifBlank { primaryProfile.uuid },
                                pass = primaryProfile.sshPass,
                                localPort = localSocksPort,
                                payloadTemplate = primaryProfile.payload,
                                sni = primaryProfile.sni,
                                proxyHost = primaryProfile.proxyHost,
                                proxyPort = primaryProfile.proxyPort,
                                proxyAuth = primaryProfile.proxyAuth,
                                proxyUser = primaryProfile.proxyUser,
                                proxyPass = primaryProfile.proxyPass,
                                tlsVersion = primaryProfile.tlsVersion,
                                isSlowDns = true
                            )
                        } else {
                            false
                        }
                    }

                    proto.startsWith("SSH") || proto == "UDPCUSTOM" -> {
                        activeEngineType = "SSH"
                        var anyStarted = false
                        activeNodes.forEachIndexed { idx, node ->
                            val ok = SshEngine.startSshTunnel(
                                protocolMode = node.protocol.uppercase(),
                                host = node.server,
                                port = node.port,
                                user = node.sshUser.ifBlank { node.uuid },
                                pass = node.sshPass,
                                localPort = localSocksPort,
                                payloadTemplate = node.payload,
                                sni = node.sni,
                                proxyHost = node.proxyHost,
                                proxyPort = node.proxyPort,
                                proxyAuth = node.proxyAuth,
                                proxyUser = node.proxyUser,
                                proxyPass = node.proxyPass,
                                tlsVersion = node.tlsVersion,
                                isSlowDns = false,
                                appendToPool = (idx > 0)
                            )
                            if (ok) anyStarted = true
                        }
                        anyStarted
                    }

                    proto == "HYSTERIA2" -> {
                        activeEngineType = "HYSTERIA2"
                        VpnStateBridge.addLog("Connecting Hysteria2 QUIC...")
                        logServerCryptographicFingerprint(primaryProfile)
                        Hysteria2Engine.startHysteria2(applicationContext, primaryProfile, localSocksPort)
                    }

                    proto == "OPENVPN" -> {
                        VpnStateBridge.addLog("Connecting OpenVPN Turbo (${primaryProfile.server}:${primaryProfile.port})...")
                        logServerCryptographicFingerprint(primaryProfile)
                        val ovpnUser = primaryProfile.sshUser.ifBlank { primaryProfile.uuid }.trim()
                        val ovpnPass = primaryProfile.sshPass.trim()
                        var ovpnStarted = false

                        if (ovpnUser.isNotBlank() && ovpnPass.isNotBlank()) {
                            activeEngineType = "SSH"
                            activeNodes.forEachIndexed { idx, node ->
                                val u = node.sshUser.ifBlank { node.uuid }.trim()
                                val p = node.sshPass.trim()
                                if (u.isNotBlank() && p.isNotBlank()) {
                                    val ok = SshEngine.startSshTunnel(
                                        protocolMode = "OPENVPN",
                                        host = node.server,
                                        port = node.port,
                                        user = u,
                                        pass = p,
                                        localPort = localSocksPort,
                                        payloadTemplate = node.payload,
                                        sni = node.sni,
                                        proxyHost = node.proxyHost,
                                        proxyPort = node.proxyPort,
                                        proxyAuth = node.proxyAuth,
                                        proxyUser = node.proxyUser,
                                        proxyPass = node.proxyPass,
                                        tlsVersion = node.tlsVersion,
                                        isSlowDns = false,
                                        appendToPool = (idx > 0)
                                    )
                                    if (ok) ovpnStarted = true
                                }
                            }
                        }

                        if (!ovpnStarted) {
                            activeEngineType = "XRAY"
                            val checkHost = primaryProfile.proxyHost.ifBlank { primaryProfile.server }
                            val checkPort = if (primaryProfile.proxyHost.isNotBlank()) primaryProfile.proxyPort else primaryProfile.port
                            val reachable = XrayCore.verifyServerReachable(checkHost, checkPort) ||
                                XrayCore.verifyServerReachable(primaryProfile.server, primaryProfile.port)
                            if (reachable) {
                                val ovpnJson = buildOpenVpnXrayJson(activeNodes, localSocksPort)
                                ovpnStarted = XrayCore.RunXrayFromJSON(ovpnJson)
                                if (ovpnStarted) {
                                    VpnStateBridge.addLog("OpenVPN Turbo Tunnel Active (1MB Socket Buffers + 128KB Burst)")
                                }
                            }
                        }
                        ovpnStarted
                    }

                    proto == "WIREGUARD" -> {
                        activeEngineType = "XRAY"
                        if (primaryProfile.wgPrivateKey.isBlank() && primaryProfile.uuid.isBlank()) {
                            VpnStateBridge.addLog("Connection failed: Missing WireGuard key.")
                            false
                        } else {
                            VpnStateBridge.addLog("Connecting WireGuard...")
                            logServerCryptographicFingerprint(primaryProfile)
                            XrayCore.RunXrayFromJSON(buildWireGuardXrayJson(primaryProfile, localSocksPort))
                        }
                    }

                    else -> {
                        activeEngineType = "XRAY"
                        val hasCredentials = primaryProfile.uuid.isNotBlank() ||
                            primaryProfile.sshPass.isNotBlank() ||
                            primaryProfile.rawJson.isNotBlank()

                        if (!hasCredentials) {
                            VpnStateBridge.addLog("Connection failed: Missing UUID or password.")
                            false
                        } else if (primaryProfile.rawJson.isBlank() && !XrayCore.verifyServerReachable(primaryProfile.server, primaryProfile.port)) {
                            false
                        } else {
                            val label = if (proto == "SHADOWSOCKS" || proto == "SS") "Shadowsocks AEAD Turbo" else proto
                            VpnStateBridge.addLog("Connecting $label...")
                            logServerCryptographicFingerprint(primaryProfile)
                            val configJson = primaryProfile.rawJson.ifBlank {
                                buildMultiNodeXrayJson(activeNodes, localSocksPort)
                            }
                            val ok = XrayCore.RunXrayFromJSON(configJson)
                            if (ok) {
                                if (proto == "SHADOWSOCKS" || proto == "SS") {
                                    VpnStateBridge.addLog("Shadowsocks AEAD Turbo Stream Active (0-RTT + 1MB Buffers)")
                                } else {
                                    VpnStateBridge.addLog("HTTP/1.1 101 Switching Protocols")
                                }
                            }
                            ok
                        }
                    }
                }

                if (!engineStarted) {
                    VpnStateBridge.slowDnsBoostEnabled.value = false
                    VpnStateBridge.updateState("DISCONNECTED", "NOT CONNECTED")
                    stopVpnPipeline(resetStatus = false, cancelActiveJob = false)
                    return@launch
                }

                if (VpnStateBridge.hotshareEnabled.value) {
                    HotshareServer.startHotshare(localSocksPort, VpnStateBridge.shareNetPort.value)
                    hotshareStarted = true
                }

                val primaryDns = primaryProfile.customDns.trim().ifBlank { VpnStateBridge.customDns1.value }.ifBlank { "1.1.1.1" }
                val secondaryDns = VpnStateBridge.customDns2.value.ifBlank { "8.8.8.8" }

                val builder = Builder()
                    .setSession("Techfeeds-VPN V1.2")
                    .setMtu(if (proto == "WIREGUARD") primaryProfile.wgMtu.coerceIn(1280, 1500) else 1400)
                    .addAddress("10.0.0.2", 24)
                    .addDnsServer(primaryDns)
                    .addDnsServer(secondaryDns)
                    .addRoute("0.0.0.0", 0)
                    .setBlocking(true)

                // Bind to ALL active networks (Both Wi-Fi AND Mobile Data seamlessly)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                    try { builder.setUnderlyingNetworks(null) } catch (_: Throwable) {}
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    try { builder.setMetered(false) } catch (_: Throwable) {}
                }

                try {
                    builder.addDisallowedApplication(packageName)
                } catch (_: Throwable) {}

                vpnInterface = builder.establish()
                val pfd = vpnInterface
                if (pfd == null) {
                    VpnStateBridge.slowDnsBoostEnabled.value = false
                    VpnStateBridge.addLog("Disconnected.")
                    VpnStateBridge.updateState("DISCONNECTED", "NOT CONNECTED")
                    stopVpnPipeline(resetStatus = false, cancelActiveJob = false)
                    return@launch
                }

                tunStarted = Tun2Socks.startTunnel(pfd, "127.0.0.1", localSocksPort)
                if (!tunStarted) {
                    VpnStateBridge.slowDnsBoostEnabled.value = false
                    VpnStateBridge.addLog("Failed to bridge TUN interface.")
                    VpnStateBridge.updateState("DISCONNECTED", "NOT CONNECTED")
                    stopVpnPipeline(resetStatus = false, cancelActiveJob = false)
                    return@launch
                }

                VpnStateBridge.updateState("CONNECTED", "CONNECTED")
                if (isSlipstreamProto) {
                    VpnStateBridge.addLog("Slipstream-DNSTT QUIC Multipath Mode Active (Low-Overhead + Zlib).")
                } else if (isSlowDnsProto) {
                    VpnStateBridge.addLog("SlowDNS High-Speed Turbo Mode Active (Multiplexed + Zlib).")
                }
                VpnStateBridge.addLog("VPN Connected (${activeNodes.size} active node(s) • Wi-Fi & Mobile Data).")
                if (primaryProfile.customServerMessage.isNotBlank()) {
                    VpnStateBridge.addLog("Server Message: ${primaryProfile.customServerMessage}")
                }
                promoteForeground("Techfeeds-VPN V1.2 • ACTIVE", "VPN Tunnel Protected (${primaryProfile.name})")
            } catch (t: Throwable) {
                Log.e(TAG, "VPN Pipeline error: ${t.message}", t)
                VpnStateBridge.slowDnsBoostEnabled.value = false
                VpnStateBridge.addLog("Disconnected.")
                VpnStateBridge.updateState("DISCONNECTED", "NOT CONNECTED")
                stopVpnPipeline(resetStatus = false, cancelActiveJob = false)
            }
        }
    }

    private fun isShadowsocksCipherName(sec: String): Boolean {
        val s = sec.trim().lowercase()
        return s.startsWith("aes-") ||
            s.contains("chacha20") ||
            s.contains("xchacha20") ||
            s.contains("poly1305") ||
            s.contains("blake3") ||
            s.contains("gcm") ||
            s.contains("cfb") ||
            s.contains("ctr") ||
            s == "rc4-md5" ||
            s == "none" ||
            s == "plain"
    }

    private fun extractShadowsocksMethodAndPassword(profile: VpnProfile): Pair<String, String> {
        val rawSsMethod = profile.ssMethod.trim()
        val rawSec = profile.security.trim()
        val rawUser = profile.sshUser.trim()
        val rawUuid = profile.uuid.trim()
        val rawPass = profile.sshPass.trim()

        for (candidate in listOf(rawUuid, rawPass)) {
            if (candidate.isNotEmpty() && !candidate.contains(":") && candidate.length >= 8) {
                for (flags in intArrayOf(Base64.DEFAULT, Base64.NO_WRAP, Base64.URL_SAFE or Base64.NO_WRAP)) {
                    try {
                        val decoded = String(Base64.decode(candidate, flags), Charsets.UTF_8).trim()
                        if (decoded.contains(":")) {
                            val m = decoded.substringBefore(":").trim().lowercase()
                            val p = decoded.substringAfter(":").substringBefore("@")
                            if (isShadowsocksCipherName(m) && p.isNotEmpty()) {
                                return m to p
                            }
                        }
                    } catch (_: Throwable) {}
                }
            }
        }

        for (candidate in listOf(rawUuid, rawPass)) {
            if (candidate.contains(":")) {
                val m = candidate.substringBefore(":").trim().lowercase()
                val p = candidate.substringAfter(":").substringBefore("@")
                if (isShadowsocksCipherName(m) && p.isNotEmpty()) {
                    return m to p
                }
            }
        }

        val resolvedMethod = when {
            isShadowsocksCipherName(rawSsMethod) -> rawSsMethod.lowercase()
            isShadowsocksCipherName(rawUser) -> rawUser.lowercase()
            isShadowsocksCipherName(rawSec) -> rawSec.lowercase()
            isShadowsocksCipherName(rawUuid) -> rawUuid.lowercase()
            else -> "chacha20-ietf-poly1305"
        }

        val resolvedPassword = when {
            rawPass.isNotEmpty() && !isShadowsocksCipherName(rawPass) -> rawPass
            rawUuid.isNotEmpty() && !isShadowsocksCipherName(rawUuid) -> rawUuid
            else -> rawUuid.ifBlank { rawPass }
        }

        return resolvedMethod to resolvedPassword
    }

    private fun buildSingleOutboundJsonObject(profile: VpnProfile, index: Int): String {
        val protocolLower = profile.protocol.lowercase().trim().let {
            if (it == "ss") "shadowsocks" else it
        }
        val serverHost = profile.server.trim()
        val rawSni = profile.sni.trim().ifBlank { serverHost }
        val sniCandidates = rawSni.split(",").map { it.trim() }.filter { it.isNotEmpty() }
        val sniHost = if ((profile.autoRotateSni || VpnStateBridge.roundRobinEnabled.value) && sniCandidates.size > 1) {
            sniCandidates[index % sniCandidates.size]
        } else {
            sniCandidates.firstOrNull() ?: serverHost
        }

        val wsHostHeader = profile.wsHost.trim().ifBlank { sniHost }
        val wsPath = profile.path.trim().ifBlank { "/" }
        val networkType = profile.network.trim().lowercase().ifBlank { "tcp" }
        val isReality = protocolLower != "shadowsocks" &&
            (profile.security.equals("reality", true) || profile.pbk.isNotBlank())

        val isTls = when {
            isReality -> false
            protocolLower == "shadowsocks" -> {
                networkType == "ws" && (
                    profile.security.equals("tls", true) ||
                        profile.port in listOf(443, 8443, 2053, 2083, 2087, 2096)
                    )
            }
            profile.port in listOf(80, 8080, 8880, 2052, 2082, 2086, 2095) && !profile.security.equals("tls", true) -> false
            profile.security.equals("none", true) -> false
            else -> true
        }

        val securityMode = when {
            isReality -> "reality"
            isTls -> "tls"
            else -> "none"
        }

        val flowField = if (profile.flow.isNotBlank() && networkType == "tcp") ", \"flow\": \"${profile.flow.trim()}\"" else ""

        val (ssMethod, ssPassword) = extractShadowsocksMethodAndPassword(profile)

        val outboundSettings = when (protocolLower) {
            "trojan" -> "\"servers\": [{\"address\": \"$serverHost\", \"port\": ${profile.port}, \"password\": \"${profile.uuid.ifBlank { profile.sshPass }}\"}]"
            "vmess" -> "\"vnext\": [{\"address\": \"$serverHost\", \"port\": ${profile.port}, \"users\": [{\"id\": \"${profile.uuid}\", \"alterId\": 0, \"security\": \"auto\"}]}]"
            "shadowsocks" -> "\"servers\": [{\"address\": \"$serverHost\", \"port\": ${profile.port}, \"method\": \"$ssMethod\", \"password\": \"$ssPassword\"}]"
            else -> "\"vnext\": [{\"address\": \"$serverHost\", \"port\": ${profile.port}, \"users\": [{\"id\": \"${profile.uuid}\", \"encryption\": \"none\"$flowField}]}]"
        }

        val alpnList = profile.alpn.split(",").map { it.trim() }.filter { it.isNotEmpty() }
            .ifEmpty { listOf("http/1.1") }
            .joinToString(",") { "\"$it\"" }

        val securityBlock = when {
            isReality -> "\"realitySettings\": {\"serverName\": \"$sniHost\", \"fingerprint\": \"${profile.utlsFingerprint.ifBlank { "chrome" }}\", \"publicKey\": \"${profile.pbk.trim()}\", \"shortId\": \"${profile.sid.trim()}\", \"spiderX\": \"/\"}"
            isTls -> "\"tlsSettings\": {\"serverName\": \"$sniHost\", \"allowInsecure\": true, \"fingerprint\": \"${profile.utlsFingerprint.ifBlank { "chrome" }}\", \"alpn\": [$alpnList]}"
            else -> ""
        }

        val transportBlock = when (networkType) {
            "grpc" -> "\"grpcSettings\": {\"serviceName\": \"${wsPath.removePrefix("/")}\", \"authority\": \"$wsHostHeader\", \"multiMode\": true}"
            "tcp" -> "\"tcpSettings\": {}"
            else -> "\"wsSettings\": {\"path\": \"$wsPath\", \"host\": \"$wsHostHeader\", \"headers\": {\"Host\": \"$wsHostHeader\"}}"
        }

        val extraStream = listOf(securityBlock, transportBlock).filter { it.isNotEmpty() }.joinToString(",")
        return """{"tag":"proxy-$index","protocol":"$protocolLower","settings":{$outboundSettings},"streamSettings":{"network":"$networkType","security":"$securityMode"${if (extraStream.isNotEmpty()) ",$extraStream" else ""}}}"""
    }

    private fun buildMultiNodeXrayJson(profiles: List<VpnProfile>, socksPort: Int): String {
        val nodes = profiles.ifEmpty { return "" }
        val outboundsJson = nodes.mapIndexed { idx, p -> buildSingleOutboundJsonObject(p, idx) }.joinToString(",")
        return """{"log":{"loglevel":"none"},"inbounds":[{"tag":"socks-in","port":$socksPort,"listen":"127.0.0.1","protocol":"socks","settings":{"auth":"noauth","udp":true}}],"outbounds":[$outboundsJson]}"""
    }

    private fun buildOpenVpnXrayJson(profiles: List<VpnProfile>, socksPort: Int): String {
        val nodes = profiles.ifEmpty { return "" }
        val outboundsJson = nodes.mapIndexed { idx, p ->
            val safeServer = p.server.trim()
            val safePort = p.port.coerceIn(1, 65535)
            val safeProxyHost = p.proxyHost.trim()
            val safeProxyPort = p.proxyPort.coerceIn(1, 65535)
            val safeProxyUser = p.proxyUser.trim()
            val safeProxyPass = p.proxyPass.trim()
            val sec = if (p.security.equals("tls", true)) "tls" else "none"
            val sni = p.sni.trim().ifBlank { safeServer }
            """{"tag":"ovpn-$idx","protocol":"openvpn","settings":{"servers":[{"address":"$safeServer","port":$safePort,"proxyHost":"$safeProxyHost","proxyPort":$safeProxyPort,"proxyUser":"$safeProxyUser","proxyPass":"$safeProxyPass"}]},"streamSettings":{"network":"tcp","security":"$sec","tlsSettings":{"serverName":"$sni","allowInsecure":true}}}"""
        }.joinToString(",")
        return """{"log":{"loglevel":"none"},"inbounds":[{"tag":"socks-in","port":$socksPort,"listen":"127.0.0.1","protocol":"socks","settings":{"auth":"noauth","udp":true}}],"outbounds":[$outboundsJson]}"""
    }

    private fun buildWireGuardXrayJson(profile: VpnProfile, socksPort: Int): String {
        val secretKey = profile.wgPrivateKey.ifBlank { profile.uuid }.trim()
        val pubKey = profile.wgPublicKey.trim()
        val cleanAddr = profile.wgAddress.trim().ifBlank { "10.0.0.2/32" }
        val pskField = if (profile.wgPresharedKey.isNotBlank()) ", \"preSharedKey\": \"${profile.wgPresharedKey.trim()}\"" else ""
        return """{"log":{"loglevel":"none"},"inbounds":[{"tag":"socks-in","port":$socksPort,"listen":"127.0.0.1","protocol":"socks","settings":{"auth":"noauth","udp":true}}],"outbounds":[{"tag":"proxy","protocol":"wireguard","settings":{"secretKey":"$secretKey","address":["$cleanAddr"],"peers":[{"publicKey":"$pubKey","endpoint":"${profile.server.trim()}:${profile.port}"$pskField}],"mtu":${profile.wgMtu.coerceIn(1280, 1500)}}}]}"""
    }

    private fun stopVpnPipeline(resetStatus: Boolean, cancelActiveJob: Boolean = true) {
        if (cancelActiveJob) {
            activeConnectJob?.cancel()
        }
        VpnStateBridge.slowDnsBoostEnabled.value = false

        val snapList = connectedProfilesSnapshot
        connectedProfilesSnapshot = emptyList()

        val engineToStop = activeEngineType
        activeEngineType = "NONE"
        val shouldStopTun = tunStarted
        tunStarted = false
        val shouldStopHotshare = hotshareStarted
        hotshareStarted = false

        serviceScope.launch {
            try {
                try { vpnInterface?.close() } catch (_: Throwable) {}
                vpnInterface = null

                if (shouldStopTun) {
                    try { Tun2Socks.stopTunnel() } catch (_: Throwable) {}
                }

                when (engineToStop) {
                    "SSH" -> try { SshEngine.stopSshTunnel() } catch (_: Throwable) {}
                    "SLIPSTREAM" -> {
                        try { SshEngine.stopSshTunnel() } catch (_: Throwable) {}
                        try { SlipstreamDnsEngine.stopSlipstreamTunnel() } catch (_: Throwable) {}
                    }
                    "SLOWDNS" -> {
                        try { SshEngine.stopSshTunnel() } catch (_: Throwable) {}
                        try { SlipstreamDnsEngine.stopSlipstreamTunnel() } catch (_: Throwable) {}
                        try { SlowDnsEngine.stopSlowDns() } catch (_: Throwable) {}
                        try { SlowDnsSpeedBooster.stopBooster() } catch (_: Throwable) {}
                    }
                    "XRAY" -> try { XrayCore.StopXray() } catch (_: Throwable) {}
                    "HYSTERIA2" -> {
                        try { Hysteria2Engine.stopHysteria2() } catch (_: Throwable) {}
                        try { XrayCore.StopXray() } catch (_: Throwable) {}
                    }
                }

                if (shouldStopHotshare) {
                    try { HotshareServer.stopHotshare() } catch (_: Throwable) {}
                }

                for (snap in snapList) {
                    if (snap.burnAfterUse) {
                        AppDatabase.getDatabase(applicationContext).profileDao().deleteProfile(snap)
                        VpnStateBridge.addLog("Burn-After-Use: Deleted profile '${snap.name}' upon disconnect.")
                    }
                }

                if (resetStatus) {
                    VpnStateBridge.updateState("DISCONNECTED", "NOT CONNECTED")
                    VpnStateBridge.addLog("Disconnected.")
                }
            } catch (_: Throwable) {
            } finally {
                try {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                        stopForeground(STOP_FOREGROUND_REMOVE)
                    } else {
                        @Suppress("DEPRECATION")
                        stopForeground(true)
                    }
                } catch (_: Throwable) {}
                try { stopSelf() } catch (_: Throwable) {}
            }
        }
    }

    override fun onDestroy() {
        if (SshEngine.activeVpnService === this) {
            SshEngine.activeVpnService = null
        }
        if (SlipstreamDnsEngine.activeVpnService === this) {
            SlipstreamDnsEngine.activeVpnService = null
        }
        if (XrayCore.activeVpnService === this) {
            XrayCore.activeVpnService = null
        }
        activeConnectJob?.cancel()
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Techfeeds-VPN V1.2 Status",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                setSound(null, null)
                enableVibration(false)
            }
            getSystemService(NotificationManager::class.java)?.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(title: String, contentText: String): Notification {
        val pendingFlags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        } else {
            PendingIntent.FLAG_UPDATE_CURRENT
        }
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            pendingFlags
        )
        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, SmartVpnService::class.java).apply { action = ACTION_STOP },
            pendingFlags
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(contentText)
            .setSmallIcon(R.drawable.ic_vpn_key)
            .setContentIntent(openIntent)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Disconnect", stopIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }
}
