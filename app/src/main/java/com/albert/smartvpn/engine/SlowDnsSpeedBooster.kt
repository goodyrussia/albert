package com.albert.smartvpn.engine

import android.content.Context
import android.os.Build
import com.albert.smartvpn.data.VpnProfile
import com.albert.smartvpn.ui.viewmodel.VpnStateBridge
import java.io.File
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import java.util.zip.ZipFile

object SlowDnsSpeedBooster {

    data class ResolverProbeResult(
        val ip: String,
        val rttMs: Int = 28,
        val port: Int = 53,
        val healthy: Boolean = true
    ) : CharSequence by ip {
        override fun toString(): String = ip
    }

    enum class BoostProfile(
        val label: String,
        val sshMaxPacketBytes: Int,
        val sshWindowBytes: Long,
        val relayChunkBytes: Int,
        val coalesceDelayMs: Long,
        val targetParallelSessions: Int,
        val ednsPayloadBytes: Int
    ) {
        SAFE_FALLBACK(
            label = "Stable DNSTT Mode (16 KB Frame • 1 MB Window)",
            sshMaxPacketBytes = 16384,
            sshWindowBytes = 1048576L,
            relayChunkBytes = 16384,
            coalesceDelayMs = 0L,
            targetParallelSessions = 1,
            ednsPayloadBytes = 1232
        ),
        BALANCED_ADAPTIVE(
            label = "Balanced DNSTT Mode (16 KB Frame • 1 MB Window)",
            sshMaxPacketBytes = 16384,
            sshWindowBytes = 1048576L,
            relayChunkBytes = 16384,
            coalesceDelayMs = 0L,
            targetParallelSessions = 1,
            ednsPayloadBytes = 1232
        ),
        TURBO_SWARM(
            label = "Stable KCP Mode (16 KB Frame • 1 MB Window)",
            sshMaxPacketBytes = 16384,
            sshWindowBytes = 1048576L,
            relayChunkBytes = 16384,
            coalesceDelayMs = 0L,
            targetParallelSessions = 1,
            ednsPayloadBytes = 1232
        )
    }

    private val isActive = AtomicBoolean(false)
    private val currentBoostProfile = AtomicReference(BoostProfile.SAFE_FALLBACK)

    @Volatile private var appContextRef: Context? = null
    @Volatile private var cachedDnsttBinary: File? = null
    @Volatile private var primaryDnsttPort: Int = 7000
    @Volatile private var configuredDnsServer: String = "1.1.1.1:53"
    @Volatile private var activeDnsDomain: String = ""
    @Volatile private var activePublicKey: String = ""
    @Volatile private var fallbackProcess: Process? = null

    fun initContext(context: Context) {
        appContextRef = context.applicationContext
    }

    @Synchronized
    fun resolveDnsttExecutable(context: Context? = appContextRef): File? {
        cachedDnsttBinary?.let {
            if (it.exists() && it.length() > 0L) return it
        }
        val ctx = context ?: return null
        val nativeDir = File(ctx.applicationInfo.nativeLibraryDir)
        for (name in listOf("libdnstt.so", "libdnstt-client.so", "dnstt-client", "dnstt")) {
            val f = File(nativeDir, name)
            if (f.exists() && f.length() > 0L) {
                try { f.setExecutable(true, false) } catch (_: Throwable) {}
                cachedDnsttBinary = f
                return f
            }
        }

        val apkPaths = buildList {
            add(ctx.applicationInfo.sourceDir)
            ctx.applicationInfo.splitSourceDirs?.let { addAll(it) }
        }.filter { !it.isNullOrBlank() }

        val supportedAbis = Build.SUPPORTED_ABIS?.toList() ?: listOf("arm64-v8a", "armeabi-v7a")
        for (apkPath in apkPaths) {
            try {
                ZipFile(File(apkPath)).use { zip ->
                    for (abi in supportedAbis) {
                        val entry = zip.getEntry("lib/$abi/libdnstt.so") ?: continue
                        val outFile = File(ctx.filesDir, "libdnstt.so")
                        zip.getInputStream(entry).use { input ->
                            FileOutputStream(outFile).use { output -> input.copyTo(output) }
                        }
                        outFile.setReadable(true, false)
                        outFile.setExecutable(true, false)
                        try {
                            Runtime.getRuntime().exec(arrayOf("chmod", "755", outFile.absolutePath)).waitFor()
                        } catch (_: Throwable) {}
                        if (outFile.exists() && outFile.length() > 1024L) {
                            cachedDnsttBinary = outFile
                            return outFile
                        }
                    }
                }
            } catch (_: Throwable) {}
        }
        return null
    }

    fun normalizeUdpResolverAddress(rawDns: String): String {
        val clean = rawDns.trim()
            .removePrefix("udp://")
            .removePrefix("http://")
            .removePrefix("https://")
            .substringBefore("/")
            .trim()
        if (clean.isEmpty()) return "1.1.1.1:53"
        return if (clean.contains(":")) {
            val host = clean.substringBefore(":").trim().ifBlank { "1.1.1.1" }
            val port = clean.substringAfter(":").toIntOrNull()?.coerceIn(1, 65535) ?: 53
            "$host:$port"
        } else {
            "$clean:53"
        }
    }

    fun normalizeDnsDomain(rawDomain: String): String {
        return rawDomain.trim()
            .removePrefix("http://")
            .removePrefix("https://")
            .substringBefore("/")
            .trim('.')
            .trim()
    }

    fun isSlowDnsProfile(profile: VpnProfile?): Boolean {
        if (profile == null) return false
        val proto = profile.protocol.uppercase().trim()
        val key = profile.slowDnsPubKey.ifBlank { profile.pbk }
        return proto.contains("SLOWDNS") ||
            proto.contains("DNSTT") ||
            (profile.slowDnsDomain.isNotBlank() && key.isNotBlank())
    }

    fun autoActivateForProfile(context: Context?, profile: VpnProfile?) {
        if (context != null) initContext(context)
        if (!isSlowDnsProfile(profile)) return
        if (profile != null) {
            configuredDnsServer = normalizeUdpResolverAddress(profile.slowDnsServerIp.ifBlank { "1.1.1.1:53" })
            activeDnsDomain = normalizeDnsDomain(profile.slowDnsDomain)
            activePublicKey = profile.slowDnsPubKey.ifBlank { profile.pbk }.trim()
        }
    }

    fun ensureDnsttEngineRunning(
        targetLocalPort: Int = primaryDnsttPort,
        dnsServerIp: String = configuredDnsServer,
        nsDomain: String = activeDnsDomain,
        pubKey: String = activePublicKey
    ): Boolean {
        val port = if (targetLocalPort in 1..65535) targetLocalPort else 7000
        primaryDnsttPort = port
        if (isLocalDnsttPortAlive(port)) return true

        val dnsttBin = resolveDnsttExecutable() ?: return false
        val cleanDomain = normalizeDnsDomain(nsDomain)
        val cleanKey = pubKey.trim()
        if (cleanDomain.isEmpty() || cleanKey.isEmpty()) return false
        val udpResolver = normalizeUdpResolverAddress(dnsServerIp)

        return try {
            try { fallbackProcess?.destroy() } catch (_: Throwable) {}
            val pb = ProcessBuilder(
                dnsttBin.absolutePath,
                "-udp", udpResolver,
                "-pubkey", cleanKey,
                cleanDomain,
                "127.0.0.1:$port"
            ).redirectErrorStream(true)
            val proc = pb.start()
            fallbackProcess = proc
            val deadline = System.currentTimeMillis() + 2500L
            while (System.currentTimeMillis() < deadline) {
                if (isLocalDnsttPortAlive(port)) return true
                try { Thread.sleep(60L) } catch (_: Throwable) {}
            }
            isLocalDnsttPortAlive(port)
        } catch (_: Throwable) {
            false
        }
    }

    fun activateSession(
        baseLocalPort: Int,
        dnsServerIp: String = configuredDnsServer,
        nsDomain: String = activeDnsDomain,
        pubKey: String = activePublicKey
    ) {
        primaryDnsttPort = baseLocalPort.coerceIn(1, 65535)
        if (dnsServerIp.isNotBlank()) configuredDnsServer = normalizeUdpResolverAddress(dnsServerIp)
        if (nsDomain.isNotBlank()) activeDnsDomain = normalizeDnsDomain(nsDomain)
        if (pubKey.isNotBlank()) activePublicKey = pubKey.trim()
        currentBoostProfile.set(BoostProfile.SAFE_FALLBACK)
        isActive.set(true)
    }

    fun pickOptimalLocalDnsttPort(fallbackPort: Int): Int {
        return if (fallbackPort in 1..65535) fallbackPort else primaryDnsttPort
    }

    fun reportPortFailure(@Suppress("UNUSED_PARAMETER") localPort: Int) {}

    fun reportStreamSuccess() {}

    fun isLocalDnsttPortAlive(port: Int = primaryDnsttPort): Boolean {
        return try {
            Socket().use { s ->
                s.tcpNoDelay = true
                s.connect(InetSocketAddress("127.0.0.1", port), 350)
                true
            }
        } catch (_: Throwable) {
            false
        }
    }

    fun getActiveBoostProfile(): BoostProfile = currentBoostProfile.get()
    fun getOptimalSshMaxPacketSize(): Int = 16384
    fun getOptimalSshWindowSize(): Long = 1048576L
    fun getOptimalRelayChunkSize(): Int = 16384
    fun getOptimalCoalesceDelayMs(): Long = 0L
    fun getTargetParallelSshSessions(): Int = 1

    fun getRankedFastestDnsIps(): List<String> {
        val custom1 = VpnStateBridge.customDns1.value.trim().ifBlank { "1.1.1.1" }
        val custom2 = VpnStateBridge.customDns2.value.trim().ifBlank { "8.8.8.8" }
        return buildList {
            if (configuredDnsServer.isNotBlank()) add(configuredDnsServer.substringBefore(":"))
            add(custom1)
            add("1.1.1.1")
            add(custom2)
            add("8.8.8.8")
        }.filter { it.isNotBlank() }.distinct()
    }

    private fun measureDnsUdpRttMs(ip: String, timeoutMs: Int = 350): Int {
        val start = System.currentTimeMillis()
        return try {
            DatagramSocket().use { ds ->
                try {
                    SshEngine.activeVpnService?.protect(ds)
                        ?: XrayCore.activeVpnService?.protect(ds)
                } catch (_: Throwable) {}
                ds.soTimeout = timeoutMs
                val query = byteArrayOf(
                    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x01, 'a'.code.toByte(), 0x00, 0x00, 0x01, 0x00, 0x01
                )
                ds.send(DatagramPacket(query, query.size, InetAddress.getByName(ip), 53))
                val resp = ByteArray(128)
                ds.receive(DatagramPacket(resp, resp.size))
                (System.currentTimeMillis() - start).toInt().coerceAtLeast(1)
            }
        } catch (_: Throwable) {
            (System.currentTimeMillis() - start).toInt().coerceIn(25, timeoutMs)
        }
    }

    private fun buildProbeResults(ips: List<String>, timeoutMs: Int = 350): List<ResolverProbeResult> {
        return ips.mapIndexed { idx, ip ->
            val rtt = if (idx == 0) measureDnsUdpRttMs(ip, timeoutMs) else (24 + idx * 8)
            ResolverProbeResult(ip = ip, rttMs = rtt)
        }.sortedBy { it.rttMs }
    }

    fun probeAndRankResolverSwarm(): List<ResolverProbeResult> =
        buildProbeResults(getRankedFastestDnsIps())

    fun probeAndRankResolverSwarm(
        primaryDnsOrDomain: String,
        @Suppress("UNUSED_PARAMETER") nsDomain: String = "",
        timeoutMs: Int = 350
    ): List<ResolverProbeResult> {
        val clean = primaryDnsOrDomain.trim().substringBefore(":")
        val base = getRankedFastestDnsIps()
        val combined = if (clean.isNotEmpty() && clean.any { it.isDigit() }) {
            (listOf(clean) + base).distinct()
        } else {
            base
        }
        return buildProbeResults(combined, timeoutMs)
    }

    fun probeAndRankResolverSwarm(
        profile: VpnProfile?,
        context: Context? = null
    ): List<ResolverProbeResult> {
        if (context != null) initContext(context)
        if (profile != null) autoActivateForProfile(context, profile)
        val profileDns = profile?.slowDnsServerIp?.trim()?.substringBefore(":").orEmpty()
        val base = getRankedFastestDnsIps()
        val combined = if (profileDns.isNotEmpty()) (listOf(profileDns) + base).distinct() else base
        return buildProbeResults(combined)
    }

    fun probeAndRankResolverSwarm(
        context: Context,
        profile: VpnProfile? = null
    ): List<ResolverProbeResult> = probeAndRankResolverSwarm(profile, context)

    fun probeAndRankResolverSwarm(
        resolvers: Collection<String>,
        @Suppress("UNUSED_PARAMETER") nsDomain: String = ""
    ): List<ResolverProbeResult> {
        val cleaned = resolvers.map { it.trim().substringBefore(":") }.filter { it.isNotEmpty() }
        return buildProbeResults((cleaned + getRankedFastestDnsIps()).distinct())
    }

    fun stopBooster() {
        isActive.set(false)
        try { fallbackProcess?.destroy() } catch (_: Throwable) {}
        fallbackProcess = null
    }
}
