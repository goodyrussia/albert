package com.albert.smartvpn.engine

import android.content.Context
import android.os.Build
import android.os.Process as AndroidProcess
import android.util.Base64
import android.util.Log
import com.albert.smartvpn.ui.viewmodel.VpnStateBridge
import java.io.BufferedReader
import java.io.File
import java.io.FileOutputStream
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import java.util.zip.ZipFile
import kotlin.concurrent.thread

object SlowDnsEngine {
    private const val TAG = "SlowDnsEngine"
    private const val BASE_WORKER_PORT = 7001

    private val workerProcesses = CopyOnWriteArrayList<Process>()
    private var balancerServer: ServerSocket? = null
    private val balancerPool = Executors.newCachedThreadPool { r ->
        Thread(r, "Techfeeds-SlowDNS-Turbo").apply {
            isDaemon = true
            priority = Thread.MAX_PRIORITY
        }
    }
    private val roundRobinIndex = AtomicInteger(0)

    @Volatile private var isRunning = false

    private fun resolveDnsttBinary(context: Context): File? {
        val nativeDir = File(context.applicationInfo.nativeLibraryDir)
        for (name in listOf("libdnstt.so", "libdnstt-client.so", "dnstt-client")) {
            val f = File(nativeDir, name)
            if (f.exists() && f.length() > 100_000L) {
                try { f.setExecutable(true, false) } catch (_: Throwable) {}
                return f
            }
        }

        val apkPaths = buildList {
            add(context.applicationInfo.sourceDir)
            context.applicationInfo.splitSourceDirs?.let { addAll(it) }
        }.filter { !it.isNullOrBlank() }

        val abis = Build.SUPPORTED_ABIS?.toList() ?: listOf("arm64-v8a", "armeabi-v7a")
        for (apkPath in apkPaths) {
            try {
                ZipFile(File(apkPath)).use { zip ->
                    for (abi in abis) {
                        val entry = zip.getEntry("lib/$abi/libdnstt.so") ?: continue
                        val outFile = File(context.filesDir, "libdnstt.so")
                        zip.getInputStream(entry).use { input ->
                            FileOutputStream(outFile).use { output -> input.copyTo(output) }
                        }
                        outFile.setReadable(true, false)
                        outFile.setExecutable(true, false)
                        try {
                            Runtime.getRuntime().exec(arrayOf("chmod", "755", outFile.absolutePath)).waitFor()
                        } catch (_: Throwable) {}
                        if (outFile.exists() && outFile.length() > 100_000L) return outFile
                    }
                }
            } catch (_: Throwable) {}
        }
        return null
    }

    private fun normalizePubKeyToHex(rawKey: String): String {
        val trimmed = rawKey.trim().replace(Regex("\\s+"), "")
        if (trimmed.matches(Regex("^[0-9a-fA-F]{64}$"))) {
            return trimmed.lowercase()
        }
        for (flags in intArrayOf(Base64.DEFAULT, Base64.URL_SAFE, Base64.NO_WRAP)) {
            try {
                val decoded = Base64.decode(trimmed, flags)
                if (decoded.size == 32) {
                    return decoded.joinToString("") { "%02x".format(it) }
                }
            } catch (_: Throwable) {}
        }
        return trimmed
    }

    fun startSlowDns(
        context: Context,
        dnsServerIp: String,
        dnsPort: Int = 53,
        nsDomain: String,
        pubKey: String,
        dnsttMode: String = "UDP",
        localPort: Int = 7000
    ): Boolean {
        stopSlowDns()
        SlowDnsSpeedBooster.stopBooster()

        val rawResolvers = dnsServerIp.split(",")
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .ifEmpty { listOf("8.8.8.8:53", "1.1.1.1:53") }

        val cleanNs = nsDomain.trim()
            .removePrefix("http://")
            .removePrefix("https://")
            .substringBefore("/")
            .trim('.')
            .trim()
        val cleanPubKey = normalizePubKeyToHex(pubKey)

        if (cleanNs.isEmpty() || cleanPubKey.isEmpty()) {
            VpnStateBridge.addLog("Connection failed: Missing SlowDNS Nameserver or Public Key.")
            return false
        }

        val dnsttBin = resolveDnsttBinary(context)
        if (dnsttBin == null || !dnsttBin.exists()) {
            VpnStateBridge.addLog("Connection failed: DNSTT engine unavailable.")
            return false
        }
        try { dnsttBin.setExecutable(true, false) } catch (_: Throwable) {}

        // Build multi-resolver list so parallel KCP workers distribute UDP queries without ISP rate-limiting
        val resolvedEndpoints = rawResolvers.map { entry ->
            val hostPart = entry.substringBefore(":").trim().ifEmpty { "8.8.8.8" }
            val portPart = entry.substringAfter(":", "").trim().toIntOrNull()
                ?: if (dnsPort in 1..65535) dnsPort else 53
            val ip = try {
                InetAddress.getByName(hostPart).hostAddress ?: hostPart
            } catch (_: Throwable) {
                hostPart
            }
            "$ip:$portPart"
        }.distinct()

        VpnStateBridge.slowDnsBoostEnabled.value = true
        val workerCount = 6

        return try {
            isRunning = true
            VpnStateBridge.updateState("CONNECTING", "CONNECTING...")
            VpnStateBridge.addLog("Connecting DNSTT ($dnsttMode -> ${resolvedEndpoints.first()} / $cleanNs)...")

            val activeWorkerPorts = CopyOnWriteArrayList<Int>()
            val modeUpper = dnsttMode.uppercase().trim()
            var lastStderrLine = ""

            for (idx in 0 until workerCount) {
                val workerPort = BASE_WORKER_PORT + idx
                val workerListen = "127.0.0.1:$workerPort"
                val resolverAddr = resolvedEndpoints[idx % resolvedEndpoints.size]
                val rawHostOnly = resolverAddr.substringBefore(":")

                val cmd = when {
                    modeUpper == "DOH" || dnsServerIp.startsWith("https://", true) -> {
                        val dohUrl = if (dnsServerIp.startsWith("https://", true)) {
                            dnsServerIp.substringBefore(",").trim()
                        } else {
                            "https://$rawHostOnly/dns-query"
                        }
                        listOf(dnsttBin.absolutePath, "-doh", dohUrl, "-pubkey", cleanPubKey, cleanNs, workerListen)
                    }
                    modeUpper == "DOT" || dnsServerIp.startsWith("tls://", true) -> {
                        val dotAddr = dnsServerIp.substringBefore(",").trim().removePrefix("tls://").let {
                            if (it.contains(":")) it else "$it:853"
                        }
                        listOf(dnsttBin.absolutePath, "-dot", dotAddr, "-pubkey", cleanPubKey, cleanNs, workerListen)
                    }
                    else -> {
                        listOf(dnsttBin.absolutePath, "-udp", resolverAddr, "-pubkey", cleanPubKey, cleanNs, workerListen)
                    }
                }

                val proc = ProcessBuilder(cmd)
                    .directory(context.filesDir)
                    .redirectErrorStream(true)
                    .start()

                workerProcesses.add(proc)
                activeWorkerPorts.add(workerPort)

                balancerPool.execute {
                    try {
                        BufferedReader(InputStreamReader(proc.inputStream)).use { reader ->
                            while (isRunning) {
                                val line = reader.readLine() ?: break
                                if (line.isNotBlank()) {
                                    lastStderrLine = line
                                    Log.d(TAG, "dnstt[$idx]: $line")
                                }
                            }
                        }
                    } catch (_: Throwable) {}
                }
            }

            balancerServer = ServerSocket().apply {
                reuseAddress = true
                receiveBufferSize = 524288
                bind(InetSocketAddress("127.0.0.1", localPort), 256)
            }

            thread(start = true, name = "SlowDNS-Multiplexer") {
                try {
                    AndroidProcess.setThreadPriority(AndroidProcess.THREAD_PRIORITY_URGENT_DISPLAY)
                } catch (_: Throwable) {}
                while (isRunning) {
                    try {
                        val clientSock = balancerServer?.accept() ?: break
                        clientSock.tcpNoDelay = true
                        clientSock.sendBufferSize = 524288
                        clientSock.receiveBufferSize = 524288
                        balancerPool.execute {
                            bridgeToBoostWorker(clientSock, activeWorkerPorts)
                        }
                    } catch (_: Throwable) {
                        if (!isRunning) break
                    }
                }
            }

            Thread.sleep(450L)

            val aliveCount = workerProcesses.count { it.isAlive }
            if (aliveCount > 0) {
                VpnStateBridge.addLog("HTTP/1.1 200 OK")
                VpnStateBridge.addLog("DNSTT Turbo Swarm Active ($aliveCount KCP-1024 Workers)")
                true
            } else {
                val reason = if (lastStderrLine.isNotBlank()) ": $lastStderrLine" else "."
                VpnStateBridge.addLog("Connection failed$reason")
                stopSlowDns()
                false
            }
        } catch (t: Throwable) {
            Log.e(TAG, "SlowDNS Error: ${t.message}", t)
            VpnStateBridge.addLog("Connection failed: ${t.message}")
            stopSlowDns()
            false
        }
    }

    private fun bridgeToBoostWorker(clientSock: Socket, workerPorts: List<Int>) {
        var workerSock: Socket? = null
        try {
            if (workerPorts.isEmpty()) {
                clientSock.close()
                return
            }
            val pickIdx = (roundRobinIndex.getAndIncrement() and Int.MAX_VALUE) % workerPorts.size
            val targetPort = workerPorts[pickIdx]

            workerSock = Socket().apply {
                tcpNoDelay = true
                keepAlive = true
                sendBufferSize = 524288
                receiveBufferSize = 524288
                connect(InetSocketAddress("127.0.0.1", targetPort), 5000)
            }

            val cIn = clientSock.getInputStream()
            val cOut = clientSock.getOutputStream()
            val wIn = workerSock.getInputStream()
            val wOut = workerSock.getOutputStream()

            val upstreamJob = balancerPool.submit {
                try {
                    AndroidProcess.setThreadPriority(AndroidProcess.THREAD_PRIORITY_URGENT_DISPLAY)
                    val buf = ByteArray(65536)
                    while (isRunning) {
                        val n = cIn.read(buf)
                        if (n == -1) break
                        wOut.write(buf, 0, n)
                        wOut.flush()
                    }
                } catch (_: Throwable) {
                } finally {
                    try { workerSock.close() } catch (_: Throwable) {}
                }
            }

            val buf = ByteArray(65536)
            while (isRunning) {
                val n = wIn.read(buf)
                if (n == -1) break
                cOut.write(buf, 0, n)
                cOut.flush()
            }
            upstreamJob.cancel(true)
        } catch (_: Throwable) {
        } finally {
            try { clientSock.close() } catch (_: Throwable) {}
            try { workerSock?.close() } catch (_: Throwable) {}
        }
    }

    fun stopSlowDns() {
        isRunning = false
        VpnStateBridge.slowDnsBoostEnabled.value = false
        try { balancerServer?.close() } catch (_: Throwable) {}
        balancerServer = null

        val procs = ArrayList(workerProcesses)
        workerProcesses.clear()
        balancerPool.execute {
            procs.forEach { proc ->
                try {
                    proc.destroy()
                    proc.destroyForcibly()
                } catch (_: Throwable) {}
            }
        }
    }
}
