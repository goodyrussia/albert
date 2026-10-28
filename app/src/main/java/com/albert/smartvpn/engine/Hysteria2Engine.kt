package com.albert.smartvpn.engine

import android.content.Context
import android.os.Build
import android.util.Log
import com.albert.smartvpn.data.VpnProfile
import com.albert.smartvpn.ui.viewmodel.VpnStateBridge
import java.io.File
import java.io.FileOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.zip.ZipFile
import kotlin.concurrent.thread

object Hysteria2Engine {
    private const val TAG = "Hysteria2Engine"
    private var hy2Process: Process? = null
    private var activeConfigFile: File? = null

    private fun resolveHysteria2Binary(context: Context): File? {
        val nativeDir = File(context.applicationInfo.nativeLibraryDir)
        for (name in listOf("libhysteria2.so", "libhysteria.so", "hysteria2")) {
            val f = File(nativeDir, name)
            if (f.exists() && f.length() > 0L) {
                try { f.setExecutable(true, false) } catch (_: Throwable) {}
                return f
            }
        }

        for (dir in listOf(context.codeCacheDir, context.filesDir)) {
            val extracted = File(dir, "libhysteria2.so")
            if (extracted.exists() && extracted.length() > 1024L) {
                try { extracted.setExecutable(true, false) } catch (_: Throwable) {}
                return extracted
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
                        val entry = zip.getEntry("lib/$abi/libhysteria2.so") ?: continue
                        val outFile = File(context.codeCacheDir ?: context.filesDir, "libhysteria2.so")
                        zip.getInputStream(entry).use { input ->
                            FileOutputStream(outFile).use { output -> input.copyTo(output) }
                        }
                        outFile.setReadable(true, false)
                        outFile.setExecutable(true, false)
                        try {
                            Runtime.getRuntime().exec(arrayOf("chmod", "755", outFile.absolutePath)).waitFor()
                        } catch (_: Throwable) {}
                        if (outFile.exists() && outFile.length() > 1024L) return outFile
                    }
                }
            } catch (_: Throwable) {}
        }
        return null
    }

    fun startHysteria2(
        context: Context,
        profile: VpnProfile,
        localSocksPort: Int
    ): Boolean {
        stopHysteria2()

        val rawHost = profile.server.trim()
        val authPass = profile.hy2Password.ifBlank { profile.uuid.ifBlank { profile.sshPass } }.trim()
        if (rawHost.isEmpty() || authPass.isEmpty()) {
            VpnStateBridge.addLog("Connection failed: Missing Hysteria2 server or password.")
            return false
        }

        val hy2Bin = resolveHysteria2Binary(context)
        if (hy2Bin == null || !hy2Bin.exists()) {
            VpnStateBridge.addLog("Connection failed: Hysteria2 binary missing.")
            return false
        }
        try { hy2Bin.setExecutable(true, false) } catch (_: Throwable) {}

        val resolvedIp = try {
            InetAddress.getByName(rawHost).hostAddress ?: rawHost
        } catch (_: Throwable) {
            rawHost
        }
        val sniHost = profile.sni.trim().ifBlank { rawHost }
        val hoppingSuffix = profile.hy2PortHopping.trim().takeIf { it.isNotEmpty() }?.let { ",$it" } ?: ""
        val serverEndpoint = "$resolvedIp:${profile.port}$hoppingSuffix"

        return try {
            val salamanderPass = profile.hy2ObfsPassword.ifBlank { profile.hy2Obfs }.trim()
            val obfsBlock = if (salamanderPass.isNotEmpty()) {
                """
                "obfs": {
                  "type": "salamander",
                  "salamander": {
                    "password": "$salamanderPass"
                  }
                },
                """.trimIndent()
            } else {
                ""
            }

            val pinBlock = if (profile.pinSha256.isNotBlank()) {
                """, "pinSHA256": "${profile.pinSha256.trim()}""""
            } else {
                ""
            }

            val allowInsecureTls = profile.allowInsecure ||
                VpnStateBridge.allowInsecureTls.value ||
                profile.pinSha256.isNotBlank()

            val upMbps = profile.hy2UpMbps.coerceIn(10, 200)
            val downMbps = profile.hy2DownMbps.coerceIn(20, 400)

            val configJson = """
                {
                  "server": "$serverEndpoint",
                  "auth": "$authPass",
                  $obfsBlock
                  "tls": {
                    "sni": "$sniHost",
                    "insecure": $allowInsecureTls$pinBlock
                  },
                  "bandwidth": {
                    "up": "$upMbps mbps",
                    "down": "$downMbps mbps"
                  },
                  "quic": {
                    "initStreamReceiveWindow": 8388608,
                    "maxStreamReceiveWindow": 8388608,
                    "initConnReceiveWindow": 20971520,
                    "maxConnReceiveWindow": 20971520
                  },
                  "socks5": {
                    "listen": "127.0.0.1:$localSocksPort"
                  }
                }
            """.trimIndent()

            val cfgFile = File(context.cacheDir, "hy2_smartv3.json")
            cfgFile.writeText(configJson)
            activeConfigFile = cfgFile

            val cmd = listOf(hy2Bin.absolutePath, "client", "-c", cfgFile.absolutePath)
            val proc = ProcessBuilder(cmd)
                .redirectErrorStream(true)
                .start()
            hy2Process = proc

            // Drain process output so libhysteria2.so never blocks on a full stdout/stderr pipe
            thread(start = true, isDaemon = true, name = "Hysteria2-LogDrain") {
                try {
                    val ins = proc.inputStream
                    val buf = ByteArray(512)
                    while (proc.isAlive && ins.read(buf) != -1) {}
                } catch (_: Throwable) {}
            }

            var socksReady = false
            for (attempt in 1..20) {
                Thread.sleep(250)
                if (!proc.isAlive) break
                try {
                    Socket().use { s ->
                        s.connect(InetSocketAddress("127.0.0.1", localSocksPort), 200)
                        socksReady = true
                    }
                    if (socksReady) break
                } catch (_: Throwable) {}
            }

            if (proc.isAlive && socksReady) {
                VpnStateBridge.addLog("HTTP/1.1 200 OK")
                VpnStateBridge.addLog("Hysteria2 QUIC Tunnel Connected")
                true
            } else {
                VpnStateBridge.addLog("Connection failed.")
                stopHysteria2()
                false
            }
        } catch (t: Throwable) {
            Log.e(TAG, "Hysteria2 Error: ${t.message}", t)
            VpnStateBridge.addLog("Connection failed.")
            stopHysteria2()
            false
        }
    }

    fun stopHysteria2() {
        try {
            hy2Process?.destroy()
            hy2Process?.destroyForcibly()
        } catch (_: Throwable) {}
        hy2Process = null
        try { activeConfigFile?.delete() } catch (_: Throwable) {}
        activeConfigFile = null
    }
}
