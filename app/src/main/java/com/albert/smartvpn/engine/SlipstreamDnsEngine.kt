package com.albert.smartvpn.engine

import android.content.Context
import android.net.VpnService
import android.util.Base64
import android.util.Log
import com.albert.smartvpn.data.VpnProfile
import com.albert.smartvpn.ui.viewmodel.VpnStateBridge

object SlipstreamDnsEngine {
    private const val TAG = "SlipstreamDnsEngine"

    @Volatile var activeVpnService: VpnService? = null
    @Volatile private var appContext: Context? = null
    @Volatile private var isRunning = false

    fun initContext(context: Context) {
        appContext = context.applicationContext
    }

    fun isSlipstreamProtocol(proto: String?): Boolean {
        val p = proto?.uppercase()?.trim() ?: return false
        return p.contains("SLIPSTREAM") || p == "SLIPNET"
    }

    /**
     * Distinguishes the DNSTT Tunnel Domain (e.g. `t.slip.smartking.com.ng`)
     * from the Nameserver A-record (e.g. `ns.slip.smartking.com.ng`) even if
     * both fields were swapped or set to the same value.
     */
    fun resolveTunnelAndNsDomains(serverField: String, nsField: String, sniField: String = ""): Pair<String, String> {
        fun cleanDomain(raw: String): String = raw.trim()
            .removePrefix("http://")
            .removePrefix("https://")
            .substringBefore("/")
            .substringBefore(":")
            .trim('.')
            .trim()

        fun isIpAddress(host: String): Boolean {
            val parts = host.split(".")
            return (parts.size == 4 && parts.all { it.toIntOrNull() in 0..255 }) || host == "127.0.0.1"
        }

        val cleanSrv = cleanDomain(serverField)
        val cleanNs = cleanDomain(nsField)
        val cleanSni = cleanDomain(sniField)

        val candidates = listOf(cleanSrv, cleanNs, cleanSni)
            .filter { it.isNotEmpty() && !isIpAddress(it) }
            .distinct()

        if (candidates.isEmpty()) {
            return cleanNs.ifEmpty { cleanSrv } to cleanSrv.ifEmpty { cleanNs }
        }

        val tunnelPrefixCandidate = candidates.firstOrNull { c ->
            val lower = c.lowercase()
            lower.startsWith("t.") || lower.startsWith("tun.") || lower.startsWith("dns.") ||
                lower.startsWith("d.") || lower.startsWith("slip.")
        }
        val nonNsCandidate = candidates.firstOrNull { c ->
            !c.lowercase().startsWith("ns.") && !c.lowercase().startsWith("ns1.") && !c.lowercase().startsWith("ns2.")
        }
        val nsRecordCandidate = candidates.firstOrNull { c ->
            c.lowercase().startsWith("ns.") || c.lowercase().startsWith("ns1.") || c.lowercase().startsWith("ns2.")
        }

        val resolvedTunnelDomain = tunnelPrefixCandidate ?: nonNsCandidate ?: candidates.first()
        val derivedNsHost = nsRecordCandidate ?: run {
            val dotIdx = resolvedTunnelDomain.indexOf('.')
            if (dotIdx > 0) "ns." + resolvedTunnelDomain.substring(dotIdx + 1) else resolvedTunnelDomain
        }

        return resolvedTunnelDomain to derivedNsHost
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

    /**
     * Filters out authoritative `ns.` domain entries from the resolver list so
     * `SlowDnsEngine` uses fast recursive DNS resolvers (`8.8.8.8:53,1.1.1.1:53`)
     * that aren't dropped by ISP transparent DNS proxies.
     */
    private fun buildCleanRecursiveResolvers(rawServerIpField: String, tunnelDomain: String, nsHost: String): String {
        val entries = rawServerIpField.split(",")
            .map { it.trim() }
            .filter { entry ->
                if (entry.isEmpty()) return@filter false
                val hostOnly = entry.substringBefore(":").lowercase()
                hostOnly != tunnelDomain.lowercase() &&
                    hostOnly != nsHost.lowercase() &&
                    !hostOnly.startsWith("ns.") &&
                    !hostOnly.startsWith("t.")
            }

        val combined = buildList {
            addAll(entries)
            add("8.8.8.8:53")
            add("1.1.1.1:53")
            add("8.8.4.4:53")
            add("1.0.0.1:53")
        }.distinct()

        return combined.joinToString(",")
    }

    fun startSlipstreamTunnel(
        context: Context,
        profile: VpnProfile,
        localListenPort: Int = 7000
    ): Boolean {
        stopSlipstreamTunnel()
        initContext(context)

        val (tunnelDomain, nsHost) = resolveTunnelAndNsDomains(
            serverField = profile.server,
            nsField = profile.slowDnsDomain,
            sniField = profile.sni
        )
        val cleanPubKey = normalizePubKeyToHex(profile.slowDnsPubKey.ifBlank { profile.pbk })

        if (tunnelDomain.isEmpty() || cleanPubKey.isEmpty()) {
            VpnStateBridge.addLog("Connection failed: Missing Slipstream Tunnel Domain or Public Key.")
            return false
        }

        val cleanResolvers = buildCleanRecursiveResolvers(
            rawServerIpField = profile.slowDnsServerIp,
            tunnelDomain = tunnelDomain,
            nsHost = nsHost
        )
        val firstResolver = cleanResolvers.substringBefore(",").trim()
        val targetDnsPort = firstResolver.substringAfter(":", "53").toIntOrNull() ?: 53
        val mode = profile.dnsttMode.trim().ifBlank { "UDP" }

        return try {
            isRunning = true
            VpnStateBridge.slowDnsBoostEnabled.value = true
            SlowDnsSpeedBooster.stopBooster()
            VpnStateBridge.addLog("🌊 Slipstream-DNSTT starting (Tunnel: $tunnelDomain • NS: $nsHost)")

            val started = SlowDnsEngine.startSlowDns(
                context = context,
                dnsServerIp = cleanResolvers,
                dnsPort = targetDnsPort,
                nsDomain = tunnelDomain,
                pubKey = cleanPubKey,
                dnsttMode = mode,
                localPort = localListenPort
            )

            if (started) {
                VpnStateBridge.addLog("🌊 Slipstream-DNSTT Turbo Swarm Active on 127.0.0.1:$localListenPort")
                true
            } else {
                isRunning = false
                false
            }
        } catch (t: Throwable) {
            Log.e(TAG, "Slipstream start error: ${t.message}", t)
            VpnStateBridge.addLog("Slipstream error: ${t.message}")
            stopSlipstreamTunnel()
            false
        }
    }

    fun stopSlipstreamTunnel() {
        isRunning = false
        try { SlowDnsEngine.stopSlowDns() } catch (_: Throwable) {}
        try { SlowDnsSpeedBooster.stopBooster() } catch (_: Throwable) {}
    }
}
