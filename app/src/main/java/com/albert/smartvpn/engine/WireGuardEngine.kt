package com.albert.smartvpn.engine

import com.albert.smartvpn.data.VpnProfile

object WireGuardEngine {

    fun buildWireGuardConfigJson(profile: VpnProfile, socksPort: Int): String {
        val cleanAddr = profile.wgAddress.trim().ifBlank { "10.0.0.2/32" }
        val pskField = if (profile.wgPresharedKey.isNotBlank()) ", \"preSharedKey\": \"${profile.wgPresharedKey.trim()}\"" else ""
        return """
        {
          "log": {"loglevel": "none"},
          "inbounds": [{
            "tag": "socks-in",
            "port": $socksPort,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": true}
          }],
          "outbounds": [{
            "tag": "proxy",
            "protocol": "wireguard",
            "settings": {
              "secretKey": "${profile.wgPrivateKey.trim()}",
              "address": ["$cleanAddr"],
              "peers": [{
                "publicKey": "${profile.wgPublicKey.trim()}",
                "endpoint": "${profile.server.trim()}:${profile.port}"
                $pskField
              }],
              "mtu": ${profile.wgMtu.coerceIn(1280, 1500)}
            }
          }]
        }
        """.trimIndent()
    }
}
