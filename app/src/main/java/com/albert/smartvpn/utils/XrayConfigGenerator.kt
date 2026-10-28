package com.albert.smartvpn.utils

import com.albert.smartvpn.data.VpnProfile
import com.google.gson.JsonArray
import com.google.gson.JsonObject

object XrayConfigGenerator {
    fun buildJson(profile: VpnProfile, localSocksPort: Int = 10808): String {
        if (profile.rawJson.isNotEmpty()) return profile.rawJson

        val root = JsonObject()

        // 1. Inbounds: SOCKS5 listener for the hev-socks5-tunnel
        val inbound = JsonObject().apply {
            addProperty("port", localSocksPort)
            addProperty("listen", "127.0.0.1")
            addProperty("protocol", "socks")
            add("settings", JsonObject().apply {
                addProperty("udp", true)
            })
            addProperty("sniffing", false) // Enable for traffic routing rules
        }
        root.add("inbounds", JsonArray().apply { add(inbound) })

        // 2. Outbounds: Target Server
        val outbound = JsonObject().apply {
            addProperty("protocol", profile.protocol)
            add("settings", JsonObject().apply {
                val vnext = JsonObject().apply {
                    addProperty("address", profile.server)
                    addProperty("port", profile.port)
                    add("users", JsonArray().apply {
                        add(JsonObject().apply {
                            if (profile.protocol == "trojan") {
                                addProperty("password", profile.uuid)
                            } else {
                                addProperty("id", profile.uuid)
                                addProperty("encryption", "none")
                                if (profile.flow.isNotEmpty()) addProperty("flow", profile.flow)
                            }
                        })
                    })
                }
                if (profile.protocol == "trojan") {
                    add("servers", JsonArray().apply { add(vnext) })
                } else {
                    add("vnext", JsonArray().apply { add(vnext) })
                }
            })
            add("streamSettings", buildStreamSettings(profile))
        }
        root.add("outbounds", JsonArray().apply { add(outbound) })

        return root.toString()
    }

    private fun buildStreamSettings(profile: VpnProfile): JsonObject {
        val stream = JsonObject().apply {
            addProperty("network", profile.network)
            addProperty("security", profile.security)
            
            if (profile.security == "reality") {
                add("realitySettings", JsonObject().apply {
                    addProperty("serverName", profile.sni)
                    addProperty("publicKey", profile.pbk)
                    addProperty("shortId", profile.sid)
                    addProperty("fingerprint", "chrome")
                })
            } else if (profile.security == "tls") {
                add("tlsSettings", JsonObject().apply {
                    addProperty("serverName", profile.sni)
                })
            }

            if (profile.network == "ws") {
                add("wsSettings", JsonObject().apply {
                    addProperty("path", profile.path)
                    add("headers", JsonObject().apply {
                        addProperty("Host", profile.sni)
                    })
                })
            }
        }
        return stream
    }
}
