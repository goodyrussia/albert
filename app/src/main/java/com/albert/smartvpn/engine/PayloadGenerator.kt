package com.albert.smartvpn.engine

object PayloadGenerator {
    fun generatePayload(
        template: String,
        targetHost: String,
        targetPort: Int,
        sni: String
    ): String {
        val cleanHost = targetHost.trim().ifEmpty { sni.trim() }
        val cleanSni = sni.trim().ifEmpty { cleanHost }

        return template
            .replace("[host_port]", "$cleanHost:$targetPort", ignoreCase = true)
            .replace("[host]", cleanHost, ignoreCase = true)
            .replace("[sni]", cleanSni, ignoreCase = true)
            .replace("[bughost]", cleanSni, ignoreCase = true)
            .replace("[port]", targetPort.toString(), ignoreCase = true)
            .replace("[protocol]", "HTTP/1.1", ignoreCase = true)
            .replace("[ua]", "Mozilla/5.0 (Linux; Android 14; SmartVPN/4.0)", ignoreCase = true)
            .replace("[crlf]", "\r\n", ignoreCase = true)
            .replace("[cr]", "\r", ignoreCase = true)
            .replace("[lf]", "\n", ignoreCase = true)
    }
}
