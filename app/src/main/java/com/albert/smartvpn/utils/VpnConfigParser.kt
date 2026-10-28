package com.albert.smartvpn.utils

import android.net.Uri
import android.util.Base64
import com.albert.smartvpn.data.VpnProfile
import com.google.gson.GsonBuilder
import com.google.gson.JsonParser
import java.net.URLDecoder
import java.net.URLEncoder

object VpnConfigParser {

    fun detectFlag(host: String, name: String): String {
        val combined = "$host $name".lowercase()
        return when {
            combined.contains(".ng") || combined.contains("nigeria") || combined.contains("lagos") -> "🇳🇬"
            combined.contains("us") || combined.contains("united states") || combined.contains("america") -> "🇺🇸"
            combined.contains("uk") || combined.contains("london") || combined.contains("britain") -> "🇬🇧"
            combined.contains("de") || combined.contains("germany") || combined.contains("frankfurt") -> "🇩🇪"
            combined.contains("nl") || combined.contains("netherlands") || combined.contains("amsterdam") -> "🇳🇱"
            combined.contains("FR") || combined.contains("france") || combined.contains("paris") -> "🇫🇷"
            combined.contains("sg") || combined.contains("singapore") -> "🇸🇬"
            combined.contains("jp") || combined.contains("japan") || combined.contains("tokyo") -> "🇯🇵"
            combined.contains("ca") || combined.contains("canada") -> "🇨🇦"
            combined.contains("za") || combined.contains("south africa") -> "🇿🇦"
            else -> "🌐"
        }
    }

    /**
     * Extracts all valid VPN URIs (`slipnet://`, `dnst://`, `dnstt://`, `vless://`, `vmess://`, `ss://`, `trojan://`, `hy2://`, `ssh://`)
     * even when pasted inside multi-line terminal blocks with `====` borders.
     */
    fun extractAndParseAllUris(rawClipboardText: String): List<VpnProfile> {
        val results = ArrayList<VpnProfile>()
        val trimmed = rawClipboardText.trim()
        if (trimmed.isEmpty()) return results

        // 1. Direct single parse attempt
        parseUri(trimmed)?.let {
            results.add(it)
            return results
        }

        // 2. Scan for embedded URI schemes in multi-line terminal paste blocks
        val schemeRegex = Regex(
            "(?:slipnet|slipstream|dnstt?|slowdns|vless|vmess|trojan|ss|hy2|hysteria2|ssh|wg|wireguard)://[^\\s\"'<>]+",
            RegexOption.IGNORE_CASE
        )
        val matches = schemeRegex.findAll(trimmed).map { it.value }.toList()
        for (rawMatch in matches) {
            // Strip trailing ==== terminal separator banners while keeping valid Base64 content
            val cleaned = cleanTrailingBannerEquals(rawMatch)
            parseUri(cleaned)?.let { profile ->
                results.add(profile)
            }
        }
        return results
    }

    private fun cleanTrailingBannerEquals(uri: String): String {
        val schemePart = uri.substringBefore("://", "")
        val bodyPart = uri.substringAfter("://", "")
        if (schemePart.isEmpty() || bodyPart.isEmpty()) return uri
        // If there are 3 or more trailing '=' from a terminal separator line (======), strip all trailing '=' and re-pad cleanly
        val core = bodyPart.trimEnd('=')
        return "$schemePart://$core"
    }

    private fun decodeBase64Flexible(rawB64: String): String? {
        val clean = rawB64.trim()
            .substringBefore("#")
            .substringBefore("?")
            .replace(Regex("[^A-Za-z0-9+/=_-]"), "")
            .trimEnd('=')
        if (clean.isEmpty()) return null

        val padded = when (clean.length % 4) {
            2 -> "$clean=="
            3 -> "$clean="
            else -> clean
        }

        for (flags in intArrayOf(Base64.DEFAULT, Base64.URL_SAFE, Base64.NO_WRAP, Base64.URL_SAFE or Base64.NO_WRAP)) {
            try {
                val bytes = Base64.decode(padded, flags)
                val str = String(bytes, Charsets.UTF_8).trim()
                if (str.isNotEmpty()) return str
            } catch (_: Throwable) {}
        }
        return null
    }

    fun parseUri(rawUri: String): VpnProfile? {
        val text = rawUri.trim()
        if (text.isEmpty()) return null

        // If user pasted a terminal block containing slipnet:// or dnst:// with headers/banners, extract the first URI
        if (!text.startsWith("{") && text.contains("://") && (text.contains("\n") || text.contains("===="))) {
            val schemeRegex = Regex(
                "(?:slipnet|slipstream|dnstt?|slowdns|vless|vmess|trojan|ss|hy2|hysteria2|ssh)://[^\\s\"'<>]+",
                RegexOption.IGNORE_CASE
            )
            val firstMatch = schemeRegex.find(text)?.value
            if (firstMatch != null) {
                val cleaned = cleanTrailingBannerEquals(firstMatch)
                if (cleaned != text) return parseUri(cleaned)
            }
        }

        val cleanedText = if (text.contains("====")) cleanTrailingBannerEquals(text) else text

        return when {
            cleanedText.startsWith("slipnet://", true) ||
            cleanedText.startsWith("slipstream://", true) ||
            cleanedText.startsWith("dnst://", true) ||
            cleanedText.startsWith("dnstt://", true) ||
            cleanedText.startsWith("slowdns://", true) -> parseSlipstreamOrSlowDnsUri(cleanedText)

            cleanedText.startsWith("vless://", true) -> parseVlessOrTrojan(cleanedText, "VLESS")
            cleanedText.startsWith("trojan://", true) -> parseVlessOrTrojan(cleanedText, "TROJAN")
            cleanedText.startsWith("vmess://", true) -> parseVmess(cleanedText)
            cleanedText.startsWith("ss://", true) -> parseShadowsocks(cleanedText)
            cleanedText.startsWith("hy2://", true) || cleanedText.startsWith("hysteria2://", true) -> parseHysteria2(cleanedText)
            cleanedText.startsWith("ssh://", true) -> parseSshUri(cleanedText)
            cleanedText.contains("[Interface]") && cleanedText.contains("[Peer]") -> parseWireGuardConf(cleanedText)
            cleanedText.contains("client") && cleanedText.contains("remote ") -> parseOpenVpnConf(cleanedText)
            cleanedText.startsWith("{") && cleanedText.endsWith("}") -> parseRawJsonProfile(cleanedText)
            else -> null
        }
    }

    /**
     * Parses `slipnet://BASE64_JSON`, `dnst://BASE64_JSON`, `dnstt://...`, and `slowdns://...` links.
     * Supports the Techfeeds Slipstream JSON schema:
     * `{"app":"Techfeeds Slipstream VPN v1","name":"lance@Techfeeds","domain":"t.slip.smartking.com.ng","ns":"ns.slip.smartking.com.ng","pubkey":"...","user":"lance","pass":"1","ports":[53,443]}`
     */
    private fun parseSlipstreamOrSlowDnsUri(uriString: String): VpnProfile? {
        return try {
            val scheme = uriString.substringBefore("://").lowercase().trim()
            val isSlipstreamScheme = scheme == "slipnet" || scheme == "slipstream"
            val body = uriString.substringAfter("://").trim()

            // Case 1: Base64-encoded JSON payload (slipnet://eyJ... or dnst://eyJ...)
            val decoded = decodeBase64Flexible(body)
            if (decoded != null && decoded.contains("{") && decoded.contains("}")) {
                val jsonSlice = decoded.substring(decoded.indexOf('{'), decoded.lastIndexOf('}') + 1)
                val obj = JsonParser.parseString(jsonSlice).asJsonObject

                val appTitle = obj.get("app")?.asString ?: ""
                val profileName = obj.get("name")?.asString
                    ?: obj.get("ps")?.asString
                    ?: obj.get("remarks")?.asString
                    ?: if (isSlipstreamScheme) "Techfeeds-Slipstream" else "Techfeeds-SlowDNS"

                val tunnelDomain = obj.get("domain")?.asString?.trim()
                    ?: obj.get("tunnelDomain")?.asString?.trim()
                    ?: obj.get("slowDnsDomain")?.asString?.trim()
                    ?: ""
                val nsHost = obj.get("ns")?.asString?.trim()
                    ?: obj.get("nameserver")?.asString?.trim()
                    ?: obj.get("server")?.asString?.trim()
                    ?: tunnelDomain

                val effectiveTunnelDomain = tunnelDomain.ifEmpty { nsHost }
                val effectiveServerHost = nsHost.ifEmpty { effectiveTunnelDomain }

                val pubKey = (
                    obj.get("pubkey")?.asString
                        ?: obj.get("publicKey")?.asString
                        ?: obj.get("pbk")?.asString
                        ?: obj.get("key")?.asString
                        ?: ""
                    ).trim()

                val sshUser = (
                    obj.get("user")?.asString
                        ?: obj.get("username")?.asString
                        ?: obj.get("sshUser")?.asString
                        ?: ""
                    ).trim()

                val sshPass = (
                    obj.get("pass")?.asString
                        ?: obj.get("password")?.asString
                        ?: obj.get("sshPass")?.asString
                        ?: ""
                    ).trim()

                val customResolvers = obj.get("resolver")?.asString
                    ?: obj.get("resolvers")?.asString
                    ?: obj.get("dns")?.asString
                    ?: "8.8.8.8:53,1.1.1.1:53"

                val port = try {
                    val portsArr = obj.getAsJsonArray("ports")
                    if (portsArr != null && portsArr.size() > 0) portsArr[0].asInt else 53
                } catch (_: Throwable) {
                    obj.get("port")?.asInt ?: 53
                }

                // Use SLIPSTREAM-DNSTT for slipnet:// or when app header mentions Slipstream
                val resolvedProtocol = if (isSlipstreamScheme || appTitle.contains("Slipstream", true)) {
                    "SLIPSTREAM-DNSTT"
                } else {
                    "SLOWDNS"
                }

                return VpnProfile(
                    name = profileName,
                    protocol = resolvedProtocol,
                    server = effectiveTunnelDomain,
                    port = port.coerceIn(1, 65535),
                    sshUser = sshUser,
                    sshPass = sshPass,
                    uuid = sshUser,
                    sni = effectiveServerHost,
                    slowDnsDomain = effectiveTunnelDomain,
                    slowDnsPubKey = pubKey,
                    pbk = pubKey,
                    slowDnsServerIp = customResolvers,
                    dnsttMode = if (resolvedProtocol == "SLIPSTREAM-DNSTT") "QUIC-Multipath" else "UDP",
                    countryFlag = detectFlag(effectiveTunnelDomain, profileName),
                    isSelected = true
                )
            }

            // Case 2: URI query format: dnstt://user:pass@nsDomain:53?pubkey=HEX&dns=8.8.8.8:53#Name
            val normalizedUri = "http://" + body
            val parsed = Uri.parse(normalizedUri)
            val userInfo = parsed.userInfo ?: ""
            val user = userInfo.substringBefore(":").trim()
            val pass = userInfo.substringAfter(":", "").trim()
            val host = parsed.host ?: ""
            val port = if (parsed.port > 0) parsed.port else 53
            val pubKey = parsed.getQueryParameter("pubkey")
                ?: parsed.getQueryParameter("pbk")
                ?: parsed.getQueryParameter("key")
                ?: ""
            val dnsServer = parsed.getQueryParameter("dns")
                ?: parsed.getQueryParameter("resolver")
                ?: "8.8.8.8:53,1.1.1.1:53"
            val nsDomain = parsed.getQueryParameter("domain")
                ?: parsed.getQueryParameter("ns")
                ?: host
            val remark = parsed.fragment?.let { URLDecoder.decode(it, "UTF-8") }
                ?: if (isSlipstreamScheme) "Slipstream-DNSTT" else "SlowDNS"
            val proto = if (isSlipstreamScheme) "SLIPSTREAM-DNSTT" else "SLOWDNS"

            if (nsDomain.isEmpty()) null else VpnProfile(
                name = remark,
                protocol = proto,
                server = host.ifEmpty { nsDomain },
                port = port,
                sshUser = user,
                sshPass = pass,
                uuid = user,
                slowDnsDomain = nsDomain,
                slowDnsPubKey = pubKey,
                pbk = pubKey,
                slowDnsServerIp = dnsServer,
                dnsttMode = if (isSlipstreamScheme) "QUIC-Multipath" else "UDP",
                countryFlag = detectFlag(nsDomain, remark),
                isSelected = true
            )
        } catch (_: Throwable) {
            null
        }
    }

    private fun parseVlessOrTrojan(uriString: String, protocol: String): VpnProfile? {
        return try {
            val uri = Uri.parse(uriString)
            val uuidOrPass = uri.userInfo ?: ""
            val host = uri.host ?: return null
            val port = if (uri.port > 0) uri.port else 443
            val name = uri.fragment?.let { URLDecoder.decode(it, "UTF-8") } ?: "$protocol-$host"
            val network = uri.getQueryParameter("type") ?: "tcp"
            val security = uri.getQueryParameter("security") ?: if (protocol == "TROJAN") "tls" else "none"
            val sni = uri.getQueryParameter("sni") ?: uri.getQueryParameter("peer") ?: host
            val wsHost = uri.getQueryParameter("host") ?: sni
            val path = uri.getQueryParameter("path") ?: uri.getQueryParameter("serviceName") ?: "/"
            val pbk = uri.getQueryParameter("pbk") ?: ""
            val sid = uri.getQueryParameter("sid") ?: ""
            val fp = uri.getQueryParameter("fp") ?: "chrome"
            val flow = uri.getQueryParameter("flow") ?: ""
            val allowInsecure = uri.getQueryParameter("allowInsecure") == "1" || uri.getQueryParameter("insecure") == "1"

            VpnProfile(
                name = name,
                protocol = protocol,
                server = host,
                port = port,
                uuid = uuidOrPass,
                sshPass = uuidOrPass,
                network = network,
                security = security,
                sni = sni,
                wsHost = wsHost,
                path = path,
                pbk = pbk,
                sid = sid,
                utlsFingerprint = fp,
                flow = flow,
                allowInsecure = allowInsecure,
                countryFlag = detectFlag(host, name),
                isSelected = true
            )
        } catch (_: Throwable) {
            null
        }
    }

    private fun parseVmess(uriString: String): VpnProfile? {
        return try {
            val b64 = uriString.removePrefix("vmess://").removePrefix("VMESS://").trim()
            val jsonStr = decodeBase64Flexible(b64) ?: return null
            val obj = JsonParser.parseString(jsonStr).asJsonObject
            val host = obj.get("add")?.asString ?: return null
            val port = obj.get("port")?.asString?.toIntOrNull() ?: 443
            val uuid = obj.get("id")?.asString ?: ""
            val name = obj.get("ps")?.asString ?: "VMess-$host"
            val net = obj.get("net")?.asString ?: "tcp"
            val tls = obj.get("tls")?.asString ?: ""
            val sni = obj.get("sni")?.asString?.ifBlank { null } ?: obj.get("host")?.asString?.ifBlank { null } ?: host
            val wsHost = obj.get("host")?.asString?.ifBlank { null } ?: sni
            val path = obj.get("path")?.asString ?: "/"

            VpnProfile(
                name = name,
                protocol = "VMESS",
                server = host,
                port = port,
                uuid = uuid,
                network = net,
                security = if (tls.equals("tls", true)) "tls" else "none",
                sni = sni,
                wsHost = wsHost,
                path = path,
                countryFlag = detectFlag(host, name),
                isSelected = true
            )
        } catch (_: Throwable) {
            null
        }
    }

    private fun parseShadowsocks(uriString: String): VpnProfile? {
        return try {
            val withoutScheme = uriString.removePrefix("ss://").removePrefix("SS://").trim()
            val remark = if (withoutScheme.contains("#")) {
                URLDecoder.decode(withoutScheme.substringAfterLast("#"), "UTF-8")
            } else ""
            val mainPart = withoutScheme.substringBefore("#").substringBefore("?")

            val method: String
            val password: String
            val host: String
            val port: Int

            if (mainPart.contains("@")) {
                val userPart = mainPart.substringBeforeLast("@")
                val hostPort = mainPart.substringAfterLast("@")
                host = hostPort.substringBeforeLast(":")
                port = hostPort.substringAfterLast(":", "8388").toIntOrNull() ?: 8388
                val decodedUser = if (userPart.contains(":")) userPart else (decodeBase64Flexible(userPart) ?: userPart)
                method = decodedUser.substringBefore(":").lowercase().trim()
                password = decodedUser.substringAfter(":")
            } else {
                val decodedAll = decodeBase64Flexible(mainPart) ?: return null
                val userPart = decodedAll.substringBeforeLast("@")
                val hostPort = decodedAll.substringAfterLast("@")
                method = userPart.substringBefore(":").lowercase().trim()
                password = userPart.substringAfter(":")
                host = hostPort.substringBeforeLast(":")
                port = hostPort.substringAfterLast(":", "8388").toIntOrNull() ?: 8388
            }

            val finalName = remark.ifBlank { "SS-$host" }
            VpnProfile(
                name = finalName,
                protocol = "SHADOWSOCKS",
                server = host,
                port = port,
                uuid = password,
                sshPass = password,
                ssMethod = method.ifBlank { "chacha20-ietf-poly1305" },
                security = method.ifBlank { "chacha20-ietf-poly1305" },
                countryFlag = detectFlag(host, finalName),
                isSelected = true
            )
        } catch (_: Throwable) {
            null
        }
    }

    private fun parseHysteria2(uriString: String): VpnProfile? {
        return try {
            val normalized = uriString.replaceFirst(Regex("^hysteria2://", RegexOption.IGNORE_CASE), "hy2://")
            val uri = Uri.parse(normalized)
            val auth = uri.userInfo ?: ""
            val host = uri.host ?: return null
            val port = if (uri.port > 0) uri.port else 443
            val sni = uri.getQueryParameter("sni") ?: host
            val obfs = uri.getQueryParameter("obfs") ?: ""
            val obfsPass = uri.getQueryParameter("obfs-password") ?: ""
            val insecure = uri.getQueryParameter("insecure") == "1"
            val name = uri.fragment?.let { URLDecoder.decode(it, "UTF-8") } ?: "Hysteria2-$host"

            VpnProfile(
                name = name,
                protocol = "HYSTERIA2",
                server = host,
                port = port,
                uuid = auth,
                sshPass = auth,
                hy2Password = auth,
                hy2Obfs = obfs,
                hy2ObfsPassword = obfsPass,
                sni = sni,
                allowInsecure = insecure,
                countryFlag = detectFlag(host, name),
                isSelected = true
            )
        } catch (_: Throwable) {
            null
        }
    }

    private fun parseSshUri(uriString: String): VpnProfile? {
        return try {
            val uri = Uri.parse(uriString)
            val userInfo = uri.userInfo ?: ""
            val user = userInfo.substringBefore(":")
            val pass = userInfo.substringAfter(":", "")
            val host = uri.host ?: return null
            val port = if (uri.port > 0) uri.port else 22
            val name = uri.fragment?.let { URLDecoder.decode(it, "UTF-8") } ?: "SSH-$host"
            val sni = uri.getQueryParameter("sni") ?: ""
            val payload = uri.getQueryParameter("payload")?.let { URLDecoder.decode(it, "UTF-8") } ?: ""

            VpnProfile(
                name = name,
                protocol = if (payload.isNotBlank()) "SSH-PAYLOAD" else if (sni.isNotBlank()) "SSH-TLS" else "SSH",
                server = host,
                port = port,
                sshUser = user,
                sshPass = pass,
                uuid = user,
                sni = sni,
                payload = payload,
                countryFlag = detectFlag(host, name),
                isSelected = true
            )
        } catch (_: Throwable) {
            null
        }
    }

    private fun parseWireGuardConf(confText: String): VpnProfile? {
        return try {
            var privKey = ""
            var pubKey = ""
            var address = "10.0.0.2/32"
            var endpointHost = ""
            var endpointPort = 51820
            var mtu = 1420

            confText.lineSequence().forEach { rawLine ->
                val line = rawLine.substringBefore("#").trim()
                val key = line.substringBefore("=").trim().lowercase()
                val value = line.substringAfter("=", "").trim()
                when (key) {
                    "privatekey" -> privKey = value
                    "publickey" -> pubKey = value
                    "address" -> address = value.substringBefore(",").trim()
                    "mtu" -> mtu = value.toIntOrNull() ?: 1420
                    "endpoint" -> {
                        endpointHost = value.substringBeforeLast(":").trim()
                        endpointPort = value.substringAfterLast(":", "51820").toIntOrNull() ?: 51820
                    }
                }
            }
            if (endpointHost.isEmpty()) null else VpnProfile(
                name = "WireGuard-$endpointHost",
                protocol = "WIREGUARD",
                server = endpointHost,
                port = endpointPort,
                uuid = privKey,
                wgPrivateKey = privKey,
                wgPublicKey = pubKey,
                wgAddress = address,
                wgMtu = mtu,
                countryFlag = detectFlag(endpointHost, "WireGuard"),
                isSelected = true
            )
        } catch (_: Throwable) {
            null
        }
    }

    private fun parseOpenVpnConf(ovpnText: String): VpnProfile? {
        return try {
            val remoteLine = ovpnText.lineSequence()
                .map { it.trim() }
                .firstOrNull { it.startsWith("remote ") } ?: return null
            val parts = remoteLine.split(Regex("\\s+"))
            val host = parts.getOrNull(1) ?: return null
            val port = parts.getOrNull(2)?.toIntOrNull() ?: 1194
            VpnProfile(
                name = "OpenVPN-$host",
                protocol = "OPENVPN",
                server = host,
                port = port,
                countryFlag = detectFlag(host, "OpenVPN"),
                isSelected = true
            )
        } catch (_: Throwable) {
            null
        }
    }

    private fun parseRawJsonProfile(jsonText: String): VpnProfile? {
        return try {
            val root = JsonParser.parseString(jsonText).asJsonObject
            // Check if it's a Slipstream / DNSTT JSON object pasted directly
            if (root.has("pubkey") && (root.has("domain") || root.has("ns"))) {
                val b64 = Base64.encodeToString(jsonText.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
                return parseSlipstreamOrSlowDnsUri("slipnet://$b64")
            }
            val outbounds = root.getAsJsonArray("outbounds")
            val firstOut = outbounds?.firstOrNull()?.asJsonObject ?: return null
            val proto = firstOut.get("protocol")?.asString?.uppercase() ?: "VLESS"
            VpnProfile(
                name = "Xray-JSON-$proto",
                protocol = proto,
                server = "json-config",
                port = 443,
                rawJson = jsonText,
                isSelected = true
            )
        } catch (_: Throwable) {
            null
        }
    }

    fun toStandardUri(profile: VpnProfile): String {
        val proto = profile.protocol.uppercase().trim()
        if (proto.contains("SLIPSTREAM") || proto.contains("DNSTT") || proto == "SLOWDNS") {
            val tunnelDom = profile.slowDnsDomain.ifBlank { profile.server }.trim()
            val nsDom = profile.sni.ifBlank { profile.server }.trim()
            val pubKey = profile.slowDnsPubKey.ifBlank { profile.pbk }.trim()
            val user = profile.sshUser.ifBlank { profile.uuid }.trim()
            val pass = profile.sshPass.trim()
            val json = """{"app":"Techfeeds Slipstream VPN v1","name":"${profile.name.ifBlank { "Techfeeds" }}","domain":"$tunnelDom","ns":"$nsDom","pubkey":"$pubKey","user":"$user","pass":"$pass","quota":"Unlimited Data","ports":[${profile.port},443]}"""
            val b64 = Base64.encodeToString(json.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
            val prefix = if (proto.contains("SLIPSTREAM")) "slipnet://" else "dnst://"
            return "$prefix$b64"
        }

        val remark = try { URLEncoder.encode(profile.name.ifBlank { "Techfeeds" }, "UTF-8") } catch (_: Throwable) { "Techfeeds" }
        val host = profile.server.trim()
        val port = profile.port.coerceIn(1, 65535)
        return when (proto) {
            "SHADOWSOCKS", "SS" -> {
                val method = profile.ssMethod.ifBlank { "chacha20-ietf-poly1305" }
                val pass = profile.sshPass.ifBlank { profile.uuid }
                val b64 = Base64.encodeToString("$method:$pass".toByteArray(), Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
                "ss://$b64@$host:$port#$remark"
            }
            else -> "vless://${profile.uuid}@$host:$port?security=${profile.security}&type=${profile.network}&sni=${profile.sni}#$remark"
        }
    }

    fun toStandardJson(profile: VpnProfile): String {
        if (profile.rawJson.isNotBlank()) return profile.rawJson
        val gson = GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create()
        return gson.toJson(profile)
    }
}
