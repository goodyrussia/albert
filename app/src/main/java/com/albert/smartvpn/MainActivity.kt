package com.albert.smartvpn

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.util.Base64
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.core.content.ContextCompat
import com.albert.smartvpn.data.VpnProfile
import com.albert.smartvpn.engine.SlowDnsSpeedBooster
import com.albert.smartvpn.ui.screens.ConfigsScreen
import com.albert.smartvpn.ui.screens.HomeScreen
import com.albert.smartvpn.ui.screens.LogsScreen
import com.albert.smartvpn.ui.screens.NetworkToolsScreen
import com.albert.smartvpn.ui.screens.SettingsScreen
import com.albert.smartvpn.ui.theme.SmartVpnTheme
import com.albert.smartvpn.ui.viewmodel.AppShareHelper
import com.albert.smartvpn.ui.viewmodel.ConfigCryptoHelper
import com.albert.smartvpn.ui.viewmodel.SecretCodeManager
import com.albert.smartvpn.ui.viewmodel.VpnStateBridge
import com.albert.smartvpn.ui.viewmodel.VpnViewModel
import com.albert.smartvpn.vpn.SmartVpnService
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonParser
import com.google.gson.reflect.TypeToken
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import kotlin.math.cos
import kotlin.math.sin
import kotlin.system.exitProcess

private val RoyalGold = Color(0xFFFFD54F)
private val DeepGold = Color(0xFFFFB300)
private val AmethystLight = Color(0xFFB388FF)
private val AmethystNeon = Color(0xFFE040FB)
private val CyberEmerald = Color(0xFF00E676)
private val RoyalBgTop = Color(0xFF0F051D)
private val RoyalBgMid = Color(0xFF1F0B3B)
private val RoyalBgBottom = Color(0xFF07020F)
private val RoyalCardSurface = Color(0xFF180930)

private const val CURRENT_BUILD_CODE = 123
private const val CURRENT_VERSION_NAME = "1.2.3"

private val OTA_MANIFEST_URLS = listOf(
    "https://github.com/albertlanc/albert/releases/latest/download/update.json",
    "https://raw.githubusercontent.com/albertlanc/albert/main/update.json"
)

data class OtaUpdateInfo(
    val versionCode: Int,
    val versionName: String,
    val apkUrl: String,
    val releaseNotes: String
)

class MainActivity : ComponentActivity() {
    private val viewModel: VpnViewModel by viewModels()

    private val notificationPermissionRequest = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { _ -> }

    private val filePickerLauncher = registerForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        if (uri != null) {
            try {
                val content = contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() } ?: ""
                if (content.isNotBlank()) {
                    handleUniversalImport(content)
                }
            } catch (t: Throwable) {
                viewModel.showToastPill("Failed to read file: ${t.message}")
            }
        }
    }

    private var pendingFileExportContent: String = ""
    private var pendingFileExportToast: String = "Saved to file!"
    private val createDocumentFileLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("*/*")
    ) { uri: Uri? ->
        if (uri != null && pendingFileExportContent.isNotBlank()) {
            try {
                contentResolver.openOutputStream(uri)?.use { out ->
                    out.write(pendingFileExportContent.toByteArray(Charsets.UTF_8))
                }
                viewModel.showToastPill(pendingFileExportToast)
            } catch (t: Throwable) {
                viewModel.showToastPill("Failed to save file: ${t.message}")
            }
        }
    }

    private val vpnRequest = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpnService()
        } else {
            VpnStateBridge.updateState("DISCONNECTED", "NOT CONNECTED")
            VpnStateBridge.addLog("Disconnected.")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        SecretCodeManager.enforceV12ExclusiveState(applicationContext)
        VpnStateBridge.initPrefs(applicationContext)
        SlowDnsSpeedBooster.initContext(applicationContext)
        requestNotificationPermissionIfNeeded()

        setContent {
            SmartVpnTheme {
                var showLaunchWelcomeSplash by rememberSaveable { mutableStateOf(true) }
                val isCodeVerified by VpnStateBridge.secretCodeVerified.collectAsState()
                val expiresAtMs by VpnStateBridge.secretCodeExpiresAtMs.collectAsState()
                var remainingTimeText by remember { mutableStateOf("") }

                LaunchedEffect(isCodeVerified, expiresAtMs) {
                    while (isCodeVerified && expiresAtMs > 0L) {
                        val rem = expiresAtMs - System.currentTimeMillis()
                        if (rem <= 0L) {
                            SecretCodeManager.clearExpiredAccess(applicationContext)
                            if (VpnStateBridge.connectionState.value != "DISCONNECTED") {
                                toggleVpn(true)
                            }
                            VpnStateBridge.addLog("V1.2 Secret Code expired. Session locked.")
                            viewModel.showToastPill("Access Code Expired. Please enter a new V1.2 Secret Code.")
                            break
                        } else {
                            remainingTimeText = SecretCodeManager.formatRemainingTime(rem)
                        }
                        delay(1000L)
                    }
                }

                when {
                    showLaunchWelcomeSplash -> {
                        TechfeedsV12AdvancedSplashScreen(
                            onContinue = {
                                SecretCodeManager.checkSavedAccessSession(applicationContext)
                                showLaunchWelcomeSplash = false
                            }
                        )
                    }
                    !isCodeVerified -> {
                        TechfeedsSecretCodeGateScreen(
                            onCodeUnlocked = {
                                viewModel.showToastPill("Welcome to Techfeeds-VPN V$CURRENT_VERSION_NAME!")
                            }
                        )
                    }
                    else -> {
                        MainDashboardContent(remainingTimeText = remainingTimeText)
                    }
                }
            }
        }
    }

    private fun handleUniversalImport(rawInput: String, passphrase: String = "") {
        val text = rawInput.trim()
        if (text.isEmpty()) {
            viewModel.showToastPill("Clipboard or file is empty")
            return
        }

        if (text.startsWith("tfvpnbundle://", ignoreCase = true)) {
            val importedCount = importTickedMultiBundle(text, passphrase)
            if (importedCount > 0) {
                VpnStateBridge.addLog("Imported $importedCount configuration(s) from bundle.")
                viewModel.showToastPill("Imported $importedCount configuration(s)!")
                return
            }
        }

        val slipDnsttRegex = Regex("(?i)(slipnet|slipstream|dnst|dnstt|slowdns)://([A-Za-z0-9+/=_-]+)")
        val matches = slipDnsttRegex.findAll(text).toList()
        if (matches.isNotEmpty()) {
            val parsedProfiles = ArrayList<VpnProfile>()
            for (match in matches) {
                val scheme = match.groupValues[1].lowercase()
                val rawB64 = match.groupValues[2].trim().trimEnd('=')
                parseSlipnetOrDnsttBase64Json(scheme, rawB64)?.let { parsedProfiles.add(it) }
            }

            if (parsedProfiles.isNotEmpty()) {
                val uniqueList = if (parsedProfiles.size > 1 &&
                    parsedProfiles.map { "${it.server}:${it.sshUser}:${it.slowDnsPubKey}" }.distinct().size == 1
                ) {
                    parsedProfiles.distinctBy { it.protocol }.map { p ->
                        val suffix = if (p.protocol == "SLIPSTREAM-DNSTT") " [Slipstream]" else " [DNSTT]"
                        if (p.name.contains("Slipstream", true) || p.name.contains("DNSTT", true)) p
                        else p.copy(name = "${p.name}$suffix")
                    }
                } else {
                    parsedProfiles
                }

                uniqueList.forEach { profile ->
                    viewModel.saveManualProfile(profile)
                    VpnStateBridge.addLog("Saved configuration: ${profile.name} (${profile.protocol})")
                }
                viewModel.showToastPill("Imported ${uniqueList.size} Slipstream/DNSTT config(s)!")
                return
            }
        }

        viewModel.importFromClipboard(text, passphrase)
    }

    private fun parseSlipnetOrDnsttBase64Json(scheme: String, cleanB64WithoutEquals: String): VpnProfile? {
        if (cleanB64WithoutEquals.length < 8) return null
        val padded = cleanB64WithoutEquals + "=".repeat((4 - cleanB64WithoutEquals.length % 4) % 4)
        for (flags in intArrayOf(Base64.DEFAULT, Base64.URL_SAFE, Base64.NO_WRAP)) {
            try {
                val decodedBytes = Base64.decode(padded, flags)
                val decodedStr = String(decodedBytes, Charsets.UTF_8)
                val firstBrace = decodedStr.indexOf('{')
                val lastBrace = decodedStr.lastIndexOf('}')
                if (firstBrace >= 0 && lastBrace > firstBrace) {
                    val jsonSlice = decodedStr.substring(firstBrace, lastBrace + 1)
                    val obj = JsonParser.parseString(jsonSlice).asJsonObject

                    val rawName = obj.get("name")?.asString?.trim()?.takeIf { it.isNotEmpty() }
                        ?: "Techfeeds-Slipstream"
                    val domain = (obj.get("domain") ?: obj.get("tunnelDomain") ?: obj.get("host"))
                        ?.asString?.trim() ?: ""
                    val ns = (obj.get("ns") ?: obj.get("nameserver") ?: obj.get("nsDomain"))
                        ?.asString?.trim() ?: ""
                    val pubkey = (obj.get("pubkey") ?: obj.get("publicKey") ?: obj.get("pbk") ?: obj.get("key"))
                        ?.asString?.trim() ?: ""
                    val user = (obj.get("user") ?: obj.get("username") ?: obj.get("sshUser"))
                        ?.asString?.trim() ?: ""
                    val pass = (obj.get("pass") ?: obj.get("password") ?: obj.get("sshPass"))
                        ?.asString?.trim() ?: ""

                    val portsArr = obj.getAsJsonArray("ports")
                    val parsedPorts = portsArr?.mapNotNull { it.asInt }?.filter { it in 1..65535 }
                        ?.ifEmpty { listOf(53, 443) }
                        ?: listOf(obj.get("port")?.asInt ?: 53, 443).distinct()
                    val firstPort = parsedPorts.firstOrNull() ?: 53

                    val tunnelDomain = domain.ifBlank { ns }
                    val nsRecordHost = ns.ifBlank {
                        val dot = tunnelDomain.indexOf('.')
                        if (dot > 0) "ns." + tunnelDomain.substring(dot + 1) else tunnelDomain
                    }
                    if (tunnelDomain.isEmpty() || pubkey.isEmpty()) return null

                    // Build resolver list including direct NS host ports (53, 443) + public resolvers
                    val explicitResolver = (obj.get("resolver") ?: obj.get("resolvers") ?: obj.get("dns"))
                        ?.asString?.trim().orEmpty()
                    val nsEndpoints = parsedPorts.map { p -> "$nsRecordHost:$p" }
                    val resolver = buildList {
                        if (explicitResolver.isNotEmpty()) add(explicitResolver)
                        addAll(nsEndpoints)
                        add("8.8.8.8:53")
                        add("1.1.1.1:53")
                    }.distinct().joinToString(",")

                    val resolvedProtocol = if (scheme.startsWith("slip")) "SLIPSTREAM-DNSTT" else "SLOWDNS"

                    return VpnProfile(
                        name = rawName,
                        protocol = resolvedProtocol,
                        server = nsRecordHost,
                        port = firstPort.coerceIn(1, 65535),
                        sshUser = user,
                        sshPass = pass,
                        uuid = user,
                        slowDnsDomain = tunnelDomain,
                        slowDnsPubKey = pubkey,
                        pbk = pubkey,
                        slowDnsServerIp = resolver,
                        sni = nsRecordHost,
                        dnsttMode = "UDP",
                        isSelected = true
                    )
                }
            } catch (_: Throwable) {}
        }
        return null
    }

    private fun exportTickedMultiBundle(
        selectedList: List<VpnProfile>,
        lockConfig: Boolean,
        passphrase: String,
        expiryDays: Int,
        lockedHwid: String,
        blockRoot: Boolean,
        customMsg: String
    ): String {
        val now = System.currentTimeMillis()
        val expMs = if (lockConfig && expiryDays > 0) now + (expiryDays.toLong() * 86_400_000L) else 0L
        val preparedProfiles = selectedList.map { p ->
            p.copy(
                id = 0,
                isImported = lockConfig,
                isLocked = lockConfig,
                lockedDeviceId = if (lockConfig) lockedHwid.trim() else "",
                blockRootedDevices = if (lockConfig) blockRoot else false,
                customServerMessage = customMsg.trim().ifBlank { p.customServerMessage },
                isSelected = true
            )
        }

        if (passphrase.isBlank()) {
            try {
                val standardBundle = ConfigCryptoHelper.exportLoadBalanceBundle(preparedProfiles)
                if (standardBundle.isNotBlank()) return standardBundle
            } catch (_: Throwable) {}
        }

        val wrapper = mapOf(
            "v" to 123,
            "pwd" to passphrase.trim(),
            "exp" to expMs,
            "hwid" to lockedHwid.trim(),
            "profiles" to preparedProfiles
        )
        val json = Gson().toJson(wrapper)
        val b64 = Base64.encodeToString(json.toByteArray(Charsets.UTF_8), Base64.URL_SAFE or Base64.NO_WRAP)
        return "tfvpnbundle://$b64"
    }

    private fun importTickedMultiBundle(uri: String, passphrase: String): Int {
        return try {
            val rawB64 = uri.substringAfter("://").trim()
            val json = String(Base64.decode(rawB64, Base64.URL_SAFE or Base64.NO_WRAP), Charsets.UTF_8)
            val root = JsonParser.parseString(json).asJsonObject
            val expectedPwd = root.get("pwd")?.asString?.trim() ?: ""
            if (expectedPwd.isNotEmpty() && expectedPwd != passphrase.trim()) {
                VpnStateBridge.addLog("Import failed: Incorrect bundle password.")
                viewModel.showToastPill("Incorrect bundle password!")
                return 0
            }
            val expMs = root.get("exp")?.asLong ?: 0L
            if (expMs > 0L && System.currentTimeMillis() > expMs) {
                VpnStateBridge.addLog("Import failed: Bundle has expired.")
                viewModel.showToastPill("This configuration bundle has expired!")
                return 0
            }
            val lockedHwid = root.get("hwid")?.asString?.trim() ?: ""
            if (lockedHwid.isNotEmpty()) {
                val myHwid = VpnStateBridge.getDeviceHardwareId(applicationContext)
                val allowed = lockedHwid.split(",").map { it.trim().uppercase() }.filter { it.isNotEmpty() }
                if (allowed.isNotEmpty() && myHwid.uppercase() !in allowed) {
                    VpnStateBridge.addLog("Import failed: HWID Lock mismatch ($myHwid).")
                    viewModel.showToastPill("HWID Lock Rejected ($myHwid)")
                    return 0
                }
            }
            val listType = object : TypeToken<List<VpnProfile>>() {}.type
            val profiles: List<VpnProfile> = Gson().fromJson(root.get("profiles"), listType) ?: emptyList()
            profiles.forEach { p ->
                viewModel.saveManualProfile(p.copy(id = 0, isSelected = true))
            }
            profiles.size
        } catch (_: Throwable) {
            0
        }
    }

    private suspend fun fetchLatestOtaUpdate(): OtaUpdateInfo? = withContext(Dispatchers.IO) {
        for (manifestUrl in OTA_MANIFEST_URLS) {
            try {
                val conn = (URL("$manifestUrl?t=${System.currentTimeMillis()}").openConnection() as HttpURLConnection).apply {
                    connectTimeout = 5000
                    readTimeout = 5000
                    instanceFollowRedirects = true
                    setRequestProperty("Accept", "application/json")
                    setRequestProperty("Cache-Control", "no-cache")
                }
                if (conn.responseCode in 200..299) {
                    val body = conn.inputStream.bufferedReader().use { it.readText() }
                    val json = JsonParser.parseString(body).asJsonObject
                    val remoteCode = json.get("versionCode")?.asInt ?: 0
                    val remoteName = json.get("versionName")?.asString ?: "1.2.3"
                    val apkUrl = json.get("apkUrl")?.asString ?: ""
                    val notes = json.get("releaseNotes")?.asString
                        ?: "• Fixed Slipstream-DNSTT connection & slipnet:// / dnst:// imports\n• Fixed APK signature for seamless in-place OTA updates\n• Fixed bandwidth persistence across tabs"
                    if (remoteCode > CURRENT_BUILD_CODE && apkUrl.isNotBlank()) {
                        return@withContext OtaUpdateInfo(remoteCode, remoteName, apkUrl, notes)
                    }
                }
            } catch (_: Throwable) {}
        }
        null
    }

    private fun buildExportStandardUri(profile: VpnProfile): String {
        val proto = profile.protocol.uppercase().trim()
        val remark = try {
            URLEncoder.encode(profile.name.ifBlank { "Techfeeds-V1.2.3" }, "UTF-8")
        } catch (_: Throwable) {
            "Techfeeds-V1.2.3"
        }
        val host = profile.server.trim()
        val port = profile.port.coerceIn(1, 65535)
        val net = profile.network.trim().lowercase().ifBlank { "tcp" }
        val sec = profile.security.trim().lowercase().ifBlank { "none" }
        val sni = profile.sni.trim().ifBlank { host }
        val path = profile.path.trim().ifBlank { "/" }
        val wsHost = profile.wsHost.trim().ifBlank { sni }

        return when (proto) {
            "SLIPSTREAM-DNSTT", "SLIPSTREAM", "SLOWDNS", "SSH-DNSTT", "DNSTT" -> {
                val scheme = if (proto.contains("SLIP")) "slipnet" else "dnst"
                val tunDom = profile.slowDnsDomain.ifBlank { host }
                val nsDom = profile.sni.ifBlank { host }
                val pubK = profile.slowDnsPubKey.ifBlank { profile.pbk }.trim()
                val u = profile.sshUser.ifBlank { profile.uuid }.trim()
                val p = profile.sshPass.trim()
                val json = """{"app":"Techfeeds Slipstream VPN v1","name":"${profile.name.ifBlank { "Techfeeds" }}","domain":"$tunDom","ns":"$nsDom","pubkey":"$pubK","user":"$u","pass":"$p","quota":"Unlimited Data","ports":[$port,443]}"""
                val b64 = Base64.encodeToString(json.toByteArray(Charsets.UTF_8), Base64.NO_WRAP).trimEnd('=')
                "$scheme://$b64"
            }
            "SHADOWSOCKS", "SS" -> {
                val method = profile.ssMethod.trim().ifBlank {
                    if (sec.startsWith("aes-") || sec.contains("chacha20")) sec else "chacha20-ietf-poly1305"
                }
                val pass = profile.sshPass.ifBlank { profile.uuid }.trim()
                val userInfoB64 = Base64.encodeToString(
                    "$method:$pass".toByteArray(Charsets.UTF_8),
                    Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
                )
                "ss://$userInfoB64@$host:$port#$remark"
            }
            "VMESS" -> {
                val vmessJson = """
                    {
                      "v": "2",
                      "ps": "${profile.name.ifBlank { "Techfeeds-VMess" }}",
                      "add": "$host",
                      "port": "$port",
                      "id": "${profile.uuid.trim()}",
                      "aid": "0",
                      "scy": "auto",
                      "net": "$net",
                      "type": "none",
                      "host": "$wsHost",
                      "path": "$path",
                      "tls": "${if (sec == "tls") "tls" else ""}",
                      "sni": "$sni",
                      "fp": "${profile.utlsFingerprint.ifBlank { "chrome" }}"
                    }
                """.trimIndent()
                val b64 = Base64.encodeToString(vmessJson.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
                "vmess://$b64"
            }
            "TROJAN" -> {
                val pass = profile.uuid.ifBlank { profile.sshPass }.trim()
                val encPath = try { URLEncoder.encode(path, "UTF-8") } catch (_: Throwable) { path }
                "trojan://$pass@$host:$port?security=$sec&type=$net&sni=$sni&host=$wsHost&path=$encPath#$remark"
            }
            "HYSTERIA2" -> {
                val auth = profile.hy2Password.ifBlank { profile.uuid.ifBlank { profile.sshPass } }.trim()
                val obfs = profile.hy2ObfsPassword.ifBlank { profile.hy2Obfs }.trim()
                val obfsParam = if (obfs.isNotEmpty()) "&obfs=salamander&obfs-password=$obfs" else ""
                "hy2://$auth@$host:$port?sni=$sni&insecure=${if (profile.allowInsecure) 1 else 0}$obfsParam#$remark"
            }
            else -> {
                val uuid = profile.uuid.ifBlank { profile.sshPass }.trim()
                val encPath = try { URLEncoder.encode(path, "UTF-8") } catch (_: Throwable) { path }
                val pbkParam = if (profile.pbk.isNotBlank()) "&pbk=${profile.pbk.trim()}" else ""
                val sidParam = if (profile.sid.isNotBlank()) "&sid=${profile.sid.trim()}" else ""
                val flowParam = if (profile.flow.isNotBlank()) "&flow=${profile.flow.trim()}" else ""
                val fp = profile.utlsFingerprint.ifBlank { "chrome" }
                "vless://$uuid@$host:$port?encryption=none&security=$sec&type=$net&sni=$sni&fp=$fp&host=$wsHost&path=$encPath$pbkParam$sidParam$flowParam#$remark"
            }
        }
    }

    private fun buildExportPrettyXrayJson(profile: VpnProfile): String {
        val socksPort = VpnStateBridge.localSocksPort.value.coerceIn(1025, 65534)
        if (profile.rawJson.isNotBlank()) {
            return try {
                val parsed = JsonParser.parseString(profile.rawJson)
                GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(parsed)
            } catch (_: Throwable) {
                profile.rawJson
            }
        }

        val protoLower = profile.protocol.lowercase().trim().let {
            if (it == "ss") "shadowsocks" else it
        }
        val host = profile.server.trim()
        val port = profile.port.coerceIn(1, 65535)
        val sni = profile.sni.trim().ifBlank { host }
        val wsHost = profile.wsHost.trim().ifBlank { sni }
        val path = profile.path.trim().ifBlank { "/" }
        val net = profile.network.trim().lowercase().ifBlank { "tcp" }
        val isReality = protoLower != "shadowsocks" && (profile.security.equals("reality", true) || profile.pbk.isNotBlank())
        val isTls = !isReality && (profile.security.equals("tls", true) || (protoLower != "shadowsocks" && port in listOf(443, 8443, 2053, 2083, 2087, 2096)))
        val secMode = when {
            isReality -> "reality"
            isTls -> "tls"
            else -> "none"
        }

        val ssMethod = profile.ssMethod.trim().ifBlank { "chacha20-ietf-poly1305" }
        val ssPass = profile.sshPass.ifBlank { profile.uuid }.trim()

        val settingsBlock = when (protoLower) {
            "shadowsocks" -> """"servers": [{"address": "$host", "port": $port, "method": "$ssMethod", "password": "$ssPass"}]"""
            "trojan" -> """"servers": [{"address": "$host", "port": $port, "password": "${profile.uuid.ifBlank { profile.sshPass }.trim()}"}]"""
            "vmess" -> """"vnext": [{"address": "$host", "port": $port, "users": [{"id": "${profile.uuid.trim()}", "alterId": 0, "security": "auto"}]}]"""
            else -> {
                val flowField = if (profile.flow.isNotBlank() && net == "tcp") """, "flow": "${profile.flow.trim()}"""" else ""
                """"vnext": [{"address": "$host", "port": $port, "users": [{"id": "${profile.uuid.trim()}", "encryption": "none"$flowField}]}]"""
            }
        }

        val secBlock = when {
            isReality -> """"realitySettings": {"serverName": "$sni", "fingerprint": "${profile.utlsFingerprint.ifBlank { "chrome" }}", "publicKey": "${profile.pbk.trim()}", "shortId": "${profile.sid.trim()}"}"""
            isTls -> """"tlsSettings": {"serverName": "$sni", "allowInsecure": ${profile.allowInsecure}, "fingerprint": "${profile.utlsFingerprint.ifBlank { "chrome" }}"}"""
            else -> ""
        }

        val transBlock = when (net) {
            "ws" -> """"wsSettings": {"path": "$path", "headers": {"Host": "$wsHost"}}"""
            "grpc" -> """"grpcSettings": {"serviceName": "${path.removePrefix("/")}", "multiMode": true}"""
            else -> """"tcpSettings": {}"""
        }

        val extraStream = listOf(secBlock, transBlock).filter { it.isNotEmpty() }.joinToString(",")
        val raw = """
            {
              "log": {"loglevel": "warning"},
              "inbounds": [
                {
                  "tag": "socks-in",
                  "port": $socksPort,
                  "listen": "127.0.0.1",
                  "protocol": "socks",
                  "settings": {"auth": "noauth", "udp": true}
                }
              ],
              "outbounds": [
                {
                  "tag": "proxy",
                  "protocol": "$protoLower",
                  "settings": {$settingsBlock},
                  "streamSettings": {
                    "network": "$net",
                    "security": "$secMode"${if (extraStream.isNotEmpty()) ", $extraStream" else ""}
                  }
                }
              ]
            }
        """.trimIndent()

        return try {
            val parsed = JsonParser.parseString(raw)
            GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(parsed)
        } catch (_: Throwable) {
            raw
        }
    }

    @Composable
    private fun TechfeedsBrandCrest(sizeDp: Int = 46, animated: Boolean = false) {
        val infinite = rememberInfiniteTransition(label = "QuantumCrest")
        val outerAngle by infinite.animateFloat(
            initialValue = 0f,
            targetValue = 360f,
            animationSpec = infiniteRepeatable(
                animation = tween(durationMillis = 9000, easing = LinearEasing),
                repeatMode = RepeatMode.Restart
            ),
            label = "OuterRing"
        )
        val innerAngle by infinite.animateFloat(
            initialValue = 360f,
            targetValue = 0f,
            animationSpec = infiniteRepeatable(
                animation = tween(durationMillis = 6500, easing = LinearEasing),
                repeatMode = RepeatMode.Restart
            ),
            label = "InnerRing"
        )
        val glowPulse by infinite.animateFloat(
            initialValue = 0.25f,
            targetValue = 0.65f,
            animationSpec = infiniteRepeatable(
                animation = tween(durationMillis = 1800, easing = FastOutSlowInEasing),
                repeatMode = RepeatMode.Reverse
            ),
            label = "GlowPulse"
        )
        val degOuter = if (animated) outerAngle else 35f
        val degInner = if (animated) innerAngle else -35f

        Box(
            modifier = Modifier.size(sizeDp.dp),
            contentAlignment = Alignment.Center
        ) {
            Canvas(modifier = Modifier.fillMaxSize()) {
                val w = size.width
                val h = size.height
                val cx = w / 2f
                val cy = h / 2f

                drawCircle(
                    brush = Brush.radialGradient(
                        colors = listOf(
                            AmethystNeon.copy(alpha = if (animated) glowPulse else 0.35f),
                            RoyalGold.copy(alpha = 0.14f),
                            Color.Transparent
                        ),
                        center = Offset(cx, cy),
                        radius = w * 0.50f
                    )
                )

                rotate(degOuter) {
                    drawArc(
                        brush = Brush.sweepGradient(
                            colors = listOf(RoyalGold, AmethystNeon, Color.Transparent, RoyalGold)
                        ),
                        startAngle = 0f,
                        sweepAngle = 290f,
                        useCenter = false,
                        style = Stroke(width = w * 0.038f, cap = StrokeCap.Round)
                    )
                    val nodeRadius = w * 0.47f
                    for (angleDeg in listOf(0.0, 120.0, 240.0)) {
                        val rad = Math.toRadians(angleDeg)
                        val nx = cx + (nodeRadius * cos(rad)).toFloat()
                        val ny = cy + (nodeRadius * sin(rad)).toFloat()
                        drawCircle(
                            color = RoyalGold,
                            radius = w * 0.032f,
                            center = Offset(nx, ny)
                        )
                    }
                }

                rotate(degInner) {
                    drawArc(
                        color = AmethystLight.copy(alpha = 0.85f),
                        startAngle = 20f,
                        sweepAngle = 120f,
                        useCenter = false,
                        topLeft = Offset(w * 0.08f, h * 0.08f),
                        size = Size(w * 0.84f, h * 0.84f),
                        style = Stroke(width = w * 0.024f, cap = StrokeCap.Round)
                    )
                    drawArc(
                        color = RoyalGold.copy(alpha = 0.85f),
                        startAngle = 200f,
                        sweepAngle = 120f,
                        useCenter = false,
                        topLeft = Offset(w * 0.08f, h * 0.08f),
                        size = Size(w * 0.84f, h * 0.84f),
                        style = Stroke(width = w * 0.024f, cap = StrokeCap.Round)
                    )
                }

                val shieldPath = Path().apply {
                    moveTo(cx, h * 0.12f)
                    lineTo(w * 0.83f, h * 0.25f)
                    lineTo(w * 0.83f, h * 0.55f)
                    cubicTo(w * 0.83f, h * 0.74f, w * 0.69f, h * 0.86f, cx, h * 0.91f)
                    cubicTo(w * 0.31f, h * 0.86f, w * 0.17f, h * 0.74f, w * 0.17f, h * 0.55f)
                    lineTo(w * 0.17f, h * 0.25f)
                    close()
                }
                drawPath(
                    path = shieldPath,
                    brush = Brush.linearGradient(
                        colors = listOf(Color(0xFF341269), Color(0xFF1A0738), Color(0xFF0B021A))
                    )
                )
                drawPath(
                    path = shieldPath,
                    brush = Brush.linearGradient(
                        colors = listOf(RoyalGold, AmethystNeon, DeepGold)
                    ),
                    style = Stroke(width = w * 0.042f)
                )
                drawRoundRect(
                    brush = Brush.linearGradient(listOf(Color(0xFFFFF59D), RoyalGold, DeepGold)),
                    topLeft = Offset(w * 0.30f, h * 0.31f),
                    size = Size(w * 0.40f, h * 0.085f),
                    cornerRadius = CornerRadius(w * 0.03f, w * 0.03f)
                )
                drawRoundRect(
                    brush = Brush.linearGradient(listOf(RoyalGold, DeepGold)),
                    topLeft = Offset(cx - w * 0.052f, h * 0.36f),
                    size = Size(w * 0.104f, h * 0.37f),
                    cornerRadius = CornerRadius(w * 0.03f, w * 0.03f)
                )
            }
        }
    }

    @Composable
    private fun TechfeedsV12AdvancedSplashScreen(onContinue: () -> Unit) {
        val context = LocalContext.current
        val clipboardManager = LocalClipboardManager.current
        val hwid = remember { VpnStateBridge.getDeviceHardwareId(context) }
        var copiedHwid by remember { mutableStateOf(false) }
        var bootStage by remember { mutableStateOf(1) }
        var bootProgressTarget by remember { mutableStateOf(0.25f) }
        val animatedProgress by animateFloatAsState(
            targetValue = bootProgressTarget,
            animationSpec = tween(durationMillis = 450, easing = FastOutSlowInEasing),
            label = "BootProgress"
        )

        LaunchedEffect(Unit) {
            with(Dispatchers.IO) {
                SlowDnsSpeedBooster.resolveDnsttExecutable(context)
            }
            delay(280L)
            bootStage = 2
            bootProgressTarget = 0.55f
            delay(280L)
            bootStage = 3
            bootProgressTarget = 0.85f
            delay(280L)
            bootStage = 4
            bootProgressTarget = 1.0f
        }

        val bootStatusLabel = when (bootStage) {
            1 -> "⚡ [1/4] Mounting Slipstream & SlowDNS KCP-64 Swarm..."
            2 -> "🛡️ [2/4] Arming Native Xray-Core & X25519/ECDH SSH Engine..."
            3 -> "🔒 [3/4] Enforcing V1.2.3 Cryptographic APK Lock..."
            else -> "✓ [4/4] Techfeeds-VPN V$CURRENT_VERSION_NAME Quantum Core Armed"
        }

        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(
                    Brush.verticalGradient(
                        colors = listOf(RoyalBgTop, RoyalBgMid, RoyalBgBottom)
                    )
                )
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 18.dp, vertical = 20.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(
                            width = 1.8.dp,
                            brush = Brush.linearGradient(
                                colors = listOf(RoyalGold, AmethystNeon, DeepGold, RoyalGold)
                            ),
                            shape = RoundedCornerShape(32.dp)
                        ),
                    shape = RoundedCornerShape(32.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = RoyalCardSurface.copy(alpha = 0.94f)
                    )
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(22.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(14.dp)
                    ) {
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Surface(
                                shape = RoundedCornerShape(50),
                                color = RoyalGold.copy(alpha = 0.16f),
                                border = BorderStroke(1.dp, RoyalGold.copy(alpha = 0.75f))
                            ) {
                                Text(
                                    text = "👑 ROYAL GOLD & AMETHYST",
                                    color = RoyalGold,
                                    fontSize = 10.sp,
                                    fontWeight = FontWeight.ExtraBold,
                                    letterSpacing = 1.sp,
                                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 5.dp)
                                )
                            }
                            Surface(
                                shape = RoundedCornerShape(50),
                                color = CyberEmerald.copy(alpha = 0.16f),
                                border = BorderStroke(1.dp, CyberEmerald.copy(alpha = 0.75f))
                            ) {
                                Text(
                                    text = "BUILD $CURRENT_BUILD_CODE",
                                    color = CyberEmerald,
                                    fontSize = 10.sp,
                                    fontWeight = FontWeight.ExtraBold,
                                    letterSpacing = 0.8.sp,
                                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp)
                                )
                            }
                        }

                        TechfeedsBrandCrest(sizeDp = 114, animated = true)

                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Text(
                                text = "Techfeeds-VPN V$CURRENT_VERSION_NAME",
                                style = MaterialTheme.typography.headlineMedium,
                                fontWeight = FontWeight.ExtraBold,
                                color = Color.White,
                                letterSpacing = 0.8.sp
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = "SLIPSTREAM-DNSTT SWARM • NATIVE XRAY & 6X SSH CORE",
                                color = AmethystLight,
                                fontSize = 10.sp,
                                fontWeight = FontWeight.ExtraBold,
                                letterSpacing = 1.1.sp,
                                textAlign = TextAlign.Center
                            )
                        }

                        Surface(
                            shape = RoundedCornerShape(18.dp),
                            color = Color(0xFF0E041D),
                            border = BorderStroke(1.dp, RoyalGold.copy(alpha = 0.45f)),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Column(
                                modifier = Modifier.padding(14.dp),
                                verticalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = "V$CURRENT_VERSION_NAME ENCLAVE TELEMETRY",
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.ExtraBold,
                                        color = RoyalGold
                                    )
                                    Text(
                                        text = "${(animatedProgress * 100).toInt()}%",
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.ExtraBold,
                                        color = CyberEmerald
                                    )
                                }
                                Box(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .height(7.dp)
                                        .clip(RoundedCornerShape(50))
                                        .background(Color(0xFF261147))
                                ) {
                                    Box(
                                        modifier = Modifier
                                            .fillMaxWidth(animatedProgress.coerceIn(0.08f, 1f))
                                            .fillMaxHeight()
                                            .clip(RoundedCornerShape(50))
                                            .background(
                                                Brush.horizontalGradient(
                                                    colors = listOf(RoyalGold, AmethystNeon, CyberEmerald)
                                                )
                                            )
                                    )
                                }
                                Text(
                                    text = bootStatusLabel,
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = CyberEmerald
                                )
                                Text(
                                    text = "• Slipstream & DNSTT: NS:53/443 + DoH Multipath Race\n" +
                                        "• SSH Engine: Universal X25519 + ECDH Fallback Active\n" +
                                        "• Permanent Keystore: Seamless OTA In-Place Updates",
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 10.sp,
                                    color = Color(0xFFD1C4E9),
                                    lineHeight = 15.sp
                                )
                            }
                        }

                        Surface(
                            shape = RoundedCornerShape(14.dp),
                            color = Color(0xFF0E041D),
                            border = BorderStroke(1.dp, RoyalGold.copy(alpha = 0.60f)),
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    clipboardManager.setText(AnnotatedString(hwid))
                                    copiedHwid = true
                                }
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 14.dp, vertical = 10.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Column {
                                    Text(
                                        text = "🆔 DEVICE HARDWARE ID (TAP TO COPY)",
                                        fontSize = 9.sp,
                                        fontWeight = FontWeight.ExtraBold,
                                        color = RoyalGold
                                    )
                                    Text(
                                        text = hwid,
                                        fontFamily = FontFamily.Monospace,
                                        fontSize = 12.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = Color.White
                                    )
                                }
                                Surface(
                                    shape = RoundedCornerShape(8.dp),
                                    color = RoyalGold.copy(alpha = 0.2f),
                                    border = BorderStroke(1.dp, RoyalGold)
                                ) {
                                    Text(
                                        text = if (copiedHwid) "✓ COPIED" else "📋 COPY",
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.ExtraBold,
                                        color = RoyalGold,
                                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp)
                                    )
                                }
                            }
                        }

                        Button(
                            onClick = onContinue,
                            colors = ButtonDefaults.buttonColors(
                                containerColor = RoyalGold,
                                contentColor = Color(0xFF1A0933)
                            ),
                            shape = RoundedCornerShape(24.dp),
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(54.dp)
                        ) {
                            Text(
                                text = "ENTER TECHFEEDS-VPN V$CURRENT_VERSION_NAME ⚡",
                                fontWeight = FontWeight.ExtraBold,
                                fontSize = 14.sp,
                                letterSpacing = 0.7.sp
                            )
                        }
                    }
                }
            }
        }
    }

    @Composable
    private fun TechfeedsSecretCodeGateScreen(onCodeUnlocked: () -> Unit) {
        val context = LocalContext.current
        val clipboardManager = LocalClipboardManager.current
        var secretCodeInput by rememberSaveable { mutableStateOf("") }
        var errorMessage by remember { mutableStateOf("") }

        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(
                    Brush.verticalGradient(
                        colors = listOf(RoyalBgTop, RoyalBgMid, RoyalBgBottom)
                    )
                )
                .padding(horizontal = 20.dp, vertical = 18.dp),
            contentAlignment = Alignment.Center
        ) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .border(
                        width = 1.5.dp,
                        brush = Brush.linearGradient(listOf(RoyalGold, AmethystNeon, DeepGold)),
                        shape = RoundedCornerShape(28.dp)
                    ),
                shape = RoundedCornerShape(28.dp),
                colors = CardDefaults.cardColors(containerColor = RoyalCardSurface.copy(alpha = 0.98f))
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .verticalScroll(rememberScrollState())
                        .padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(14.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(68.dp)
                            .clip(CircleShape)
                            .background(RoyalGold.copy(alpha = 0.15f))
                            .border(1.5.dp, RoyalGold, CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Default.Lock,
                            contentDescription = "V1.2 Secret Code Vault",
                            tint = RoyalGold,
                            modifier = Modifier.size(32.dp)
                        )
                    }

                    Text(
                        text = "Techfeeds-VPN V$CURRENT_VERSION_NAME Login",
                        fontSize = 22.sp,
                        fontWeight = FontWeight.ExtraBold,
                        color = Color.White
                    )
                    Text(
                        text = "Enter your V1.2 Secret Access Code (TFV12-...) to unlock Techfeeds-VPN V$CURRENT_VERSION_NAME.",
                        fontSize = 12.sp,
                        color = Color(0xFFD1C4E9),
                        textAlign = TextAlign.Center,
                        lineHeight = 17.sp
                    )

                    OutlinedTextField(
                        value = secretCodeInput,
                        onValueChange = {
                            secretCodeInput = it.uppercase()
                            if (errorMessage.isNotEmpty()) errorMessage = ""
                        },
                        label = { Text("Enter V1.2 Secret Code (TFV12-...)") },
                        placeholder = { Text("TFV12-24H-B204-2E7D95A1") },
                        singleLine = true,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = RoyalGold,
                            unfocusedBorderColor = AmethystLight.copy(alpha = 0.5f),
                            focusedLabelColor = RoyalGold,
                            unfocusedLabelColor = Color(0xFFD1C4E9),
                            cursorColor = RoyalGold,
                            focusedTextColor = Color.White,
                            unfocusedTextColor = Color.White
                        ),
                        modifier = Modifier.fillMaxWidth()
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.End
                    ) {
                        TextButton(
                            onClick = {
                                val clip = clipboardManager.getText()?.text?.trim() ?: ""
                                if (clip.isNotEmpty()) {
                                    secretCodeInput = clip.uppercase()
                                    errorMessage = ""
                                }
                            }
                        ) {
                            Text(
                                text = "📋 Paste V1.2 Code from Clipboard",
                                color = RoyalGold,
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }

                    if (errorMessage.isNotBlank()) {
                        Surface(
                            shape = RoundedCornerShape(12.dp),
                            color = Color(0xFF3B0D1E),
                            border = BorderStroke(1.dp, Color(0xFFFF5252)),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(
                                text = "⚠️ $errorMessage",
                                color = Color(0xFFFF8A80),
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.padding(12.dp)
                            )
                        }
                    }

                    Button(
                        onClick = {
                            val res = SecretCodeManager.activateSecretCode(context, secretCodeInput)
                            if (res.success) {
                                VpnStateBridge.addLog("V1.2 Secret Code verified (${res.durationLabel}). Access granted.")
                                onCodeUnlocked()
                            } else {
                                errorMessage = res.message
                            }
                        },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = RoyalGold,
                            contentColor = Color(0xFF1A0933)
                        ),
                        shape = RoundedCornerShape(24.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(52.dp)
                    ) {
                        Text(
                            text = "UNLOCK TECHFEEDS-VPN V$CURRENT_VERSION_NAME 🔓",
                            fontWeight = FontWeight.ExtraBold,
                            fontSize = 14.sp
                        )
                    }
                }
            }
        }
    }

    @OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
    @Composable
    private fun MainDashboardContent(remainingTimeText: String) {
        val context = LocalContext.current
        val clipboardManager = LocalClipboardManager.current
        val scope = rememberCoroutineScope()
        val drawerState = rememberDrawerState(initialValue = DrawerValue.Closed)
        val pagerState = rememberPagerState(initialPage = 0, pageCount = { 4 })

        var showThemeMenu by remember { mutableStateOf(false) }
        var showUserManual by remember { mutableStateOf(false) }
        var showPlusMenu by remember { mutableStateOf(false) }
        var showCloudImportModal by remember { mutableStateOf(false) }
        var showQrScannerModal by remember { mutableStateOf(false) }
        var showAboutModal by remember { mutableStateOf(false) }
        var showXrayUriJsonExportModal by remember { mutableStateOf(false) }
        var showMultiTickExportModal by remember { mutableStateOf(false) }
        var showExitOrMinimizeModal by remember { mutableStateOf(false) }
        var otaUpdateAvailable by remember { mutableStateOf<OtaUpdateInfo?>(null) }

        val isConnected by viewModel.isConnected.collectAsState()
        val connectionState by viewModel.connectionState.collectAsState()
        val profiles by viewModel.profiles.collectAsState()
        val currentThemeMode by VpnStateBridge.themeMode.collectAsState()
        val triggerQr by VpnStateBridge.triggerQrScannerDialog.collectAsState()
        val activeDrawerScreen by VpnStateBridge.activeDrawerScreen.collectAsState()

        val selectedProfiles = remember(profiles) { profiles.filter { it.isSelected } }
        val exportableTickedProfiles = remember(selectedProfiles, profiles) {
            val chosen = selectedProfiles.filter { !(it.isImported && it.isLocked) }
            if (chosen.isNotEmpty()) chosen else profiles.filter { !(it.isImported && it.isLocked) }.take(1)
        }
        val activeProfile = selectedProfiles.firstOrNull() ?: profiles.firstOrNull()
        val hwid = remember { VpnStateBridge.getDeviceHardwareId(context) }

        LaunchedEffect(Unit) {
            val update = fetchLatestOtaUpdate()
            if (update != null) {
                otaUpdateAvailable = update
            }
        }

        BackHandler {
            when {
                drawerState.isOpen -> scope.launch { drawerState.close() }
                pagerState.currentPage != 0 -> scope.launch { pagerState.animateScrollToPage(0) }
                else -> showExitOrMinimizeModal = true
            }
        }

        LaunchedEffect(triggerQr) {
            if (triggerQr) {
                VpnStateBridge.triggerQrScannerDialog.value = false
                showQrScannerModal = true
            }
        }

        val themeOptions = listOf(
            "5. Royal Gold & Amethyst",
            "Auto (Day / Night)",
            "1. Midnight Obsidian (Dark)",
            "2. Daylight Sapphire (Light)",
            "3. Synthwave Neon (Violet)",
            "4. Emerald Matrix (Cyber Green)",
            "6. Crimson Phantom (Red Ops)",
            "7. Arctic Glacier (Ice Light)",
            "8. Ocean Titanium (Deep Navy)",
            "9. Sunset Amber (Warm Dark)",
            "10. Monochrome Slate (Minimal)"
        )

        ModalNavigationDrawer(
            drawerState = drawerState,
            drawerContent = {
                ModalDrawerSheet(
                    drawerContainerColor = MaterialTheme.colorScheme.surface,
                    drawerContentColor = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.width(320.dp)
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .verticalScroll(rememberScrollState())
                    ) {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(
                                    Brush.linearGradient(
                                        colors = listOf(RoyalBgTop, RoyalBgMid, Color(0xFF341463))
                                    )
                                )
                                .padding(18.dp)
                        ) {
                            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    TechfeedsBrandCrest(sizeDp = 54, animated = false)
                                    Spacer(modifier = Modifier.width(12.dp))
                                    Column {
                                        Text(
                                            text = "Techfeeds-VPN V$CURRENT_VERSION_NAME",
                                            fontWeight = FontWeight.ExtraBold,
                                            fontSize = 19.sp,
                                            color = Color.White
                                        )
                                        Text(
                                            text = "ROYAL GOLD & AMETHYST • BUILD $CURRENT_BUILD_CODE",
                                            fontSize = 10.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = RoyalGold,
                                            letterSpacing = 0.9.sp
                                        )
                                    }
                                }
                                if (remainingTimeText.isNotBlank()) {
                                    Surface(
                                        shape = RoundedCornerShape(10.dp),
                                        color = RoyalGold.copy(alpha = 0.15f),
                                        border = BorderStroke(1.dp, RoyalGold.copy(alpha = 0.6f)),
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        Row(
                                            modifier = Modifier
                                                .fillMaxWidth()
                                                .padding(horizontal = 12.dp, vertical = 8.dp),
                                            horizontalArrangement = Arrangement.SpaceBetween,
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Text(
                                                text = "🔑 V1.2 ACCESS:",
                                                fontSize = 10.sp,
                                                fontWeight = FontWeight.ExtraBold,
                                                color = RoyalGold
                                            )
                                            Text(
                                                text = remainingTimeText,
                                                fontFamily = FontFamily.Monospace,
                                                fontSize = 11.sp,
                                                fontWeight = FontWeight.ExtraBold,
                                                color = Color.White
                                            )
                                        }
                                    }
                                }
                                Surface(
                                    shape = RoundedCornerShape(14.dp),
                                    color = Color.Black.copy(alpha = 0.42f),
                                    border = BorderStroke(1.dp, RoyalGold.copy(alpha = 0.65f)),
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable {
                                            clipboardManager.setText(AnnotatedString(hwid))
                                            viewModel.showToastPill("Hardware 🆔 copied: $hwid")
                                        }
                                ) {
                                    Row(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .padding(horizontal = 12.dp, vertical = 10.dp),
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        Column(modifier = Modifier.weight(1f)) {
                                            Text(
                                                text = "🆔 HARDWARE ID (TAP TO COPY)",
                                                fontSize = 9.sp,
                                                fontWeight = FontWeight.ExtraBold,
                                                color = RoyalGold
                                            )
                                            Text(
                                                text = hwid,
                                                fontFamily = FontFamily.Monospace,
                                                fontSize = 12.sp,
                                                fontWeight = FontWeight.Bold,
                                                color = Color.White
                                            )
                                        }
                                        Surface(
                                            shape = RoundedCornerShape(8.dp),
                                            color = RoyalGold
                                        ) {
                                            Text(
                                                text = "COPY",
                                                color = Color(0xFF1A0933),
                                                fontSize = 10.sp,
                                                fontWeight = FontWeight.ExtraBold,
                                                modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp)
                                            )
                                        }
                                    }
                                }
                            }
                        }

                        Column(
                            modifier = Modifier.padding(12.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Text(
                                text = "CORE ENGINE",
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.ExtraBold,
                                color = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp)
                            )
                            NavigationDrawerItem(
                                label = { Text("⚙️ Engine Settings", fontWeight = FontWeight.SemiBold) },
                                selected = false,
                                onClick = {
                                    VpnStateBridge.activeDrawerScreen.value = "SETTINGS"
                                    scope.launch { drawerState.close(); pagerState.animateScrollToPage(3) }
                                }
                            )
                            NavigationDrawerItem(
                                label = { Text("📡 Response Checker", fontWeight = FontWeight.SemiBold) },
                                selected = false,
                                onClick = {
                                    VpnStateBridge.activeDrawerScreen.value = "RESPONSE_CHECKER"
                                    scope.launch { drawerState.close(); pagerState.animateScrollToPage(3) }
                                }
                            )
                            NavigationDrawerItem(
                                label = { Text("📶 ShareNet Hotspot & Proxy", fontWeight = FontWeight.SemiBold) },
                                selected = false,
                                onClick = {
                                    VpnStateBridge.activeDrawerScreen.value = "SHARENET"
                                    scope.launch { drawerState.close(); pagerState.animateScrollToPage(3) }
                                }
                            )
                            NavigationDrawerItem(
                                label = { Text("🛠️ Network Tools", fontWeight = FontWeight.SemiBold) },
                                selected = false,
                                onClick = {
                                    VpnStateBridge.activeDrawerScreen.value = "NETWORK_TOOLS"
                                    scope.launch { drawerState.close(); pagerState.animateScrollToPage(3) }
                                }
                            )
                            NavigationDrawerItem(
                                label = { Text("⚡ Payload Generator", fontWeight = FontWeight.SemiBold) },
                                selected = false,
                                onClick = {
                                    VpnStateBridge.activeDrawerScreen.value = "PAYLOAD_GEN"
                                    scope.launch { drawerState.close(); pagerState.animateScrollToPage(3) }
                                }
                            )
                            NavigationDrawerItem(
                                label = { Text("🎨 Themes (Royal Gold Default)", fontWeight = FontWeight.SemiBold) },
                                selected = false,
                                onClick = {
                                    scope.launch { drawerState.close() }
                                    showThemeMenu = true
                                }
                            )
                            NavigationDrawerItem(
                                label = { Text("🔄 Check for App Update (OTA)", fontWeight = FontWeight.ExtraBold, color = RoyalGold) },
                                selected = false,
                                onClick = {
                                    scope.launch {
                                        drawerState.close()
                                        val update = fetchLatestOtaUpdate()
                                        if (update != null) {
                                            otaUpdateAvailable = update
                                        } else {
                                            viewModel.showToastPill("You are on the latest version (V$CURRENT_VERSION_NAME)!")
                                        }
                                    }
                                }
                            )
                            NavigationDrawerItem(
                                label = { Text("📖 User Manual & Guide", fontWeight = FontWeight.SemiBold) },
                                selected = false,
                                onClick = {
                                    scope.launch { drawerState.close() }
                                    showUserManual = true
                                }
                            )
                            NavigationDrawerItem(
                                label = { Text("ℹ️ About Techfeeds-VPN V$CURRENT_VERSION_NAME", fontWeight = FontWeight.SemiBold) },
                                selected = false,
                                onClick = {
                                    scope.launch { drawerState.close() }
                                    showAboutModal = true
                                }
                            )
                            NavigationDrawerItem(
                                label = { Text("🚪 Exit or Minimize App", fontWeight = FontWeight.ExtraBold, color = Color(0xFFFF8A80)) },
                                selected = false,
                                onClick = {
                                    scope.launch { drawerState.close() }
                                    showExitOrMinimizeModal = true
                                }
                            )
                            HorizontalDivider(modifier = Modifier.padding(vertical = 6.dp))
                            Text(
                                text = "COMMUNITY & SUPPORT",
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.ExtraBold,
                                color = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp)
                            )
                            NavigationDrawerItem(
                                label = { Text("📢 Telegram Channel") },
                                selected = false,
                                onClick = {
                                    scope.launch { drawerState.close() }
                                    openExternalUrl("https://t.me/Smartking4luV")
                                }
                            )
                            NavigationDrawerItem(
                                label = { Text("💬 Telegram Group") },
                                selected = false,
                                onClick = {
                                    scope.launch { drawerState.close() }
                                    openExternalUrl("https://t.me/lancecreation")
                                }
                            )
                            NavigationDrawerItem(
                                label = { Text("🟢 WhatsApp Community") },
                                selected = false,
                                onClick = {
                                    scope.launch { drawerState.close() }
                                    openExternalUrl("https://chat.whatsapp.com/G9Jb6bgmvFqDAei8oVFU5k")
                                }
                            )
                            NavigationDrawerItem(
                                label = { Text("🔗 Share Techfeeds-VPN V$CURRENT_VERSION_NAME") },
                                selected = false,
                                onClick = {
                                    scope.launch { drawerState.close() }
                                    shareSmartVpnApp()
                                }
                            )
                        }
                    }
                }
            }
        ) {
            Scaffold(
                topBar = {
                    TopAppBar(
                        title = {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                TechfeedsBrandCrest(sizeDp = 34, animated = false)
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = "Techfeeds-VPN",
                                    fontWeight = FontWeight.ExtraBold,
                                    fontSize = 17.sp,
                                    color = MaterialTheme.colorScheme.primary
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Surface(
                                    shape = RoundedCornerShape(8.dp),
                                    color = RoyalGold
                                ) {
                                    Text(
                                        text = "V$CURRENT_VERSION_NAME",
                                        color = Color(0xFF1A0933),
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.ExtraBold,
                                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                    )
                                }
                                if (isConnected) {
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Surface(
                                        shape = RoundedCornerShape(8.dp),
                                        color = CyberEmerald.copy(alpha = 0.2f),
                                        border = BorderStroke(1.dp, CyberEmerald)
                                    ) {
                                        Text(
                                            text = "🔒 ON",
                                            color = CyberEmerald,
                                            fontSize = 10.sp,
                                            fontWeight = FontWeight.ExtraBold,
                                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                        )
                                    }
                                }
                            }
                        },
                        navigationIcon = {
                            IconButton(onClick = { scope.launch { drawerState.open() } }) {
                                Icon(Icons.Default.Menu, "Open Menu")
                            }
                        },
                        actions = {
                            IconButton(onClick = { showUserManual = true }) {
                                Text("📖", fontSize = 18.sp)
                            }
                            Box {
                                Surface(
                                    shape = RoundedCornerShape(12.dp),
                                    color = if (showPlusMenu) Color(0xFFD50000) else MaterialTheme.colorScheme.surfaceVariant,
                                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.5f)),
                                    modifier = Modifier
                                        .padding(end = 10.dp)
                                        .size(38.dp)
                                        .clickable { showPlusMenu = !showPlusMenu }
                                ) {
                                    Box(contentAlignment = Alignment.Center) {
                                        Icon(
                                            imageVector = if (showPlusMenu) Icons.Default.Close else Icons.Default.Add,
                                            contentDescription = "Add Menu",
                                            tint = if (showPlusMenu) Color.White else MaterialTheme.colorScheme.onSurfaceVariant,
                                            modifier = Modifier.size(20.dp)
                                        )
                                    }
                                }
                                DropdownMenu(
                                    expanded = showPlusMenu,
                                    onDismissRequest = { showPlusMenu = false },
                                    modifier = Modifier
                                        .background(MaterialTheme.colorScheme.surface)
                                        .width(285.dp)
                                ) {
                                    DropdownMenuItem(
                                        text = { Text("Import from Clipboard (All URIs / slipnet / dnst)", fontWeight = FontWeight.SemiBold) },
                                        onClick = {
                                            showPlusMenu = false
                                            val clip = clipboardManager.getText()?.text ?: ""
                                            handleUniversalImport(clip)
                                        }
                                    )
                                    DropdownMenuItem(
                                        text = { Text("Import from File (.svpn / .json)", fontWeight = FontWeight.SemiBold) },
                                        onClick = {
                                            showPlusMenu = false
                                            try { filePickerLauncher.launch("*/*") } catch (_: Throwable) {}
                                        }
                                    )
                                    DropdownMenuItem(
                                        text = { Text("Import from Cloud", fontWeight = FontWeight.SemiBold) },
                                        onClick = {
                                            showPlusMenu = false
                                            showCloudImportModal = true
                                        }
                                    )
                                    DropdownMenuItem(
                                        text = { Text("Scan / Import QR Code", fontWeight = FontWeight.SemiBold) },
                                        onClick = {
                                            showPlusMenu = false
                                            showQrScannerModal = true
                                        }
                                    )
                                    DropdownMenuItem(
                                        text = { Text("Manual Configuration", fontWeight = FontWeight.SemiBold) },
                                        onClick = {
                                            showPlusMenu = false
                                            scope.launch {
                                                pagerState.animateScrollToPage(1)
                                                VpnStateBridge.triggerManualConfigDialog.value = true
                                            }
                                        }
                                    )
                                    HorizontalDivider()
                                    DropdownMenuItem(
                                        text = {
                                            Text(
                                                "Export Ticked Configs (${exportableTickedProfiles.size}) 📦",
                                                fontWeight = FontWeight.ExtraBold,
                                                color = RoyalGold
                                            )
                                        },
                                        onClick = {
                                            showPlusMenu = false
                                            if (exportableTickedProfiles.isEmpty()) {
                                                viewModel.showToastPill("Tick at least 1 open configuration on the Configs page to export")
                                            } else {
                                                showMultiTickExportModal = true
                                            }
                                        }
                                    )
                                    DropdownMenuItem(
                                        text = { Text("Export Active Config (URI / JSON) 📤", fontWeight = FontWeight.SemiBold) },
                                        onClick = {
                                            showPlusMenu = false
                                            if (activeProfile == null) {
                                                viewModel.showToastPill("No active configuration to export")
                                            } else if (activeProfile.isImported && activeProfile.isLocked) {
                                                viewModel.showToastPill("Locked configurations cannot be exported as open URI/JSON")
                                            } else {
                                                showXrayUriJsonExportModal = true
                                            }
                                        }
                                    )
                                    DropdownMenuItem(
                                        text = { Text("Lock & Export Single V1.2 Config 🔒", fontWeight = FontWeight.SemiBold) },
                                        onClick = {
                                            showPlusMenu = false
                                            if (activeProfile == null) {
                                                viewModel.showToastPill("No active configuration to export")
                                            } else if (activeProfile.isImported && activeProfile.isLocked) {
                                                viewModel.showToastPill("Locked imported configurations cannot be shared")
                                            } else {
                                                scope.launch {
                                                    pagerState.animateScrollToPage(1)
                                                    VpnStateBridge.triggerExportActiveDialog.value = true
                                                }
                                            }
                                        }
                                    )
                                }
                            }
                        },
                        colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.surface)
                    )
                },
                bottomBar = {
                    NavigationBar(containerColor = MaterialTheme.colorScheme.surface) {
                        NavigationBarItem(
                            selected = pagerState.currentPage == 0,
                            onClick = { scope.launch { pagerState.animateScrollToPage(0) } },
                            icon = { Text("🏠", fontSize = 18.sp) },
                            label = { Text("Home") }
                        )
                        NavigationBarItem(
                            selected = pagerState.currentPage == 1,
                            onClick = { scope.launch { pagerState.animateScrollToPage(1) } },
                            icon = { Text("📁", fontSize = 18.sp) },
                            label = { Text("Configs") }
                        )
                        NavigationBarItem(
                            selected = pagerState.currentPage == 2,
                            onClick = { scope.launch { pagerState.animateScrollToPage(2) } },
                            icon = { Text("📝", fontSize = 18.sp) },
                            label = { Text("Logs") }
                        )
                        NavigationBarItem(
                            selected = pagerState.currentPage == 3,
                            onClick = {
                                VpnStateBridge.activeDrawerScreen.value = "SETTINGS"
                                scope.launch { pagerState.animateScrollToPage(3) }
                            },
                            icon = { Text("⚙️", fontSize = 18.sp) },
                            label = { Text("Settings") }
                        )
                    }
                }
            ) { innerPadding ->
                HorizontalPager(
                    state = pagerState,
                    beyondBoundsPageCount = 3,
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(innerPadding)
                ) { page ->
                    when (page) {
                        0 -> HomeScreen(
                            isConnected = isConnected,
                            activeProfile = activeProfile,
                            selectedCount = selectedProfiles.size.coerceAtLeast(1),
                            onToggleConnection = {
                                if (activeProfile == null) scope.launch { pagerState.animateScrollToPage(1) }
                                else toggleVpn(connectionState != "DISCONNECTED")
                            },
                            onPingClick = { viewModel.executeConnectedPing(activeProfile) }
                        )
                        1 -> Box(modifier = Modifier.fillMaxSize()) {
                            ConfigsScreen(
                                profiles = profiles,
                                onSelectProfile = { viewModel.toggleProfileSelection(it) },
                                onDeleteProfile = { viewModel.deleteProfile(it) },
                                onDuplicateProfile = { viewModel.duplicateProfile(it) },
                                onPingProfile = { viewModel.pingSingleProfile(it) },
                                onPingAllProfiles = { viewModel.pingAllProfiles() },
                                onImportClipboard = { handleUniversalImport(it) },
                                onSaveProfile = { viewModel.saveManualProfile(it) }
                            )
                            if (exportableTickedProfiles.size > 1) {
                                ExtendedFloatingActionButton(
                                    onClick = { showMultiTickExportModal = true },
                                    containerColor = RoyalGold,
                                    contentColor = Color(0xFF1A0933),
                                    modifier = Modifier
                                        .align(Alignment.BottomEnd)
                                        .padding(16.dp)
                                ) {
                                    Text(
                                        text = "📦 Export ${exportableTickedProfiles.size} Ticked Configs",
                                        fontWeight = FontWeight.ExtraBold,
                                        fontSize = 12.sp
                                    )
                                }
                            }
                        }
                        2 -> LogsScreen(logs = viewModel.logs.collectAsState().value)
                        3 -> {
                            if (activeDrawerScreen in listOf("RESPONSE_CHECKER", "SHARENET", "NETWORK_TOOLS", "PAYLOAD_GEN")) {
                                Column(modifier = Modifier.fillMaxSize()) {
                                    Surface(
                                        color = Color(0xFF170B2C),
                                        border = BorderStroke(0.5.dp, RoyalGold.copy(alpha = 0.5f)),
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        Row(
                                            modifier = Modifier
                                                .fillMaxWidth()
                                                .clickable {
                                                    VpnStateBridge.activeDrawerScreen.value = "SETTINGS"
                                                }
                                                .padding(horizontal = 16.dp, vertical = 10.dp),
                                            verticalAlignment = Alignment.CenterVertically,
                                            horizontalArrangement = Arrangement.SpaceBetween
                                        ) {
                                            Text(
                                                text = "← Back to Techfeeds-VPN V$CURRENT_VERSION_NAME Settings",
                                                color = RoyalGold,
                                                fontWeight = FontWeight.ExtraBold,
                                                fontSize = 13.sp
                                            )
                                            Text(
                                                text = "Settings",
                                                color = Color.White,
                                                fontWeight = FontWeight.SemiBold,
                                                fontSize = 12.sp
                                            )
                                        }
                                    }
                                    Box(modifier = Modifier.weight(1f)) {
                                        NetworkToolsScreen()
                                    }
                                }
                            } else {
                                SettingsScreen(viewModel = viewModel)
                            }
                        }
                    }
                }
            }
        }

        if (showMultiTickExportModal && exportableTickedProfiles.isNotEmpty()) {
            var bundleName by remember { mutableStateOf("Techfeeds_Multi_${exportableTickedProfiles.size}_Configs") }
            var lockBundle by remember { mutableStateOf(true) }
            var expiryDaysInput by remember { mutableStateOf("30") }
            var bundlePassword by remember { mutableStateOf("") }
            var targetHwid by remember { mutableStateOf("") }
            var customMessage by remember { mutableStateOf("") }
            var blockRoot by remember { mutableStateOf(false) }

            AlertDialog(
                onDismissRequest = { showMultiTickExportModal = false },
                title = {
                    Text(
                        text = "📦 Export ${exportableTickedProfiles.size} Ticked Configuration(s)",
                        fontWeight = FontWeight.ExtraBold,
                        fontSize = 16.sp,
                        color = RoyalGold
                    )
                },
                text = {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .verticalScroll(rememberScrollState()),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text(
                            text = "Ticked: " + exportableTickedProfiles.joinToString(", ") { it.name.ifBlank { it.protocol } },
                            fontSize = 12.sp,
                            color = CyberEmerald,
                            fontWeight = FontWeight.Bold
                        )
                        OutlinedTextField(
                            value = bundleName,
                            onValueChange = { bundleName = it },
                            label = { Text("Export File Name (.svpn)") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("🔒 Lock Configs (Hide Server Details)", fontSize = 13.sp, fontWeight = FontWeight.Bold)
                            Switch(checked = lockBundle, onCheckedChange = { lockBundle = it })
                        }
                        if (lockBundle) {
                            OutlinedTextField(
                                value = expiryDaysInput,
                                onValueChange = { expiryDaysInput = it.filter { ch -> ch.isDigit() } },
                                label = { Text("Validity (Days, 0 = Unlimited)") },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth()
                            )
                            OutlinedTextField(
                                value = bundlePassword,
                                onValueChange = { bundlePassword = it },
                                label = { Text("Optional Password Lock") },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth()
                            )
                            OutlinedTextField(
                                value = targetHwid,
                                onValueChange = { targetHwid = it },
                                label = { Text("Optional User HWID Lock (Comma-separated)") },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth()
                            )
                            OutlinedTextField(
                                value = customMessage,
                                onValueChange = { customMessage = it },
                                label = { Text("Custom Server Message / Notice") },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth()
                            )
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text("🛡️ Block Rooted Devices", fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                                Switch(checked = blockRoot, onCheckedChange = { blockRoot = it })
                            }
                        }

                        Spacer(modifier = Modifier.height(4.dp))
                        Button(
                            onClick = {
                                val days = expiryDaysInput.toIntOrNull() ?: 0
                                val bundleContent = exportTickedMultiBundle(
                                    selectedList = exportableTickedProfiles,
                                    lockConfig = lockBundle,
                                    passphrase = bundlePassword,
                                    expiryDays = days,
                                    lockedHwid = targetHwid,
                                    blockRoot = blockRoot,
                                    customMsg = customMessage
                                )
                                pendingFileExportContent = bundleContent
                                pendingFileExportToast = "Saved ${exportableTickedProfiles.size} config(s) to .svpn file!"
                                val safeFile = bundleName.replace(Regex("[^a-zA-Z0-9_-]"), "_").ifBlank { "Techfeeds_Bundle" }
                                showMultiTickExportModal = false
                                try {
                                    createDocumentFileLauncher.launch("$safeFile.svpn")
                                } catch (_: Throwable) {}
                            },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = RoyalGold,
                                contentColor = Color(0xFF1A0933)
                            ),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("💾 Save ${exportableTickedProfiles.size} Ticked Config(s) as .svpn File", fontWeight = FontWeight.ExtraBold, fontSize = 12.sp)
                        }

                        Button(
                            onClick = {
                                val days = expiryDaysInput.toIntOrNull() ?: 0
                                val bundleUri = exportTickedMultiBundle(
                                    selectedList = exportableTickedProfiles,
                                    lockConfig = lockBundle,
                                    passphrase = bundlePassword,
                                    expiryDays = days,
                                    lockedHwid = targetHwid,
                                    blockRoot = blockRoot,
                                    customMsg = customMessage
                                )
                                clipboardManager.setText(AnnotatedString(bundleUri))
                                viewModel.showToastPill("Copied ${exportableTickedProfiles.size} ticked config(s) bundle link!")
                                showMultiTickExportModal = false
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("📋 Copy Bundle Link to Clipboard", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                        }

                        if (!lockBundle) {
                            OutlinedButton(
                                onClick = {
                                    val multiUris = exportableTickedProfiles.joinToString("\n") { buildExportStandardUri(it) }
                                    clipboardManager.setText(AnnotatedString(multiUris))
                                    viewModel.showToastPill("Copied ${exportableTickedProfiles.size} Share URIs to clipboard!")
                                    showMultiTickExportModal = false
                                },
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text("🔗 Copy All as Open Share URIs (slipnet / dnst / vless)", fontWeight = FontWeight.Bold, fontSize = 11.sp)
                            }
                        }
                    }
                },
                confirmButton = {
                    TextButton(onClick = { showMultiTickExportModal = false }) {
                        Text("Close", fontWeight = FontWeight.Bold)
                    }
                }
            )
        }

        otaUpdateAvailable?.let { update ->
            AlertDialog(
                onDismissRequest = { otaUpdateAvailable = null },
                title = {
                    Text(
                        text = "🚀 Update Available (V${update.versionName})",
                        fontWeight = FontWeight.ExtraBold,
                        fontSize = 17.sp,
                        color = RoyalGold
                    )
                },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        Text(
                            text = "A new build (Build ${update.versionCode}) of Techfeeds-VPN is ready! Install it over your current app without losing your configs or active Secret Code.",
                            fontSize = 13.sp
                        )
                        Surface(
                            shape = RoundedCornerShape(12.dp),
                            color = MaterialTheme.colorScheme.surfaceVariant,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(
                                text = update.releaseNotes,
                                fontSize = 12.sp,
                                modifier = Modifier.padding(12.dp)
                            )
                        }
                    }
                },
                confirmButton = {
                    Button(
                        onClick = {
                            val url = update.apkUrl
                            otaUpdateAvailable = null
                            openExternalUrl(url)
                        },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = RoyalGold,
                            contentColor = Color(0xFF1A0933)
                        )
                    ) {
                        Text("⬇️ Download & Update Now", fontWeight = FontWeight.ExtraBold)
                    }
                },
                dismissButton = {
                    TextButton(onClick = { otaUpdateAvailable = null }) {
                        Text("Later")
                    }
                }
            )
        }

        if (showExitOrMinimizeModal) {
            AlertDialog(
                onDismissRequest = { showExitOrMinimizeModal = false },
                title = {
                    Text(
                        text = "🚪 Exit or Minimize Techfeeds-VPN",
                        fontWeight = FontWeight.ExtraBold,
                        fontSize = 17.sp
                    )
                },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        Text(
                            text = if (isConnected) {
                                "Your VPN tunnel is currently ACTIVE. Would you like to minimize the app to keep the VPN running in the background, or disconnect and exit completely?"
                            } else {
                                "Would you like to minimize Techfeeds-VPN to the background or close the application completely?"
                            },
                            fontSize = 13.sp
                        )
                        Button(
                            onClick = {
                                showExitOrMinimizeModal = false
                                moveTaskToBack(true)
                            },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = RoyalGold,
                                contentColor = Color(0xFF1A0933)
                            ),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("🗕 Minimize to Background (Keep Running)", fontWeight = FontWeight.ExtraBold, fontSize = 12.sp)
                        }
                        OutlinedButton(
                            onClick = {
                                showExitOrMinimizeModal = false
                                try {
                                    stopService(Intent(this@MainActivity, SmartVpnService::class.java))
                                } catch (_: Throwable) {}
                                finishAffinity()
                                exitProcess(0)
                            },
                            border = BorderStroke(1.dp, Color(0xFFFF5252)),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("✖ Disconnect & Exit App", color = Color(0xFFFF5252), fontWeight = FontWeight.ExtraBold, fontSize = 12.sp)
                        }
                    }
                },
                confirmButton = {
                    TextButton(onClick = { showExitOrMinimizeModal = false }) {
                        Text("Cancel", fontWeight = FontWeight.Bold)
                    }
                }
            )
        }

        if (showXrayUriJsonExportModal && activeProfile != null) {
            val generatedUri = remember(activeProfile) { buildExportStandardUri(activeProfile) }
            val generatedJson = remember(activeProfile) { buildExportPrettyXrayJson(activeProfile) }
            var selectedExportTab by remember { mutableStateOf(0) }

            AlertDialog(
                onDismissRequest = { showXrayUriJsonExportModal = false },
                title = {
                    Text(
                        text = "📤 Export Config (URI & JSON)",
                        fontWeight = FontWeight.ExtraBold,
                        fontSize = 16.sp
                    )
                },
                text = {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .verticalScroll(rememberScrollState()),
                        verticalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Button(
                                onClick = { selectedExportTab = 0 },
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = if (selectedExportTab == 0) RoyalGold else MaterialTheme.colorScheme.surfaceVariant,
                                    contentColor = if (selectedExportTab == 0) Color(0xFF1A0933) else MaterialTheme.colorScheme.onSurfaceVariant
                                ),
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("🔗 Share URI", fontWeight = FontWeight.ExtraBold, fontSize = 12.sp)
                            }
                            Button(
                                onClick = { selectedExportTab = 1 },
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = if (selectedExportTab == 1) RoyalGold else MaterialTheme.colorScheme.surfaceVariant,
                                    contentColor = if (selectedExportTab == 1) Color(0xFF1A0933) else MaterialTheme.colorScheme.onSurfaceVariant
                                ),
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("📄 Xray JSON", fontWeight = FontWeight.ExtraBold, fontSize = 12.sp)
                            }
                        }

                        OutlinedTextField(
                            value = if (selectedExportTab == 0) generatedUri else generatedJson,
                            onValueChange = {},
                            readOnly = true,
                            label = {
                                Text(
                                    if (selectedExportTab == 0) "Standard Share URI (${activeProfile.protocol})"
                                    else "Full Xray-Core JSON Config"
                                )
                            },
                            modifier = Modifier
                                .fillMaxWidth()
                                .heightIn(min = 120.dp, max = 260.dp)
                        )

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Button(
                                onClick = {
                                    clipboardManager.setText(AnnotatedString(generatedUri))
                                    viewModel.showToastPill("Copied ${activeProfile.protocol} URI to clipboard!")
                                },
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("📋 Copy URI", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                            }
                            Button(
                                onClick = {
                                    clipboardManager.setText(AnnotatedString(generatedJson))
                                    viewModel.showToastPill("Copied JSON to clipboard!")
                                },
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("📋 Copy JSON", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                            }
                        }

                        OutlinedButton(
                            onClick = {
                                pendingFileExportContent = generatedJson
                                pendingFileExportToast = "Xray JSON saved to file!"
                                val cleanName = activeProfile.name.replace(Regex("[^a-zA-Z0-9_-]"), "_").ifBlank { "xray_config" }
                                try {
                                    createDocumentFileLauncher.launch("$cleanName.json")
                                } catch (_: Throwable) {}
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("💾 Save Config as .json File", fontWeight = FontWeight.Bold)
                        }
                    }
                },
                confirmButton = {
                    TextButton(onClick = { showXrayUriJsonExportModal = false }) {
                        Text("Done", fontWeight = FontWeight.Bold)
                    }
                }
            )
        }

        if (showCloudImportModal) {
            var cloudUrl by remember { mutableStateOf("") }
            var cloudPassphrase by remember { mutableStateOf("") }
            AlertDialog(
                onDismissRequest = { showCloudImportModal = false },
                title = { Text("☁️ Import Locked V1.2 / Cloud Config", fontWeight = FontWeight.ExtraBold) },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        Text("Paste the encrypted cloud URL, slipnet://, dnst://, or tfvpn:// link:", style = MaterialTheme.typography.bodySmall)
                        OutlinedTextField(
                            value = cloudUrl,
                            onValueChange = { cloudUrl = it },
                            label = { Text("Cloud URL or Config Link") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                        OutlinedTextField(
                            value = cloudPassphrase,
                            onValueChange = { cloudPassphrase = it },
                            label = { Text("Decryption Password (If Set)") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                },
                confirmButton = {
                    TextButton(onClick = {
                        if (cloudUrl.isNotBlank()) {
                            if (cloudUrl.startsWith("http://", true) || cloudUrl.startsWith("https://", true)) {
                                viewModel.importFromCloudUrl(cloudUrl, cloudPassphrase)
                            } else {
                                handleUniversalImport(cloudUrl, cloudPassphrase)
                            }
                            showCloudImportModal = false
                        }
                    }) { Text("Decrypt & Import", fontWeight = FontWeight.Bold) }
                },
                dismissButton = {
                    TextButton(onClick = { showCloudImportModal = false }) { Text("Cancel") }
                }
            )
        }

        if (showQrScannerModal) {
            var manualQrPayload by remember { mutableStateOf("") }
            var qrPassphrase by remember { mutableStateOf("") }
            AlertDialog(
                onDismissRequest = { showQrScannerModal = false },
                title = { Text("📷 Scan / Decrypt V1.2 QR Config", fontWeight = FontWeight.ExtraBold) },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        Text("Paste URI (tfvpn://, slipnet://, dnst://) or select a locked .svpn file:", style = MaterialTheme.typography.bodySmall)
                        OutlinedTextField(
                            value = manualQrPayload,
                            onValueChange = { manualQrPayload = it },
                            label = { Text("Config URI / QR Payload") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                        OutlinedTextField(
                            value = qrPassphrase,
                            onValueChange = { qrPassphrase = it },
                            label = { Text("Decryption Password (If Set)") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                        OutlinedButton(
                            onClick = {
                                showQrScannerModal = false
                                try { filePickerLauncher.launch("*/*") } catch (_: Throwable) {}
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) { Text("📁 Select .svpn File from Device") }
                    }
                },
                confirmButton = {
                    TextButton(onClick = {
                        if (manualQrPayload.isNotBlank()) {
                            handleUniversalImport(manualQrPayload, qrPassphrase)
                        }
                        showQrScannerModal = false
                    }) { Text("Decrypt & Import", fontWeight = FontWeight.Bold) }
                },
                dismissButton = {
                    TextButton(onClick = { showQrScannerModal = false }) { Text("Close") }
                }
            )
        }

        if (showThemeMenu) {
            AlertDialog(
                onDismissRequest = { showThemeMenu = false },
                title = { Text("Techfeeds-VPN V$CURRENT_VERSION_NAME Themes", fontWeight = FontWeight.ExtraBold, fontSize = 16.sp) },
                text = {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(max = 380.dp)
                            .verticalScroll(rememberScrollState()),
                        verticalArrangement = Arrangement.spacedBy(2.dp)
                    ) {
                        themeOptions.forEach { th ->
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        VpnStateBridge.themeMode.value = th
                                        VpnStateBridge.persistAllSettings(context)
                                        showThemeMenu = false
                                    }
                                    .padding(vertical = 6.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                RadioButton(
                                    selected = currentThemeMode == th,
                                    onClick = {
                                        VpnStateBridge.themeMode.value = th
                                        VpnStateBridge.persistAllSettings(context)
                                        showThemeMenu = false
                                    }
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Text(th, fontSize = 13.sp, fontWeight = if (currentThemeMode == th) FontWeight.Bold else FontWeight.Normal)
                            }
                        }
                    }
                },
                confirmButton = {
                    TextButton(onClick = { showThemeMenu = false }) { Text("Close") }
                }
            )
        }

        if (showAboutModal) {
            AlertDialog(
                onDismissRequest = { showAboutModal = false },
                title = { Text("Techfeeds-VPN V$CURRENT_VERSION_NAME", fontWeight = FontWeight.ExtraBold) },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("Version: V$CURRENT_VERSION_NAME (Build $CURRENT_BUILD_CODE • Exclusive Release)", fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.primary)
                        Text("Hardware 🆔: $hwid", fontFamily = FontFamily.Monospace, fontSize = 12.sp)
                        Text("Enterprise Multi-Protocol Stealth VPN supporting 25 protocols (including Slipstream-DNSTT & SlowDNS Multipath Swarm, Universal X25519/ECDH SSH Engine, Native Xray-Core, Multi-Tick Bundle Export, and Live OTA Updates).")
                    }
                },
                confirmButton = {
                    TextButton(onClick = {
                        clipboardManager.setText(AnnotatedString(hwid))
                        viewModel.showToastPill("Copied Hardware 🆔: $hwid")
                        showAboutModal = false
                    }) { Text("Copy HWID & Close") }
                }
            )
        }

        if (showUserManual) {
            TechfeedsUserManualDialog(onDismiss = { showUserManual = false })
        }
    }

    @Composable
    private fun TechfeedsUserManualDialog(onDismiss: () -> Unit) {
        var selectedTab by remember { mutableStateOf("All") }
        val tabs = listOf("All", "⚠️ Tips", "⚡ Speed & Mux", "🌐 Protocols", "⚖️ Multi-Tick", "🔒 Lock Vault")
        Dialog(onDismissRequest = onDismiss) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(520.dp)
                    .border(1.5.dp, MaterialTheme.colorScheme.primary, RoundedCornerShape(22.dp)),
                shape = RoundedCornerShape(22.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(
                    modifier = Modifier.fillMaxSize().padding(16.dp),
                    verticalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text("📖 Techfeeds-VPN V$CURRENT_VERSION_NAME Manual", fontWeight = FontWeight.ExtraBold, fontSize = 16.sp)
                            IconButton(onClick = onDismiss) { Icon(Icons.Default.Close, null) }
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            tabs.forEach { tab ->
                                val isSel = selectedTab == tab
                                Surface(
                                    shape = RoundedCornerShape(18.dp),
                                    color = if (isSel) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surfaceVariant,
                                    modifier = Modifier.clickable { selectedTab = tab }
                                ) {
                                    Text(
                                        text = tab,
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = if (isSel) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurfaceVariant,
                                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
                                    )
                                }
                            }
                        }
                        Spacer(modifier = Modifier.height(10.dp))
                        Column(
                            modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()),
                            verticalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            if (selectedTab in listOf("All", "⚠️ Tips")) {
                                ManualCard(
                                    "💡 Important Tips",
                                    "• Set Techfeeds-VPN battery usage to Unrestricted.\n• Copy any slipnet:// or dnst:// link directly from your server terminal and tap Import from Clipboard."
                                )
                            }
                            if (selectedTab in listOf("All", "⚡ Speed & Mux")) {
                                ManualCard(
                                    "🚀 Slipstream & SlowDNS Multipath Swarm",
                                    "• Slipstream-DNSTT races Direct NS UDP (:53 & :443), Recursive DNS, and DoH workers in parallel so whichever path responds first wins immediately."
                                )
                            }
                            if (selectedTab in listOf("All", "🌐 Protocols")) {
                                ManualCard(
                                    "🌐 25 Supported Protocols",
                                    "• SLIPSTREAM-DNSTT (slipnet://), SlowDNS (dnst://), UDPCUSTOM, 17 SSH/TLS/Payload modes, VMess, VLESS Reality, Trojan, Shadowsocks, and Hysteria2."
                                )
                            }
                            if (selectedTab in listOf("All", "⚖️ Multi-Tick")) {
                                ManualCard(
                                    "⚖️ Multi-Tick Export & Load Balancing",
                                    "• Tick multiple configs on the Configs tab and tap + -> Export Ticked Configs 📦 (or the floating button) to export them as a single .svpn file or bundle link."
                                )
                            }
                            if (selectedTab in listOf("All", "🔒 Lock Vault")) {
                                ManualCard(
                                    "🔒 V1.2-Exclusive Lock + URI/JSON Export",
                                    "• Lock single or multiple ticked configs with Expiration Days, Password, HWID Lock, and Custom Server Messages."
                                )
                            }
                        }
                    }
                    Button(
                        onClick = onDismiss,
                        colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary),
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("✓ Got It", fontWeight = FontWeight.Bold)
                    }
                }
            }
        }
    }

    @Composable
    private fun ManualCard(title: String, body: String) {
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(title, fontWeight = FontWeight.ExtraBold, fontSize = 13.sp, color = MaterialTheme.colorScheme.primary)
                Text(body, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }

    private fun openExternalUrl(url: String) {
        try {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)).apply { addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) })
        } catch (t: Throwable) {
            viewModel.showToastPill("Could not open link: ${t.message}")
        }
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                notificationPermissionRequest.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    private fun toggleVpn(isActiveOrConnecting: Boolean) {
        if (isActiveOrConnecting) {
            startService(Intent(this, SmartVpnService::class.java).apply { action = SmartVpnService.ACTION_STOP })
            VpnStateBridge.updateState("DISCONNECTED", "NOT CONNECTED")
        } else {
            requestNotificationPermissionIfNeeded()
            val intent = VpnService.prepare(this)
            if (intent != null) vpnRequest.launch(intent) else startVpnService()
        }
    }

    private fun startVpnService() {
        VpnStateBridge.updateState("CONNECTING", "CONNECTING...")
        ContextCompat.startForegroundService(
            this,
            Intent(this, SmartVpnService::class.java).apply { action = SmartVpnService.ACTION_START }
        )
    }

    private fun shareSmartVpnApp() {
        AppShareHelper.shareDownloadLink(this)
    }
}
