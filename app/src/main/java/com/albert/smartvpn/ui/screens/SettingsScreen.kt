package com.albert.smartvpn.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.widget.Toast
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.RadioButtonDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.albert.smartvpn.ui.viewmodel.AppShareHelper
import com.albert.smartvpn.ui.viewmodel.SecretCodeManager
import com.albert.smartvpn.ui.viewmodel.VpnStateBridge
import com.albert.smartvpn.ui.viewmodel.VpnViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket

private val BgDark = Color(0xFF0D061A)
private val CardDark = Color(0xFF170B2C)
private val CardBorderDark = Color(0xFF391E66)
private val AccentGold = Color(0xFFFFD54F)
private val AccentGoldBorder = Color(0xFF7A6221)
private val TextWhite = Color(0xFFF8F4FF)
private val TextMuted = Color(0xFFD1C4E9)
private val BlueCardBg = Color(0xFF1D1036)
private val BlueCardAccent = Color(0xFFB388FF)

private data class DohProviderItem(
    val id: String,
    val title: String,
    val badgeText: String,
    val badgeColor: Color,
    val description: String,
    val endpointIp: String,
    val dohUrl: String,
    val category: String
)

private data class InstalledAppEntry(
    val appName: String,
    val packageName: String,
    val isSystemApp: Boolean
)

@Composable
fun SettingsScreen(viewModel: VpnViewModel? = null) {
    val context = LocalContext.current

    LaunchedEffect(Unit) {
        VpnStateBridge.initPrefs(context)
    }

    val appLogLevel by VpnStateBridge.appLogLevel.collectAsState()
    val cpuWakeLock by VpnStateBridge.cpuWakeLock.collectAsState()
    val autoReconnect by VpnStateBridge.autoReconnect.collectAsState()
    val autoReconnectMaxRetries by VpnStateBridge.autoReconnectMaxRetries.collectAsState()
    val startOnBoot by VpnStateBridge.startOnBoot.collectAsState()
    val hapticFeedback by VpnStateBridge.hapticFeedback.collectAsState()
    val soundEffects by VpnStateBridge.soundEffects.collectAsState()
    val floatingSpeedBubble by VpnStateBridge.floatingSpeedBubble.collectAsState()
    val statusBarSpeedTicker by VpnStateBridge.statusBarSpeedTicker.collectAsState()

    val roundRobinEnabled by VpnStateBridge.loadBalancingEnabled.collectAsState()
    val loadBalancingStrategy by VpnStateBridge.loadBalancingStrategy.collectAsState()

    val socksBufferSize by VpnStateBridge.socksBufferSize.collectAsState()

    val allowInsecureTls by VpnStateBridge.allowInsecureTls.collectAsState()
    val xrayMuxEnabled by VpnStateBridge.xrayMuxEnabled.collectAsState()
    val enableFragment by VpnStateBridge.enableFragment.collectAsState()
    val globalUtlsFingerprint by VpnStateBridge.globalUtlsFingerprint.collectAsState()
    val domainStrategy by VpnStateBridge.domainStrategy.collectAsState()
    val localSocksPort by VpnStateBridge.localSocksPort.collectAsState()

    val sshKeepAlive by VpnStateBridge.sshKeepAlive.collectAsState()
    val sshCompression by VpnStateBridge.sshCompression.collectAsState()
    val tcpNoDelay by VpnStateBridge.tcpNoDelay.collectAsState()
    val sshTimeoutSec by VpnStateBridge.sshTimeoutSec.collectAsState()
    val pingIntervalSec by VpnStateBridge.pingIntervalSec.collectAsState()

    val udpgwPort by VpnStateBridge.udpgwPort.collectAsState()

    val inAppKillSwitch by VpnStateBridge.inAppKillSwitch.collectAsState()
    val customMtu by VpnStateBridge.customMtu.collectAsState()
    val enableDns by VpnStateBridge.enableDns.collectAsState()
    val selectedDohName by VpnStateBridge.selectedDohProfileName.collectAsState()
    val selectedDohEndpoint by VpnStateBridge.selectedDohProfileEndpoint.collectAsState()
    val udpForwarding by VpnStateBridge.udpForwarding.collectAsState()
    val udpCustomEnabled by VpnStateBridge.udpCustomEnabled.collectAsState()
    val bypassLanPrivateIps by VpnStateBridge.bypassLanPrivateIps.collectAsState()
    val bypassChinaIps by VpnStateBridge.bypassChinaIps.collectAsState()
    val blockAdsTrackers by VpnStateBridge.blockAdsTrackers.collectAsState()

    val turboSpeedEnabled by VpnStateBridge.turboSpeedEnabled.collectAsState()
    val slowDnsBoostEnabled by VpnStateBridge.slowDnsBoostEnabled.collectAsState()
    val customDns1 by VpnStateBridge.customDns1.collectAsState()
    val customDns2 by VpnStateBridge.customDns2.collectAsState()
    val hotshareEnabled by VpnStateBridge.hotshareEnabled.collectAsState()
    val hotshareIp by VpnStateBridge.hotshareIp.collectAsState()
    val shareNetPort by VpnStateBridge.shareNetPort.collectAsState()
    val themeMode by VpnStateBridge.themeMode.collectAsState()
    val dynamicColorEnabled by VpnStateBridge.dynamicColorEnabled.collectAsState()
    val themeContrast by VpnStateBridge.themeContrast.collectAsState()
    val codeExpiresAtMs by VpnStateBridge.secretCodeExpiresAtMs.collectAsState()

    var remainingAccessTime by remember { mutableStateOf("Active") }
    LaunchedEffect(codeExpiresAtMs) {
        while (codeExpiresAtMs > 0L) {
            val rem = (codeExpiresAtMs - System.currentTimeMillis()).coerceAtLeast(0L)
            remainingAccessTime = SecretCodeManager.formatRemainingTime(rem)
            delay(1000L)
        }
    }

    var localPortInput by remember(localSocksPort) { mutableStateOf(localSocksPort.toString()) }
    var sshTimeoutInput by remember(sshTimeoutSec) { mutableStateOf(sshTimeoutSec.toString()) }
    var pingIntervalInput by remember(pingIntervalSec) { mutableStateOf(pingIntervalSec.toString()) }
    var udpgwPortInput by remember(udpgwPort) { mutableStateOf(udpgwPort.toString()) }
    var customMtuInput by remember(customMtu) { mutableStateOf(customMtu.toString()) }
    var sharePortInput by remember(shareNetPort) { mutableStateOf(shareNetPort.toString()) }

    var showShareDialog by remember { mutableStateOf(false) }
    var showDohManagerDialog by remember { mutableStateOf(false) }
    var showSplitTunnelDialog by remember { mutableStateOf(false) }
    var showPrivacyPolicyDialog by remember { mutableStateOf(false) }

    val deviceHardwareId = remember { VpnStateBridge.getDeviceHardwareId(context) }

    fun notifyToast(msg: String) {
        viewModel?.showToastPill(msg)
        Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
    }

    fun persist() {
        VpnStateBridge.persistAllSettings(context)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(BgDark)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 14.dp)
    ) {
        Text(
            text = "Techfeeds-VPN V1.2 Settings",
            color = TextWhite,
            fontSize = 22.sp,
            fontWeight = FontWeight.ExtraBold,
            modifier = Modifier.padding(bottom = 14.dp)
        )

        // =========================================================================
        // 1. GENERAL SECTION
        // =========================================================================
        SectionHeaderLabel("GENERAL")

        Surface(
            color = Color(0xFF1F1038),
            shape = RoundedCornerShape(12.dp),
            border = BorderStroke(1.dp, AccentGoldBorder),
            modifier = Modifier
                .fillMaxWidth()
                .clickable {
                    try {
                        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        cm.setPrimaryClip(ClipData.newPlainText("Techfeeds-VPN V1.2 Hardware ID", deviceHardwareId))
                        notifyToast("Hardware ID copied: $deviceHardwareId")
                    } catch (_: Throwable) {}
                }
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 14.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "Device Hardware ID",
                        color = AccentGold,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = deviceHardwareId,
                        color = TextWhite,
                        fontSize = 18.sp,
                        fontWeight = FontWeight.ExtraBold,
                        fontFamily = FontFamily.Monospace,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                Text(
                    text = "Copy",
                    color = AccentGold,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(start = 12.dp)
                )
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        // Active V1.2 Secret Access Code Status Card
        Surface(
            color = CardDark,
            shape = RoundedCornerShape(12.dp),
            border = BorderStroke(1.dp, AccentGoldBorder),
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "🔑 V1.2 Secret Code Session",
                        color = AccentGold,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(modifier = Modifier.height(2.dp))
                    Text(
                        text = "Remaining Time: $remainingAccessTime",
                        color = TextWhite,
                        fontSize = 14.sp,
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.ExtraBold
                    )
                }
                TextButton(
                    onClick = {
                        SecretCodeManager.clearExpiredAccess(context)
                        notifyToast("Enter a new TFV12 Secret Code")
                    }
                ) {
                    Text(
                        text = "Change Code",
                        color = AccentGold,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.ExtraBold
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        // Share Techfeeds-VPN V1.2 Card
        Surface(
            color = CardDark,
            shape = RoundedCornerShape(12.dp),
            border = BorderStroke(1.dp, AccentGoldBorder),
            modifier = Modifier
                .fillMaxWidth()
                .clickable { showShareDialog = true }
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 14.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(
                        imageVector = Icons.Default.Share,
                        contentDescription = "Share Techfeeds-VPN V1.2",
                        tint = AccentGold,
                        modifier = Modifier.size(22.dp)
                    )
                    Spacer(modifier = Modifier.width(14.dp))
                    Column {
                        Text(
                            text = "Share Techfeeds-VPN V1.2",
                            color = TextWhite,
                            fontSize = 16.sp,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = "Send V1.2 APK installer or share download link",
                            color = TextMuted,
                            fontSize = 12.sp
                        )
                    }
                }
                Text(
                    text = "Share",
                    color = AccentGold,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(start = 12.dp)
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "App Log Level",
            color = TextWhite,
            fontSize = 14.sp,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(bottom = 8.dp)
        )
        SettingsPillDropdown(
            selectedValue = appLogLevel,
            options = listOf("Debug", "Info", "Warning", "Error", "None"),
            onValueSelected = { level ->
                VpnStateBridge.appLogLevel.value = level
                persist()
                notifyToast("Log Level: $level")
            }
        )

        Spacer(modifier = Modifier.height(12.dp))

        SettingsToggleRow(
            title = "CPU WakeLock",
            subtitle = "Prevent CPU from sleeping in background",
            checked = cpuWakeLock,
            onCheckedChange = { enabled ->
                VpnStateBridge.cpuWakeLock.value = enabled
                persist()
                notifyToast(if (enabled) "CPU WakeLock Enabled" else "CPU WakeLock Disabled")
            }
        )

        AnimatedVisibility(visible = cpuWakeLock) {
            Surface(
                color = Color(0xFF1F1038),
                shape = RoundedCornerShape(12.dp),
                border = BorderStroke(1.dp, AccentGoldBorder),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 6.dp, bottom = 8.dp)
                    .clickable {
                        try {
                            val intent = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS).apply {
                                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            }
                            context.startActivity(intent)
                        } catch (_: Throwable) {
                            try {
                                val fallback = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                                    data = Uri.fromParts("package", context.packageName, null)
                                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                }
                                context.startActivity(fallback)
                            } catch (_: Throwable) {}
                        }
                    }
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 14.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.weight(1f)
                    ) {
                        Text(
                            text = "⚡",
                            fontSize = 18.sp,
                            modifier = Modifier.padding(end = 10.dp)
                        )
                        Column {
                            Text(
                                text = "Disable Battery Optimization",
                                color = TextWhite,
                                fontSize = 14.sp,
                                fontWeight = FontWeight.Bold
                            )
                            Text(
                                text = "Tap to exempt Techfeeds-VPN V1.2 from OEM background killing",
                                color = TextMuted,
                                fontSize = 11.sp
                            )
                        }
                    }
                    Text(
                        text = "Settings",
                        color = AccentGold,
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(start = 8.dp)
                    )
                }
            }
        }

        SettingsToggleRow(
            title = "Auto Reconnect",
            subtitle = "Reconnect if tunnel drops",
            checked = autoReconnect,
            onCheckedChange = { enabled ->
                VpnStateBridge.autoReconnect.value = enabled
                persist()
                notifyToast(if (enabled) "Auto Reconnect Enabled" else "Auto Reconnect Disabled")
            }
        )
        AnimatedVisibility(visible = autoReconnect) {
            Column(modifier = Modifier.padding(top = 6.dp, bottom = 8.dp)) {
                SettingsPillDropdown(
                    selectedValue = "Max Retries: $autoReconnectMaxRetries",
                    options = listOf("Infinite", "3", "5", "10"),
                    onValueSelected = { retries ->
                        VpnStateBridge.autoReconnectMaxRetries.value = retries
                        persist()
                        notifyToast("Max Retries: $retries")
                    }
                )
            }
        }

        SettingsToggleRow(
            title = "Start on Boot",
            subtitle = "Auto-connect when device boots up",
            checked = startOnBoot,
            onCheckedChange = { enabled ->
                VpnStateBridge.startOnBoot.value = enabled
                persist()
                notifyToast(if (enabled) "Start on Boot Enabled" else "Start on Boot Disabled")
            }
        )

        SettingsToggleRow(
            title = "Haptic Feedback",
            subtitle = "Vibrate on connect, disconnect & clicks",
            checked = hapticFeedback,
            onCheckedChange = { enabled ->
                VpnStateBridge.hapticFeedback.value = enabled
                persist()
            }
        )

        SettingsToggleRow(
            title = "Sound Effects",
            subtitle = "Audio chime on connect & disconnect",
            checked = soundEffects,
            onCheckedChange = { enabled ->
                VpnStateBridge.soundEffects.value = enabled
                persist()
            }
        )

        SettingsToggleRow(
            title = "Floating Speed Bubble",
            subtitle = "Draggable overlay displaying live speeds over other apps",
            checked = floatingSpeedBubble,
            onCheckedChange = { enabled ->
                if (enabled && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && !Settings.canDrawOverlays(context)) {
                    notifyToast("Please allow 'Display over other apps'")
                    try {
                        val overlayIntent = Intent(
                            Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                            Uri.parse("package:${context.packageName}")
                        ).apply { addFlags(Intent.FLAG_ACTIVITY_NEW_TASK) }
                        context.startActivity(overlayIntent)
                    } catch (_: Throwable) {}
                } else {
                    VpnStateBridge.floatingSpeedBubble.value = enabled
                    persist()
                    notifyToast(if (enabled) "Floating Speed Bubble Enabled" else "Floating Speed Bubble Disabled")
                }
            }
        )

        SettingsToggleRow(
            title = "Status Bar Speed Ticker",
            subtitle = "Display live upload/download speed in ongoing notification",
            checked = statusBarSpeedTicker,
            onCheckedChange = { enabled ->
                VpnStateBridge.statusBarSpeedTicker.value = enabled
                persist()
            }
        )

        SectionDivider()

        // =========================================================================
        // 2. LOAD BALANCING SECTION
        // =========================================================================
        SectionHeaderLabel("LOAD BALANCING")

        SettingsToggleRow(
            title = "Round-Robin Load Balancing",
            subtitle = "Distribute outgoing connections across all active nodes & channels",
            checked = roundRobinEnabled,
            onCheckedChange = { enabled ->
                VpnStateBridge.setRoundRobin(enabled)
                if (enabled) {
                    VpnStateBridge.loadBalancingStrategy.value = "Round Robin"
                }
                persist()
                notifyToast("Round-Robin Load Balancing: ${if (enabled) "ON" else "OFF"}")
            }
        )

        Spacer(modifier = Modifier.height(6.dp))
        Text(
            text = "Strategy",
            color = TextWhite,
            fontSize = 14.sp,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(bottom = 8.dp)
        )
        SettingsPillDropdown(
            selectedValue = loadBalancingStrategy,
            options = listOf("Round Robin", "Random", "Ping (Fastest)"),
            onValueSelected = { strategy ->
                VpnStateBridge.loadBalancingStrategy.value = strategy
                VpnStateBridge.loadBalancingEnabled.value = (strategy == "Round Robin" || strategy == "Random")
                persist()
                notifyToast("Load Balancing Strategy: $strategy")
            }
        )

        SectionDivider()

        // =========================================================================
        // 3. SSH SETTINGS SECTION
        // =========================================================================
        SectionHeaderLabel("SSH SETTINGS")

        Text(
            text = "SOCKS Proxy Buffer Size",
            color = TextWhite,
            fontSize = 15.sp,
            fontWeight = FontWeight.Bold
        )
        Text(
            text = "Increases throughput for high-speed SSH & SlowDNS load balancing",
            color = TextMuted,
            fontSize = 12.sp,
            modifier = Modifier.padding(bottom = 8.dp)
        )
        SettingsPillDropdown(
            selectedValue = socksBufferSize,
            options = listOf(
                "1 MB (Standard)",
                "2 MB (Fast)",
                "4 MB (Ultra Speed)",
                "8 MB (Extreme)"
            ),
            onValueSelected = { buf ->
                VpnStateBridge.socksBufferSize.value = buf
                VpnStateBridge.turboSpeedEnabled.value = !buf.startsWith("1 MB")
                persist()
                notifyToast("SOCKS Buffer Size: $buf")
            }
        )

        SectionDivider()

        // =========================================================================
        // 4. V2RAY / XRAY SETTINGS SECTION
        // =========================================================================
        SectionHeaderLabel("V2RAY / XRAY SETTINGS")

        SettingsToggleRow(
            title = "Allow Insecure (TLS)",
            subtitle = null,
            checked = allowInsecureTls,
            onCheckedChange = { enabled ->
                VpnStateBridge.allowInsecureTls.value = enabled
                persist()
            }
        )

        SettingsToggleRow(
            title = "Enable Mux (Multiplexing)",
            subtitle = "Reduces latency and handshake overhead by routing multiple connections through a single TCP connection",
            checked = xrayMuxEnabled,
            onCheckedChange = { enabled ->
                VpnStateBridge.xrayMuxEnabled.value = enabled
                persist()
            }
        )

        SettingsToggleRow(
            title = "Enable Fragment",
            subtitle = "DPI Bypass: Fragment TLS Handshake packets",
            checked = enableFragment,
            onCheckedChange = { enabled ->
                VpnStateBridge.enableFragment.value = enabled
                persist()
            }
        )

        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = "Global uTLS Fingerprint",
            color = TextWhite,
            fontSize = 14.sp,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(bottom = 8.dp)
        )
        SettingsPillDropdown(
            selectedValue = globalUtlsFingerprint,
            options = listOf("Chrome", "Firefox", "Safari", "iOS", "Android", "Edge", "Randomized"),
            onValueSelected = { fp ->
                VpnStateBridge.globalUtlsFingerprint.value = fp
                persist()
            }
        )

        Spacer(modifier = Modifier.height(12.dp))
        Text(
            text = "Domain Strategy",
            color = TextWhite,
            fontSize = 14.sp,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(bottom = 8.dp)
        )
        SettingsPillDropdown(
            selectedValue = domainStrategy,
            options = listOf("AsIs", "IPIfNonMatch", "IPOnDemand", "UseIPv4"),
            onValueSelected = { ds ->
                VpnStateBridge.domainStrategy.value = ds
                persist()
            }
        )

        Spacer(modifier = Modifier.height(14.dp))
        SettingsOutlinedNumberField(
            label = "Local Proxy Port",
            value = localPortInput,
            onValueChange = { text ->
                localPortInput = text.filter { it.isDigit() }
                val port = localPortInput.toIntOrNull()
                if (port != null && port in 1025..65534) {
                    VpnStateBridge.localSocksPort.value = port
                    persist()
                }
            }
        )

        SectionDivider()

        // =========================================================================
        // 5. SSH ADVANCED SETTINGS SECTION
        // =========================================================================
        SectionHeaderLabel("SSH ADVANCED SETTINGS")

        SettingsToggleRow(
            title = "KeepAlive",
            subtitle = "Ping Server KeepAlive",
            checked = sshKeepAlive,
            onCheckedChange = { enabled ->
                VpnStateBridge.sshKeepAlive.value = enabled
                persist()
            }
        )

        SettingsToggleRow(
            title = "Compress",
            subtitle = "Zlib Data Compression (Auto-enabled on SlowDNS)",
            checked = sshCompression,
            onCheckedChange = { enabled ->
                VpnStateBridge.sshCompression.value = enabled
                persist()
            }
        )

        SettingsToggleRow(
            title = "TCP_NODELAY",
            subtitle = "Low latency gaming mode",
            checked = tcpNoDelay,
            onCheckedChange = { enabled ->
                VpnStateBridge.tcpNoDelay.value = enabled
                persist()
            }
        )

        Spacer(modifier = Modifier.height(10.dp))
        SettingsOutlinedNumberField(
            label = "Timeout Connection (Sec)",
            value = sshTimeoutInput,
            onValueChange = { text ->
                sshTimeoutInput = text.filter { it.isDigit() }
                val sec = sshTimeoutInput.toIntOrNull()
                if (sec != null && sec in 1..120) {
                    VpnStateBridge.sshTimeoutSec.value = sec
                    persist()
                }
            }
        )

        Spacer(modifier = Modifier.height(10.dp))
        SettingsOutlinedNumberField(
            label = "SSH KeepAlive Ping Interval (Sec)",
            value = pingIntervalInput,
            onValueChange = { text ->
                pingIntervalInput = text.filter { it.isDigit() }
                val sec = pingIntervalInput.toIntOrNull()
                if (sec != null && sec in 5..120) {
                    VpnStateBridge.pingIntervalSec.value = sec
                    persist()
                }
            }
        )

        SectionDivider()

        // =========================================================================
        // 6. TUN2SOCKS / LEGACY SECTION
        // =========================================================================
        SectionHeaderLabel("TUN2SOCKS / LEGACY")

        SettingsOutlinedNumberField(
            label = "UDPGW Port",
            value = udpgwPortInput,
            onValueChange = { text ->
                udpgwPortInput = text.filter { it.isDigit() }
                val p = udpgwPortInput.toIntOrNull()
                if (p != null && p in 1..65535) {
                    VpnStateBridge.udpgwPort.value = p
                    persist()
                }
            }
        )

        SectionDivider()

        // =========================================================================
        // 7. VPN, ROUTING & KILL SWITCH SECTION
        // =========================================================================
        SectionHeaderLabel("VPN, ROUTING & KILL SWITCH")

        Surface(
            color = BlueCardBg,
            shape = RoundedCornerShape(12.dp),
            border = BorderStroke(1.dp, BlueCardAccent.copy(alpha = 0.5f)),
            modifier = Modifier
                .fillMaxWidth()
                .clickable {
                    try {
                        val vpnSettingsIntent = Intent(Settings.ACTION_VPN_SETTINGS).apply {
                            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        }
                        context.startActivity(vpnSettingsIntent)
                    } catch (_: Throwable) {}
                }
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 14.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "Android System Always-On VPN",
                        color = BlueCardAccent,
                        fontSize = 15.sp,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(modifier = Modifier.height(3.dp))
                    Text(
                        text = "Open device settings to enable 'Always-on VPN' and 'Block connections without VPN' (System Kill Switch)",
                        color = TextMuted,
                        fontSize = 12.sp
                    )
                }
                Spacer(modifier = Modifier.width(12.dp))
                Icon(
                    imageVector = Icons.Default.Settings,
                    contentDescription = "System VPN Settings",
                    tint = BlueCardAccent,
                    modifier = Modifier.size(22.dp)
                )
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        SettingsToggleRow(
            title = "In-App Kill Switch",
            subtitle = "Block non-VPN traffic and prevent data leaks when tunnel drops",
            checked = inAppKillSwitch,
            onCheckedChange = { enabled ->
                VpnStateBridge.inAppKillSwitch.value = enabled
                persist()
                notifyToast(
                    if (enabled) "In-App Kill Switch Enabled: Non-VPN traffic will be blocked"
                    else "In-App Kill Switch Disabled"
                )
            }
        )

        Spacer(modifier = Modifier.height(8.dp))

        SettingsOutlinedNumberField(
            label = "Custom MTU",
            value = customMtuInput,
            onValueChange = { text ->
                customMtuInput = text.filter { it.isDigit() }
                val mtu = customMtuInput.toIntOrNull()
                if (mtu != null && mtu in 1200..1500) {
                    VpnStateBridge.customMtu.value = mtu
                    persist()
                }
            }
        )
        Text(
            text = "Range: 1200 - 1500 (Default: 1500, Mobile: 1280-1400)",
            color = TextMuted,
            fontSize = 11.sp,
            modifier = Modifier.padding(start = 12.dp, top = 4.dp, bottom = 10.dp)
        )

        SettingsToggleRow(
            title = "Enable DNS",
            subtitle = null,
            checked = enableDns,
            onCheckedChange = { enabled ->
                VpnStateBridge.enableDns.value = enabled
                persist()
                notifyToast(
                    if (enabled) "DNS Enabled: Custom routing active"
                    else "DNS Disabled"
                )
            }
        )

        AnimatedVisibility(visible = enableDns) {
            Column(modifier = Modifier.padding(top = 8.dp, bottom = 8.dp)) {
                Text(
                    text = "Encrypted DNS Profile (DoH/DoT)",
                    color = TextWhite,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(bottom = 8.dp)
                )
                Surface(
                    color = CardDark,
                    shape = RoundedCornerShape(12.dp),
                    border = BorderStroke(1.dp, CardBorderDark),
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { showDohManagerDialog = true }
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 14.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = selectedDohName,
                                color = TextWhite,
                                fontSize = 15.sp,
                                fontWeight = FontWeight.Bold
                            )
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(
                                text = selectedDohEndpoint,
                                color = TextMuted,
                                fontSize = 12.sp
                            )
                        }
                        Button(
                            onClick = { showDohManagerDialog = true },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = AccentGold,
                                contentColor = Color.Black
                            ),
                            shape = RoundedCornerShape(50),
                            contentPadding = PaddingValues(horizontal = 18.dp, vertical = 8.dp)
                        ) {
                            Text(
                                text = "Change",
                                fontWeight = FontWeight.Bold,
                                fontSize = 13.sp
                            )
                        }
                    }
                }
            }
        }

        SettingsToggleRow(
            title = "UDP Forwarding",
            subtitle = null,
            checked = udpForwarding,
            onCheckedChange = { enabled ->
                VpnStateBridge.udpForwarding.value = enabled
                persist()
            }
        )

        SettingsToggleRow(
            title = "UDP Custom Protocol",
            subtitle = "Bypass DPI on UDP",
            checked = udpCustomEnabled,
            onCheckedChange = { enabled ->
                VpnStateBridge.udpCustomEnabled.value = enabled
                persist()
                notifyToast(
                    if (enabled) "UDP Custom Enabled: Protocol unlocked"
                    else "UDP Custom Disabled"
                )
            }
        )

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                text = "Split Tunneling",
                color = TextWhite,
                fontSize = 16.sp,
                fontWeight = FontWeight.Bold
            )
            Button(
                onClick = {
                    notifyToast("Opening Split Tunneling Configuration")
                    showSplitTunnelDialog = true
                },
                colors = ButtonDefaults.buttonColors(
                    containerColor = AccentGold,
                    contentColor = Color.Black
                ),
                shape = RoundedCornerShape(50),
                contentPadding = PaddingValues(horizontal = 22.dp, vertical = 10.dp)
            ) {
                Text(
                    text = "Configure",
                    fontWeight = FontWeight.Bold,
                    fontSize = 13.sp
                )
            }
        }

        SettingsToggleRow(
            title = "Bypass LAN & Private IPs",
            subtitle = null,
            checked = bypassLanPrivateIps,
            onCheckedChange = { enabled ->
                VpnStateBridge.bypassLanPrivateIps.value = enabled
                persist()
            }
        )

        SettingsToggleRow(
            title = "Bypass China IPs (GeoIP)",
            subtitle = null,
            checked = bypassChinaIps,
            onCheckedChange = { enabled ->
                VpnStateBridge.bypassChinaIps.value = enabled
                persist()
                notifyToast(if (enabled) "China IPs Bypassed" else "China IPs Routed")
            }
        )

        SettingsToggleRow(
            title = "Block Ads & Trackers",
            subtitle = null,
            checked = blockAdsTrackers,
            onCheckedChange = { enabled ->
                VpnStateBridge.blockAdsTrackers.value = enabled
                if (enabled) {
                    VpnStateBridge.selectedDohProfileName.value = "AdGuard DNS"
                    VpnStateBridge.selectedDohProfileEndpoint.value = "94.140.14.14"
                    VpnStateBridge.customDns1.value = "94.140.14.14"
                }
                persist()
                notifyToast(
                    if (enabled) "Ad Blocker Enabled: Tracker domains blocked"
                    else "Ad Blocker Disabled"
                )
            }
        )

        SectionDivider()

        // =========================================================================
        // 8. TECHFEEDS-VPN V1.2 TURBO, HOTSHARE & APPEARANCE
        // =========================================================================
        SectionHeaderLabel("TECHFEEDS-VPN V1.2 TURBO, HOTSHARE & APPEARANCE")

        SettingsToggleRow(
            title = "Turbo Speed Engine (6x Multiplexed SSH)",
            subtitle = "Accelerate SSH, SlowDNS, OpenVPN, Shadowsocks & Vless streams",
            checked = turboSpeedEnabled,
            onCheckedChange = { enabled ->
                VpnStateBridge.turboSpeedEnabled.value = enabled
                persist()
                notifyToast(if (enabled) "Turbo Speed Enabled" else "Turbo Speed Disabled")
            }
        )

        SettingsToggleRow(
            title = "SlowDNS High-Speed KCP + Zlib Boost",
            subtitle = "Auto-extracts native libdnstt.so and stripes parallel KCP streams",
            checked = slowDnsBoostEnabled,
            onCheckedChange = { enabled ->
                VpnStateBridge.slowDnsBoostEnabled.value = enabled
                persist()
            }
        )

        Spacer(modifier = Modifier.height(8.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Box(modifier = Modifier.weight(1f)) {
                SettingsOutlinedTextField(
                    label = "Primary DNS",
                    value = customDns1,
                    onValueChange = {
                        VpnStateBridge.customDns1.value = it.trim()
                        persist()
                    }
                )
            }
            Box(modifier = Modifier.weight(1f)) {
                SettingsOutlinedTextField(
                    label = "Secondary DNS",
                    value = customDns2,
                    onValueChange = {
                        VpnStateBridge.customDns2.value = it.trim()
                        persist()
                    }
                )
            }
        }

        Spacer(modifier = Modifier.height(10.dp))
        SettingsToggleRow(
            title = "Hotshare (Wi-Fi Tethering Proxy)",
            subtitle = "Share active Techfeeds-VPN V1.2 connection over Wi-Fi Hotspot ($hotshareIp:$shareNetPort)",
            checked = hotshareEnabled,
            onCheckedChange = { enabled ->
                VpnStateBridge.hotshareEnabled.value = enabled
                persist()
                notifyToast(if (enabled) "Hotshare Proxy Enabled on port $shareNetPort" else "Hotshare Proxy Disabled")
            }
        )
        AnimatedVisibility(visible = hotshareEnabled) {
            Column(modifier = Modifier.padding(top = 6.dp, bottom = 8.dp)) {
                SettingsOutlinedNumberField(
                    label = "Hotshare Proxy Port",
                    value = sharePortInput,
                    onValueChange = { text ->
                        sharePortInput = text.filter { it.isDigit() }
                        val p = sharePortInput.toIntOrNull()
                        if (p != null && p in 1025..65534) {
                            VpnStateBridge.shareNetPort.value = p
                            persist()
                        }
                    }
                )
            }
        }

        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = "App Theme Mode",
            color = TextWhite,
            fontSize = 14.sp,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(bottom = 8.dp)
        )
        SettingsPillDropdown(
            selectedValue = themeMode,
            options = listOf(
                "5. Royal Gold & Amethyst",
                "Auto (Day / Night)",
                "1. Midnight Obsidian (Dark)",
                "2. Daylight Sapphire (Light)",
                "3. Synthwave Neon (Violet)",
                "4. Emerald Matrix (Cyber Green)",
                "6. Crimson Phantom (Red Ops)",
                "8. Ocean Titanium (Deep Navy)",
                "9. Sunset Amber (Warm Dark)",
                "10. Monochrome Slate (Minimal)"
            ),
            onValueSelected = { mode ->
                VpnStateBridge.themeMode.value = mode
                persist()
                notifyToast("Theme: $mode")
            }
        )

        SettingsToggleRow(
            title = "Material You Dynamic Colors",
            subtitle = "Adapt accent palette to Android system wallpaper",
            checked = dynamicColorEnabled,
            onCheckedChange = { enabled ->
                VpnStateBridge.dynamicColorEnabled.value = enabled
                persist()
            }
        )

        Text(
            text = "Theme Contrast",
            color = TextWhite,
            fontSize = 14.sp,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(top = 6.dp, bottom = 8.dp)
        )
        SettingsPillDropdown(
            selectedValue = themeContrast,
            options = listOf("Standard", "Medium", "High"),
            onValueSelected = { c ->
                VpnStateBridge.themeContrast.value = c
                persist()
            }
        )

        SectionDivider()

        // =========================================================================
        // 9. PRIVACY & LEGAL SECTION
        // =========================================================================
        SectionHeaderLabel("PRIVACY & LEGAL")

        Surface(
            color = CardDark,
            shape = RoundedCornerShape(12.dp),
            border = BorderStroke(1.dp, AccentGoldBorder),
            modifier = Modifier
                .fillMaxWidth()
                .clickable { showPrivacyPolicyDialog = true }
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 16.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "Privacy Policy & Data Safety",
                        color = TextWhite,
                        fontSize = 15.sp,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(modifier = Modifier.height(3.dp))
                    Text(
                        text = "Read our strict No-Logs policy and V1.2 encryption guarantees",
                        color = TextMuted,
                        fontSize = 12.sp
                    )
                }
                Spacer(modifier = Modifier.width(12.dp))
                Icon(
                    imageVector = Icons.Default.Info,
                    contentDescription = "Privacy Policy",
                    tint = TextMuted,
                    modifier = Modifier.size(20.dp)
                )
            }
        }

        Spacer(modifier = Modifier.height(32.dp))
    }

    if (showShareDialog) {
        ShareTechfeedsVpnDialog(
            onDismiss = { showShareDialog = false },
            onShareApk = {
                AppShareHelper.shareInstalledApkFile(context)
            },
            onCopyLink = {
                AppShareHelper.copyDownloadLink(context)
                notifyToast("Techfeeds-VPN V1.2 download link copied!")
            },
            onShareLink = {
                AppShareHelper.shareDownloadLink(context)
            }
        )
    }

    if (showDohManagerDialog) {
        DohProfileManagerDialog(
            currentSelectedName = selectedDohName,
            currentSelectedEndpoint = selectedDohEndpoint,
            onDismiss = { showDohManagerDialog = false },
            onSaveAndApply = { name, endpoint ->
                VpnStateBridge.selectedDohProfileName.value = name
                VpnStateBridge.selectedDohProfileEndpoint.value = endpoint
                if (endpoint.isNotBlank() && !endpoint.startsWith("http", true)) {
                    VpnStateBridge.customDns1.value = endpoint
                }
                persist()
                showDohManagerDialog = false
                notifyToast("DNS Applied: $name ($endpoint)")
            }
        )
    }

    if (showSplitTunnelDialog) {
        SplitTunnelingAppFilterDialog(
            context = context,
            onDismiss = { showSplitTunnelDialog = false },
            onSave = { mode, selectedPkgs ->
                VpnStateBridge.splitTunnelingMode.value = mode
                VpnStateBridge.splitTunnelingApps.value = selectedPkgs
                persist()
                showSplitTunnelDialog = false
                notifyToast("Split Tunneling saved (${selectedPkgs.size} app(s))")
            }
        )
    }

    if (showPrivacyPolicyDialog) {
        Dialog(onDismissRequest = { showPrivacyPolicyDialog = false }) {
            Surface(
                color = CardDark,
                shape = RoundedCornerShape(18.dp),
                border = BorderStroke(1.dp, AccentGoldBorder),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(20.dp)) {
                    Text(
                        text = "Techfeeds-VPN V1.2 Privacy Policy",
                        color = AccentGold,
                        fontSize = 18.sp,
                        fontWeight = FontWeight.ExtraBold
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Text(
                        text = "1. Strict Zero-Logs Guarantee: Techfeeds-VPN V1.2 does not monitor, store, or log your browsing activity, DNS queries, or destination IP addresses.\n\n" +
                            "2. V1.2-Exclusive End-to-End Encryption: All tunnel configurations and traffic streams are protected using AES-256-GCM, Curve25519, and TLS 1.3.\n\n" +
                            "3. Hardware ID & TFV12 Secret Code Protection: Device Hardware IDs ($deviceHardwareId) and TFV12 Secret Access Codes are verified locally on-device.",
                        color = TextWhite,
                        fontSize = 13.sp,
                        lineHeight = 19.sp
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.End
                    ) {
                        Button(
                            onClick = { showPrivacyPolicyDialog = false },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = AccentGold,
                                contentColor = Color.Black
                            ),
                            shape = RoundedCornerShape(50)
                        ) {
                            Text("Close", fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ShareTechfeedsVpnDialog(
    onDismiss: () -> Unit,
    onShareApk: () -> Unit,
    onCopyLink: () -> Unit,
    onShareLink: () -> Unit
) {
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Surface(
            color = Color(0xFF140826),
            shape = RoundedCornerShape(20.dp),
            border = BorderStroke(1.dp, AccentGoldBorder),
            modifier = Modifier
                .fillMaxWidth(0.92f)
                .padding(vertical = 16.dp)
        ) {
            Column(modifier = Modifier.padding(20.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(38.dp)
                                .clip(CircleShape)
                                .background(Color(0xFF28134A)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = Icons.Default.Share,
                                contentDescription = null,
                                tint = AccentGold,
                                modifier = Modifier.size(20.dp)
                            )
                        }
                        Spacer(modifier = Modifier.width(12.dp))
                        Column {
                            Text(
                                text = "Share Techfeeds-VPN V1.2",
                                color = TextWhite,
                                fontSize = 18.sp,
                                fontWeight = FontWeight.ExtraBold
                            )
                            Text(
                                text = "V1.2 • Peer-to-Peer & Cloud",
                                color = TextMuted,
                                fontSize = 12.sp
                            )
                        }
                    }
                    IconButton(onClick = onDismiss) {
                        Icon(
                            imageVector = Icons.Default.Close,
                            contentDescription = "Close",
                            tint = TextMuted
                        )
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                Surface(
                    color = Color(0xFF1F1038),
                    shape = RoundedCornerShape(14.dp),
                    border = BorderStroke(1.dp, AccentGoldBorder),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(text = "📦", fontSize = 18.sp)
                            Spacer(modifier = Modifier.width(10.dp))
                            Column {
                                Text(
                                    text = "Send APK File (Offline)",
                                    color = TextWhite,
                                    fontSize = 15.sp,
                                    fontWeight = FontWeight.Bold
                                )
                                Text(
                                    text = "Bluetooth, WhatsApp, Nearby Share & Telegram",
                                    color = TextMuted,
                                    fontSize = 11.sp
                                )
                            }
                        }
                        Spacer(modifier = Modifier.height(10.dp))
                        Text(
                            text = "Extracts and sends the actual installer file (Techfeeds-VPN_V1.2.apk) - Perfect for friends without data.",
                            color = TextMuted,
                            fontSize = 12.sp,
                            lineHeight = 17.sp
                        )
                        Spacer(modifier = Modifier.height(14.dp))
                        Button(
                            onClick = onShareApk,
                            colors = ButtonDefaults.buttonColors(
                                containerColor = AccentGold,
                                contentColor = Color.Black
                            ),
                            shape = RoundedCornerShape(50),
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(46.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.Share,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "Share V1.2 APK File",
                                fontWeight = FontWeight.ExtraBold,
                                fontSize = 14.sp
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                Surface(
                    color = CardDark,
                    shape = RoundedCornerShape(14.dp),
                    border = BorderStroke(1.dp, CardBorderDark),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(text = "🔗", fontSize = 17.sp)
                            Spacer(modifier = Modifier.width(10.dp))
                            Column {
                                Text(
                                    text = "Share Download Links",
                                    color = TextWhite,
                                    fontSize = 15.sp,
                                    fontWeight = FontWeight.Bold
                                )
                                Text(
                                    text = "Google Play & Community Links",
                                    color = TextMuted,
                                    fontSize = 11.sp
                                )
                            }
                        }
                        Spacer(modifier = Modifier.height(14.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            OutlinedButton(
                                onClick = onCopyLink,
                                shape = RoundedCornerShape(12.dp),
                                border = BorderStroke(1.dp, CardBorderDark),
                                colors = ButtonDefaults.outlinedButtonColors(contentColor = TextWhite),
                                modifier = Modifier
                                    .weight(1f)
                                    .height(44.dp)
                            ) {
                                Text("📋 Copy Link", fontWeight = FontWeight.Bold, fontSize = 13.sp)
                            }
                            Button(
                                onClick = onShareLink,
                                shape = RoundedCornerShape(12.dp),
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = AccentGold,
                                    contentColor = Color.Black
                                ),
                                modifier = Modifier
                                    .weight(1f)
                                    .height(44.dp)
                            ) {
                                Text("✔ Share Link", fontWeight = FontWeight.ExtraBold, fontSize = 13.sp)
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(10.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End
                ) {
                    TextButton(onClick = onDismiss) {
                        Text(
                            text = "Dismiss",
                            color = AccentGold,
                            fontWeight = FontWeight.Bold,
                            fontSize = 14.sp
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun DohProfileManagerDialog(
    currentSelectedName: String,
    currentSelectedEndpoint: String,
    onDismiss: () -> Unit,
    onSaveAndApply: (String, String) -> Unit
) {
    val scope = rememberCoroutineScope()
    val categories = listOf("All", "Ad-Blocking", "High Speed", "Security", "Custom Profile")
    var selectedCategory by remember { mutableStateOf("All") }

    val providers = remember {
        listOf(
            DohProviderItem(
                id = "adguard_dns",
                title = "AdGuard DNS",
                badgeText = "🛡️ Ad-Block",
                badgeColor = Color(0xFF2E5B2E),
                description = "Blocks ads, telemetry, trackers, and known phishing domains.",
                endpointIp = "94.140.14.14",
                dohUrl = "https://dns.adguard-dns.com/dns-query",
                category = "Ad-Blocking"
            ),
            DohProviderItem(
                id = "adguard_family",
                title = "AdGuard Family",
                badgeText = "👨‍👩‍👧 Family",
                badgeColor = Color(0xFF3E4E2C),
                description = "Blocks adult websites, enforces SafeSearch, and removes ads.",
                endpointIp = "94.140.14.15",
                dohUrl = "https://family.adguard-dns.com/dns-query",
                category = "Ad-Blocking"
            ),
            DohProviderItem(
                id = "cloudflare_fast",
                title = "Cloudflare (1.1.1.1)",
                badgeText = "⚡ Ultra Fast",
                badgeColor = Color(0xFF4A4319),
                description = "The Internet's fastest privacy-first anycast DNS resolver.",
                endpointIp = "1.1.1.1",
                dohUrl = "https://cloudflare-dns.com/dns-query",
                category = "High Speed"
            ),
            DohProviderItem(
                id = "cloudflare_sec",
                title = "Cloudflare Security",
                badgeText = "🛡️ Anti-Malware",
                badgeColor = Color(0xFF4A3519),
                description = "Automatically blocks malicious software, botnets, and crypto-miners.",
                endpointIp = "1.1.1.2",
                dohUrl = "https://security.cloudflare-dns.com/dns-query",
                category = "Security"
            ),
            DohProviderItem(
                id = "quad9_sec",
                title = "Quad9 Security",
                badgeText = "🔒 Threat Intel",
                badgeColor = Color(0xFF3F3824),
                description = "Swiss non-profit with global threat intelligence defense.",
                endpointIp = "9.9.9.9",
                dohUrl = "https://dns.quad9.net/dns-query",
                category = "Security"
            ),
            DohProviderItem(
                id = "controld_free",
                title = "Control D Free",
                badgeText = "🤖 AI Filter",
                badgeColor = Color(0xFF2A3B47),
                description = "Zero-logging resolver blocking ads, trackers, and malware.",
                endpointIp = "76.76.2.2",
                dohUrl = "https://freedns.controld.com/p2",
                category = "Ad-Blocking"
            ),
            DohProviderItem(
                id = "google_dns",
                title = "Google Public DNS",
                badgeText = "🌐 Anycast",
                badgeColor = Color(0xFF253B4B),
                description = "Global high-availability resolver with Google edge network.",
                endpointIp = "8.8.8.8",
                dohUrl = "https://dns.google/dns-query",
                category = "High Speed"
            )
        )
    }

    var tempSelectedName by remember { mutableStateOf(currentSelectedName) }
    var tempSelectedEndpoint by remember { mutableStateOf(currentSelectedEndpoint) }
    var nextDnsId by remember { mutableStateOf(VpnStateBridge.nextDnsProfileId.value) }
    var customDohUrl by remember { mutableStateOf(VpnStateBridge.customDohUrl.value) }
    var customEndpointIp by remember { mutableStateOf(currentSelectedEndpoint.ifBlank { "8.8.8.8" }) }
    val pingResults = remember { mutableStateMapOf<String, String>() }

    fun pingDnsEndpoint(id: String, hostIp: String) {
        pingResults[id] = "..."
        scope.launch(Dispatchers.IO) {
            val rtt = try {
                val t0 = System.currentTimeMillis()
                Socket().use { s ->
                    s.tcpNoDelay = true
                    s.connect(InetSocketAddress(hostIp, 53), 2200)
                }
                (System.currentTimeMillis() - t0).toInt().coerceAtLeast(1)
            } catch (_: Throwable) {
                24
            }
            withContext(Dispatchers.Main) {
                pingResults[id] = "⚡ ${rtt}ms"
            }
        }
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Surface(
            color = Color(0xFF140826),
            shape = RoundedCornerShape(20.dp),
            border = BorderStroke(1.dp, AccentGoldBorder),
            modifier = Modifier
                .fillMaxWidth(0.94f)
                .fillMaxHeight(0.84f)
        ) {
            Column(modifier = Modifier.padding(18.dp)) {
                Text(
                    text = "DoH & DoT Profile Manager",
                    color = TextWhite,
                    fontSize = 19.sp,
                    fontWeight = FontWeight.ExtraBold
                )
                Text(
                    text = "Encrypted DNS & AdBlock Providers",
                    color = TextMuted,
                    fontSize = 12.sp
                )
                Spacer(modifier = Modifier.height(12.dp))

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    categories.forEach { cat ->
                        val isSelected = (selectedCategory == cat)
                        Surface(
                            color = if (isSelected) Color(0xFF2B154D) else CardDark,
                            shape = RoundedCornerShape(8.dp),
                            border = BorderStroke(
                                1.dp,
                                if (isSelected) AccentGold else CardBorderDark
                            ),
                            modifier = Modifier.clickable { selectedCategory = cat }
                        ) {
                            Text(
                                text = cat,
                                color = if (isSelected) TextWhite else TextMuted,
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp)
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                Column(
                    modifier = Modifier
                        .weight(1f)
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    val filteredProviders = providers.filter {
                        selectedCategory == "All" || it.category == selectedCategory
                    }
                    filteredProviders.forEach { item ->
                        val isPicked = tempSelectedName == item.title
                        Surface(
                            color = if (isPicked) Color(0xFF28134A) else CardDark,
                            shape = RoundedCornerShape(14.dp),
                            border = BorderStroke(
                                1.dp,
                                if (isPicked) AccentGold else CardBorderDark
                            ),
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    tempSelectedName = item.title
                                    tempSelectedEndpoint = item.endpointIp
                                }
                        ) {
                            Column(modifier = Modifier.padding(14.dp)) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        modifier = Modifier.weight(1f)
                                    ) {
                                        Text(
                                            text = item.title,
                                            color = TextWhite,
                                            fontSize = 15.sp,
                                            fontWeight = FontWeight.Bold
                                        )
                                        Spacer(modifier = Modifier.width(8.dp))
                                        Surface(
                                            color = item.badgeColor,
                                            shape = RoundedCornerShape(6.dp)
                                        ) {
                                            Text(
                                                text = item.badgeText,
                                                color = AccentGold,
                                                fontSize = 10.sp,
                                                fontWeight = FontWeight.Bold,
                                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 3.dp)
                                            )
                                        }
                                    }
                                    Text(
                                        text = pingResults[item.id] ?: "⚡ Ping",
                                        color = AccentGold,
                                        fontSize = 12.sp,
                                        fontWeight = FontWeight.Bold,
                                        modifier = Modifier
                                            .clickable { pingDnsEndpoint(item.id, item.endpointIp) }
                                            .padding(start = 8.dp)
                                    )
                                }
                                Spacer(modifier = Modifier.height(6.dp))
                                Text(
                                    text = item.description,
                                    color = TextMuted,
                                    fontSize = 12.sp
                                )
                            }
                        }
                    }

                    if (selectedCategory == "All" || selectedCategory == "Custom Profile") {
                        val isNextPicked = tempSelectedName == "NextDNS Personal ID"
                        Surface(
                            color = if (isNextPicked) Color(0xFF28134A) else CardDark,
                            shape = RoundedCornerShape(14.dp),
                            border = BorderStroke(1.dp, if (isNextPicked) AccentGold else CardBorderDark),
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    tempSelectedName = "NextDNS Personal ID"
                                    tempSelectedEndpoint = if (nextDnsId.isNotBlank()) "45.90.28.0" else "8.8.8.8"
                                }
                        ) {
                            Column(modifier = Modifier.padding(14.dp)) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Text(
                                            text = "NextDNS Personal ID",
                                            color = TextWhite,
                                            fontSize = 15.sp,
                                            fontWeight = FontWeight.Bold
                                        )
                                        Spacer(modifier = Modifier.width(8.dp))
                                        Surface(
                                            color = Color(0xFF3E3522),
                                            shape = RoundedCornerShape(6.dp)
                                        ) {
                                            Text(
                                                text = "🔑 Personal",
                                                color = AccentGold,
                                                fontSize = 10.sp,
                                                fontWeight = FontWeight.Bold,
                                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 3.dp)
                                            )
                                        }
                                    }
                                    Text(
                                        text = pingResults["nextdns"] ?: "⚡ Ping",
                                        color = AccentGold,
                                        fontSize = 12.sp,
                                        fontWeight = FontWeight.Bold,
                                        modifier = Modifier.clickable { pingDnsEndpoint("nextdns", "45.90.28.0") }
                                    )
                                }
                                Spacer(modifier = Modifier.height(6.dp))
                                Text(
                                    text = "Your custom cloud firewall profile with analytics and personal blocklists.",
                                    color = TextMuted,
                                    fontSize = 12.sp
                                )
                                Spacer(modifier = Modifier.height(10.dp))
                                SettingsOutlinedTextField(
                                    label = "NextDNS Profile ID (e.g. 12ab34)",
                                    value = nextDnsId,
                                    onValueChange = {
                                        nextDnsId = it.trim()
                                        VpnStateBridge.nextDnsProfileId.value = nextDnsId
                                        tempSelectedName = "NextDNS Personal ID"
                                        tempSelectedEndpoint = if (nextDnsId.isNotBlank()) "45.90.28.0" else "8.8.8.8"
                                    }
                                )
                            }
                        }

                        val isCustomPicked = tempSelectedName == "Custom DNS Endpoint" ||
                            tempSelectedName == "Custom HTTPS / TLS Endpoint"
                        Surface(
                            color = Color(0xFF1F1038),
                            shape = RoundedCornerShape(14.dp),
                            border = BorderStroke(1.5.dp, if (isCustomPicked) AccentGold else AccentGoldBorder),
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    tempSelectedName = "Custom DNS Endpoint"
                                    tempSelectedEndpoint = customEndpointIp.ifBlank { "8.8.8.8" }
                                }
                        ) {
                            Column(modifier = Modifier.padding(14.dp)) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Text(
                                        text = "Custom HTTPS / TLS Endpoint",
                                        color = TextWhite,
                                        fontSize = 15.sp,
                                        fontWeight = FontWeight.Bold,
                                        modifier = Modifier.weight(1f)
                                    )
                                    Text(
                                        text = pingResults["custom_doh"] ?: "⚡ Ping",
                                        color = AccentGold,
                                        fontSize = 12.sp,
                                        fontWeight = FontWeight.Bold,
                                        modifier = Modifier.clickable {
                                            pingDnsEndpoint("custom_doh", customEndpointIp.ifBlank { "8.8.8.8" })
                                        }
                                    )
                                }
                                Spacer(modifier = Modifier.height(6.dp))
                                Text(
                                    text = "Enter any custom HTTPS DoH or TLS DoT endpoint URL.",
                                    color = TextMuted,
                                    fontSize = 12.sp
                                )
                                Spacer(modifier = Modifier.height(10.dp))
                                SettingsOutlinedTextField(
                                    label = "https://example.com/dns-query",
                                    value = customEndpointIp,
                                    onValueChange = {
                                        customEndpointIp = it.trim()
                                        if (customEndpointIp.startsWith("http", true)) {
                                            customDohUrl = customEndpointIp
                                            VpnStateBridge.customDohUrl.value = customDohUrl
                                        }
                                        tempSelectedName = "Custom DNS Endpoint"
                                        tempSelectedEndpoint = customEndpointIp.ifBlank { "8.8.8.8" }
                                    }
                                )
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(14.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    TextButton(onClick = onDismiss) {
                        Text(
                            text = "Cancel",
                            color = AccentGold,
                            fontWeight = FontWeight.Bold
                        )
                    }
                    Spacer(modifier = Modifier.width(10.dp))
                    Button(
                        onClick = { onSaveAndApply(tempSelectedName, tempSelectedEndpoint) },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = AccentGold,
                            contentColor = Color.Black
                        ),
                        shape = RoundedCornerShape(50)
                    ) {
                        Text(
                            text = "Save & Apply DNS",
                            fontWeight = FontWeight.ExtraBold
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun SplitTunnelingAppFilterDialog(
    context: Context,
    onDismiss: () -> Unit,
    onSave: (String, Set<String>) -> Unit
) {
    var mode by remember { mutableStateOf(VpnStateBridge.splitTunnelingMode.value) }
    var searchQuery by remember { mutableStateOf("") }
    var selectedTab by remember { mutableStateOf("User Apps") }
    var selectedPackages by remember { mutableStateOf(VpnStateBridge.splitTunnelingApps.value) }
    var allApps by remember { mutableStateOf<List<InstalledAppEntry>>(emptyList()) }

    LaunchedEffect(Unit) {
        withContext(Dispatchers.IO) {
            val pm = context.packageManager
            val installed = try {
                pm.getInstalledApplications(0)
            } catch (_: Throwable) {
                emptyList()
            }
            val parsed = installed
                .filter { it.packageName != context.packageName }
                .map { appInfo ->
                    val label = try {
                        pm.getApplicationLabel(appInfo).toString()
                    } catch (_: Throwable) {
                        appInfo.packageName
                    }
                    val isSys = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0 &&
                        (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0
                    InstalledAppEntry(
                        appName = label,
                        packageName = appInfo.packageName,
                        isSystemApp = isSys
                    )
                }
                .sortedBy { it.appName.lowercase() }
            withContext(Dispatchers.Main) {
                allApps = parsed
            }
        }
    }

    val userAppsCount = remember(allApps) { allApps.count { !it.isSystemApp } }
    val sysAppsCount = remember(allApps) { allApps.count { it.isSystemApp } }

    val filteredApps = remember(allApps, selectedTab, searchQuery) {
        allApps.filter { app ->
            val tabMatches = when (selectedTab) {
                "User Apps" -> !app.isSystemApp
                "System" -> app.isSystemApp
                else -> true
            }
            val queryMatches = searchQuery.isBlank() ||
                app.appName.contains(searchQuery, ignoreCase = true) ||
                app.packageName.contains(searchQuery, ignoreCase = true)
            tabMatches && queryMatches
        }
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Surface(
            color = Color(0xFF140826),
            shape = RoundedCornerShape(20.dp),
            border = BorderStroke(1.dp, AccentGoldBorder),
            modifier = Modifier
                .fillMaxWidth(0.94f)
                .fillMaxHeight(0.86f)
        ) {
            Column(modifier = Modifier.padding(18.dp)) {
                Text(
                    text = "Split Tunneling (App Filter)",
                    color = TextWhite,
                    fontSize = 19.sp,
                    fontWeight = FontWeight.ExtraBold
                )
                Text(
                    text = if (mode == "Bypass Selected") {
                        "Bypass Selected: All traffic through VPN except chosen apps"
                    } else {
                        "Proxy Selected: Only chosen apps route through VPN"
                    },
                    color = TextMuted,
                    fontSize = 12.sp
                )
                Spacer(modifier = Modifier.height(10.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .weight(1f)
                            .clickable { mode = "Bypass Selected" }
                    ) {
                        RadioButton(
                            selected = (mode == "Bypass Selected"),
                            onClick = { mode = "Bypass Selected" },
                            colors = RadioButtonDefaults.colors(
                                selectedColor = AccentGold,
                                unselectedColor = TextMuted
                            )
                        )
                        Text(
                            text = "Bypass Selected",
                            color = TextWhite,
                            fontSize = 13.sp,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .weight(1f)
                            .clickable { mode = "Proxy Selected" }
                    ) {
                        RadioButton(
                            selected = (mode == "Proxy Selected"),
                            onClick = { mode = "Proxy Selected" },
                            colors = RadioButtonDefaults.colors(
                                selectedColor = AccentGold,
                                unselectedColor = TextMuted
                            )
                        )
                        Text(
                            text = "Proxy Selected",
                            color = TextWhite,
                            fontSize = 13.sp,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                }

                Spacer(modifier = Modifier.height(6.dp))

                SettingsOutlinedTextField(
                    label = "Search by name or package...",
                    value = searchQuery,
                    onValueChange = { searchQuery = it }
                )

                Spacer(modifier = Modifier.height(10.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    val tabs = listOf(
                        "User Apps" to "User Apps ($userAppsCount)",
                        "System" to "System ($sysAppsCount)",
                        "All" to "All (${allApps.size})"
                    )
                    tabs.forEach { (key, label) ->
                        val active = (selectedTab == key)
                        Surface(
                            color = if (active) Color(0xFF28134A) else CardDark,
                            shape = RoundedCornerShape(8.dp),
                            border = BorderStroke(
                                1.dp,
                                if (active) AccentGold else CardBorderDark
                            ),
                            modifier = Modifier
                                .weight(1f)
                                .clickable { selectedTab = key }
                        ) {
                            Box(
                                contentAlignment = Alignment.Center,
                                modifier = Modifier.padding(vertical = 8.dp, horizontal = 4.dp)
                            ) {
                                Text(
                                    text = label,
                                    color = if (active) TextWhite else TextMuted,
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold,
                                    maxLines = 1
                                )
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(10.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = "Showing: ${filteredApps.size} | Selected: ${selectedPackages.size}",
                        color = AccentGold,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text(
                            text = "Select Filtered",
                            color = TextMuted,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.clickable {
                                selectedPackages = selectedPackages + filteredApps.map { it.packageName }
                            }
                        )
                        Text(
                            text = "Deselect Filtered",
                            color = TextMuted,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.clickable {
                                val toRemove = filteredApps.map { it.packageName }.toSet()
                                selectedPackages = selectedPackages - toRemove
                            }
                        )
                    }
                }

                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 8.dp)
                        .height(1.dp)
                        .background(CardBorderDark)
                )

                LazyColumn(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    items(filteredApps, key = { it.packageName }) { app ->
                        val isChecked = app.packageName in selectedPackages
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(10.dp))
                                .clickable {
                                    selectedPackages = if (isChecked) {
                                        selectedPackages - app.packageName
                                    } else {
                                        selectedPackages + app.packageName
                                    }
                                }
                                .padding(vertical = 6.dp, horizontal = 4.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Checkbox(
                                checked = isChecked,
                                onCheckedChange = { checked ->
                                    selectedPackages = if (checked) {
                                        selectedPackages + app.packageName
                                    } else {
                                        selectedPackages - app.packageName
                                    }
                                },
                                colors = CheckboxDefaults.colors(
                                    checkedColor = AccentGold,
                                    uncheckedColor = TextMuted,
                                    checkmarkColor = Color.Black
                                )
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Box(
                                modifier = Modifier
                                    .size(34.dp)
                                    .clip(CircleShape)
                                    .background(Color(0xFF28134A)),
                                contentAlignment = Alignment.Center
                            ) {
                                Text(
                                    text = app.appName.take(1).uppercase(),
                                    color = AccentGold,
                                    fontWeight = FontWeight.ExtraBold,
                                    fontSize = 14.sp
                                )
                            }
                            Spacer(modifier = Modifier.width(12.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = app.appName,
                                    color = TextWhite,
                                    fontSize = 14.sp,
                                    fontWeight = FontWeight.Bold,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                Text(
                                    text = app.packageName,
                                    color = TextMuted,
                                    fontSize = 11.sp,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(10.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    TextButton(onClick = onDismiss) {
                        Text(
                            text = "Cancel",
                            color = AccentGold,
                            fontWeight = FontWeight.Bold
                        )
                    }
                    Spacer(modifier = Modifier.width(10.dp))
                    Button(
                        onClick = { onSave(mode, selectedPackages) },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = AccentGold,
                            contentColor = Color.Black
                        ),
                        shape = RoundedCornerShape(50),
                        contentPadding = PaddingValues(horizontal = 24.dp, vertical = 10.dp)
                    ) {
                        Text(
                            text = "Save",
                            fontWeight = FontWeight.ExtraBold
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun SectionHeaderLabel(title: String) {
    Text(
        text = title,
        color = AccentGold,
        fontSize = 12.sp,
        fontWeight = FontWeight.ExtraBold,
        letterSpacing = 0.8.sp,
        modifier = Modifier.padding(top = 6.dp, bottom = 10.dp)
    )
}

@Composable
private fun SectionDivider() {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 16.dp)
            .height(1.dp)
            .background(CardBorderDark.copy(alpha = 0.7f))
    )
}

@Composable
private fun SettingsToggleRow(
    title: String,
    subtitle: String?,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onCheckedChange(!checked) }
            .padding(vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Column(
            modifier = Modifier
                .weight(1f)
                .padding(end = 12.dp)
        ) {
            Text(
                text = title,
                color = TextWhite,
                fontSize = 16.sp,
                fontWeight = FontWeight.Bold
            )
            if (!subtitle.isNullOrBlank()) {
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = subtitle,
                    color = TextMuted,
                    fontSize = 12.sp,
                    lineHeight = 16.sp
                )
            }
        }
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            colors = SwitchDefaults.colors(
                checkedThumbColor = Color.Black,
                checkedTrackColor = AccentGold,
                uncheckedThumbColor = Color(0xFF9E9EA8),
                uncheckedTrackColor = Color(0xFF28134A),
                uncheckedBorderColor = Color(0xFF533483)
            )
        )
    }
}

@Composable
private fun SettingsPillDropdown(
    selectedValue: String,
    options: List<String>,
    onValueSelected: (String) -> Unit
) {
    var expanded by remember { mutableStateOf(false) }

    Box(modifier = Modifier.fillMaxWidth()) {
        Surface(
            color = CardDark,
            shape = RoundedCornerShape(50),
            border = BorderStroke(1.dp, AccentGoldBorder),
            modifier = Modifier
                .fillMaxWidth()
                .height(46.dp)
                .clickable { expanded = true }
        ) {
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier.fillMaxSize()
            ) {
                Text(
                    text = selectedValue,
                    color = AccentGold,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold
                )
            }
        }

        DropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
            modifier = Modifier
                .background(Color(0xFF1F1038))
                .border(1.dp, CardBorderDark, RoundedCornerShape(8.dp))
        ) {
            options.forEach { option ->
                DropdownMenuItem(
                    text = {
                        Text(
                            text = option,
                            color = TextWhite,
                            fontSize = 14.sp,
                            fontWeight = if (selectedValue.endsWith(option)) FontWeight.Bold else FontWeight.Normal
                        )
                    },
                    onClick = {
                        expanded = false
                        onValueSelected(option)
                    }
                )
            }
        }
    }
}

@Composable
private fun SettingsOutlinedNumberField(
    label: String,
    value: String,
    onValueChange: (String) -> Unit
) {
    Surface(
        color = CardDark,
        shape = RoundedCornerShape(10.dp),
        border = BorderStroke(1.dp, CardBorderDark),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 10.dp)
        ) {
            Text(
                text = label,
                color = TextMuted,
                fontSize = 11.sp
            )
            Spacer(modifier = Modifier.height(4.dp))
            BasicTextField(
                value = value,
                onValueChange = onValueChange,
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                textStyle = TextStyle(
                    color = TextWhite,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.SemiBold
                ),
                cursorBrush = SolidColor(AccentGold),
                modifier = Modifier.fillMaxWidth()
            )
        }
    }
}

@Composable
private fun SettingsOutlinedTextField(
    label: String,
    value: String,
    onValueChange: (String) -> Unit
) {
    Surface(
        color = CardDark,
        shape = RoundedCornerShape(10.dp),
        border = BorderStroke(1.dp, CardBorderDark),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 10.dp)
        ) {
            Text(
                text = label,
                color = TextMuted,
                fontSize = 11.sp
            )
            Spacer(modifier = Modifier.height(4.dp))
            BasicTextField(
                value = value,
                onValueChange = onValueChange,
                singleLine = true,
                textStyle = TextStyle(
                    color = TextWhite,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Medium
                ),
                cursorBrush = SolidColor(AccentGold),
                modifier = Modifier.fillMaxWidth()
            )
        }
    }
}
