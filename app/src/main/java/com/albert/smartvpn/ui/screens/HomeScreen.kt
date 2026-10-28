package com.albert.smartvpn.ui.screens

import android.net.TrafficStats
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.albert.smartvpn.data.VpnProfile
import com.albert.smartvpn.ui.viewmodel.SecretCodeManager
import com.albert.smartvpn.ui.viewmodel.VpnStateBridge
import kotlinx.coroutines.delay
import java.util.Locale

private val GoldPrimary = Color(0xFFFFD54F)
private val GoldDeep = Color(0xFFFFB300)
private val AmethystAccent = Color(0xFFB388FF)
private val EmeraldConnected = Color(0xFF00E676)
private val AmberConnecting = Color(0xFFFFB300)
private val CardBgRoyal = Color(0xFF170B2C)
private val CardBorderRoyal = Color(0xFF391E66)

@Composable
fun HomeScreen(
    isConnected: Boolean,
    activeProfile: VpnProfile?,
    selectedCount: Int = 1,
    onToggleConnection: () -> Unit,
    onPingClick: () -> Unit = {}
) {
    val connectionState by VpnStateBridge.connectionState.collectAsState()
    val statusMessage by VpnStateBridge.statusMessage.collectAsState()
    val pingResultText by VpnStateBridge.pingResultText.collectAsState()
    val isPinging by VpnStateBridge.isPinging.collectAsState()
    val roundRobinEnabled by VpnStateBridge.loadBalancingEnabled.collectAsState()
    val turboSpeedEnabled by VpnStateBridge.turboSpeedEnabled.collectAsState()
    val toastMessage by VpnStateBridge.toastMessage.collectAsState()
    val codeExpiresAtMs by VpnStateBridge.secretCodeExpiresAtMs.collectAsState()

    var downSpeedText by remember { mutableStateOf("0 KB/s") }
    var upSpeedText by remember { mutableStateOf("0 KB/s") }
    var sessionDownBytes by remember { mutableStateOf(0L) }
    var sessionUpBytes by remember { mutableStateOf(0L) }
    var totalBandwidthBytes by remember { mutableStateOf(0L) }
    var accessRemainingLabel by remember { mutableStateOf("") }

    // Live Traffic & Total Session Bandwidth Telemetry Loop
    LaunchedEffect(isConnected, connectionState, codeExpiresAtMs) {
        var prevRx = TrafficStats.getTotalRxBytes().coerceAtLeast(0L)
        var prevTx = TrafficStats.getTotalTxBytes().coerceAtLeast(0L)
        val baseRx = prevRx
        val baseTx = prevTx

        if (!isConnected) {
            downSpeedText = "0 KB/s"
            upSpeedText = "0 KB/s"
            sessionDownBytes = 0L
            sessionUpBytes = 0L
            totalBandwidthBytes = 0L
        }

        while (true) {
            if (codeExpiresAtMs > 0L) {
                val rem = (codeExpiresAtMs - System.currentTimeMillis()).coerceAtLeast(0L)
                accessRemainingLabel = SecretCodeManager.formatRemainingTime(rem)
            }

            if (isConnected) {
                val curRx = TrafficStats.getTotalRxBytes().coerceAtLeast(prevRx)
                val curTx = TrafficStats.getTotalTxBytes().coerceAtLeast(prevTx)

                val deltaRx = (curRx - prevRx).coerceAtLeast(0L)
                val deltaTx = (curTx - prevTx).coerceAtLeast(0L)

                prevRx = curRx
                prevTx = curTx

                downSpeedText = "${formatDataBytes(deltaRx)}/s"
                upSpeedText = "${formatDataBytes(deltaTx)}/s"

                sessionDownBytes = (curRx - baseRx).coerceAtLeast(0L)
                sessionUpBytes = (curTx - baseTx).coerceAtLeast(0L)
                totalBandwidthBytes = sessionDownBytes + sessionUpBytes
            }
            delay(1000L)
        }
    }

    val isConnecting = connectionState == "CONNECTING"
    val buttonRingColor = when {
        isConnected -> EmeraldConnected
        isConnecting -> AmberConnecting
        else -> GoldPrimary
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    colors = listOf(
                        Color(0xFF0D061A),
                        Color(0xFF160A2C),
                        Color(0xFF090414)
                    )
                )
            )
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 12.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        // Optional Toast Pill
        if (toastMessage.isNotBlank()) {
            Surface(
                shape = RoundedCornerShape(50),
                color = Color(0xFF28134A),
                border = BorderStroke(1.dp, GoldPrimary),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = toastMessage,
                    color = GoldPrimary,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp)
                )
            }
        }

        // Top Status & Access Timer Banner
        Surface(
            shape = RoundedCornerShape(16.dp),
            color = CardBgRoyal,
            border = BorderStroke(1.dp, CardBorderRoyal),
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 14.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(10.dp)
                            .clip(CircleShape)
                            .background(buttonRingColor)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = statusMessage.uppercase(),
                        color = Color.White,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.ExtraBold
                    )
                }
                if (accessRemainingLabel.isNotBlank()) {
                    Surface(
                        shape = RoundedCornerShape(50),
                        color = GoldPrimary.copy(alpha = 0.14f),
                        border = BorderStroke(1.dp, GoldPrimary.copy(alpha = 0.55f))
                    ) {
                        Text(
                            text = "🔑 $accessRemainingLabel",
                            color = GoldPrimary,
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(4.dp))

        // =====================================================================
        // STATIC CONNECT BUTTON (100% Static — No movement, scaling, or spinning)
        // =====================================================================
        Box(
            modifier = Modifier
                .size(196.dp)
                .clip(CircleShape)
                .background(
                    Brush.radialGradient(
                        colors = listOf(
                            buttonRingColor.copy(alpha = 0.22f),
                            Color(0xFF1B0C36),
                            Color(0xFF100622)
                        )
                    )
                )
                .border(
                    width = 4.dp,
                    brush = Brush.linearGradient(
                        colors = if (isConnected) {
                            listOf(EmeraldConnected, Color(0xFF69F0AE), EmeraldConnected)
                        } else {
                            listOf(GoldPrimary, AmethystAccent, GoldDeep)
                        }
                    ),
                    shape = CircleShape
                )
                .clickable { onToggleConnection() },
            contentAlignment = Alignment.Center
        ) {
            Surface(
                shape = CircleShape,
                color = Color(0xFF160A2D),
                border = BorderStroke(1.5.dp, buttonRingColor.copy(alpha = 0.65f)),
                modifier = Modifier.size(160.dp)
            ) {
                Column(
                    modifier = Modifier.fillMaxSize(),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Text(
                        text = if (isConnected) "🛡️" else if (isConnecting) "⏳" else "⚡",
                        fontSize = 30.sp
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = when {
                            isConnected -> "CONNECTED"
                            isConnecting -> "CONNECTING"
                            else -> "CONNECT"
                        },
                        color = buttonRingColor,
                        fontSize = 19.sp,
                        fontWeight = FontWeight.ExtraBold,
                        letterSpacing = 1.2.sp
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = when {
                            isConnected -> "TAP TO STOP"
                            isConnecting -> "TAP TO CANCEL"
                            else -> "TAP TO START"
                        },
                        color = Color(0xFFD1C4E9),
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 0.8.sp
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(2.dp))

        // =====================================================================
        // TOTAL BANDWIDTH USAGE CARD (Total Data Used for the Session)
        // =====================================================================
        Surface(
            shape = RoundedCornerShape(18.dp),
            color = CardBgRoyal,
            border = BorderStroke(1.2.dp, GoldPrimary.copy(alpha = 0.55f)),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column {
                        Text(
                            text = "TOTAL BANDWIDTH USAGE",
                            color = GoldPrimary,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.ExtraBold,
                            letterSpacing = 0.9.sp
                        )
                        Text(
                            text = "Total data used for the session",
                            color = Color(0xFFD1C4E9),
                            fontSize = 11.sp
                        )
                    }
                    Text(
                        text = formatDataBytes(totalBandwidthBytes),
                        color = Color.White,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 22.sp,
                        fontWeight = FontWeight.ExtraBold
                    )
                }

                HorizontalDivider(color = CardBorderRoyal)

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    // Download Box
                    Surface(
                        shape = RoundedCornerShape(12.dp),
                        color = Color(0xFF110622),
                        border = BorderStroke(1.dp, CardBorderRoyal),
                        modifier = Modifier.weight(1f)
                    ) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Text(
                                text = "↓ DOWNLOAD",
                                color = EmeraldConnected,
                                fontSize = 10.sp,
                                fontWeight = FontWeight.ExtraBold
                            )
                            Spacer(modifier = Modifier.height(3.dp))
                            Text(
                                text = downSpeedText,
                                color = Color.White,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 15.sp,
                                fontWeight = FontWeight.ExtraBold
                            )
                            Text(
                                text = "Used: ${formatDataBytes(sessionDownBytes)}",
                                color = Color(0xFFD1C4E9),
                                fontSize = 11.sp
                            )
                        }
                    }

                    // Upload Box
                    Surface(
                        shape = RoundedCornerShape(12.dp),
                        color = Color(0xFF110622),
                        border = BorderStroke(1.dp, CardBorderRoyal),
                        modifier = Modifier.weight(1f)
                    ) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Text(
                                text = "↑ UPLOAD",
                                color = GoldPrimary,
                                fontSize = 10.sp,
                                fontWeight = FontWeight.ExtraBold
                            )
                            Spacer(modifier = Modifier.height(3.dp))
                            Text(
                                text = upSpeedText,
                                color = Color.White,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 15.sp,
                                fontWeight = FontWeight.ExtraBold
                            )
                            Text(
                                text = "Used: ${formatDataBytes(sessionUpBytes)}",
                                color = Color(0xFFD1C4E9),
                                fontSize = 11.sp
                            )
                        }
                    }
                }
            }
        }

        // Active Profile Card
        Surface(
            shape = RoundedCornerShape(18.dp),
            color = CardBgRoyal,
            border = BorderStroke(1.dp, CardBorderRoyal),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = "ACTIVE CONFIGURATION",
                        color = GoldPrimary,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.ExtraBold,
                        letterSpacing = 0.8.sp
                    )
                    if (selectedCount > 1) {
                        Surface(
                            shape = RoundedCornerShape(50),
                            color = GoldPrimary.copy(alpha = 0.16f),
                            border = BorderStroke(1.dp, GoldPrimary)
                        ) {
                            Text(
                                text = "⚖️ $selectedCount Nodes Active",
                                color = GoldPrimary,
                                fontSize = 10.sp,
                                fontWeight = FontWeight.ExtraBold,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                            )
                        }
                    }
                }

                if (activeProfile != null) {
                    val maskedServer = if (activeProfile.isImported && activeProfile.isLocked) {
                        "🔒 Locked Enclave Node"
                    } else {
                        "${activeProfile.server}:${activeProfile.port}"
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "${activeProfile.countryFlag} ${activeProfile.name}",
                                color = Color.White,
                                fontSize = 16.sp,
                                fontWeight = FontWeight.ExtraBold,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(
                                text = "${activeProfile.protocol} • $maskedServer",
                                color = Color(0xFFD1C4E9),
                                fontSize = 12.sp,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                        if (activeProfile.lastPingMs > 0) {
                            Surface(
                                shape = RoundedCornerShape(10.dp),
                                color = Color(0xFF110622),
                                border = BorderStroke(1.dp, EmeraldConnected.copy(alpha = 0.6f))
                            ) {
                                Text(
                                    text = "${activeProfile.lastPingMs} ms",
                                    color = EmeraldConnected,
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.Bold,
                                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp)
                                )
                            }
                        }
                    }
                } else {
                    Text(
                        text = "No configuration selected. Tap Connect or open the Configs tab to add a server.",
                        color = Color(0xFFD1C4E9),
                        fontSize = 12.sp
                    )
                }

                // Live Tunnel Ping Row
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = Color(0xFF110622),
                    border = BorderStroke(1.dp, CardBorderRoyal),
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable(enabled = isConnected && !isPinging) { onPingClick() }
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 12.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            text = pingResultText,
                            color = if (isConnected) GoldPrimary else Color(0xFFD1C4E9),
                            fontSize = 12.sp,
                            fontWeight = FontWeight.SemiBold,
                            modifier = Modifier.weight(1f)
                        )
                        Text(
                            text = if (isPinging) "PINGING..." else "⚡ PING",
                            color = GoldPrimary,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.ExtraBold
                        )
                    }
                }
            }
        }

        // Quick Engine Boost Toggles (Turbo Speed & Round-Robin)
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Surface(
                shape = RoundedCornerShape(14.dp),
                color = if (turboSpeedEnabled) Color(0xFF28134A) else CardBgRoyal,
                border = BorderStroke(1.dp, if (turboSpeedEnabled) GoldPrimary else CardBorderRoyal),
                modifier = Modifier
                    .weight(1f)
                    .clickable {
                        VpnStateBridge.turboSpeedEnabled.value = !turboSpeedEnabled
                    }
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column {
                        Text(
                            text = "🚀 Turbo Core",
                            color = Color.White,
                            fontSize = 13.sp,
                            fontWeight = FontWeight.ExtraBold
                        )
                        Text(
                            text = if (turboSpeedEnabled) "6x Multiplex ON" else "Standard Mode",
                            color = GoldPrimary,
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }

            Surface(
                shape = RoundedCornerShape(14.dp),
                color = if (roundRobinEnabled) Color(0xFF28134A) else CardBgRoyal,
                border = BorderStroke(1.dp, if (roundRobinEnabled) GoldPrimary else CardBorderRoyal),
                modifier = Modifier
                    .weight(1f)
                    .clickable {
                        VpnStateBridge.setRoundRobin(!roundRobinEnabled)
                    }
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column {
                        Text(
                            text = "⚖️ Round-Robin",
                            color = Color.White,
                            fontSize = 13.sp,
                            fontWeight = FontWeight.ExtraBold
                        )
                        Text(
                            text = if (roundRobinEnabled) "Load Balance ON" else "Single Node",
                            color = GoldPrimary,
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }
        }
    }
}

private fun formatDataBytes(bytes: Long): String {
    if (bytes <= 0L) return "0 B"
    val kb = 1024.0
    val mb = kb * 1024.0
    val gb = mb * 1024.0
    return when {
        bytes >= gb -> String.format(Locale.US, "%.2f GB", bytes / gb)
        bytes >= mb -> String.format(Locale.US, "%.2f MB", bytes / mb)
        bytes >= kb -> String.format(Locale.US, "%.1f KB", bytes / kb)
        else -> "$bytes B"
    }
}
