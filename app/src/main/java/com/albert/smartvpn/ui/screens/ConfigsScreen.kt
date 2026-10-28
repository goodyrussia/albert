package com.albert.smartvpn.ui.screens

import android.app.DatePickerDialog
import android.app.TimePickerDialog
import android.content.Intent
import android.util.Base64
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.albert.smartvpn.data.VpnProfile
import com.albert.smartvpn.ui.viewmodel.ConfigCryptoHelper
import com.albert.smartvpn.ui.viewmodel.VpnStateBridge
import com.google.gson.GsonBuilder
import com.google.gson.JsonParser
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.net.URLEncoder
import java.security.MessageDigest
import java.util.Calendar

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConfigsScreen(
    profiles: List<VpnProfile>,
    onSelectProfile: (VpnProfile) -> Unit,
    onDeleteProfile: (VpnProfile) -> Unit,
    onDuplicateProfile: (VpnProfile) -> Unit,
    onPingProfile: (VpnProfile) -> Unit,
    onPingAllProfiles: () -> Unit,
    @Suppress("UNUSED_PARAMETER") onImportClipboard: (String) -> Unit,
    onSaveProfile: (VpnProfile) -> Unit = {},
    modifier: Modifier = Modifier
) {
    val clipboardManager = LocalClipboardManager.current
    val connectionState by VpnStateBridge.connectionState.collectAsState()
    val toastMessage by VpnStateBridge.toastMessage.collectAsState()
    val triggerManual by VpnStateBridge.triggerManualConfigDialog.collectAsState()
    val triggerExportActive by VpnStateBridge.triggerExportActiveDialog.collectAsState()

    val isTunnelBusy = connectionState != "DISCONNECTED"

    var showConfigDialog by remember { mutableStateOf(false) }
    var editingProfile by remember { mutableStateOf<VpnProfile?>(null) }
    var shareMenuProfile by remember { mutableStateOf<VpnProfile?>(null) }
    var exportingProfile by remember { mutableStateOf<VpnProfile?>(null) }
    var openUriJsonExportProfile by remember { mutableStateOf<VpnProfile?>(null) }
    var qrProfile by remember { mutableStateOf<VpnProfile?>(null) }
    var deletingProfile by remember { mutableStateOf<VpnProfile?>(null) }
    var showConnectedEditBlockAlert by remember { mutableStateOf(false) }

    val tickedProfiles = remember(profiles) { profiles.filter { it.isSelected } }

    LaunchedEffect(triggerManual) {
        if (triggerManual) {
            VpnStateBridge.triggerManualConfigDialog.value = false
            editingProfile = null
            showConfigDialog = true
        }
    }

    LaunchedEffect(triggerExportActive) {
        if (triggerExportActive) {
            VpnStateBridge.triggerExportActiveDialog.value = false
            val active = profiles.firstOrNull { it.isSelected } ?: profiles.firstOrNull()
            when {
                active == null -> VpnStateBridge.toastMessage.value = "No active configuration to export"
                active.isImported && active.isLocked -> VpnStateBridge.toastMessage.value = "Locked imported configurations cannot be re-exported"
                else -> exportingProfile = active
            }
        }
    }

    Box(modifier = modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .background(MaterialTheme.colorScheme.background)
                .padding(horizontal = 16.dp, vertical = 12.dp)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column {
                    Text(
                        text = "Configurations",
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.ExtraBold,
                        color = MaterialTheme.colorScheme.onBackground
                    )
                    Text(
                        text = when {
                            tickedProfiles.size > 1 -> "✓ ${tickedProfiles.size} Open/Manual Configs Ticked (Simultaneous)"
                            tickedProfiles.firstOrNull()?.let { it.isImported && it.isLocked } == true -> "🔒 1 Locked Config Selected (AES-256-GCM Protected)"
                            tickedProfiles.size == 1 -> "🔓 1 Open Config Selected (Can Lock or Export URI/JSON)"
                            else -> "Tap to tick open configs or select a locked config"
                        },
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary
                    )
                }

                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    IconButton(onClick = { VpnStateBridge.triggerQrScannerDialog.value = true }) {
                        Text("📷", fontSize = 18.sp)
                    }
                    IconButton(onClick = {
                        val sel = profiles.firstOrNull { it.isSelected }
                        if (sel != null) {
                            if (isTunnelBusy) showConnectedEditBlockAlert = true else deletingProfile = sel
                        }
                    }) {
                        Text("🗑️", fontSize = 18.sp)
                    }
                    IconButton(onClick = onPingAllProfiles) {
                        Text("⚡", fontSize = 19.sp)
                    }
                }
            }

            if (profiles.isEmpty()) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(24.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text("No configurations saved", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "Tap the + button at the top right to import a config from Clipboard, File, Cloud, or QR, or create a Manual Configuration.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            textAlign = TextAlign.Center
                        )
                    }
                }
            } else {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    items(profiles) { profile: VpnProfile ->
                        val isCurrentlyConnectedProfile = isTunnelBusy && profile.isSelected
                        val isLockedImport = profile.isImported && profile.isLocked

                        val protoBadge = if (profile.network.isNotBlank() && profile.protocol in listOf("VMESS", "VLESS", "TROJAN")) {
                            "${profile.protocol.uppercase()} (${profile.network.uppercase()})"
                        } else {
                            profile.protocol.uppercase()
                        }

                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .border(
                                    width = if (profile.isSelected) 2.dp else 1.dp,
                                    color = if (profile.isSelected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline.copy(alpha = 0.35f),
                                    shape = RoundedCornerShape(18.dp)
                                )
                                .clickable {
                                    if (!isTunnelBusy) onSelectProfile(profile)
                                    else VpnStateBridge.toastMessage.value = "Disconnect VPN before changing ticked configs"
                                },
                            shape = RoundedCornerShape(18.dp),
                            colors = CardDefaults.cardColors(
                                containerColor = if (profile.isSelected) MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.32f)
                                else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.75f)
                            )
                        ) {
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 14.dp, vertical = 12.dp)
                            ) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        modifier = Modifier.weight(1f)
                                    ) {
                                        Checkbox(
                                            checked = profile.isSelected,
                                            onCheckedChange = {
                                                if (!isTunnelBusy) onSelectProfile(profile)
                                                else VpnStateBridge.toastMessage.value = "Disconnect VPN before changing ticked configs"
                                            }
                                        )
                                        Spacer(modifier = Modifier.width(4.dp))
                                        Text(
                                            text = profile.name,
                                            style = MaterialTheme.typography.titleMedium,
                                            fontWeight = FontWeight.ExtraBold,
                                            color = MaterialTheme.colorScheme.onSurface
                                        )
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Text(profile.countryFlag, fontSize = 16.sp)
                                    }

                                    Surface(
                                        shape = RoundedCornerShape(8.dp),
                                        color = if (isLockedImport) Color(0xFFD97706).copy(alpha = 0.2f) else Color(0xFF00E676).copy(alpha = 0.16f),
                                        border = BorderStroke(1.dp, if (isLockedImport) Color(0xFFFFB300) else Color(0xFF00E676))
                                    ) {
                                        Text(
                                            text = if (isLockedImport) "🔒 LOCKED" else "🔓 OPEN",
                                            fontSize = 10.sp,
                                            fontWeight = FontWeight.ExtraBold,
                                            color = if (isLockedImport) Color(0xFFFFB300) else Color(0xFF00E676),
                                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                                        )
                                    }
                                }

                                Spacer(modifier = Modifier.height(6.dp))

                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        modifier = Modifier.weight(1f)
                                    ) {
                                        Surface(
                                            shape = RoundedCornerShape(6.dp),
                                            color = MaterialTheme.colorScheme.primary.copy(alpha = 0.2f)
                                        ) {
                                            Text(
                                                text = protoBadge,
                                                color = MaterialTheme.colorScheme.primary,
                                                fontSize = 11.sp,
                                                fontWeight = FontWeight.Bold,
                                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                            )
                                        }
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Text(
                                            text = if (isLockedImport) {
                                                "• [AES-256-GCM Enclave Locked]"
                                            } else {
                                                "• ${profile.server}:${profile.port}"
                                            },
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                            maxLines = 1
                                        )
                                    }

                                    if (profile.lastPingMs > 0) {
                                        Text(
                                            text = "${profile.lastPingMs}ms",
                                            fontFamily = FontFamily.Monospace,
                                            fontSize = 12.sp,
                                            fontWeight = FontWeight.Bold,
                                            color = Color(0xFF00E676)
                                        )
                                    }
                                }

                                Spacer(modifier = Modifier.height(8.dp))

                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.End,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    IconButton(onClick = { onPingProfile(profile) }, modifier = Modifier.size(34.dp)) {
                                        Text("⚡", fontSize = 15.sp)
                                    }

                                    if (!isLockedImport) {
                                        Spacer(modifier = Modifier.width(6.dp))
                                        IconButton(onClick = { openUriJsonExportProfile = profile }, modifier = Modifier.size(34.dp)) {
                                            Text("📤", fontSize = 15.sp)
                                        }
                                        Spacer(modifier = Modifier.width(6.dp))
                                        IconButton(onClick = { shareMenuProfile = profile }, modifier = Modifier.size(34.dp)) {
                                            Text("🔒", fontSize = 15.sp)
                                        }
                                        Spacer(modifier = Modifier.width(6.dp))
                                        IconButton(onClick = { onDuplicateProfile(profile) }, modifier = Modifier.size(34.dp)) {
                                            Text("📄", fontSize = 15.sp)
                                        }
                                        Spacer(modifier = Modifier.width(6.dp))
                                        IconButton(
                                            onClick = {
                                                if (isCurrentlyConnectedProfile) {
                                                    showConnectedEditBlockAlert = true
                                                } else {
                                                    editingProfile = profile
                                                    showConfigDialog = true
                                                }
                                            },
                                            modifier = Modifier.size(34.dp)
                                        ) {
                                            Text("✏️", fontSize = 15.sp)
                                        }
                                    }

                                    Spacer(modifier = Modifier.width(6.dp))
                                    IconButton(
                                        onClick = {
                                            if (isCurrentlyConnectedProfile) {
                                                showConnectedEditBlockAlert = true
                                            } else {
                                                deletingProfile = profile
                                            }
                                        },
                                        modifier = Modifier.size(34.dp)
                                    ) {
                                        Text("🗑️", fontSize = 15.sp)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if (toastMessage.isNotEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(bottom = 24.dp),
                contentAlignment = Alignment.BottomCenter
            ) {
                Surface(
                    shape = RoundedCornerShape(24.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.5f)),
                    shadowElevation = 8.dp
                ) {
                    Text(
                        text = toastMessage,
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.padding(horizontal = 20.dp, vertical = 10.dp)
                    )
                }
            }
        }
    }

    if (deletingProfile != null) {
        val target = deletingProfile!!
        AlertDialog(
            onDismissRequest = { deletingProfile = null },
            title = { Text("Delete Configuration", fontWeight = FontWeight.ExtraBold) },
            text = { Text("Are you sure you want to delete \"${target.name}\"? This action cannot be undone.") },
            confirmButton = {
                TextButton(onClick = {
                    onDeleteProfile(target)
                    deletingProfile = null
                }) {
                    Text("Delete", color = MaterialTheme.colorScheme.error, fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { deletingProfile = null }) {
                    Text("Cancel", color = MaterialTheme.colorScheme.primary)
                }
            }
        )
    }

    if (showConnectedEditBlockAlert) {
        AlertDialog(
            onDismissRequest = { showConnectedEditBlockAlert = false },
            title = { Text("Profile Connected") },
            text = { Text("Cannot edit or delete an active configuration while the VPN tunnel is connected. Please disconnect first.") },
            confirmButton = {
                Button(onClick = { showConnectedEditBlockAlert = false }) { Text("OK") }
            }
        )
    }

    if (shareMenuProfile != null) {
        val target = shareMenuProfile!!
        if (target.isImported && target.isLocked) {
            shareMenuProfile = null
            VpnStateBridge.toastMessage.value = "Locked configurations cannot be shared or exported"
        } else {
            val openProfiles = profiles.filter { !(it.isImported && it.isLocked) }
            AlertDialog(
                onDismissRequest = { shareMenuProfile = null },
                title = { Text("Export & Lock Vault: ${target.name}", fontWeight = FontWeight.ExtraBold) },
                text = {
                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        TextButton(onClick = {
                            shareMenuProfile = null
                            openUriJsonExportProfile = target
                        }) {
                            Text("📤 Export Open Xray Config (URI / JSON)", color = Color(0xFFFFD54F), fontWeight = FontWeight.ExtraBold)
                        }
                        TextButton(onClick = {
                            shareMenuProfile = null
                            exportingProfile = target
                        }) {
                            Text("🔒 Lock via File (.svpn) or Cloud", color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.ExtraBold)
                        }
                        TextButton(onClick = {
                            shareMenuProfile = null
                            qrProfile = target
                        }) {
                            Text("🔒 Lock via Encrypted QR Code", color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.ExtraBold)
                        }
                        TextButton(onClick = {
                            shareMenuProfile = null
                            if (openProfiles.size < 2) {
                                VpnStateBridge.toastMessage.value = "You need at least 2 open configurations to create a Locked Bundle"
                            } else {
                                val bundleUri = ConfigCryptoHelper.exportLoadBalanceBundle(openProfiles)
                                clipboardManager.setText(AnnotatedString(bundleUri))
                                VpnStateBridge.toastMessage.value = "Encrypted Locked Bundle copied to clipboard"
                            }
                        }) {
                            Text("⚖️ Create Encrypted Multi-Node Bundle", color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.Bold)
                        }
                    }
                },
                confirmButton = {
                    TextButton(onClick = { shareMenuProfile = null }) {
                        Text("Cancel", color = MaterialTheme.colorScheme.primary)
                    }
                }
            )
        }
    }

    if (openUriJsonExportProfile != null) {
        val target = openUriJsonExportProfile!!
        ExportOpenUriAndJsonDialog(
            profile = target,
            onDismiss = { openUriJsonExportProfile = null }
        )
    }

    if (qrProfile != null) {
        val target = qrProfile!!
        if (target.isImported && target.isLocked) {
            qrProfile = null
        } else {
            val svpnUri = remember(target) {
                ConfigCryptoHelper.exportProfileUri(target, true, target.lockPassphrase, target.lockedDeviceId)
            }
            AlertDialog(
                onDismissRequest = { qrProfile = null },
                title = { Text("🔒 Encrypted QR Vault: ${target.name}", fontWeight = FontWeight.Bold) },
                text = {
                    Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
                        ConfigQrMatrixView(data = svpnUri)
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "AES-256-GCM + PBKDF2-SHA512 Locked QR\nCannot be decrypted outside Techfeeds VPN",
                            fontSize = 11.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            textAlign = TextAlign.Center
                        )
                    }
                },
                confirmButton = {
                    TextButton(onClick = {
                        clipboardManager.setText(AnnotatedString(svpnUri))
                        VpnStateBridge.toastMessage.value = "Locked QR payload copied!"
                        qrProfile = null
                    }) { Text("Copy Locked Payload & Close") }
                },
                dismissButton = {
                    TextButton(onClick = { qrProfile = null }) { Text("Close") }
                }
            )
        }
    }

    if (exportingProfile != null) {
        val target = exportingProfile!!
        if (target.isImported && target.isLocked) {
            exportingProfile = null
            VpnStateBridge.toastMessage.value = "Locked configurations cannot be exported"
        } else {
            ExportConfigurationFullDialog(
                profile = target,
                onDismiss = { exportingProfile = null },
                onSaveLockedProfile = { updated ->
                    onSaveProfile(updated)
                    exportingProfile = null
                },
                onShowQr = { lockedTarget ->
                    exportingProfile = null
                    qrProfile = lockedTarget
                }
            )
        }
    }

    if (showConfigDialog) {
        ProtocolConfigDialog(
            initialProfile = editingProfile,
            onDismiss = { showConfigDialog = false },
            onSave = {
                onSaveProfile(it.copy(isImported = false, isLocked = false))
                showConfigDialog = false
            }
        )
    }
}

@Composable
fun ExportOpenUriAndJsonDialog(
    profile: VpnProfile,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val clipboardManager = LocalClipboardManager.current

    val generatedUri = remember(profile) { buildStandardShareUri(profile) }
    val generatedJson = remember(profile) { buildStandardPrettyXrayJson(profile) }
    var selectedTab by remember { mutableStateOf(0) } // 0 = URI, 1 = JSON

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = "📤 Export URI & Xray JSON: ${profile.name}",
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
                        onClick = { selectedTab = 0 },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (selectedTab == 0) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surfaceVariant,
                            contentColor = if (selectedTab == 0) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurfaceVariant
                        ),
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("🔗 Share URI", fontWeight = FontWeight.ExtraBold, fontSize = 12.sp)
                    }
                    Button(
                        onClick = { selectedTab = 1 },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (selectedTab == 1) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surfaceVariant,
                            contentColor = if (selectedTab == 1) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurfaceVariant
                        ),
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("📄 Xray JSON", fontWeight = FontWeight.ExtraBold, fontSize = 12.sp)
                    }
                }

                OutlinedTextField(
                    value = if (selectedTab == 0) generatedUri else generatedJson,
                    onValueChange = {},
                    readOnly = true,
                    label = {
                        Text(
                            if (selectedTab == 0) "Standard Share URI (${profile.protocol})"
                            else "Xray-Core JSON Configuration"
                        )
                    },
                    textStyle = LocalTextStyle.current.copy(fontFamily = FontFamily.Monospace, fontSize = 11.sp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 120.dp, max = 250.dp)
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Button(
                        onClick = {
                            clipboardManager.setText(AnnotatedString(generatedUri))
                            VpnStateBridge.toastMessage.value = "Copied ${profile.protocol} URI to clipboard!"
                        },
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("📋 Copy URI", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                    }
                    Button(
                        onClick = {
                            clipboardManager.setText(AnnotatedString(generatedJson))
                            VpnStateBridge.toastMessage.value = "Copied Xray JSON to clipboard!"
                        },
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("📋 Copy JSON", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                    }
                }

                OutlinedButton(
                    onClick = {
                        try {
                            val cleanName = profile.name.ifBlank { "xray_config" }.replace(Regex("[^a-zA-Z0-9_-]"), "_")
                            val shareText = if (selectedTab == 0) generatedUri else generatedJson
                            val sendIntent = Intent(Intent.ACTION_SEND).apply {
                                type = "text/plain"
                                putExtra(Intent.EXTRA_SUBJECT, if (selectedTab == 0) "$cleanName-uri.txt" else "$cleanName.json")
                                putExtra(Intent.EXTRA_TEXT, shareText)
                            }
                            context.startActivity(Intent.createChooser(sendIntent, "Share Xray URI / JSON"))
                        } catch (_: Throwable) {}
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = if (selectedTab == 0) "📤 Share URI Link" else "📤 Share Xray .json Config",
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("Done", fontWeight = FontWeight.Bold)
            }
        }
    )
}

private fun buildStandardShareUri(profile: VpnProfile): String {
    val proto = profile.protocol.uppercase().trim()
    val remark = try {
        URLEncoder.encode(profile.name.ifBlank { "Techfeeds-V1.2" }, "UTF-8")
    } catch (_: Throwable) {
        "Techfeeds-V1.2"
    }
    val host = profile.server.trim()
    val port = profile.port.coerceIn(1, 65535)
    val net = profile.network.trim().lowercase().ifBlank { "tcp" }
    val sec = profile.security.trim().lowercase().ifBlank { "none" }
    val sni = profile.sni.trim().ifBlank { host }
    val path = profile.path.trim().ifBlank { "/" }
    val wsHost = profile.wsHost.trim().ifBlank { sni }

    return when (proto) {
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
            "vless://$uuid@$host:$port?encryption=none&security=$sec&type=$net&sni=$sni&fp=$fp&host=$wsHost&path=$encPath$flowParam$pbkParam$sidParam#$remark"
        }
    }
}

private fun buildStandardPrettyXrayJson(profile: VpnProfile): String {
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
        isReality -> """"realitySettings": {"serverName": "$sni", "fingerprint": "${profile.utlsFingerprint.ifBlank { "chrome" }}", "publicKey": "${profile.pbk.trim()}", "shortId": "${profile.sid.trim()}", "spiderX": "/"}"""
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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ExportConfigurationFullDialog(
    profile: VpnProfile,
    onDismiss: () -> Unit,
    onSaveLockedProfile: (VpnProfile) -> Unit,
    onShowQr: (VpnProfile) -> Unit
) {
    val context = LocalContext.current
    val clipboardManager = LocalClipboardManager.current
    val scope = rememberCoroutineScope()

    var filename by remember { mutableStateOf(profile.name) }
    var exportMethod by remember { mutableStateOf("FILE") }
    var cloudProvider by remember { mutableStateOf(profile.cloudProvider.ifBlank { "TechfeedsCloud" }) }
    var burnAfterFirstImport by remember { mutableStateOf(profile.burnAfterFirstImport) }

    var password by remember { mutableStateOf(profile.lockPassphrase) }
    var targetHwids by remember { mutableStateOf(profile.lockedDeviceId) }
    var authorMessage by remember { mutableStateOf(profile.authorMessage) }
    var customServerMessage by remember { mutableStateOf(profile.customServerMessage) }
    var expiryDate by remember { mutableStateOf(profile.expiryDate) }
    var expiryTime by remember { mutableStateOf(profile.expiryTime) }
    var slidingDuration by remember { mutableStateOf(profile.slidingDuration.ifBlank { "None" }) }
    var activeUptimeLimit by remember { mutableStateOf(if (profile.activeUptimeLimitHours > 0) profile.activeUptimeLimitHours.toString() else "") }
    var dataQuotaLimit by remember { mutableStateOf(if (profile.dataQuotaLimitGb > 0f) profile.dataQuotaLimitGb.toString() else "") }
    var maxConnectionRuns by remember { mutableStateOf(if (profile.maxConnectionRuns > 0) profile.maxConnectionRuns.toString() else "") }
    var burnAfterUse by remember { mutableStateOf(profile.burnAfterUse) }
    var allowedNetworkImport by remember { mutableStateOf(profile.allowedNetworkImport.ifBlank { "Any (WiFi & Mobile)" }) }
    // Default ON: Both Wi-Fi & Mobile Data allowed (mobileDataOnly = !allowWifiAndMobile)
    var allowWifiAndMobile by remember { mutableStateOf(!profile.mobileDataOnly) }
    var blockRooted by remember { mutableStateOf(profile.blockRootedDevices) }
    var blockEmulators by remember { mutableStateOf(profile.blockEmulators) }
    var blockSniffers by remember { mutableStateOf(profile.blockSniffers) }
    var playStoreOnly by remember { mutableStateOf(profile.playStoreInstallOnly) }

    Dialog(onDismissRequest = onDismiss, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
                    .padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("🔒 AES-256-GCM Config Lock Vault", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.ExtraBold)
                    IconButton(onClick = onDismiss) { Icon(Icons.Default.Close, null) }
                }

                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = Color(0xFF00E676).copy(alpha = 0.12f),
                    border = BorderStroke(1.dp, Color(0xFF00E676))
                ) {
                    Text(
                        text = "🛡️ Techfeeds VPN Enclave Security Active: PBKDF2-HMAC-SHA512 + 16-Byte Salt + AES-256-GCM AEAD. Locked configs cannot be decrypted or read by any third party.",
                        fontSize = 11.sp,
                        color = Color(0xFF00E676),
                        fontWeight = FontWeight.SemiBold,
                        modifier = Modifier.padding(10.dp)
                    )
                }

                OutlinedTextField(
                    value = filename,
                    onValueChange = { filename = it },
                    label = { Text("Locked Config Name") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                Text("Select Lock & Export Channel", fontWeight = FontWeight.ExtraBold, fontSize = 13.sp)
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    listOf("FILE" to "📁 .svpn File", "CLOUD" to "☁️ Cloud Lock", "QR" to "📷 QR Lock").forEach { (code, label) ->
                        val sel = exportMethod == code
                        Button(
                            onClick = { exportMethod = code },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = if (sel) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surfaceVariant,
                                contentColor = if (sel) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurfaceVariant
                            ),
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.weight(1f)
                        ) {
                            Text(label, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                }

                if (exportMethod == "CLOUD") {
                    Card(
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                            Text("Select Encrypted Cloud Vault", fontWeight = FontWeight.Bold, fontSize = 13.sp)
                            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                listOf("TechfeedsCloud", "Ghost", "Rentry").forEach { prov ->
                                    val sel = cloudProvider == prov
                                    Button(
                                        onClick = {
                                            cloudProvider = prov
                                            if (prov == "Ghost" || prov == "Rentry") burnAfterFirstImport = true
                                        },
                                        colors = ButtonDefaults.buttonColors(
                                            containerColor = if (sel) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surface
                                        ),
                                        shape = RoundedCornerShape(10.dp),
                                        modifier = Modifier.weight(1f)
                                    ) {
                                        Text(prov, fontSize = 11.sp)
                                    }
                                }
                            }
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text("Burn After First Import", fontSize = 13.sp)
                                Switch(checked = burnAfterFirstImport, onCheckedChange = { burnAfterFirstImport = it })
                            }
                        }
                    }
                }

                HorizontalDivider()

                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text("Decryption Password (Optional extra key)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = targetHwids,
                    onValueChange = { targetHwids = it },
                    label = { Text("Bind to Target Hardware ID(s) (Comma-separated)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = authorMessage,
                    onValueChange = { authorMessage = it },
                    label = { Text("Author Note / Banner") },
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = customServerMessage,
                    onValueChange = { customServerMessage = it },
                    label = { Text("Custom Connected Message") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    AssistChip(
                        onClick = {
                            val cal = Calendar.getInstance()
                            DatePickerDialog(
                                context,
                                { _, y, m, d -> expiryDate = "%04d-%02d-%02d".format(y, m + 1, d) },
                                cal.get(Calendar.YEAR),
                                cal.get(Calendar.MONTH),
                                cal.get(Calendar.DAY_OF_MONTH)
                            ).show()
                        },
                        label = { Text(if (expiryDate.isBlank()) "📅 Pick Expiry Date" else "📅 $expiryDate") }
                    )
                    AssistChip(
                        onClick = {
                            val cal = Calendar.getInstance()
                            TimePickerDialog(
                                context,
                                { _, hr, min -> expiryTime = "%02d:%02d".format(hr, min) },
                                cal.get(Calendar.HOUR_OF_DAY),
                                cal.get(Calendar.MINUTE),
                                true
                            ).show()
                        },
                        label = { Text(if (expiryTime.isBlank()) "⏰ Pick Time" else "⏰ $expiryTime") }
                    )
                }

                DropdownSelectorField(
                    label = "Sliding Duration",
                    selected = "Sliding Duration: $slidingDuration",
                    options = listOf("None", "1 Hour", "12 Hours", "1 Day", "3 Days", "7 Days", "14 Days", "30 Days"),
                    onSelect = { slidingDuration = it }
                )

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = activeUptimeLimit,
                        onValueChange = { activeUptimeLimit = it },
                        label = { Text("Uptime Limit (Hrs)") },
                        singleLine = true,
                        modifier = Modifier.weight(1f)
                    )
                    OutlinedTextField(
                        value = dataQuotaLimit,
                        onValueChange = { dataQuotaLimit = it },
                        label = { Text("Quota Limit (GB)") },
                        singleLine = true,
                        modifier = Modifier.weight(1f)
                    )
                }

                OutlinedTextField(
                    value = maxConnectionRuns,
                    onValueChange = { maxConnectionRuns = it },
                    label = { Text("Max Connection Runs") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                    Text("🔥 Burn-After-Use (Self-Destruct)", fontWeight = FontWeight.Bold)
                    Switch(checked = burnAfterUse, onCheckedChange = { burnAfterUse = it })
                }

                DropdownSelectorField(
                    label = "Allowed Network for Import",
                    selected = allowedNetworkImport,
                    options = listOf("Any (WiFi & Mobile)", "Mobile Data Only", "WiFi Only"),
                    onSelect = { allowedNetworkImport = it }
                )

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                    Text("VPN Connection: Wi-Fi & Mobile Data")
                    Switch(checked = allowWifiAndMobile, onCheckedChange = { allowWifiAndMobile = it })
                }
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                    Text("Block Rooted Devices")
                    Switch(checked = blockRooted, onCheckedChange = { blockRooted = it })
                }
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                    Text("Block Emulators")
                    Switch(checked = blockEmulators, onCheckedChange = { blockEmulators = it })
                }
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                    Text("Block Packet Sniffers (HTTPCanary)")
                    Switch(checked = blockSniffers, onCheckedChange = { blockSniffers = it })
                }
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                    Text("PlayStore Install Only")
                    Switch(checked = playStoreOnly, onCheckedChange = { playStoreOnly = it })
                }

                Button(
                    onClick = {
                        val updatedProfile = profile.copy(
                            name = filename.ifBlank { profile.name },
                            isImported = false,
                            isLocked = false,
                            uploadToCloud = (exportMethod == "CLOUD"),
                            cloudProvider = cloudProvider,
                            burnAfterFirstImport = burnAfterFirstImport,
                            lockPassphrase = password,
                            lockedDeviceId = targetHwids,
                            authorMessage = authorMessage,
                            customServerMessage = customServerMessage,
                            expiryDate = expiryDate,
                            expiryTime = expiryTime,
                            slidingDuration = slidingDuration,
                            activeUptimeLimitHours = activeUptimeLimit.toIntOrNull() ?: 0,
                            dataQuotaLimitGb = dataQuotaLimit.toFloatOrNull() ?: 0f,
                            maxConnectionRuns = maxConnectionRuns.toIntOrNull() ?: 0,
                            burnAfterUse = burnAfterUse,
                            allowedNetworkImport = allowedNetworkImport,
                            mobileDataOnly = !allowWifiAndMobile,
                            blockRootedDevices = blockRooted,
                            blockEmulators = blockEmulators,
                            blockSniffers = blockSniffers,
                            playStoreInstallOnly = playStoreOnly
                        )

                        val encryptedUri = ConfigCryptoHelper.exportProfileUri(updatedProfile, true, password, targetHwids)

                        when (exportMethod) {
                            "CLOUD" -> {
                                scope.launch(Dispatchers.IO) {
                                    val cloudLink = ConfigCryptoHelper.uploadConfigToCloud(encryptedUri, cloudProvider)
                                    withContext(Dispatchers.Main) {
                                        clipboardManager.setText(AnnotatedString(cloudLink))
                                        VpnStateBridge.toastMessage.value = "🔒 Encrypted Cloud Lock link copied!"
                                        onSaveLockedProfile(updatedProfile)
                                    }
                                }
                            }
                            "QR" -> {
                                clipboardManager.setText(AnnotatedString(encryptedUri))
                                onSaveLockedProfile(updatedProfile)
                                onShowQr(updatedProfile)
                            }
                            else -> {
                                try {
                                    val cleanName = filename.ifBlank { "config" }.replace(Regex("[^a-zA-Z0-9_-]"), "_")
                                    val outFile = File(context.cacheDir, "$cleanName.svpn")
                                    outFile.writeText(encryptedUri)
                                    clipboardManager.setText(AnnotatedString(encryptedUri))
                                    val sendIntent = Intent(Intent.ACTION_SEND).apply {
                                        type = "text/plain"
                                        putExtra(Intent.EXTRA_SUBJECT, "$cleanName.svpn")
                                        putExtra(Intent.EXTRA_TEXT, encryptedUri)
                                    }
                                    context.startActivity(Intent.createChooser(sendIntent, "Share Locked .svpn File"))
                                } catch (_: Throwable) {}
                                VpnStateBridge.toastMessage.value = "🔒 Locked .svpn encrypted & ready to share!"
                                onSaveLockedProfile(updatedProfile)
                            }
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary),
                    shape = RoundedCornerShape(26.dp),
                    modifier = Modifier.fillMaxWidth().height(52.dp)
                ) {
                    Text(
                        text = when (exportMethod) {
                            "CLOUD" -> "🔒 Encrypt & Lock to Cloud"
                            "QR" -> "🔒 Generate Encrypted QR Code"
                            else -> "🔒 Encrypt & Share .svpn File"
                        },
                        fontWeight = FontWeight.ExtraBold,
                        fontSize = 15.sp
                    )
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProtocolConfigDialog(
    initialProfile: VpnProfile?,
    onDismiss: () -> Unit,
    onSave: (VpnProfile) -> Unit
) {
    val protocolModes = listOf(
        "UDPCUSTOM",
        "SLIPSTREAM-DNSTT", "SSH-SLIPSTREAM", "SSH-SLIPSTREAM-PAYLOAD", "SSH-SLIPSTREAM-TLS", "SSH-SLIPSTREAM-PROXY",
        "SSH", "SSH-DIRECT", "SSH-PROXY", "SSH-PAYLOAD", "SSH-PROXY-PAYLOAD",
        "SSH-TLS", "SSH-TLS-PROXY", "SSH-TLS-PAYLOAD", "SSH-TLS-PROXY-PAYLOAD",
        "SSH-DNSTT", "SSH-DNSTT-PAYLOAD", "SSH-DNSTT-PROXY", "SSH-DNSTT-PROXY-PAYLOAD",
        "SSH-DNSTT-TLS", "SSH-DNSTT-TLS-PAYLOAD", "SSH-DNSTT-TLS-PROXY", "SSH-DNSTT-TLS-PROXY-PAYLOAD",
        "VMESS", "VLESS", "TROJAN", "SHADOWSOCKS", "WIREGUARD", "OPENVPN", "HYSTERIA2"
    )

    var selectedProtocol by remember { mutableStateOf(initialProfile?.protocol?.uppercase() ?: "UDPCUSTOM") }
    var name by remember { mutableStateOf(initialProfile?.name ?: "New Config") }
    var jsonEditor by remember { mutableStateOf(initialProfile?.rawJson?.isNotBlank() == true) }
    var rawJson by remember { mutableStateOf(initialProfile?.rawJson ?: "") }

    var server by remember { mutableStateOf(initialProfile?.server ?: "") }
    var port by remember {
        mutableStateOf(
            (initialProfile?.port ?: when (selectedProtocol) {
                "UDPCUSTOM" -> 36712
                "VMESS", "VLESS", "TROJAN", "HYSTERIA2" -> 443
                "SHADOWSOCKS" -> 8388
                "WIREGUARD" -> 51820
                "OPENVPN" -> 1194
                else -> 22
            }).toString()
        )
    }

    var udpgwPort by remember { mutableStateOf((initialProfile?.udpgwPort ?: 7300).toString()) }
    var enableUdpgwDns by remember { mutableStateOf(initialProfile?.enableUdpgwDns ?: false) }
    var sshUser by remember { mutableStateOf(initialProfile?.sshUser ?: "") }
    var sshPass by remember { mutableStateOf(initialProfile?.sshPass ?: "") }

    var authenticateProxy by remember { mutableStateOf(initialProfile?.proxyAuth ?: false) }
    val initProxyHost = initialProfile?.proxyHost ?: ""
    val initProxyPort = initialProfile?.proxyPort ?: 8080
    var httpProxy by remember { mutableStateOf(if (initProxyHost.isNotBlank()) "$initProxyHost:$initProxyPort" else "") }
    var payload by remember { mutableStateOf(initialProfile?.payload ?: "") }
    var showInlinePayloadGen by remember { mutableStateOf(false) }

    var tlsVersion by remember { mutableStateOf(initialProfile?.tlsVersion ?: "DEFAULT") }
    var sni by remember { mutableStateOf(initialProfile?.sni ?: "") }

    var dnsttMode by remember { mutableStateOf(initialProfile?.dnsttMode ?: "UDP") }
    var udpResolver by remember { mutableStateOf(initialProfile?.slowDnsServerIp ?: "8.8.8.8:53,1.1.1.1:53") }
    var nameserver by remember { mutableStateOf(initialProfile?.slowDnsDomain ?: "") }
    var publicKey by remember { mutableStateOf(initialProfile?.slowDnsPubKey ?: "") }

    var uuid by remember { mutableStateOf(initialProfile?.uuid?.ifBlank { initialProfile.sshPass } ?: "") }
    var ssMethod by remember { mutableStateOf(initialProfile?.ssMethod?.ifBlank { "chacha20-ietf-poly1305" } ?: "chacha20-ietf-poly1305") }
    var network by remember { mutableStateOf(initialProfile?.network ?: "tcp") }
    var security by remember { mutableStateOf(initialProfile?.security ?: "none") }
    var pbk by remember { mutableStateOf(initialProfile?.pbk ?: "") }
    var sid by remember { mutableStateOf(initialProfile?.sid ?: "") }
    var spx by remember { mutableStateOf(initialProfile?.spx ?: "") }
    var utlsFingerprint by remember { mutableStateOf(initialProfile?.utlsFingerprint ?: "chrome") }
    var alpn by remember { mutableStateOf(initialProfile?.alpn ?: "") }
    var flow by remember { mutableStateOf(initialProfile?.flow ?: "") }
    var autoRotateSni by remember { mutableStateOf(initialProfile?.autoRotateSni ?: false) }
    var pinSha256 by remember { mutableStateOf(initialProfile?.pinSha256 ?: "") }
    var verifyCertName by remember { mutableStateOf(initialProfile?.verifyCertName ?: "") }
    var wsHost by remember { mutableStateOf(initialProfile?.wsHost ?: "") }
    var wsPath by remember { mutableStateOf(initialProfile?.path ?: "") }
    var allowInsecure by remember { mutableStateOf(initialProfile?.allowInsecure ?: true) }

    var wgPrivateKey by remember { mutableStateOf(initialProfile?.wgPrivateKey ?: "") }
    var wgPublicKey by remember { mutableStateOf(initialProfile?.wgPublicKey ?: "") }
    var wgAddress by remember { mutableStateOf(initialProfile?.wgAddress ?: "10.0.0.2/32") }
    var wgAllowedIps by remember { mutableStateOf(initialProfile?.wgAllowedIps ?: "0.0.0.0/0, ::/0") }

    var hy2Password by remember { mutableStateOf(initialProfile?.hy2Password ?: "") }
    var hy2ObfsPassword by remember { mutableStateOf(initialProfile?.hy2ObfsPassword ?: "") }
    var hy2PortHopping by remember { mutableStateOf(initialProfile?.hy2PortHopping ?: "") }
    var hy2UpMbps by remember { mutableStateOf((initialProfile?.hy2UpMbps ?: 50).toString()) }
    var hy2DownMbps by remember { mutableStateOf((initialProfile?.hy2DownMbps ?: 100).toString()) }

    val pendingPayload by VpnStateBridge.pendingGeneratedPayload.collectAsState()
    LaunchedEffect(pendingPayload) {
        if (pendingPayload.isNotEmpty()) {
            payload = pendingPayload
            VpnStateBridge.pendingGeneratedPayload.value = ""
            showInlinePayloadGen = false
        }
    }

    val isSshFamily = selectedProtocol.startsWith("SSH") ||
        selectedProtocol == "UDPCUSTOM" ||
        selectedProtocol.contains("SLIPSTREAM")
    val hasProxy = selectedProtocol.contains("PROXY")
    val hasPayload = selectedProtocol.contains("PAYLOAD")
    val hasTls = selectedProtocol.contains("TLS")
    val hasDnstt = selectedProtocol.contains("DNSTT") || selectedProtocol.contains("SLIPSTREAM")

    Dialog(onDismissRequest = onDismiss, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
                    .padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = if (initialProfile == null) "New Manual Configuration" else "Edit Configuration",
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.ExtraBold,
                        modifier = Modifier.weight(1f),
                        textAlign = TextAlign.Center
                    )
                    IconButton(onClick = onDismiss) { Icon(Icons.Default.Close, contentDescription = "Close") }
                }

                OutlinedTextField(value = name, onValueChange = { name = it }, label = { Text("Profile Name") }, singleLine = true, modifier = Modifier.fillMaxWidth())

                DropdownSelectorField(
                    label = "Protocol",
                    selected = selectedProtocol,
                    options = protocolModes,
                    onSelect = { code ->
                        selectedProtocol = code
                        port = when (code) {
                            "UDPCUSTOM" -> "36712"
                            "VMESS", "VLESS", "TROJAN", "HYSTERIA2" -> "443"
                            "SHADOWSOCKS" -> "8388"
                            "WIREGUARD" -> "51820"
                            "OPENVPN" -> "1194"
                            else -> "22"
                        }
                    }
                )

                if (isSshFamily) {
                    OutlinedTextField(
                        value = server,
                        onValueChange = { server = it },
                        label = { Text(if (selectedProtocol == "UDPCUSTOM") "UDP Custom Server IP / Host" else "SSH Host") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = port,
                        onValueChange = { port = it },
                        label = { Text(if (selectedProtocol == "UDPCUSTOM") "UDP Custom Port (e.g. 36712 or 1-65535)" else "SSH Port") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(value = udpgwPort, onValueChange = { udpgwPort = it }, label = { Text("Udpgw Port") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                        Text("Enable UDPGW transparent DNS", fontSize = 12.sp, modifier = Modifier.weight(1f))
                        Checkbox(checked = enableUdpgwDns, onCheckedChange = { enableUdpgwDns = it })
                    }
                    OutlinedTextField(value = sshUser, onValueChange = { sshUser = it }, label = { Text("Username") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(value = sshPass, onValueChange = { sshPass = it }, label = { Text("Password") }, singleLine = true, modifier = Modifier.fillMaxWidth())

                    if (hasTls) {
                        DropdownSelectorField(label = "TLS Version", selected = tlsVersion, options = listOf("DEFAULT", "TLSv1.2", "TLSv1.3"), onSelect = { tlsVersion = it })
                        OutlinedTextField(value = sni, onValueChange = { sni = it }, label = { Text("SNI (Bug Host)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                    }
                    if (hasProxy) {
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                            Text("Authenticate Proxy")
                            Checkbox(checked = authenticateProxy, onCheckedChange = { authenticateProxy = it })
                        }
                        OutlinedTextField(value = httpProxy, onValueChange = { httpProxy = it }, label = { Text("HTTP Proxy (host:port)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                    }
                    if (hasPayload) {
                        OutlinedButton(onClick = { showInlinePayloadGen = !showInlinePayloadGen }, shape = RoundedCornerShape(12.dp), modifier = Modifier.fillMaxWidth()) {
                            Text("⚙ Open Payload Generator")
                        }
                        if (showInlinePayloadGen) {
                            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant), modifier = Modifier.fillMaxWidth()) {
                                FullPayloadGeneratorScreen()
                            }
                        }
                        OutlinedTextField(
                            value = payload,
                            onValueChange = { payload = it },
                            label = { Text("Payload") },
                            minLines = 4,
                            textStyle = LocalTextStyle.current.copy(fontFamily = FontFamily.Monospace, fontSize = 12.sp),
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                    if (hasDnstt) {
                        DropdownSelectorField(
                            label = if (selectedProtocol.contains("SLIPSTREAM")) "Slipstream Transport Mode" else "DNSTT Mode",
                            selected = dnsttMode,
                            options = listOf("UDP", "DoH", "DoT", "QUIC-Multipath"),
                            onSelect = { dnsttMode = it }
                        )
                        OutlinedTextField(
                            value = udpResolver,
                            onValueChange = { udpResolver = it },
                            label = { Text("Resolver(s) (e.g. 1.1.1.1:53,8.8.8.8:53)") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                        OutlinedTextField(value = nameserver, onValueChange = { nameserver = it }, label = { Text("Nameserver (NS Domain)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                        OutlinedTextField(value = publicKey, onValueChange = { publicKey = it }, label = { Text("Public Key") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                    }
                }

                if (selectedProtocol in listOf("VMESS", "VLESS", "TROJAN", "SHADOWSOCKS")) {
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                        Text("JSON Editor", fontWeight = FontWeight.Bold)
                        Switch(checked = jsonEditor, onCheckedChange = { jsonEditor = it })
                    }
                    if (jsonEditor) {
                        OutlinedTextField(value = rawJson, onValueChange = { rawJson = it }, label = { Text("Raw Xray JSON") }, minLines = 6, modifier = Modifier.fillMaxWidth())
                    } else {
                        OutlinedTextField(value = server, onValueChange = { server = it }, label = { Text("Server IP / Host") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                        OutlinedTextField(value = port, onValueChange = { port = it }, label = { Text("Server Port") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                        if (selectedProtocol == "SHADOWSOCKS") {
                            DropdownSelectorField(
                                label = "Shadowsocks Cipher",
                                selected = ssMethod,
                                options = listOf(
                                    "chacha20-ietf-poly1305",
                                    "aes-256-gcm",
                                    "aes-128-gcm",
                                    "2022-blake3-aes-256-gcm",
                                    "2022-blake3-chacha20-poly1305",
                                    "xchacha20-ietf-poly1305",
                                    "aes-256-cfb",
                                    "none"
                                ),
                                onSelect = { ssMethod = it }
                            )
                        }
                        OutlinedTextField(value = uuid, onValueChange = { uuid = it }, label = { Text(if (selectedProtocol in listOf("TROJAN", "SHADOWSOCKS")) "Password" else "UUID") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                        OutlinedTextField(value = network, onValueChange = { network = it }, label = { Text("Network (tcp, ws, grpc)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                        OutlinedTextField(value = security, onValueChange = { security = it }, label = { Text("Security (none, tls, reality)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                        if (selectedProtocol == "VLESS") {
                            OutlinedTextField(value = pbk, onValueChange = { pbk = it }, label = { Text("Reality Public Key (pbk)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                            OutlinedTextField(value = sid, onValueChange = { sid = it }, label = { Text("Reality Short ID (sid)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                            OutlinedTextField(value = spx, onValueChange = { spx = it }, label = { Text("Reality SpiderX (spx)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                            DropdownSelectorField(label = "uTLS Fingerprint", selected = utlsFingerprint, options = listOf("chrome", "firefox", "safari", "ios", "android", "edge", "randomized"), onSelect = { utlsFingerprint = it })
                        }
                        OutlinedTextField(value = alpn, onValueChange = { alpn = it }, label = { Text("ALPN (e.g. h2,http/1.1)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                        if (selectedProtocol in listOf("VLESS", "TROJAN")) {
                            OutlinedTextField(value = flow, onValueChange = { flow = it }, label = { Text("Flow (e.g. xtls-rprx-vision)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                        }
                        OutlinedTextField(value = sni, onValueChange = { sni = it }, label = { Text("SNI (Bug Host, comma-separated)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                            Text("Auto-rotate multi-SNI Bug Hosts", fontWeight = FontWeight.SemiBold)
                            Switch(checked = autoRotateSni, onCheckedChange = { autoRotateSni = it })
                        }
                        OutlinedTextField(value = pinSha256, onValueChange = { pinSha256 = it }, label = { Text("pinSHA256") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                        OutlinedTextField(value = verifyCertName, onValueChange = { verifyCertName = it }, label = { Text("Verify Peer Cert By Name") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                        OutlinedTextField(value = wsHost, onValueChange = { wsHost = it }, label = { Text("Host (WebSocket / HTTP Header)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                        OutlinedTextField(value = wsPath, onValueChange = { wsPath = it }, label = { Text("Path (WebSocket / gRPC ServiceName)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                        Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(checked = allowInsecure, onCheckedChange = { allowInsecure = it })
                            Text("Allow Insecure (Bypass TLS Cert Verification)", fontSize = 13.sp)
                        }
                    }
                }

                if (selectedProtocol == "WIREGUARD") {
                    OutlinedTextField(value = server, onValueChange = { server = it }, label = { Text("WireGuard Endpoint Host") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(value = port, onValueChange = { port = it }, label = { Text("WireGuard Endpoint Port") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(value = wgPrivateKey, onValueChange = { wgPrivateKey = it }, label = { Text("Client Private Key") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(value = wgPublicKey, onValueChange = { wgPublicKey = it }, label = { Text("Peer Public Key") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(value = wgAddress, onValueChange = { wgAddress = it }, label = { Text("Client Address (e.g. 10.0.0.2/32)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(value = wgAllowedIps, onValueChange = { wgAllowedIps = it }, label = { Text("Allowed IPs") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                }

                if (selectedProtocol == "OPENVPN") {
                    OutlinedTextField(value = server, onValueChange = { server = it }, label = { Text("Server IP / Host") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(value = port, onValueChange = { port = it }, label = { Text("Server Port") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(value = sshUser, onValueChange = { sshUser = it }, label = { Text("OpenVPN Username") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(value = sshPass, onValueChange = { sshPass = it }, label = { Text("OpenVPN Password") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                }

                if (selectedProtocol == "HYSTERIA2") {
                    OutlinedTextField(value = server, onValueChange = { server = it }, label = { Text("Server IP / Host") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(value = port, onValueChange = { port = it }, label = { Text("Server Port") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(value = hy2Password, onValueChange = { hy2Password = it }, label = { Text("Auth Password") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(value = hy2ObfsPassword, onValueChange = { hy2ObfsPassword = it }, label = { Text("Salamander Obfs Password") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(value = hy2PortHopping, onValueChange = { hy2PortHopping = it }, label = { Text("Port Hopping Range (e.g. 20000-50000)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(value = hy2UpMbps, onValueChange = { hy2UpMbps = it }, label = { Text("Up (Mbps)") }, singleLine = true, modifier = Modifier.weight(1f))
                        OutlinedTextField(value = hy2DownMbps, onValueChange = { hy2DownMbps = it }, label = { Text("Down (Mbps)") }, singleLine = true, modifier = Modifier.weight(1f))
                    }
                    OutlinedTextField(value = sni, onValueChange = { sni = it }, label = { Text("SNI (Server Name Indicator)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                    OutlinedTextField(value = pinSha256, onValueChange = { pinSha256 = it }, label = { Text("pinSHA256") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                }

                Button(
                    onClick = {
                        val resolvedPort = port.toIntOrNull() ?: 443
                        val pHost = httpProxy.substringBefore(":").trim()
                        val pPort = httpProxy.substringAfter(":", "8080").toIntOrNull() ?: 8080
                        val resolvedServer = server.trim().ifBlank { if (hasDnstt) nameserver.trim() else sni.trim() }

                        onSave(
                            VpnProfile(
                                id = initialProfile?.id ?: 0,
                                name = name.ifBlank { "$selectedProtocol-$resolvedServer" },
                                protocol = selectedProtocol,
                                server = resolvedServer,
                                port = resolvedPort,
                                uuid = when (selectedProtocol) {
                                    "HYSTERIA2" -> hy2Password
                                    "WIREGUARD" -> wgPrivateKey
                                    else -> uuid.ifBlank { sshUser }
                                },
                                network = if (selectedProtocol == "UDPCUSTOM") "udp" else network.ifBlank { "tcp" },
                                security = security.ifBlank { "none" },
                                sni = sni,
                                pbk = if (hasDnstt) publicKey else pbk,
                                sid = sid,
                                spx = spx.ifBlank { "/" },
                                utlsFingerprint = utlsFingerprint.ifBlank { "chrome" },
                                flow = flow,
                                path = wsPath.ifBlank { "/" },
                                rawJson = if (jsonEditor) rawJson else "",
                                isSelected = true,
                                isImported = false,
                                isLocked = false,
                                sshUser = sshUser,
                                sshPass = if (selectedProtocol == "SHADOWSOCKS") uuid.ifBlank { sshPass } else sshPass,
                                payload = payload,
                                proxyHost = pHost,
                                proxyPort = pPort,
                                proxyAuth = authenticateProxy,
                                udpgwPort = udpgwPort.toIntOrNull() ?: 7300,
                                enableUdpgwDns = enableUdpgwDns,
                                tlsVersion = tlsVersion,
                                slowDnsDomain = nameserver,
                                slowDnsPubKey = publicKey,
                                slowDnsServerIp = udpResolver.ifBlank { "8.8.8.8:53,1.1.1.1:53" },
                                dnsttMode = dnsttMode,
                                wgPrivateKey = wgPrivateKey,
                                wgPublicKey = wgPublicKey,
                                wgAddress = wgAddress,
                                wgAllowedIps = wgAllowedIps,
                                hy2Password = hy2Password,
                                hy2Obfs = if (hy2ObfsPassword.isNotBlank()) "salamander" else "",
                                hy2ObfsPassword = hy2ObfsPassword,
                                hy2PortHopping = hy2PortHopping,
                                hy2UpMbps = hy2UpMbps.toIntOrNull() ?: 50,
                                hy2DownMbps = hy2DownMbps.toIntOrNull() ?: 100,
                                ssMethod = ssMethod.ifBlank { "chacha20-ietf-poly1305" },
                                alpn = alpn.ifBlank { "h2, http/1.1" },
                                autoRotateSni = autoRotateSni,
                                pinSha256 = pinSha256,
                                verifyCertName = verifyCertName,
                                wsHost = wsHost,
                                allowInsecure = allowInsecure
                            )
                        )
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary),
                    shape = RoundedCornerShape(28.dp),
                    modifier = Modifier.fillMaxWidth().height(54.dp)
                ) {
                    Text("SAVE CONFIGURATION", fontWeight = FontWeight.ExtraBold, fontSize = 15.sp)
                }
            }
        }
    }
}

@Composable
fun ConfigQrMatrixView(data: String) {
    val digest = remember(data) { MessageDigest.getInstance("SHA-512").digest(data.toByteArray()) }
    Box(
        modifier = Modifier
            .size(190.dp)
            .background(Color.White, RoundedCornerShape(8.dp))
            .padding(12.dp),
        contentAlignment = Alignment.Center
    ) {
        Canvas(modifier = Modifier.fillMaxSize()) {
            val gridSize = 25
            val cellSize = size.width / gridSize
            fun isFinder(r: Int, c: Int) = (r in 0..6 && c in 0..6) || (r in 0..6 && c >= gridSize - 7) || (r >= gridSize - 7 && c in 0..6)
            fun drawFinder(sr: Int, sc: Int) {
                for (r in 0..6) for (c in 0..6) {
                    if (r == 0 || r == 6 || c == 0 || c == 6 || (r in 2..4 && c in 2..4)) {
                        drawRect(Color.Black, Offset((sc + c) * cellSize, (sr + r) * cellSize), Size(cellSize, cellSize))
                    }
                }
            }
            drawFinder(0, 0)
            drawFinder(0, gridSize - 7)
            drawFinder(gridSize - 7, 0)

            var bitIdx = 0
            for (r in 0 until gridSize) for (c in 0 until gridSize) {
                if (!isFinder(r, c)) {
                    val b = digest[(bitIdx / 8) % digest.size].toInt()
                    if (((b shr (bitIdx % 8)) and 1) == 1) {
                        drawRect(Color.Black, Offset(c * cellSize, r * cellSize), Size(cellSize, cellSize))
                    }
                    bitIdx++
                }
            }
        }
    }
}
