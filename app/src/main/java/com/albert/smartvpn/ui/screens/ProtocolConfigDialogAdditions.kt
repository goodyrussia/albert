package com.albert.smartvpn.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.albert.smartvpn.data.VpnProfile

@Composable
fun ProtocolSpecificInputs(
    selectedProtocol: String,
    server: String,
    onServerChange: (String) -> Unit,
    port: String,
    onPortChange: (String) -> Unit,
    uuid: String,
    onUuidChange: (String) -> Unit,
    // OpenVPN specific
    ovpnUser: String,
    onOvpnUserChange: (String) -> Unit,
    ovpnPass: String,
    onOvpnPassChange: (String) -> Unit,
    // WireGuard specific
    wgPrivateKey: String,
    onWgPrivateKeyChange: (String) -> Unit,
    wgPublicKey: String,
    onWgPublicKeyChange: (String) -> Unit,
    wgAddress: String,
    onWgAddressChange: (String) -> Unit,
    // ShadowSocks specific
    ssMethod: String,
    onSsMethodChange: (String) -> Unit
) {
    when (selectedProtocol) {
        "OPENVPN" -> {
            OutlinedTextField(
                value = server,
                onValueChange = onServerChange,
                label = { Text("Server IP / Host") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            OutlinedTextField(
                value = port,
                onValueChange = onPortChange,
                label = { Text("Server Port (1194)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            OutlinedTextField(
                value = ovpnUser,
                onValueChange = onOvpnUserChange,
                label = { Text("OpenVPN Username (Optional)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            OutlinedTextField(
                value = ovpnPass,
                onValueChange = onOvpnPassChange,
                label = { Text("OpenVPN Password (Optional)") },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth()
            )
        }
        "WIREGUARD" -> {
            OutlinedTextField(
                value = server,
                onValueChange = onServerChange,
                label = { Text("WireGuard Endpoint IP / Host") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            OutlinedTextField(
                value = port,
                onValueChange = onPortChange,
                label = { Text("WireGuard Endpoint Port (e.g. 51820)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            OutlinedTextField(
                value = wgPrivateKey,
                onValueChange = onWgPrivateKeyChange,
                label = { Text("Client Private Key (SecretKey)") },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth()
            )
            OutlinedTextField(
                value = wgPublicKey,
                onValueChange = onWgPublicKeyChange,
                label = { Text("Peer Public Key") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            OutlinedTextField(
                value = wgAddress,
                onValueChange = onWgAddressChange,
                label = { Text("Client Address (e.g. 10.0.0.2/32)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
        }
        "SHADOWSOCKS" -> {
            OutlinedTextField(
                value = server,
                onValueChange = onServerChange,
                label = { Text("Server IP / Host") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            OutlinedTextField(
                value = port,
                onValueChange = onPortChange,
                label = { Text("Server Port (8388)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            OutlinedTextField(
                value = ssMethod,
                onValueChange = onSsMethodChange,
                label = { Text("Encryption (e.g. aes-256-gcm)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            OutlinedTextField(
                value = uuid,
                onValueChange = onUuidChange,
                label = { Text("Password") },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth()
            )
        }
        else -> {
            // Standard fallback inputs for SSH, VLESS, VMess, Trojan, Hysteria2
        }
    }
}
