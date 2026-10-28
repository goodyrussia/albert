package com.albert.smartvpn.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import com.albert.smartvpn.ui.viewmodel.VpnStateBridge

// 5. Royal Gold & Amethyst (Default Theme for Techfeeds VPN v1)
private val RoyalGoldAmethystScheme = darkColorScheme(
    primary = Color(0xFFFFD54F),
    onPrimary = Color(0xFF1A0933),
    secondary = Color(0xFFB388FF),
    onSecondary = Color(0xFF120524),
    tertiary = Color(0xFFE040FB),
    background = Color(0xFF0D061A),
    onBackground = Color(0xFFF8F4FF),
    surface = Color(0xFF170B2C),
    onSurface = Color(0xFFF8F4FF),
    surfaceVariant = Color(0xFF241242),
    onSurfaceVariant = Color(0xFFD1C4E9)
)

private val MidnightObsidianScheme = darkColorScheme(
    primary = Color(0xFF00E5FF),
    onPrimary = Color(0xFF001F26),
    secondary = Color(0xFFFFB300),
    background = Color(0xFF070B14),
    onBackground = Color(0xFFF0F4F8),
    surface = Color(0xFF0F172A),
    onSurface = Color(0xFFF0F4F8),
    surfaceVariant = Color(0xFF1E293B),
    onSurfaceVariant = Color(0xFF94A3B8)
)

private val DaylightSapphireScheme = lightColorScheme(
    primary = Color(0xFF5E35B1),
    onPrimary = Color.White,
    secondary = Color(0xFFFF8F00),
    background = Color(0xFFF6F4FB),
    onBackground = Color(0xFF170B2C),
    surface = Color(0xFFFFFFFF),
    onSurface = Color(0xFF170B2C),
    surfaceVariant = Color(0xFFEDE7F6),
    onSurfaceVariant = Color(0xFF4A3B69)
)

private val SynthwaveNeonScheme = darkColorScheme(
    primary = Color(0xFFFF007F),
    onPrimary = Color.White,
    secondary = Color(0xFF00F0FF),
    background = Color(0xFF0F051D),
    onBackground = Color(0xFFFCE4EC),
    surface = Color(0xFF1B0B30),
    onSurface = Color(0xFFFCE4EC),
    surfaceVariant = Color(0xFF2D144B),
    onSurfaceVariant = Color(0xFFCE93D8)
)

private val EmeraldMatrixScheme = darkColorScheme(
    primary = Color(0xFF00E676),
    onPrimary = Color(0xFF00210F),
    secondary = Color(0xFF69F0AE),
    background = Color(0xFF041008),
    onBackground = Color(0xFFE8F5E9),
    surface = Color(0xFF0A1F12),
    onSurface = Color(0xFFE8F5E9),
    surfaceVariant = Color(0xFF133320),
    onSurfaceVariant = Color(0xFFA5D6A7)
)

private val CrimsonPhantomScheme = darkColorScheme(
    primary = Color(0xFFFF1744),
    onPrimary = Color.White,
    secondary = Color(0xFFFF9100),
    background = Color(0xFF120508),
    onBackground = Color(0xFFFFEBEE),
    surface = Color(0xFF21090E),
    onSurface = Color(0xFFFFEBEE),
    surfaceVariant = Color(0xFF361018),
    onSurfaceVariant = Color(0xFFEF9A9A)
)

private val OceanTitaniumScheme = darkColorScheme(
    primary = Color(0xFF38BDF8),
    onPrimary = Color(0xFF041E30),
    secondary = Color(0xFF818CF8),
    background = Color(0xFF07111E),
    onBackground = Color(0xFFE2E8F0),
    surface = Color(0xFF0E1E32),
    onSurface = Color(0xFFE2E8F0),
    surfaceVariant = Color(0xFF19304B),
    onSurfaceVariant = Color(0xFF94A3B8)
)

private val SunsetAmberScheme = darkColorScheme(
    primary = Color(0xFFFFB300),
    onPrimary = Color(0xFF261600),
    secondary = Color(0xFFFF7043),
    background = Color(0xFF140C04),
    onBackground = Color(0xFFFFF8E1),
    surface = Color(0xFF241608),
    onSurface = Color(0xFFFFF8E1),
    surfaceVariant = Color(0xFF38230D),
    onSurfaceVariant = Color(0xFFFFCC80)
)

private val MonochromeSlateScheme = darkColorScheme(
    primary = Color(0xFFE2E8F0),
    onPrimary = Color(0xFF0F172A),
    secondary = Color(0xFF94A3B8),
    background = Color(0xFF090D16),
    onBackground = Color(0xFFF8FAFC),
    surface = Color(0xFF131B2E),
    onSurface = Color(0xFFF8FAFC),
    surfaceVariant = Color(0xFF1E293B),
    onSurfaceVariant = Color(0xFFCBD5E1)
)

@Composable
fun SmartVpnTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val context = LocalContext.current
    val selectedTheme by VpnStateBridge.themeMode.collectAsState()
    val useDynamic by VpnStateBridge.dynamicColorEnabled.collectAsState()

    val colorScheme = when {
        useDynamic && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        selectedTheme.startsWith("5.") || selectedTheme.contains("Royal Gold", ignoreCase = true) -> RoyalGoldAmethystScheme
        selectedTheme.startsWith("1.") -> MidnightObsidianScheme
        selectedTheme.startsWith("2.") || selectedTheme.equals("Light", true) -> DaylightSapphireScheme
        selectedTheme.startsWith("3.") -> SynthwaveNeonScheme
        selectedTheme.startsWith("4.") -> EmeraldMatrixScheme
        selectedTheme.startsWith("6.") -> CrimsonPhantomScheme
        selectedTheme.startsWith("7.") -> DaylightSapphireScheme
        selectedTheme.startsWith("8.") -> OceanTitaniumScheme
        selectedTheme.startsWith("9.") -> SunsetAmberScheme
        selectedTheme.startsWith("10.") -> MonochromeSlateScheme
        selectedTheme.startsWith("Auto") -> if (darkTheme) RoyalGoldAmethystScheme else DaylightSapphireScheme
        else -> RoyalGoldAmethystScheme
    }

    MaterialTheme(
        colorScheme = colorScheme,
        content = content
    )
}
