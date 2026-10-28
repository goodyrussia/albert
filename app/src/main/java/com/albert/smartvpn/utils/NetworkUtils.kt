package com.albert.smartvpn.utils

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL

object NetworkUtils {
    
    suspend fun executePing(host: String): String = withContext(Dispatchers.IO) {
        val result = StringBuilder()
        try {
            val process = ProcessBuilder("ping", "-c", "4", host).start()
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                result.append(line).append("\n")
            }
            process.waitFor()
            if (result.isEmpty()) "Ping failed: Network unreachable or host down." else result.toString()
        } catch (e: Exception) {
            "Error executing ping: ${e.message}"
        }
    }

    suspend fun getIpAndGeoData(): String = withContext(Dispatchers.IO) {
        try {
            val url = URL("https://ipwho.is/")
            val connection = url.openConnection() as HttpURLConnection
            connection.requestMethod = "GET"
            connection.connectTimeout = 5000
            
            val reader = BufferedReader(InputStreamReader(connection.inputStream))
            val response = reader.readText()
            reader.close()

            val json = JSONObject(response)
            if (json.getBoolean("success")) {
                val ip = json.getString("ip")
                val country = json.getString("country")
                val isp = json.getJSONObject("connection").getString("isp")
                "IP: $ip\nLocation: $country\nISP: $isp"
            } else {
                "Failed to parse IP data."
            }
        } catch (e: Exception) {
            "Network error during IP lookup: ${e.message}"
        }
    }
}
