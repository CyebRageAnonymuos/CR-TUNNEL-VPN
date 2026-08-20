package com.cr.tunnel.handler

import com.cr.tunnel.dto.entities.ProfileItem
import com.cr.tunnel.util.HttpUtil
import com.cr.tunnel.util.JsonUtil
import com.cr.tunnel.util.LogUtil
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.InetAddress

/**
 * Resolves the country code of a server from its address and caches it per GUID.
 * Uses several fallback GeoIP endpoints and retries later if a lookup fails.
 */
object CountryResolver {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val pending = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()

    fun getCountryCode(guid: String): String? {
        return MmkvManager.getServerCountry(guid)?.takeIf { it.isNotBlank() }
    }

    fun flagEmoji(countryCode: String?): String {
        if (countryCode.isNullOrBlank()) return ""
        val code = countryCode.uppercase()
        if (code.length == 2 && code.all { it in 'A'..'Z' }) {
            val base = 0x1F1E6
            val sb = StringBuilder()
            for (c in code) sb.append((base + (c.code - 'A'.code)).toChar())
            return sb.toString()
        }
        return ""
    }

    fun resolve(guid: String, profile: ProfileItem, onResolved: (String) -> Unit = {}) {
        val cached = getCountryCode(guid)
        if (cached != null) {
            onResolved(cached)
            return
        }
        val server = profile.server?.takeIf { it.isNotBlank() } ?: return
        if (!pending.add(guid)) return

        scope.launch {
            try {
                val code = lookupCountry(server)
                if (code != null) {
                    MmkvManager.setServerCountry(guid, code)
                    withContext(Dispatchers.Main) { onResolved(code) }
                } else {
                    // The device may be offline or the API unreachable; try again later.
                    delay(15_000)
                    if (!pending.remove(guid)) return@launch
                    val retryCode = lookupCountry(server)
                    if (retryCode != null) {
                        MmkvManager.setServerCountry(guid, retryCode)
                        withContext(Dispatchers.Main) { onResolved(retryCode) }
                    }
                }
            } catch (cancelled: kotlinx.coroutines.CancellationException) {
                throw cancelled
            } catch (e: Exception) {
                LogUtil.e("CountryResolver", "resolve failed for $server", e)
            } finally {
                pending.remove(guid)
            }
        }
    }

    private fun lookupCountry(server: String): String? {
        val host = extractHost(server)
        if (host.isBlank()) return null
        val candidates = mutableListOf<String>()
        candidates += host

        val ip = runCatching { InetAddress.getAllByName(host).firstOrNull()?.hostAddress }
            .getOrNull()
        if (ip != null && ip != host) {
            candidates += ip
        }

        candidates.forEach { target ->
            try {
                val content = HttpUtil.getUrlContent(
                    com.cr.tunnel.dto.UrlContentRequest(
                        url = "https://api.ip.sb/geoip/$target",
                        timeout = 4000
                    )
                )
                if (content != null) {
                    val json = JsonUtil.parseString(content)
                    val code = json?.get("country_code")?.asString
                        ?: json?.get("country")?.asString
                        ?: json?.get("countryCode")?.asString
                    code?.takeIf { it.isNotBlank() }?.uppercase()?.let { return it }
                }
            } catch (e: Exception) {
                LogUtil.e("CountryResolver", "api.ip.sb failed for $target", e)
            }

            try {
                val content = HttpUtil.getUrlContent(
                    com.cr.tunnel.dto.UrlContentRequest(
                        url = "https://ipapi.co/$target/json/",
                        timeout = 4000
                    )
                )
                if (content != null) {
                    val json = JsonUtil.parseString(content)
                    val code = json?.get("country_code")?.asString
                        ?: json?.get("countryCode")?.asString
                    code?.takeIf { it.isNotBlank() }?.uppercase()?.let { return it }
                }
            } catch (e: Exception) {
                LogUtil.e("CountryResolver", "ipapi.co failed for $target", e)
            }
        }
        return null
    }

    private fun extractHost(server: String): String {
        var host = server.trim()
        host = host.removePrefix("http://").removePrefix("https://")
        host = host.substringBefore('/').substringBefore('@').let {
            if ('@' in server) it.substringAfterLast('@') else it
        }
        return host.substringBefore(':').trim()
    }
}