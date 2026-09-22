package io.christwatch.phone

import android.content.Context
import android.os.Process
import android.provider.Settings
import android.util.Base64
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.util.Locale

/**
 * Everything this app actually does, in one file.
 *
 * It watches one system setting and tells a Discord channel about it. It is
 * not a filter, a VPN or a firewall - Android's own Private DNS does the
 * blocking, device-wide, for every profile at once. This is the part that
 * makes turning it off something other people find out about.
 */

const val PREFS = "christwatch"

/** Which profile this copy is running in. Owner is 0, the second one is 10. */
val profileId: Int get() = Process.myUid() / 100000

/** What Discord is told. Small on purpose: nobody wants a busy channel. */
const val MARKER = "CW1 "

// --------------------------------------------------------------------------
// What we were told to expect
// --------------------------------------------------------------------------

data class Pairing(
    val webhook: String,
    val name: String,
    val expectedDns: String,
    val home: String,
) {
    companion object {
        /**
         * Read a pairing link.
         *
         * The link is christwatch://pair#<base64url of a small JSON object>,
         * and a bare blob of that base64 is accepted too, because pasting
         * from a chat window does not always bring the scheme along.
         */
        fun parse(raw: String?): Pairing? {
            var text = (raw ?: "").trim()
            if (text.isEmpty()) return null
            val hash = text.indexOf('#')
            if (hash >= 0) text = text.substring(hash + 1)
            text = text.trim().removePrefix("christwatch://pair").trim('/', ' ')
            if (text.isEmpty()) return null
            val json = try {
                val flags = Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
                JSONObject(String(Base64.decode(text, flags), Charsets.UTF_8))
            } catch (e: Exception) {
                return null
            }
            val hook = json.optString("hook")
            if (!hook.startsWith("https://")) return null
            return Pairing(
                webhook = hook,
                name = json.optString("name").ifBlank { "phone" },
                expectedDns = json.optString("dns").lowercase(Locale.ROOT),
                home = json.optString("home").ifBlank { "your channel" },
            )
        }
    }
}

fun Context.pairing(): Pairing? {
    val p = getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    val hook = p.getString("hook", "") ?: ""
    if (hook.isBlank()) return null
    return Pairing(
        hook,
        p.getString("name", "phone") ?: "phone",
        p.getString("dns", "") ?: "",
        p.getString("home", "your channel") ?: "your channel",
    )
}

fun Context.savePairing(pair: Pairing) {
    val p = getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    var id = p.getString("device", "") ?: ""
    if (id.isBlank()) {
        id = java.util.UUID.randomUUID().toString().take(8)
    }
    p.edit()
        .putString("hook", pair.webhook)
        .putString("name", pair.name)
        .putString("dns", pair.expectedDns)
        .putString("home", pair.home)
        .putString("device", id)
        .remove("last_state")          // make the next run report, whatever it finds
        .apply()
}

fun Context.deviceId(): String =
    getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("device", "") ?: ""

fun Context.forget() {
    getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().apply()
}

// --------------------------------------------------------------------------
// The one setting that matters
// --------------------------------------------------------------------------

/**
 * Private DNS lives in Settings.Global, which is shared by every profile on
 * the device. That is the whole reason this approach works across both of
 * yours at once: there is only one copy of the setting to read, and only one
 * to change.
 *
 * The constants are @hide in the SDK, so the names are spelled out here. They
 * have not moved since Android 9.
 */
class DnsState(val mode: String, val hostname: String, val expected: String) {

    val on: Boolean
        get() = mode == "hostname" && hostname.isNotBlank() &&
                (expected.isBlank() || hostname.equals(expected, ignoreCase = true))

    /** "on", "off", or "wrong" - pointed at a resolver that does not filter. */
    val word: String
        get() = when {
            on -> "on"
            mode == "hostname" -> "wrong"
            else -> "off"
        }

    val readable: String
        get() = when {
            on -> "Filtering is on"
            mode == "hostname" -> "Pointed at the wrong resolver"
            mode == "opportunistic" -> "Private DNS is on Automatic, which does not filter"
            else -> "Private DNS is off"
        }

    companion object {
        fun read(ctx: Context): DnsState {
            val cr = ctx.contentResolver
            val mode = Settings.Global.getString(cr, "private_dns_mode") ?: "off"
            val host = Settings.Global.getString(cr, "private_dns_specifier") ?: ""
            val want = ctx.pairing()?.expectedDns ?: ""
            return DnsState(mode.lowercase(Locale.ROOT), host.trim(), want)
        }
    }
}

// --------------------------------------------------------------------------
// Telling the channel
// --------------------------------------------------------------------------

object Reporter {

    /**
     * Post one line to the channel.
     *
     * The webhook is write-only: it can say things in one channel and cannot
     * read anything, anywhere. That is the reason the phone gets a webhook
     * and not the bot token.
     */
    fun post(pair: Pairing, human: String, machine: JSONObject): Boolean {
        val body = JSONObject()
            .put("username", "ChristWatch")
            .put("content", human + "\n`" + MARKER + machine.toString() + "`")
            .put("allowed_mentions", JSONObject().put("parse", org.json.JSONArray()))
        return try {
            val conn = URL(pair.webhook).openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.connectTimeout = 15000
            conn.readTimeout = 15000
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("User-Agent", "ChristWatch-phone")
            OutputStreamWriter(conn.outputStream, Charsets.UTF_8).use {
                it.write(body.toString())
            }
            val code = conn.responseCode
            conn.disconnect()
            code in 200..299
        } catch (e: Exception) {
            false
        }
    }

    fun report(ctx: Context, state: DnsState, why: String): Boolean {
        val pair = ctx.pairing() ?: return false
        val label = "${pair.name} · profile $profileId"
        val human = when {
            state.on && why == "heartbeat" -> "📱 $label — still on"
            state.on -> "📱 $label — back on"
            else -> "⚠️ **$label — ${state.readable}**"
        }
        val machine = JSONObject()
            .put("d", ctx.deviceId())
            .put("n", pair.name)
            .put("u", profileId)
            .put("s", state.word)
            .put("dns", state.hostname)
            .put("why", why)
            .put("at", System.currentTimeMillis() / 1000)
        val ok = post(pair, human, machine)
        if (ok) {
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putString("last_state", state.word)
                .putLong("last_post", System.currentTimeMillis())
                .apply()
        }
        return ok
    }
}
