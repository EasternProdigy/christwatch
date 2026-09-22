package io.christwatch.phone

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import java.text.DateFormat
import java.util.Date

class MainActivity : AppCompatActivity() {

    private lateinit var headline: TextView
    private lateinit var detail: TextView
    private lateinit var footer: TextView
    private lateinit var paste: EditText
    private lateinit var pairBtn: Button
    private lateinit var dnsBtn: Button
    private lateinit var copyBtn: Button
    private lateinit var reportBtn: Button
    private lateinit var forgetBtn: Button

    override fun onCreate(saved: Bundle?) {
        super.onCreate(saved)
        setContentView(R.layout.main)
        headline = findViewById(R.id.headline)
        detail = findViewById(R.id.detail)
        footer = findViewById(R.id.footer)
        paste = findViewById(R.id.paste)
        pairBtn = findViewById(R.id.pair)
        dnsBtn = findViewById(R.id.dns)
        copyBtn = findViewById(R.id.copy)
        reportBtn = findViewById(R.id.report)
        forgetBtn = findViewById(R.id.forget)

        pairBtn.setOnClickListener { tryPair(paste.text.toString()) }
        dnsBtn.setOnClickListener { openPrivateDns() }
        copyBtn.setOnClickListener { copyHostname() }
        reportBtn.setOnClickListener { sendReport() }
        forgetBtn.setOnClickListener {
            forget()
            Toast.makeText(this, "Unpaired", Toast.LENGTH_SHORT).show()
            draw()
        }

        askForNotifications()
        WatchWorker.schedule(applicationContext)
        handleLink(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleLink(intent)
    }

    override fun onResume() {
        super.onResume()
        draw()
    }

    /** Arriving by tapping the pairing link your laptop sent you. */
    private fun handleLink(intent: Intent?) {
        val data = intent?.data ?: return
        tryPair(data.toString())
    }

    private fun tryPair(raw: String) {
        val pair = Pairing.parse(raw)
        if (pair == null) {
            if (raw.isNotBlank()) {
                Toast.makeText(this, "That is not a pairing link",
                    Toast.LENGTH_LONG).show()
            }
            return
        }
        savePairing(pair)
        paste.setText("")
        WatchWorker.schedule(applicationContext)
        Toast.makeText(this, "Paired to ${pair.home}", Toast.LENGTH_LONG).show()
        sendReport()
        draw()
    }

    private fun draw() {
        val pair = pairing()
        val state = DnsState.read(this)

        headline.text = state.readable
        headline.setTextColor(
            ContextCompat.getColor(
                this, if (state.on) R.color.good else R.color.bad))

        val want = pair?.expectedDns.orEmpty()
        detail.text = buildString {
            append(if (want.isBlank()) "Not paired yet." else "Should be: $want")
            append("\n")
            append(
                when {
                    state.mode == "hostname" -> "Right now: ${state.hostname}"
                    state.mode == "opportunistic" -> "Right now: Automatic"
                    else -> "Right now: Off"
                }
            )
            append("\nProfile $profileId · covers all profiles")
        }

        val prefs = getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val last = prefs.getLong("last_post", 0L)
        footer.text = when {
            pair == null ->
                "Paste the link your laptop sent you, or just tap it in Discord."
            last == 0L ->
                "Watching for ${pair.home}. Nothing sent yet."
            else -> "Watching for ${pair.home} as “${pair.name}”. " +
                    "Last told them " +
                    DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
                        .format(Date(last)) + "."
        }

        val paired = pair != null
        paste.visibility = if (paired) android.view.View.GONE else android.view.View.VISIBLE
        pairBtn.visibility = if (paired) android.view.View.GONE else android.view.View.VISIBLE
        copyBtn.visibility =
            if (want.isBlank()) android.view.View.GONE else android.view.View.VISIBLE
        reportBtn.visibility = if (paired) android.view.View.VISIBLE else android.view.View.GONE
        forgetBtn.visibility = if (paired) android.view.View.VISIBLE else android.view.View.GONE
    }

    /**
     * Android has never given this screen a public way in. The hidden action
     * works on every build that has the screen; if some day it does not, the
     * network settings page is one tap away from it.
     */
    private fun openPrivateDns() {
        val tries = listOf(
            Intent("android.settings.PRIVATE_DNS_SETTINGS"),
            Intent(android.provider.Settings.ACTION_WIRELESS_SETTINGS),
            Intent(android.provider.Settings.ACTION_SETTINGS),
        )
        for (i in tries) {
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            try {
                startActivity(i)
                return
            } catch (e: Exception) {
                // try the next one
            }
        }
    }

    private fun copyHostname() {
        val want = pairing()?.expectedDns ?: return
        val cm = getSystemService(ClipboardManager::class.java) ?: return
        cm.setPrimaryClip(ClipData.newPlainText("Private DNS", want))
        Toast.makeText(this, "Copied $want", Toast.LENGTH_SHORT).show()
    }

    private fun sendReport() {
        val state = DnsState.read(this)
        Thread {
            val ok = Reporter.report(this, state, "checked")
            runOnUiThread {
                Toast.makeText(
                    this,
                    if (ok) "Told your channel" else "Could not reach Discord",
                    Toast.LENGTH_SHORT
                ).show()
                draw()
            }
        }.start()
    }

    private fun askForNotifications() {
        if (Build.VERSION.SDK_INT >= 33) {
            requestPermissions(arrayOf("android.permission.POST_NOTIFICATIONS"), 1)
        }
    }
}
