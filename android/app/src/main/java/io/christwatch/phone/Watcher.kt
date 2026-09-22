package io.christwatch.phone

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

/** How long we stay quiet while nothing is wrong. */
private const val HEARTBEAT_HOURS = 20L

class WatchWorker(ctx: Context, params: WorkerParameters) : Worker(ctx, params) {

    override fun doWork(): Result {
        val ctx = applicationContext
        val pair = ctx.pairing() ?: return Result.success()
        val prefs = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val state = DnsState.read(ctx)

        val was = prefs.getString("last_state", null)
        val lastPost = prefs.getLong("last_post", 0L)
        val stale = System.currentTimeMillis() - lastPost >
                TimeUnit.HOURS.toMillis(HEARTBEAT_HOURS)

        // A change is news and goes out at once. Nothing changing is also
        // worth saying, but once a day is plenty.
        val why = when {
            was == null || was != state.word -> "changed"
            stale -> "heartbeat"
            else -> return Result.success()
        }

        if (!state.on && why == "changed") {
            notifyOff(ctx, state, pair)
        }

        // A failed post must not be forgotten: leaving last_state alone means
        // the next run tries again, which is what you want if the phone was
        // simply out of signal when the setting changed.
        return if (Reporter.report(ctx, state, why)) Result.success() else Result.retry()
    }

    private fun notifyOff(ctx: Context, state: DnsState, pair: Pairing) {
        val nm = ctx.getSystemService(NotificationManager::class.java) ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel("christwatch", "ChristWatch",
                    NotificationManager.IMPORTANCE_HIGH)
            )
        }
        val note = NotificationCompat.Builder(ctx, "christwatch")
            .setSmallIcon(R.drawable.ic_status)
            .setContentTitle(state.readable)
            .setContentText("Telling ${pair.home}.")
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .build()
        nm.notify(1, note)
    }

    companion object {
        fun schedule(ctx: Context) {
            val work = PeriodicWorkRequestBuilder<WatchWorker>(1, TimeUnit.HOURS)
                .setConstraints(
                    Constraints.Builder()
                        .setRequiredNetworkType(NetworkType.CONNECTED)
                        .build()
                )
                .build()
            WorkManager.getInstance(ctx).enqueueUniquePeriodicWork(
                "christwatch-watch", ExistingPeriodicWorkPolicy.UPDATE, work)
        }
    }
}

/**
 * Put the watcher back after a reboot or an app update.
 *
 * WorkManager survives both on its own; this is the belt to that braces,
 * because a watcher that quietly stopped would look exactly like a phone
 * that is behaving.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        WatchWorker.schedule(context.applicationContext)
    }
}
