package ro.upb.smd.poc.target

import android.os.Bundle
import android.util.Log
import android.widget.TextView
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

class DeepLinkActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_deep_link)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }

        val tokenView = findViewById<TextView>(R.id.token_view)
        val uriView = findViewById<TextView>(R.id.uri_view)

        val uri = intent?.data
        uriView.text = "URI: ${uri ?: "(none)"}"

        // VULN 1 sink: we trust the token delivered via an unverified custom scheme.
        // A colliding companion app could have received this exact intent instead.
        val token = uri?.getQueryParameter("token")
        tokenView.text = if (token != null) {
            "Logged in. Token = $token"
        } else {
            "No token in callback"
        }
        Log.i("TARGET", "DeepLinkActivity received uri=$uri token=$token")
    }
}
