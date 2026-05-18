package ro.upb.smd.poc.target

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

class MainActivity : AppCompatActivity() {

    private val expectedPin = "1234"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }

        val pinInput = findViewById<EditText>(R.id.pin_input)
        val unlockBtn = findViewById<Button>(R.id.unlock_btn)
        val oauthBtn = findViewById<Button>(R.id.oauth_btn)
        val status = findViewById<TextView>(R.id.status)

        unlockBtn.setOnClickListener {
            if (pinInput.text.toString() == expectedPin) {
                status.text = getString(R.string.status_unlocked)
                startActivity(Intent(this, InternalActivity::class.java))
            } else {
                status.text = getString(R.string.status_wrong_pin)
                Toast.makeText(this, R.string.status_wrong_pin, Toast.LENGTH_SHORT).show()
            }
        }

        oauthBtn.setOnClickListener {
            // Simulate the OAuth provider redirecting back to us via the custom scheme.
            // In a real app this is what the browser would deliver after consent.
            val callback = Uri.parse("smdpoc://oauth/callback?token=DEMO_REAL_TOKEN_$%02x".format((0..255).random()))
            startActivity(Intent(Intent.ACTION_VIEW, callback))
        }
    }
}
