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
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions

class MainActivity : AppCompatActivity() {

    private val expectedPin = "1234"

    private val qrLauncher = registerForActivityResult(ScanContract()) { result ->
        val contents = result.contents
        if (contents.isNullOrBlank()) {
            Toast.makeText(this, R.string.scan_cancelled, Toast.LENGTH_SHORT).show()
            return@registerForActivityResult
        }
        try {
            val uri = Uri.parse(contents)
            startActivity(Intent(Intent.ACTION_VIEW, uri))
        } catch (_: Throwable) {
            Toast.makeText(this, getString(R.string.scan_invalid, contents), Toast.LENGTH_LONG).show()
        }
    }

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
            val options = ScanOptions().apply {
                setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                setPrompt(getString(R.string.scan_prompt))
                setBeepEnabled(true)
                setOrientationLocked(false)
            }
            qrLauncher.launch(options)
        }
    }
}
