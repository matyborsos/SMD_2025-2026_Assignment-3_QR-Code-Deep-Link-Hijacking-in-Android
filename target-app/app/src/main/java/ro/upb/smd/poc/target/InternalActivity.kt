package ro.upb.smd.poc.target

import android.os.Bundle
import android.util.Log
import android.widget.TextView
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

class InternalActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_internal)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }

        // VULN 2 sink: this is supposed to require the user to pass the PIN gate
        // in MainActivity, but there is no check here and no permission on the
        // <activity> in the manifest. Any app can reach it via an explicit Intent.
        val caller = referrer?.toString() ?: "(unknown)"
        findViewById<TextView>(R.id.caller_view).text = "Reached from: $caller"
        Log.w("TARGET", "InternalActivity launched. caller=$caller")
    }
}
