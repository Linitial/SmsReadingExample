package com.linitial.smsreadingexample

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.util.Base64
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import com.google.android.gms.auth.api.phone.SmsRetriever
import com.google.android.gms.common.api.CommonStatusCodes
import com.google.android.gms.common.api.Status
import kotlinx.android.synthetic.main.activity_main.*
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.util.*


class MainActivity : AppCompatActivity() {

    companion object {
        const val LOG = "SMS-Example"
    }

    val HASH_TYPE = "SHA-256"
    val NUM_HASHED_BYTES = 9
    val NUM_BASE64_CHAR = 11

    val smsReceiver = MySMSReceiver()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        registerReceiver(smsReceiver, smsReceiver.doFilter())

        btn_send?.setOnClickListener {
            startSmsRetriver()
        }
    }

    override fun onDestroy() {
        unregisterReceiver(smsReceiver)
        super.onDestroy()
    }

    fun startSmsRetriver() {
        val task = SmsRetriever.getClient(this)
            .startSmsRetriever()

        task.addOnSuccessListener {
            Log.d(LOG, "addOnSuccessListener ${getAppSignatures(this)}")
        }

        task.addOnFailureListener {
            Log.e(LOG, "addOnFailureListener $it")
        }
    }

    fun showMessage(message: String){
        et_input?.post {
            et_input?.setText(message)
        }
    }

    fun getAppSignatures(context: Context): List<String> {
        val appCodes = mutableListOf<String>()

        try {
            val packageName = context.packageName
            val packageManager = context.packageManager
            val signatures = packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES).signatures
            for (signature in signatures) {
                val hash = getHash(packageName, signature.toCharsString())

                if (hash != null) {
                    appCodes.add(String.format("%s", hash))
                }

                Log.d(LOG, String.format("이 값을 SMS 뒤에 써서 보내주면 됩니다 : %s", hash))
            }
        } catch (e: PackageManager.NameNotFoundException) {
            Log.d(LOG, "Unable to find package to obtain hash. : $e")
        }

        return appCodes
    }

    private fun getHash(packageName: String, signature: String): String? {
        val appInfo = "$packageName $signature"

        try {
            val messageDigest = MessageDigest.getInstance(HASH_TYPE)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
                messageDigest.update(appInfo.toByteArray(StandardCharsets.UTF_8))
            }

            val hashSignature = Arrays.copyOfRange(messageDigest.digest(), 0, NUM_HASHED_BYTES)
            val base64Hash = Base64
                .encodeToString(hashSignature, Base64.NO_PADDING or Base64.NO_WRAP)
                .substring(0, NUM_BASE64_CHAR)

            Log.d(LOG, String.format("\nPackage : %s\nHash : %s", packageName, base64Hash))

            return base64Hash

        } catch (e: NoSuchAlgorithmException) {
            Log.d(LOG, "hash:NoSuchAlgorithm : $e")
        }

        return null
    }

    inner class MySMSReceiver : BroadcastReceiver() {

        override fun onReceive(context: Context, intent: Intent) {
            if(SmsRetriever.SMS_RETRIEVED_ACTION == intent.action){
                val extras = intent.extras
                val status = extras?.get(SmsRetriever.EXTRA_STATUS) as? Status

                when(status?.statusCode){
                    CommonStatusCodes.SUCCESS -> {
                        val message = extras?.get(SmsRetriever.EXTRA_SMS_MESSAGE) as? String
                        Log.d(LOG, "onReceive\$SUCCESS $message")

                        if(!message.isNullOrEmpty()){
                            showMessage(message)
                        }
                    }

                    CommonStatusCodes.TIMEOUT -> {
                        Log.d(LOG, "onReceive\$TIMEOUT")
                    }
                }
            }
        }

        fun doFilter(): IntentFilter = IntentFilter().apply {
            addAction(SmsRetriever.SMS_RETRIEVED_ACTION)
        }
    }
}
