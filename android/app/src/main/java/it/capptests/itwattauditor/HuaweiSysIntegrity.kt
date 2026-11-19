package it.capptests.itwattauditor

import android.content.Context
import com.huawei.hms.api.ConnectionResult
import com.huawei.hms.api.HuaweiApiAvailability
import com.huawei.hms.common.ApiException
import com.huawei.hms.support.api.entity.safetydetect.SysIntegrityRequest
import com.huawei.hms.support.api.safetydetect.SafetyDetect
import com.huawei.hms.support.api.safetydetect.SafetyDetectStatusCodes
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * HMS Safety Detect SysIntegrity check, for the Huawei devices without Google Mobile Services, whose
 * Android key attestation is signed with the public AOSP software attestation key. HMS Core evaluates the
 * system integrity on the device (with the TEE where supported) and returns a JWS signed by the Huawei
 * SysIntegrity service, which the backend verifies.
 * Two APIs are available:
 * - [Api.REQUEST]: `sysIntegrity(SysIntegrityRequest)`, which selects the signature algorithm (PS256);
 * - [Api.LEGACY]: `sysIntegrity(nonce, appId)`, signed with RS256.
 * The App ID of AppGallery Connect is required, see the app build.gradle.kts.
 * {@link https://github.com/HMS-Core/hms-safetydetect-demo-kotlin}
 */
class HuaweiSysIntegrity(private val context: Context) {

    enum class Api(val label: String) {
        REQUEST("SysIntegrityRequest, PS256"),
        LEGACY("sysIntegrity(nonce, appId), RS256"),
    }

    val appId: String = BuildConfig.HUAWEI_APP_ID

    fun isConfigured() = appId.isNotBlank()

    /**
     * @return whether HMS Core is installed and usable, e.g. on Huawei devices without GMS.
     */
    fun isHmsCoreAvailable(): Boolean = try {
        HuaweiApiAvailability.getInstance().isHuaweiMobileServicesAvailable(context) ==
            ConnectionResult.SUCCESS
    } catch (e: Throwable) {
        false
    }

    fun isAvailable() = isConfigured() && isHmsCoreAvailable()

    /**
     * Requests a SysIntegrity result.
     * @param nonce the nonce, 32 bytes, which binds the result to the request (see the backend).
     * @param api the API to use.
     * @return the JWS returned by the SysIntegrity API.
     */
    suspend fun check(nonce: ByteArray, api: Api = Api.REQUEST): String {
        check(isConfigured()) { "Set the Huawei AppGallery Connect App ID to use SysIntegrity" }
        val client = SafetyDetect.getClient(context)
        val task = when (api) {
            Api.REQUEST -> client.sysIntegrity(SysIntegrityRequest().apply {
                appId = this@HuaweiSysIntegrity.appId
                this.nonce = nonce
                alg = "PS256"
            })
            Api.LEGACY -> client.sysIntegrity(nonce, appId)
        }
        return suspendCancellableCoroutine { continuation ->
            task.addOnSuccessListener { response -> continuation.resume(response.result) }
                .addOnFailureListener { e ->
                    val message = if (e is ApiException) {
                        "${SafetyDetectStatusCodes.getStatusCodeString(e.statusCode)} (${e.statusCode}): ${e.message}"
                    } else {
                        e.message ?: e.javaClass.simpleName
                    }
                    continuation.resumeWithException(IllegalStateException("SysIntegrity failed: $message", e))
                }
        }
    }
}
