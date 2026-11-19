package it.capptests.itwattauditor

import android.app.Application
import android.content.Context
import android.util.Base64
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.security.SecureRandom

/**
 * Test flows of the IT-Wallet hardware key attestation fallback, without Play Integrity:
 * 1. registration: GET /api/challenge, hardware key attested by the app attest key with the challenge,
 *    POST /api/register, which returns the registration token pinning the keys and the device state;
 * 2. assertion: GET /api/challenge, client data with the challenge signed by the hardware key, fresh key
 *    attestation with the SHA-256 hex digest of the client data, POST /api/assert;
 * 3. local attestation: a key attestation with a random challenge, without backend, only to export it.
 */
class AuditorViewModel(application: Application) : AndroidViewModel(application) {

    private val prefs = application.getSharedPreferences("settings", Context.MODE_PRIVATE)
    val engine = AttestationEngine(application)
    val huawei = HuaweiSysIntegrity(application)
    val records = RecordStore(application)

    var serverUrl by mutableStateOf(prefs.getString(KEY_SERVER_URL, null) ?: BuildConfig.DEFAULT_SERVER_URL)
        private set
    var registration by mutableStateOf(prefs.getString(KEY_REGISTRATION, null))
        private set
    var busy by mutableStateOf(false)
        private set
    var lastTitle by mutableStateOf("")
        private set
    var lastOutcome by mutableStateOf<Boolean?>(null)
        private set
    var lastOutput by mutableStateOf("")
        private set
    var recordCount by mutableStateOf(records.list().size)
        private set
    var sysIntegrityApi by mutableStateOf(
        HuaweiSysIntegrity.Api.entries.firstOrNull { it.name == prefs.getString(KEY_SYSINTEGRITY_API, null) }
            ?: HuaweiSysIntegrity.Api.REQUEST
    )
        private set

    fun updateSysIntegrityApi(api: HuaweiSysIntegrity.Api) {
        sysIntegrityApi = api
        prefs.edit().putString(KEY_SYSINTEGRITY_API, api.name).apply()
    }

    fun updateServerUrl(value: String) {
        serverUrl = value
        prefs.edit().putString(KEY_SERVER_URL, value.trim()).apply()
    }

    fun register() = run("Registration") {
        val client = BackendClient(serverUrl)
        val challenge = fetchChallenge(client)
        val attestation = engine.generateRegistration(challenge)
        val certificates = StepRecord.encodeChain(attestation.chain)
        val request = JSONObject()
            .put("challenge", challenge)
            .put("certificates", JSONArray(certificates))
        // Huawei devices without GMS: SysIntegrity bound to the challenge and to the hardware key,
        // nonce = SHA-256(challenge || SubjectPublicKeyInfo of the hardware key)
        val sysIntegrity = sysIntegrity(
            sha256(challenge.toByteArray(Charsets.UTF_8) + attestation.chain.first().publicKey.encoded)
        )
        sysIntegrity.jws?.let { request.put("sysIntegrity", it) }
        val response = client.post("/api/register", request)
        val ok = response.status == 200 && response.body.optBoolean("ok")
        if (ok) {
            registration = response.body.getString("registration")
            prefs.edit().putString(KEY_REGISTRATION, registration).apply()
        }
        save("register", challenge, certificates, attestation, request, response, sysIntegrity)
        ok to summary(attestation, response, sysIntegrity)
    }

    fun assert() = run("Assertion (hardware key attestation fallback)") {
        val token = registration ?: error("Register the device first")
        check(engine.isRegistered()) { "The hardware key is missing, register the device again" }
        val client = BackendClient(serverUrl)
        val challenge = fetchChallenge(client)
        val clientData = JSONObject()
            .put("challenge", challenge)
            .put("purpose", "itwattauditor-assertion")
            .put("timestamp", RecordStore.now())
            .toString()
        val signature = Base64.encodeToString(engine.sign(clientData.toByteArray(Charsets.UTF_8)), Base64.NO_WRAP)
        val requestHash = AttestationEngine.sha256Hex(clientData.toByteArray(Charsets.UTF_8))
        val attestation = engine.generateFreshAttestation(requestHash)
        val certificates = StepRecord.encodeChain(attestation.chain)
        val request = JSONObject()
            .put("registration", token)
            .put("clientData", clientData)
            .put("signature", signature)
            .put("certificates", JSONArray(certificates))
        // Huawei devices without GMS: SysIntegrity bound to the client data, nonce = SHA-256(client data)
        val sysIntegrity = sysIntegrity(sha256(clientData.toByteArray(Charsets.UTF_8)))
        sysIntegrity.jws?.let { request.put("sysIntegrity", it) }
        val response = client.post("/api/assert", request)
        save("assert", requestHash, certificates, attestation, request, response, sysIntegrity)
        (response.status == 200 && response.body.optBoolean("ok")) to summary(attestation, response, sysIntegrity)
    }

    fun localAttestation() = run("Local attestation (no backend)") {
        val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
            .joinToString("") { "%02x".format(it) }
        // With a registration the fresh attestation is signed by the attest key, as for the assertions
        val attestation = if (engine.isRegistered()) {
            engine.generateFreshAttestation(challenge)
        } else {
            engine.generateRegistration(challenge).also { engine.reset() }
        }
        val certificates = StepRecord.encodeChain(attestation.chain)
        val sysIntegrity = sysIntegrity(sha256(challenge.toByteArray(Charsets.UTF_8)))
        save("local", challenge, certificates, attestation, null, null, sysIntegrity)
        true to JSONObject()
            .put("challenge", challenge)
            .put("details", details(attestation, sysIntegrity))
            .put("note", "Not verified: export the ZIP to inspect the chain")
            .toString(2)
    }

    fun reset() = run("Reset") {
        engine.reset()
        registration = null
        prefs.edit().remove(KEY_REGISTRATION).apply()
        records.clear()
        true to "Keys, registration and recorded chains deleted"
    }

    fun deviceInfo(): JSONObject = ChainExporter.deviceInfo(engine, huawei)

    private fun fetchChallenge(client: BackendClient): String {
        val response = client.get("/api/challenge")
        return response.body.optString("challenge").takeIf { response.status == 200 && it.isNotEmpty() }
            ?: error("Challenge request failed (HTTP ${response.status}): ${response.body.optString("error")}")
    }

    /**
     * Result of the optional Huawei SysIntegrity check: the JWS or the reason why it is not available.
     */
    data class SysIntegrityResult(val jws: String?, val api: HuaweiSysIntegrity.Api?, val error: String?)

    /**
     * Requests a SysIntegrity result when HMS Core is available and the App ID is configured, never fails.
     */
    private suspend fun sysIntegrity(nonce: ByteArray): SysIntegrityResult = when {
        !huawei.isConfigured() -> SysIntegrityResult(null, null, "Huawei App ID not configured")
        !huawei.isHmsCoreAvailable() -> SysIntegrityResult(null, null, "HMS Core not available")
        else -> try {
            SysIntegrityResult(huawei.check(nonce, sysIntegrityApi), sysIntegrityApi, null)
        } catch (e: Exception) {
            SysIntegrityResult(null, sysIntegrityApi, e.message)
        }
    }

    private fun details(
        attestation: AttestationEngine.Attestation,
        sysIntegrity: SysIntegrityResult? = null,
    ) = JSONObject()
        .put("usedAttestKey", attestation.usedAttestKey)
        .put("strongBox", attestation.strongBox)
        .put("fallbackReason", attestation.fallbackReason ?: JSONObject.NULL)
        .put("certificates", attestation.chain.size)
        .apply {
            if (sysIntegrity != null) {
                put("sysIntegrity", sysIntegrity.jws ?: JSONObject.NULL)
                put("sysIntegrityApi", sysIntegrity.api?.label ?: JSONObject.NULL)
                put("sysIntegrityError", sysIntegrity.error ?: JSONObject.NULL)
            }
        }

    private fun save(
        type: String,
        challenge: String,
        certificates: List<String>,
        attestation: AttestationEngine.Attestation,
        request: JSONObject?,
        response: BackendClient.Response?,
        sysIntegrity: SysIntegrityResult? = null,
    ) {
        records.add(
            StepRecord(
                id = RecordStore.newId(type),
                type = type,
                createdAt = RecordStore.now(),
                challenge = challenge,
                chain = certificates,
                details = details(attestation, sysIntegrity),
                request = request,
                response = response?.body,
                httpStatus = response?.status,
            )
        )
    }

    private fun summary(
        attestation: AttestationEngine.Attestation,
        response: BackendClient.Response,
        sysIntegrity: SysIntegrityResult,
    ) =
        JSONObject()
            .put("httpStatus", response.status)
            .put("device", details(attestation, sysIntegrity).also { it.remove("sysIntegrity") })
            .put("backend", response.body.also { it.remove("registration") })
            .toString(2)

    private fun run(title: String, block: suspend () -> Pair<Boolean, String>) {
        if (busy) return
        busy = true
        lastTitle = title
        lastOutcome = null
        lastOutput = "…"
        viewModelScope.launch {
            val (ok, output) = try {
                withContext(Dispatchers.IO) { block() }
            } catch (e: Exception) {
                false to "${e.javaClass.simpleName}: ${e.message}"
            }
            lastOutcome = ok
            lastOutput = output
            recordCount = records.list().size
            busy = false
        }
    }

    companion object {
        private const val KEY_SERVER_URL = "serverUrl"
        private const val KEY_REGISTRATION = "registration"
        private const val KEY_SYSINTEGRITY_API = "sysIntegrityApi"

        private fun sha256(data: ByteArray): ByteArray =
            java.security.MessageDigest.getInstance("SHA-256").digest(data)
    }
}
