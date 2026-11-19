# ITW Att Auditor - Device+OS integrity fallback tests

An Android app (_Kotlin_) and a test backend (_Node.js_) which replicate the **hardware key attestation fallback** developed for IT-Wallet's IO App implementation in the forks of the io-wallet, io-react-native-integrity, io-react-native-wallet and io-app repos.

Unlike the example app and backend of io-react-native-integrity, **Google Play Integrity is not used at all** = the fresh hardware key attestation is always the integrity proof, as done by the Wallet Provider when the Play Integrity token is missing or not valid.

The app is meant for tests with real devices running GrapheneOS or devices which don't get the Play Integrity device verdict.

> This is a test tool, not a production service: see [Limits](#limits).

---------

## Flow

| Step | App | Backend |
| --- | --- | --- |
| Registration (wallet instance creation) | `GET /api/challenge`, then generates an **app attest key** (_Android 12+_) and the **hardware key** attested by it, both with the challenge (_StrongBox, TEE as fallback_). Without attest key support, or if its generation fails, the hardware key is generated without it. | `POST /api/register` verifies the key attestation and returns a signed **registration token** which pins the hardware key, the attest key and the device state (_verified boot state and key_). |
| Assertion (WIA / KA request) | `GET /api/challenge`, signs the client data (_with the challenge_) with the hardware key and generates a **fresh key attestation** of a temporary key, attested by the same attest key, with the SHA-256 hex digest of the client data as challenge. | `POST /api/assert` verifies the signature and the fresh attestation (_fallback checks below_). |
| Local attestation | Generates a key attestation with a random challenge, without backend, only to export the chain. | – |

\
Key attestation policy (registration and fresh attestations), following the [GrapheneOS attestation compatibility guide](https://grapheneos.org/articles/attestation-compatibility-guide) :

- chain rooted at a Google Hardware Attestation Root CA (RSA root and "Key Attestation CA1" ECDSA root), no certificate revoked in the [Google status list](https://android.googleapis.com/attestation/status)
- hardware backed (TEE or StrongBox), generated key, expected challenge, package name (`ANDROID_PACKAGE_NAMES`)
- **locked bootloader** and verified boot state:
  - `Verified` (green, stock OS)
  - `SelfSigned` (yellow) only with a verified boot key in the **GrapheneOS allowlist** ([attestation.json](https://grapheneos.org/attestation.json) verified with the pinned GrapheneOS SSH key, refreshed every 24 hours, with a bundled snapshot as fallback), a trusted app signing certificate (`ANDROID_SIGNATURE_DIGESTS`) and an app attest key
  - `Unverified` and `Failed` are rejected
- the app attest key, if any, must have only the `ATTEST_KEY` purpose and the same security level, root of trust and app of the attested key
- no patch level is enforced

\
Fallback checks of the assertions, as in the Wallet Provider :

1. the client data is signed by the registered hardware key
2. the device has been registered with an attest key: without it (e.g. Android 8-11) the Wallet Provider requires Play Integrity, so the assertion is rejected
3. the app signing certificate digests are configured and the fresh attestation reports one of them, for any verified boot state
4. the fresh attestation satisfies the policy above, with the SHA-256 hex digest of the client data as challenge, and is **signed by the registered attest key**, which prevents relaying an attestation of another device
5. same verified boot state and key of the registration

Every response includes a readable **report** of the attestation records (security level, root of trust, patch levels, app id, attest key), also when the verification fails, to diagnose the rejected devices.

----------

## Exporting the attestation chains

Every step (_registration, assertion, local attestation_) is recorded in the app private storage. **Share ZIP** and **Save ZIP…** export them as a ZIP file:

- `device.json`: device model, OS build fingerprint, security patch, capabilities and app signing certificate digests (no hardware identifiers)
- one folder per step with `cert_N.der` (from the attested key `cert_0`; with an attest key, `cert_1` is the attest key certificate), `chain.pem` and `step.json` (challenge, request and backend response)

\
The ZIP is created only on the device and leaves it only when the user shares it (_e.g. by email or instant-messagin_) or saves it (_e.g. in Downloads_). The chains are not stored on the server, because:

- an attestation chain processed together with a user account is personal data: keeping it only on the device, under the user's control, avoids retention, access control and GDPR duties on the test backend
- Vercel functions have NO persistent storage: uploads would need an external store and an authentication of the uploads, otherwise anyone could fill or read it
- the backend response, with its verification report, is already included in the ZIP

--------

## Backend

```bash
cd backend
npm install
npm test            # unit and end-to-end tests with synthetic and real chains
npm run dev         # local server on http://localhost:3000 (PORT to change it)
```

Endpoints: `GET /api/challenge`, `POST /api/register`, `POST /api/assert`, `GET /api/status`.

\
Environment variables:

| Variable | Required | Description |
| --- | --- | --- |
| `SERVER_SECRET` | on Vercel | At least 32 random characters, used to sign the challenges and the registration tokens (HMAC-SHA256), e.g. `openssl rand -base64 48`. Locally a random secret is generated at startup. |
| `ANDROID_SIGNATURE_DIGESTS` | for GrapheneOS and the assertions | Comma separated SHA-256 digests (hex, colons allowed) of the app signing certificates. The app shows its digest and can copy it. |
| `ANDROID_PACKAGE_NAMES` | no | Comma separated package names, `it.capptests.itwattauditor` by default. |
| `CHALLENGE_TTL_SECONDS` | no | Validity of the challenges, 300 by default. |
| `GRAPHENEOS_ALLOWED_SIGNERS` | no | Overrides the pinned GrapheneOS `allowed_signers`, after a key rotation. |
| `HUAWEI_SYSINTEGRITY` | no | `true` to accept the Huawei devices without GMS through the HMS SysIntegrity result, see [Huawei devices without GMS](#huawei-devices-without-gms). Disabled by default. |

### Deployment on Vercel

1. Import the repository in Vercel and set **Root Directory** to `backend` (framework preset "Other", no build command).
2. Add `SERVER_SECRET` and `ANDROID_SIGNATURE_DIGESTS` in *Settings → Environment Variables*.
3. Deploy, then check `https://<project>.vercel.app/api/status`.

## Android app

Requirements: JDK 17+ and the Android SDK (platform 36).

```bash
cd android
./gradlew assembleDebug -Pitwattauditor.serverUrl=https://<project>.vercel.app
# app/build/outputs/apk/debug/app-debug.apk
```

The backend URL can also be entered in the app. The debug build allows cleartext HTTP, e.g. `http://<LAN IP>:3000` with the local server.

The digest checked by the backend is the one of the certificate which signs the APK: each debug keystore has its own one. For a stable digest, build a release APK with your keystore:

```bash
keytool -genkeypair -v -keystore itwattauditor.jks -alias itwattauditor -keyalg EC -groupname secp256r1 -validity 10000
ITWATT_KEYSTORE_FILE=$PWD/itwattauditor.jks ITWATT_KEYSTORE_PASSWORD=... ITWATT_KEY_ALIAS=itwattauditor ITWATT_KEY_PASSWORD=... \
  ./gradlew assembleRelease
```

The **Android app** GitHub workflow builds the APK as an artifact: with the `ITWATT_KEYSTORE_BASE64` (`base64 -w0 itwattauditor.jks`), `ITWATT_KEYSTORE_PASSWORD`, `ITWATT_KEY_ALIAS` and `ITWATT_KEY_PASSWORD` repository secrets it builds the signed release APK, otherwise a debug APK whose digest changes at every run. It can be started manually with a default backend URL.

### Test on a device

1. Install the APK, enter the backend URL and copy the app signing digest into `ANDROID_SIGNATURE_DIGESTS` on the backend.
2. **1. Register**: GrapheneOS requires a locked bootloader and an app attest key; stock devices are accepted with the `Verified` state.
3. **2. Assert**: the assertion is accepted only through the fresh attestation signed by the registered attest key.
4. **Share ZIP** / **Save ZIP…** to collect the chains and the reports.

-----------

## Huawei devices without GMS

The Huawei devices without Google Mobile Services sold in Italy (EMUI 15, AOSP 12 base) can't provide a trustworthy Android key attestation: without the Google attestation keys, the keystore (Keymaster 3, no app attest keys) signs the chains with the **AOSP software attestation key**, whose private key is public. The backend rejects them with an explicit "Software attestation" error. HUKS key attestation, rooted at the Huawei device attestation root, is only available to HarmonyOS NEXT apps.

As an option (`HUAWEI_SYSINTEGRITY=true`), these devices can use the **HMS Safety Detect SysIntegrity** check instead, the counterpart of Play Integrity on HMS. HMS Core evaluates the system integrity on the device, with the TEE where supported, and returns a JWS signed by the Huawei SysIntegrity service. The app uses either of the two APIs of the SDK (selectable in the app):

- `sysIntegrity(SysIntegrityRequest)` with the `PS256` algorithm;
- `sysIntegrity(nonce, appId)`, signed with `RS256`.

The backend verifies the result as in the [HMS Core server sample](https://github.com/HMS-Core/hms-safetydetect-demo-android/tree/master/SafetyDetect-SysIntegrity-Sample/SafetyDetect-SysIntegrity-Server-Sample):

1. the `x5c` chain is rooted at the pinned **HUAWEI CBG Root CA** (SHA-256 `3A:A8:1A:D7:…:9D:6B:8D:A0`);
2. the signing certificate is issued to `sysintegrity.platform.hicloud.com`;
3. the `RS256` / `PS256` signature is valid;
4. the payload has the expected `nonce`, `apkPackageName` (`ANDROID_PACKAGE_NAMES`) and `apkCertificateDigestSha256` (`ANDROID_SIGNATURE_DIGESTS`), a `timestampMs` of at most 10 minutes and `basicIntegrity: true`.

| Step | SysIntegrity nonce | Accepted when |
| --- | --- | --- |
| Registration | SHA-256(challenge ‖ SubjectPublicKeyInfo of the hardware key) | the key attestation is rejected and the result is valid: the registration token pins the hardware key and the `huawei_sysintegrity` method |
| Assertion | SHA-256(client data) | the client data is signed by the registered hardware key and the result is valid |

Please note the limits of this path, the same of Play Integrity: the result is a verdict of a remote service, it is **not bound to the keys** of the app, so it doesn't prove that the hardware key is stored in secure hardware (`hardwareKeyProven: false` in the response), and there is no attest key pinning the device. Trusting it is a policy choice, hence it is disabled by default.

Setup:

1. In AppGallery Connect, add the SHA-256 fingerprint of the app signing certificate to the app `it.capptests.itwattauditor` and enable Safety Detect.
2. Build the app with the App ID: put `agconnect-services.json` in `android/app/` (it is ignored by git, as it contains the client credentials), or pass `-Pitwattauditor.huaweiAppId=<App ID>` or `ITWATT_HUAWEI_APP_ID`. The GitHub workflow reads the `ITWATT_HUAWEI_APP_ID` repository variable.
3. Set `HUAWEI_SYSINTEGRITY=true` on the backend.

The app sends the SysIntegrity result with each step when HMS Core is available, and exports it in the ZIP (`sysintegrity.jws` and the decoded `sysintegrity.json`).

-----------

## Limits

- The challenges are stateless (_HMAC with expiry_): without a storage they can't be consumed, so they can be replayed until they expire. The Wallet Provider consumes them.
- The registration token replaces the wallet instance stored by the Wallet Provider: it can't be revoked before the secret changes.
- The app uses its own package name and signing certificate, not the IO app ones.
- The HUAWEI CBG Root CA is pinned without revocation checks of the SysIntegrity certificates.

----------

## Credits

The attestation policy, ASN.1 parsing, SSHSIG verification, GrapheneOS allowlist and test fixtures are adapted from the reference backend of the [io-react-native-integrity](https://github.com/pagopa/io-react-native-integrity) fork (MIT, Copyright PagoPA). 

See [backend/test/fixtures/README.md](backend/test/fixtures/README.md) for the sources of the real attestation chains.
