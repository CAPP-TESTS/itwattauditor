plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

// Optional release signing from the environment (e.g. GitHub Actions secrets), so that the app signing
// certificate digest configured on the backend (ANDROID_SIGNATURE_DIGESTS) stays the same across builds
val releaseKeystore = System.getenv("ITWATT_KEYSTORE_FILE")?.let { file(it) }?.takeIf { it.exists() }

// Huawei AppGallery Connect App ID, required by the HMS Safety Detect SysIntegrity API: from the
// itwattauditor.huaweiAppId property, the ITWATT_HUAWEI_APP_ID variable or app/agconnect-services.json
// (client.app_id), which is not committed. Without it the SysIntegrity check is disabled.
val huaweiAppId: String = (project.findProperty("itwattauditor.huaweiAppId") as String?)
    ?.takeIf { it.isNotBlank() }
    ?: System.getenv("ITWATT_HUAWEI_APP_ID")?.takeIf { it.isNotBlank() }
    ?: file("agconnect-services.json").takeIf { it.exists() }?.let { json ->
        @Suppress("UNCHECKED_CAST")
        val config = groovy.json.JsonSlurper().parse(json) as Map<String, Any?>
        (config["client"] as Map<String, Any?>?)?.get("app_id")?.toString()
    }
    ?: ""

android {
    namespace = "it.capptests.itwattauditor"
    compileSdk = 36

    defaultConfig {
        applicationId = "it.capptests.itwattauditor"
        // Hardware key attestation is available on devices launched with Android 8.0 or later
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
        // Default backend URL, e.g. ./gradlew assembleDebug -Pitwattauditor.serverUrl=https://example.vercel.app
        buildConfigField(
            "String",
            "DEFAULT_SERVER_URL",
            "\"${project.findProperty("itwattauditor.serverUrl") ?: ""}\""
        )
        buildConfigField("String", "HUAWEI_APP_ID", "\"$huaweiAppId\"")
        manifestPlaceholders["huaweiAppId"] = huaweiAppId
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        if (releaseKeystore != null) {
            create("release") {
                storeFile = releaseKeystore
                storePassword = System.getenv("ITWATT_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("ITWATT_KEY_ALIAS")
                keyPassword = System.getenv("ITWATT_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        debug {
            // Cleartext HTTP only for a local backend during development
            manifestPlaceholders["usesCleartextTraffic"] = "true"
        }
        release {
            manifestPlaceholders["usesCleartextTraffic"] = "false"
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.hms.safetydetect)
    testImplementation(libs.junit)
}
