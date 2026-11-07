plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val appVersion = (System.getenv("APP_VERSION") ?: "2.7.2").ifBlank { "2.7.2" }
val parts = appVersion.split(".").map { it.toIntOrNull() ?: 0 } + listOf(0, 0, 0)

android {
    namespace = "com.likfridman.dpibypass"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.likfridman.dpibypass"
        minSdk = 26
        targetSdk = 35
        versionCode = parts[0] * 10000 + parts[1] * 100 + parts[2]
        versionName = appVersion
    }

    signingConfigs {
        create("release") {
            val ks = System.getenv("KEYSTORE_FILE")
            if (ks != null && file(ks).exists()) {
                storeFile = file(ks)
                storePassword = System.getenv("KEYSTORE_PASSWORD")
                keyAlias = System.getenv("KEY_ALIAS") ?: "dpi-bypass"
                keyPassword = System.getenv("KEYSTORE_PASSWORD")
            }
        }
    }

    // общий ключ из репозитория: подпись не меняется между сборками, обновления ставятся поверх.
    // Свой секретный ключ: секреты KEYSTORE_B64 и KEYSTORE_PASSWORD в настройках репозитория.
    signingConfigs.create("repo") {
        storeFile = rootProject.file("debug.keystore")
        storePassword = "android"
        keyAlias = "androiddebugkey"
        keyPassword = "android"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            val ks = System.getenv("KEYSTORE_FILE")
            signingConfig = if (ks != null && file(ks).exists()) signingConfigs.getByName("release")
                            else signingConfigs.getByName("repo")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    // byedpi лежит как исполняемый файл libciadpi.so - он должен распаковаться на диск
    packaging { jniLibs { useLegacyPackaging = true } }
}
