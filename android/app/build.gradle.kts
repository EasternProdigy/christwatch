plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "io.christwatch.phone"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.christwatch.phone"
        minSdk = 29
        targetSdk = 35
        versionCode = 6
        versionName = "1.9.0"
    }

    signingConfigs {
        create("shared") {
            storeFile = rootProject.file("keys/christwatch.jks")
            storePassword = "christwatch"
            keyAlias = "christwatch"
            keyPassword = "christwatch"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("shared")
        }
        debug {
            signingConfig = signingConfigs.getByName("shared")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        viewBinding = false
    }
}

dependencies {
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.work:work-runtime:2.10.0")
    implementation("com.google.android.material:material:1.12.0")
}
