plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    kotlin("kapt")
}

android {
    namespace = "com.muhammad.networkscan"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.muhammad.networkscan"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    buildFeatures{
        viewBinding = true
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
    }
}

dependencies {

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.androidx.activity)
    implementation(libs.androidx.constraintlayout)
    // ViewModel
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.10.0")

    // LiveData
    implementation("androidx.lifecycle:lifecycle-livedata-ktx:2.10.0")

    // Lifecycle Runtime
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.10.0")

    // Fragment KTX (required for by viewModels() in Fragment)
    implementation("androidx.fragment:fragment-ktx:1.8.9")

    // Activity KTX (required for by viewModels() in Activity)
    implementation("androidx.activity:activity-ktx:1.13.0")
    implementation("androidx.room:room-runtime:2.8.4")

    kapt("androidx.room:room-compiler:2.8.4")

    implementation("androidx.room:room-ktx:2.8.4")
    implementation("com.google.code.gson:gson:2.13.1")
    implementation("androidx.navigation:navigation-fragment-ktx:2.9.6")
    implementation("androidx.navigation:navigation-ui-ktx:2.9.6")

    implementation("org.apache.poi:poi-ooxml:5.2.5")

    // POI requires these XML libraries on Android
    // (Android doesn't ship with the full javax.xml stack POI expects)
    implementation("xerces:xercesImpl:2.12.2")
    implementation("xml-apis:xml-apis:1.4.01")

    // Required by poi-ooxml for zip handling
    implementation("org.apache.commons:commons-compress:1.26.1")
    implementation("commons-io:commons-io:2.16.1")
    implementation("org.apache.xmlbeans:xmlbeans:5.2.0")

    // ── NetCapture: Coroutines (if not already added) ───────────────────
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}