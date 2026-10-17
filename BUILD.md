# Build instructions

## Toolchain (verified target versions)

| Tool | Version |
|------|---------|
| JDK | 17+ (21 works) |
| Android Gradle Plugin | 8.5.2 |
| Gradle | 8.9 (via the bundled wrapper) |
| Kotlin | 2.0.20 |
| Compile SDK / Target SDK | 34 |
| Min SDK | 26 (Android 8.0) |
| Android Studio | Koala 2024.1+ |

The dependency versions are pinned in `gradle/libs.versions.toml`.

## 1. Get the Android SDK

Install via Android Studio (SDK Manager → Android 14 / API 34 + Build-Tools 34)
or the command-line tools. Android Studio writes `local.properties` with `sdk.dir`
automatically on first open; otherwise copy `local.properties.example` to
`local.properties` and set the path.

## 2. Debug APK

```bash
./gradlew :app:assembleDebug
# output: app/build/outputs/apk/debug/app-debug.apk
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

## 3. Unit tests (JVM, no device)

```bash
./gradlew test
# the safety-critical suites:
./gradlew :core:core-security:test
```

## 4. Instrumented tests (device/emulator)

```bash
./gradlew :app:connectedDebugAndroidTest
```

## 5. Signed release APK (reproducible)

The repo contains **no** keystore or signing secrets. Generate your own:

```bash
keytool -genkeypair -v -keystore sentinel-release.jks \
  -keyalg RSA -keysize 4096 -validity 3650 -alias sentinel
```

Create `keystore.properties` (git-ignored) at the repo root:

```properties
storeFile=/absolute/path/sentinel-release.jks
storePassword=********
keyAlias=sentinel
keyPassword=********
```

Then add a `signingConfigs` block to `app/build.gradle.kts` that reads those
properties, reference it from the `release` build type, and run:

```bash
./gradlew :app:assembleRelease
```

(The signing wiring is intentionally left out of version control so no credential
or key is ever committed — spec §19.)

## 6. Native / terminal layer (optional, needs the NDK)

The Terminal, PRoot Linux userspace, and PCAP packet reinjection require native
components that are **not** part of this build (no NDK in the authoring
environment). To add them on a machine with the NDK:

1. Install the NDK (r26+) and CMake via the SDK Manager.
2. Add an `externalNativeBuild { cmake { ... } }` block and a terminal-emulator +
   PTY implementation under a `terminal/` native module.
3. Bundle a PRoot binary and a minimal rootfs for the `linux-runtime` module, or
   download it on first run with integrity verification.

See [COMPATIBILITY.md](COMPATIBILITY.md) §2–§4 for exactly what each piece covers.

## Notes

- `./gradlew` is pinned to Gradle 8.9. The first invocation downloads the
  distribution and the AGP from Google's Maven — network access to
  `dl.google.com` / `repo.maven.apache.org` is required.
- The project is a standard multi-module Android build; no custom bootstrap is
  needed beyond the SDK.
