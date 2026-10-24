# ZVPN Android Client — Native Engine Review & Update

A reviewed update for the Android-side ZVPN transport: a Kotlin lifecycle wrapper plus a C/JNI packet tunnel engine using Zstandard and the existing ZVPN v1 TCP framing protocol.

> **Security warning:** ZVPN v1 is plain TCP without authentication, encryption, or message integrity. `VpnService.protect()` prevents the tunnel's own socket from looping back into the VPN; it does **not** encrypt or authenticate the connection. Do not expose this protocol to untrusted networks until you add an authenticated secure transport (such as TLS with proper certificate validation) and corresponding server support.

## Files in this package

```text
zvpn-client/
├── NativeProxyEngine.kt              # Kotlin engine, configuration, stats, retries
├── zvpn_jni.c                        # C/JNI tunnel transport
├── CMakeLists.txt                    # Builds libvpnengine.so
├── build-all-android-abis.ps1        # Windows/PowerShell multi-ABI build
├── build.bat                         # Windows convenience wrapper
├── tests/
│   ├── native_frame_roundtrip_test.c # Host-side frame/codec regression test
│   └── stubs/android/log.h           # Logcat stub for host-only testing
└── zstd/                             # Required Zstandard source tree; not included here
```

The `zstd/` directory is a build dependency from the existing project. Keep it beside `CMakeLists.txt` and `zvpn_jni.c`; it must contain `zstd/build/cmake/CMakeLists.txt` and `zstd/lib/zstd.h`.

## Review changes

### Native C/JNI

- **Frame sends use scatter/gather I/O.** The 16-byte ZVPN header and encoded payload are passed through `sendmsg()` with two `iovec`s, reducing send syscalls and avoiding an intentional header-only write. Correct partial writes are still handled; this does not change the wire format.
- **TCP keepalive is enabled best-effort.** Where supported by Android/Linux, the native socket asks for a 60-second idle time, 15-second probe interval, and four probes. Unsupported options produce diagnostic logs but do not fail the connection.
- **Incoming compressed-batch accounting was added.** Stats slot `[15]` counts incoming frames that were successfully decoded/validated as Zstandard. The previous 15 counter positions keep their original meaning.
- **Shutdown and framing behavior remain conservative.** The client never retries a partially transmitted frame on the same TCP stream. Invalid headers, packet lengths, IP packet lengths, and decompression output are rejected.

### Kotlin lifecycle and statistics

- **Fixed a native-handle race.** `stop()` now holds the native-handle lock across `nativeStop()`, so `close()` cannot free the handle between reading it and calling native code.
- **Fixed start/close coordination.** A lifecycle lock prevents `close()` from destroying the engine while `start()` is still creating or starting its worker threads. The lifecycle lock is not held while joining threads.
- **Fixed out-of-order statistics snapshots.** Concurrent `stats()` calls and the periodic persistence thread can finish snapshot reads in a different order. The persistent baseline now only moves forward, preventing a stale snapshot from causing duplicate lifetime-counter increments.
- **Added bounded exponential reconnect backoff with jitter.** Retry delay grows between attempts, is capped, and can be configured for a fixed delay by setting the multiplier to `1.0` and jitter to `0`.
- **Added an `onRetryScheduled` callback** so a UI can show the next retry attempt and delay.
- **Added session/lifetime convenience metrics** and a `compressedBatchesReceived` statistic.
- **Reduced default Logcat noise.** `verboseLogs` now defaults to `false`. Set it to `true` while debugging packet-level behavior; very verbose logging can hurt performance and flood Logcat.
- **Kept backwards compatibility for the old 15-counter native stats array.** If an old `.so` is accidentally packaged with the updated Kotlin code, the new compressed-receive counter reads as zero; the previous counters can still be persisted. Rebuild and package the C library to get the new counter.
- **Fixed the Windows build wrapper** so it invokes the PowerShell script by its own full path rather than depending on the current working directory.

## Existing wire protocol

The wire format is unchanged, so this update does not require a server protocol change:

- 16-byte header: `ZVPN`, version `1`, flags, two reserved bytes, raw batch length (`u32`, network byte order), payload length (`u32`, network byte order).
- Payload: repeated `[packet length (u32, network byte order)][raw IP packet bytes]`.
- Flag bit 0 means the payload is Zstandard-compressed. If compression does not make a batch smaller, the client sends the raw batch.

The C JNI symbols expect the Kotlin class package `ir.andy.zvpn` and class name `NativeProxyEngine`. Do not rename the Kotlin package without updating the JNI function names in `zvpn_jni.c`.

## Kotlin configuration

```kotlin
val engine = NativeProxyEngine(
    vpnService = this,
    config = NativeProxyEngine.Config(
        compressionLevel = 1,
        maxBatchBytes = 256 * 1024,
        flushTimeoutMs = 10,
        connectTimeoutMs = 10_000,
        compressionEnabled = true,
        verboseLogs = false,
        maxReconnectAttempts = 10,
        reconnectDelayMs = 1_000L,
        reconnectBackoffMultiplier = 1.5,
        maxReconnectDelayMs = 30_000L,
        reconnectJitterPercent = 20
    )
)
```

### Configuration fields

| Field | Default | Meaning |
|---|---:|---|
| `address` | `""` | Legacy/config convenience field; `start()` still takes the host explicitly. |
| `port` | `0` | Legacy/config convenience field; `start()` still takes the port explicitly. |
| `androidTunIpv4Address` | `""` | Legacy/config convenience field for the service/UI; this class does not configure the TUN address itself. |
| `compressionLevel` | `1` | Zstandard level, accepted range `1..22`. Higher levels can cost more CPU. |
| `maxBatchBytes` | `262144` | Maximum uncompressed encoded-packet batch (`4 KiB..4 MiB`). This is a ceiling, not a promise that batches will reach this size. |
| `flushTimeoutMs` | `10` | Maximum batch age in milliseconds. `0` flushes every packet immediately, reducing batching/compression opportunities. |
| `connectTimeoutMs` | `10000` | Timeout for each TCP connection attempt after address resolution. It does **not** impose a hard timeout on DNS lookup. |
| `compressionEnabled` | `true` | Enables Zstandard compression for outgoing batches. The server independently controls its own outgoing compression. |
| `logTag` | `"NATIVE_PROXY"` | Logcat tag. |
| `verboseLogs` | `false` | Enables per-packet and low-level debug logging when `true`. |
| `maxReconnectAttempts` | `10` | Number of retries after the first attempt; `0` disables retries. Accepted range `0..10`. |
| `reconnectDelayMs` | `1000` | Base retry delay in milliseconds (`0..60000`). |
| `reconnectBackoffMultiplier` | `1.5` | Multiplies delay after each retry (`1.0..5.0`). `1.0` disables exponential growth. |
| `maxReconnectDelayMs` | `30000` | Maximum retry delay, including backoff (`>= reconnectDelayMs`, up to `120000`). |
| `reconnectJitterPercent` | `20` | Random symmetric variation around the computed delay (`0..50`). Use `0` for deterministic delays. |

For example, with a 1-second base, multiplier `1.5`, 30-second cap, and 20% jitter, the first retry waits roughly 0.8–1.2 seconds, the next roughly 1.2–1.8 seconds, and delays continue to grow until capped.

`compressionLevel`, `maxBatchBytes`, `flushTimeoutMs`, `connectTimeoutMs`, `compressionEnabled`, `logTag`, and `verboseLogs` are passed to native code when the engine is created. Mutating a config property after construction will not change the already-created native engine.

## Starting the engine

Call `VpnService.Builder.establish()` first and pass its file descriptor to `start()`. The engine duplicates the descriptor, so native code owns and closes only its duplicate; the service must still manage its original `ParcelFileDescriptor` lifecycle.

```kotlin
import android.util.Log

engine.start(
    tunFd = tunParcelFileDescriptor.fd,
    serverHost = "203.0.113.10", // Replace with your actual server IP/hostname.
    serverPort = 61130,
    onRetryScheduled = { attempt, delayMs, errorCode ->
        Log.w("ZVPN", "Retry $attempt in ${delayMs}ms (errno=$errorCode)")
    },
    onFinished = { resultCode ->
        // This callback runs on the engine runner thread. Post to the main thread
        // before updating Views or other UI objects.
        Log.i("ZVPN", "Engine finished with result=$resultCode")
    }
)
```

The class can be started only once. Retries happen internally on the same instance when a retryable disconnect occurs; to start a new logical session after an explicit `stop()`, create a new engine instance and establish/pass the proper TUN descriptor.

### Stop and close

```kotlin
engine.stop()  // Request stop; native socket shutdown wakes the receive loop.
engine.close() // Wait for worker/persistence threads, persist the last counters, destroy native state.
```

Prefer calling `close()` from a background/service-controlled lifecycle path rather than blocking the Android main/UI thread. The native resolver still uses synchronous `getaddrinfo()`: if DNS resolution itself stalls, `connectTimeoutMs` cannot interrupt it, and `close()` may have to wait for that resolver call to return. For a stable deployment, pass a reachable server IP or resolve the hostname on the underlying network before starting the tunnel. Never blindly resolve a hostname through the tunnel's own DNS path before the transport exists.

## Reading statistics

```kotlin
val snapshot = engine.stats()
if (snapshot != null) {
    Log.i("ZVPN", "upload savings=${snapshot.uploadSavingsPercent}%")
    Log.i("ZVPN", "download savings=${snapshot.downloadSavingsPercent}%")
    Log.i("ZVPN", "combined payload savings=${snapshot.combinedSavingsPercent}%")
    Log.i("ZVPN", "compressed upload batches=${snapshot.compressedBatchesSent}")
    Log.i("ZVPN", "compressed download batches=${snapshot.compressedBatchesReceived}")
    Log.i("ZVPN", "lifetime estimated saved=${snapshot.lifetimeEstimatedWireBytesSaved} B")
}
```

`stats()` persists counter deltas. A background thread also persists at approximately one-second intervals while the engine is running. Lifetime data is held in app-private `SharedPreferences`.

### What the counters mean

- **TUN bytes** count complete IP packet bytes read from or written to the Android VPN file descriptor.
- **Transport bytes** count TCP stream bytes accepted/supplied by native `sendmsg`/`recv`; they include ZVPN framing but are not physical interface counters.
- **Payload bytes** include the per-packet 4-byte length prefixes inside each ZVPN batch but exclude the 16-byte ZVPN frame header.
- **Estimated wire bytes** add the 16-byte frame header for each completed frame. They still exclude TCP/IP headers, TCP retransmissions, link-layer overhead, and other device traffic.
- **Payload savings** are `raw payload - encoded payload`. This is useful for comparing compression, but it is not a guarantee of the exact reduction in Android's mobile-data counter.
- **Compressed batch counts** count frames that were actually encoded/received as Zstandard. A batch that fails to shrink is sent raw.

## Build the Android native library on Windows

Prerequisites:

- Android Studio/SDK with the Android NDK installed.
- CMake and Ninja available to the PowerShell script.
- A local `zstd/` source directory as described above.

1. Put `zvpn_jni.c`, `CMakeLists.txt`, `build-all-android-abis.ps1`, and `build.bat` in the same project root as the existing `zstd/` directory.
2. Open `build.bat` and update `NDK_PATH` if your installed NDK directory is not `30.0.15729638`.
3. Run `build.bat`, or from PowerShell run:

   ```powershell
   .\build-all-android-abis.ps1 `
     -NdkPath "$env:LOCALAPPDATA\Android\Sdk\ndk\30.0.15729638" `
     -AndroidPlatform android-23
   ```

4. The script builds these Android ABIs into `out/jniLibs/`:

   ```text
   out/jniLibs/arm64-v8a/libvpnengine.so
   out/jniLibs/armeabi-v7a/libvpnengine.so
   out/jniLibs/x86_64/libvpnengine.so
   out/jniLibs/x86/libvpnengine.so
   ```

5. Copy the ABI folders into the app module's `app/src/main/jniLibs/`, then rebuild the APK. Ensure your Gradle `abiFilters` include only the ABIs you intend to ship.

The app must load the library using `System.loadLibrary("vpnengine")`; CMake's target/output name is intentionally `vpnengine` so the file is `libvpnengine.so`.

## Host-side regression test

A small test round-trips both compressed and raw ZVPN frames through a local socket pair. This verifies the C frame serialization/decompression path and the new compressed-receive counter. It is **not** a live VPN or mobile-network benchmark.

On a Linux host with GCC/Clang, JDK JNI headers, and a system Zstandard development library, run (adjust the JDK include paths if needed):

```bash
clang -D_POSIX_C_SOURCE=200809L -std=c11 -O1 -Wall -Wextra -Werror -pthread \
  -Itests/stubs \
  -I/usr/lib/jvm/java-21-openjdk-amd64/include \
  -I/usr/lib/jvm/java-21-openjdk-amd64/include/linux \
  -I/usr/include \
  tests/native_frame_roundtrip_test.c -lzstd -o /tmp/zvpn-frame-test
/tmp/zvpn-frame-test
```

The production Android build still must be run with your installed Android NDK and project Zstandard sources.

## Troubleshooting

| Symptom | Likely check |
|---|---|
| `UnsatisfiedLinkError: ... nativeCreate` | Rebuild and package `libvpnengine.so` for the device ABI; verify package/class name `ir.andy.zvpn.NativeProxyEngine` matches the JNI symbol prefix. |
| `Failed to create native VPN engine` | Check Logcat for invalid compression level, batch size, flush timeout, or connection timeout. The C side rejects invalid values too. |
| `VpnService.protect()` returned false | The VPN permission/state may have been revoked, or the service is no longer prepared. Do not continue using the unprotected transport socket. |
| `ECONNREFUSED` | Check server IP, port, firewall/security rules, and whether the server is listening. |
| `ETIMEDOUT` / `EHOSTUNREACH` | Check network availability, route/firewall, endpoint reachability, and DNS resolution if using a hostname. |
| Frequent reconnects while idle | TCP keepalive is enabled best-effort; inspect native logs and server logs. OS support and actual probe timings vary. |
| Low compression savings | Most encrypted HTTPS content is inherently hard to compress. Compare weighted raw/encoded payload bytes and actual batch sizes; a 4 MiB maximum does not guarantee 4 MiB batches. |
| Lifetime counters appear duplicated | This update guards against out-of-order snapshots. Rebuild and package the matching Kotlin/C pair, then verify that only one engine instance is running at a time. Existing lifetime totals in SharedPreferences are not reset automatically. |
| Stop takes longer than expected | `connectTimeoutMs` limits TCP connection attempts after DNS resolution, not blocking `getaddrinfo()`. Use a known reachable IP or resolve before bringing up the tunnel. |

## Verification performed for this update

- C syntax/warning check with Clang, including strict warnings and static analysis, passed on the host environment.
- Kotlin `NativeProxyEngine.kt` compiled with host-side Android API stubs to check Kotlin syntax and type consistency. This is not a substitute for compiling inside the user's Android Gradle project.
- The host-side frame test successfully round-tripped raw and compressed frames. A deliberately repetitive 28,800-byte batch compressed to 42 bytes in that synthetic test; that number is not representative of encrypted Internet traffic.
- No Android NDK was available in this environment, so I have **not** built all four Android ABIs or tested on a physical Android device/live ZVPN server.
