package ir.andy.zvpn

import android.content.Context
import android.net.VpnService
import android.system.OsConstants
import android.util.Log
import androidx.annotation.Keep
import java.io.Serializable
import java.util.concurrent.ThreadLocalRandom
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.math.min

@Keep
class NativeProxyEngine(
    private val vpnService: VpnService,
    private val config: Config
) : AutoCloseable {

    data class Config(
        val address: String = "",
        val port: Int = 0,
        val androidTunIpv4Address: String = "",
        val compressionLevel: Int = 1,
        val maxBatchBytes: Int = 256 * 1024,
        val flushTimeoutMs: Int = 10,
        val connectTimeoutMs: Int = 10_000,
        val compressionEnabled: Boolean = true,
        val logTag: String = "NATIVE_PROXY",
        var verboseLogs: Boolean = false,
        /** Retries after the initial attempt. Maximum accepted value is 10. */
        val maxReconnectAttempts: Int = 10,
        /** Base retry delay. Zero disables the delay. */
        val reconnectDelayMs: Long = 1_000L,
        /** Exponential retry multiplier, from 1.0 (fixed delay) to 5.0. */
        val reconnectBackoffMultiplier: Double = 1.5,
        /** Upper limit for a retry delay, including backoff. */
        val maxReconnectDelayMs: Long = 30_000L,
        /** Randomized delay variation from 0 to 50 percent. */
        val reconnectJitterPercent: Int = 20
    ) : Serializable

    /**
     * Payload counts include ZVPN's per-packet length fields, but not its 16-byte frame header.
     * Wire-byte estimates include the 16-byte header per successfully completed frame and exclude
     * TCP/IP headers, retransmissions, and link-layer overhead.
     */
    data class Stats(
        val tunBytesRead: Long,
        val tunBytesWritten: Long,
        val transportBytesSent: Long,
        val transportBytesReceived: Long,
        val batchesSent: Long,
        val batchesReceived: Long,
        val compressedBatchesSent: Long,
        val packetsSent: Long,
        val packetsWrittenToTun: Long,

        val uncompressedPayloadBytesSent: Long,
        val encodedPayloadBytesSent: Long,
        val bytesSavedSending: Long,
        val uncompressedPayloadBytesReceived: Long,
        val encodedPayloadBytesReceived: Long,
        val bytesSavedReceiving: Long,

        val uncompressedPayloadBytes: Long,
        val encodedPayloadBytes: Long,
        val bytesSaved: Long,
        val estimatedUncompressedWireBytes: Long,
        val estimatedActualWireBytes: Long,

        /** Cumulative totals persisted in SharedPreferences across engine instances/restarts. */
        val totalPayloadBytesWithoutCompression: Long,
        val totalEncodedPayloadBytes: Long,
        val totalBytesWithoutCompression: Long,
        val totalBytesActuallyTransferred: Long,
        /** Payload bytes saved; frame headers are excluded from this counter. */
        val totalBytesSaved: Long,
        /** Number of successfully decoded incoming batches that used Zstandard. */
        val compressedBatchesReceived: Long = 0L
    ) {
        val uploadSavingsPercent: Double
            get() = savingsPercent(bytesSavedSending, uncompressedPayloadBytesSent)
        val downloadSavingsPercent: Double
            get() = savingsPercent(bytesSavedReceiving, uncompressedPayloadBytesReceived)
        val combinedSavingsPercent: Double
            get() = savingsPercent(bytesSaved, uncompressedPayloadBytes)
        val estimatedWireBytesSaved: Long
            get() = (estimatedUncompressedWireBytes - estimatedActualWireBytes).coerceAtLeast(0L)
        val estimatedWireSavingsPercent: Double
            get() = savingsPercent(estimatedWireBytesSaved, estimatedUncompressedWireBytes)
        val lifetimeEstimatedWireBytesSaved: Long
            get() = (totalBytesWithoutCompression - totalBytesActuallyTransferred).coerceAtLeast(0L)
        val lifetimeEstimatedWireSavingsPercent: Double
            get() = savingsPercent(lifetimeEstimatedWireBytesSaved, totalBytesWithoutCompression)
    }

    data class PersistedTotals(
        val totalPayloadBytesWithoutCompression: Long,
        val totalEncodedPayloadBytes: Long,
        val totalBytesWithoutCompression: Long,
        val totalBytesActuallyTransferred: Long,
        /** Cumulative payload savings, not physical-interface byte savings. */
        val totalBytesSaved: Long
    ) {
        val estimatedWireBytesSaved: Long
            get() = (totalBytesWithoutCompression - totalBytesActuallyTransferred).coerceAtLeast(0L)
        val estimatedWireSavingsPercent: Double
            get() = savingsPercent(estimatedWireBytesSaved, totalBytesWithoutCompression)
    }

    companion object {
        private const val TAG = "NativeProxyEngine"
        private const val PREFS_NAME = "zvpn_traffic_stats"
        private const val FRAME_HEADER_BYTES = 16L
        private const val LEGACY_NATIVE_STATS_COUNT = 15
        private const val NATIVE_STATS_COUNT = 16

        private const val KEY_TOTAL_RAW_PAYLOAD = "total_raw_payload_bytes"
        private const val KEY_TOTAL_ENCODED_PAYLOAD = "total_encoded_payload_bytes"
        private const val KEY_TOTAL_SAVED_PAYLOAD = "total_saved_payload_bytes"
        private const val KEY_TOTAL_RAW_WIRE = "total_raw_wire_bytes"
        private const val KEY_TOTAL_ACTUAL_WIRE = "total_actual_wire_bytes"
        private val PERSISTENCE_LOCK = Any()

        private fun savingsPercent(saved: Long, original: Long): Double =
            if (original <= 0L) 0.0 else saved.toDouble() * 100.0 / original.toDouble()

        init {
            System.loadLibrary("vpnengine")
        }
    }

    private val preferences = vpnService.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val nativeHandleLock = Any()
    /** Serializes start against the initial close transition; never held while joining threads. */
    private val lifecycleLock = Any()
    private val closeStarted = AtomicBoolean(false)

    @Volatile
    private var handle: Long = createNativeHandle()

    @Volatile
    private var runner: Thread? = null

    @Volatile
    private var persistenceThread: Thread? = null

    @Volatile
    private var userStopRequested = false

    @Volatile
    private var persistenceLoopActive = false

    @Volatile
    private var hasStarted = false

    /** Values already added to persistent totals; prevents double-counting when stats() is polled. */
    private var lastPersistedSessionStats = LongArray(NATIVE_STATS_COUNT)

    init {
        check(handle != 0L) {
            "Failed to create native VPN engine. Check configuration."
        }
    }

    private fun createNativeHandle(): Long {
        require(config.compressionLevel in 1..22) {
            "compressionLevel must be between 1 and 22"
        }
        require(config.maxBatchBytes in 4 * 1024..4 * 1024 * 1024) {
            "maxBatchBytes must be between 4 KiB and 4 MiB"
        }
        require(config.flushTimeoutMs in 0..60_000) {
            "flushTimeoutMs must be between 0 and 60000"
        }
        require(config.connectTimeoutMs in 1..120_000) {
            "connectTimeoutMs must be between 1 and 120000"
        }
        require(config.maxReconnectAttempts in 0..10) {
            "maxReconnectAttempts must be between 0 and 10"
        }
        require(config.reconnectDelayMs in 0L..60_000L) {
            "reconnectDelayMs must be between 0 and 60000"
        }
        require(config.reconnectBackoffMultiplier.isFinite() &&
                config.reconnectBackoffMultiplier in 1.0..5.0) {
            "reconnectBackoffMultiplier must be between 1.0 and 5.0"
        }
        require(config.maxReconnectDelayMs in config.reconnectDelayMs..120_000L) {
            "maxReconnectDelayMs must be >= reconnectDelayMs and <= 120000"
        }
        require(config.reconnectJitterPercent in 0..50) {
            "reconnectJitterPercent must be between 0 and 50"
        }
        return nativeCreate(
            config.compressionLevel,
            config.maxBatchBytes,
            config.flushTimeoutMs,
            config.connectTimeoutMs,
            config.compressionEnabled,
            config.logTag,
            config.verboseLogs
        )
    }

    /**
     * Starts the engine asynchronously. `onFinished` and `onRetryScheduled` run on the engine
     * runner thread; post to the main thread before updating Android views.
     * The TUN descriptor must come from VpnService.Builder.establish().
     */
    fun start(
        tunFd: Int,
        serverHost: String,
        serverPort: Int,
        onFinished: (Int) -> Unit = {},
        onRetryScheduled: (attempt: Int, delayMs: Long, errorCode: Int) -> Unit = { _, _, _ -> }
    ) {
        synchronized(lifecycleLock) {
            check(handle != 0L) { "Engine is destroyed" }
            check(!closeStarted.get()) { "Engine is closing or destroyed" }
            check(!userStopRequested) { "Engine has already been stopped" }
            check(!hasStarted) { "Engine can only be started once" }
            require(tunFd >= 0) { "tunFd must be a valid non-negative descriptor" }
            require(serverHost.isNotBlank()) { "serverHost cannot be blank" }
            require(serverPort in 1..65535) { "serverPort must be between 1 and 65535" }
            hasStarted = true

            val currentHandle = synchronized(nativeHandleLock) { handle }
            persistenceLoopActive = true

            runner = Thread({
                var result = 0
                var retriesUsed = 0
                try {
                    while (!userStopRequested) {
                        result = try {
                            nativeRun(currentHandle, vpnService, tunFd, serverHost, serverPort)
                        } catch (e: Exception) {
                            Log.e(TAG, "Native engine failed", e)
                            -1
                        }

                        persistCurrentStats()

                        if (userStopRequested) {
                            result = 0
                            break
                        }

                        if (!isRetryableDisconnect(result) || retriesUsed >= config.maxReconnectAttempts) {
                            if (isRetryableDisconnect(result) && retriesUsed >= config.maxReconnectAttempts) {
                                Log.e(TAG, "Connection failed; exhausted ${config.maxReconnectAttempts} retries")
                            }
                            break
                        }

                        retriesUsed++
                        val delayMs = reconnectDelayForAttempt(retriesUsed)
                        Log.w(
                            TAG,
                            "Tunnel disconnected (code=$result); retry $retriesUsed/" +
                                "${config.maxReconnectAttempts} in ${delayMs} ms"
                        )
                        try {
                            onRetryScheduled(retriesUsed, delayMs, result)
                        } catch (callbackError: Exception) {
                            Log.e(TAG, "onRetryScheduled callback failed", callbackError)
                        }
                        try {
                            Thread.sleep(delayMs)
                        } catch (_: InterruptedException) {
                            if (userStopRequested) {
                                result = 0
                                break
                            }
                        }
                    }
                } finally {
                    persistCurrentStats()
                    persistenceLoopActive = false
                    try {
                        onFinished(result)
                    } catch (callbackError: Exception) {
                        Log.e(TAG, "onFinished callback failed", callbackError)
                    }
                }
            }, "ZVPN-NativeRun")

            // Persist live counters once per second even if UI never calls stats().
            persistenceThread = Thread({
                while (persistenceLoopActive) {
                    persistCurrentStats()
                    try {
                        Thread.sleep(1_000L)
                    } catch (_: InterruptedException) {
                        if (!persistenceLoopActive) break
                    }
                }
                persistCurrentStats()
            }, "ZVPN-StatsPersist")

            // Start both workers while holding lifecycleLock so close() cannot destroy the handle
            // between assigning a Thread and actually starting it.
            runner?.start()
            persistenceThread?.start()
        }
    }

    /** Exponential delay with a capped maximum and optional symmetric jitter. */
    private fun reconnectDelayForAttempt(attempt: Int): Long {
        if (config.reconnectDelayMs == 0L) return 0L
        var base = config.reconnectDelayMs.toDouble()
        repeat((attempt - 1).coerceAtLeast(0)) {
            base = min(base * config.reconnectBackoffMultiplier, config.maxReconnectDelayMs.toDouble())
        }
        val capped = min(base, config.maxReconnectDelayMs.toDouble()).toLong()
        val jitterBound = capped * config.reconnectJitterPercent / 100L
        if (jitterBound <= 0L) return capped
        val jitter = ThreadLocalRandom.current().nextLong(-jitterBound, jitterBound + 1L)
        return (capped + jitter).coerceIn(0L, config.maxReconnectDelayMs)
    }

    private fun isRetryableDisconnect(code: Int): Boolean = when (code) {
        OsConstants.ECONNRESET,
        OsConstants.ECONNABORTED,
        OsConstants.ECONNREFUSED,
        OsConstants.ETIMEDOUT,
        OsConstants.EHOSTUNREACH,
        OsConstants.ENETDOWN,
        OsConstants.ENETRESET,
        OsConstants.ENETUNREACH,
        OsConstants.EPIPE -> true
        else -> false
    }

    fun stop() {
        val threads = synchronized(lifecycleLock) {
            userStopRequested = true
            persistenceLoopActive = false
            runner to persistenceThread
        }

        // Keep the handle lock for the entire nativeStop call. Otherwise close() could destroy
        // the native handle after it is read here but before nativeStop() enters C.
        synchronized(nativeHandleLock) {
            val currentHandle = handle
            if (currentHandle != 0L) nativeStop(currentHandle)
        }

        // Wakes retry-delay sleep; nativeStop shuts down the TCP socket to wake native I/O.
        threads.first?.interrupt()
        threads.second?.interrupt()
    }

    /**
     * Current-session statistics plus lifetime totals stored in app-private SharedPreferences.
     * Calling this also commits any not-yet-persisted counter deltas.
     */
    fun stats(): Stats? {
        val values = readNativeStats() ?: return null
        persistStatsDelta(values)

        fun value(index: Int): Long = values.getOrElse(index) { 0L }
        val rawSent = value(9)
        val encodedSent = value(10)
        val savedSent = value(11)
        val rawReceived = value(12)
        val encodedReceived = value(13)
        val savedReceived = value(14)
        val rawPayloadTotal = rawSent + rawReceived
        val encodedPayloadTotal = encodedSent + encodedReceived
        val savedTotal = savedSent + savedReceived
        val frames = value(4) + value(5)
        val headerBytes = frames * FRAME_HEADER_BYTES
        val lifetime = persistedTotals()

        return Stats(
            tunBytesRead = value(0),
            tunBytesWritten = value(1),
            transportBytesSent = value(2),
            transportBytesReceived = value(3),
            batchesSent = value(4),
            batchesReceived = value(5),
            compressedBatchesSent = value(6),
            packetsSent = value(7),
            packetsWrittenToTun = value(8),
            uncompressedPayloadBytesSent = rawSent,
            encodedPayloadBytesSent = encodedSent,
            bytesSavedSending = savedSent,
            uncompressedPayloadBytesReceived = rawReceived,
            encodedPayloadBytesReceived = encodedReceived,
            bytesSavedReceiving = savedReceived,
            uncompressedPayloadBytes = rawPayloadTotal,
            encodedPayloadBytes = encodedPayloadTotal,
            bytesSaved = savedTotal,
            estimatedUncompressedWireBytes = rawPayloadTotal + headerBytes,
            estimatedActualWireBytes = encodedPayloadTotal + headerBytes,
            totalPayloadBytesWithoutCompression = lifetime.totalPayloadBytesWithoutCompression,
            totalEncodedPayloadBytes = lifetime.totalEncodedPayloadBytes,
            totalBytesWithoutCompression = lifetime.totalBytesWithoutCompression,
            totalBytesActuallyTransferred = lifetime.totalBytesActuallyTransferred,
            totalBytesSaved = lifetime.totalBytesSaved,
            compressedBatchesReceived = value(15)
        )
    }

    /** Retrieve stored lifetime totals even after the native engine has been closed. */
    fun persistedTotals(): PersistedTotals = synchronized(PERSISTENCE_LOCK) {
        PersistedTotals(
            totalPayloadBytesWithoutCompression = preferences.getLong(KEY_TOTAL_RAW_PAYLOAD, 0L),
            totalEncodedPayloadBytes = preferences.getLong(KEY_TOTAL_ENCODED_PAYLOAD, 0L),
            totalBytesWithoutCompression = preferences.getLong(KEY_TOTAL_RAW_WIRE, 0L),
            totalBytesActuallyTransferred = preferences.getLong(KEY_TOTAL_ACTUAL_WIRE, 0L),
            totalBytesSaved = preferences.getLong(KEY_TOTAL_SAVED_PAYLOAD, 0L)
        )
    }

    private fun readNativeStats(): LongArray? = synchronized(nativeHandleLock) {
        val currentHandle = handle
        if (currentHandle == 0L) null else nativeGetStats(currentHandle)
    }

    private fun persistCurrentStats() {
        val values = readNativeStats() ?: return
        persistStatsDelta(values)
    }

    private fun persistStatsDelta(values: LongArray) {
        if (values.size < LEGACY_NATIVE_STATS_COUNT) {
            Log.e(
                TAG,
                "Native stats schema mismatch: expected at least $LEGACY_NATIVE_STATS_COUNT values, got ${values.size}"
            )
            return
        }

        synchronized(PERSISTENCE_LOCK) {
            // Keep compatibility with the previous 15-counter native library. In that case the
            // new compressed-RX counter is simply unavailable and defaults to zero.
            val current = LongArray(NATIVE_STATS_COUNT) {
                values.getOrElse(it) { 0L }.coerceAtLeast(0L)
            }
            val previous = lastPersistedSessionStats
            val delta = LongArray(NATIVE_STATS_COUNT) { i ->
                if (current[i] >= previous[i]) current[i] - previous[i] else 0L
            }
            // stats() and the periodic persistence thread can fetch snapshots concurrently. A
            // slower, older snapshot must never move the baseline backward and double-count later.
            lastPersistedSessionStats = LongArray(NATIVE_STATS_COUNT) { i ->
                maxOf(previous[i], current[i])
            }

            val rawPayloadDelta = delta[9] + delta[12]
            val encodedPayloadDelta = delta[10] + delta[13]
            val savedPayloadDelta = delta[11] + delta[14]
            val frameCountDelta = delta[4] + delta[5]
            val rawWireDelta = rawPayloadDelta + frameCountDelta * FRAME_HEADER_BYTES
            val actualWireDelta = encodedPayloadDelta + frameCountDelta * FRAME_HEADER_BYTES

            preferences.edit()
                .putLong(
                    KEY_TOTAL_RAW_PAYLOAD,
                    saturatedAdd(preferences.getLong(KEY_TOTAL_RAW_PAYLOAD, 0L), rawPayloadDelta)
                )
                .putLong(
                    KEY_TOTAL_ENCODED_PAYLOAD,
                    saturatedAdd(preferences.getLong(KEY_TOTAL_ENCODED_PAYLOAD, 0L), encodedPayloadDelta)
                )
                .putLong(
                    KEY_TOTAL_SAVED_PAYLOAD,
                    saturatedAdd(preferences.getLong(KEY_TOTAL_SAVED_PAYLOAD, 0L), savedPayloadDelta)
                )
                .putLong(
                    KEY_TOTAL_RAW_WIRE,
                    saturatedAdd(preferences.getLong(KEY_TOTAL_RAW_WIRE, 0L), rawWireDelta)
                )
                .putLong(
                    KEY_TOTAL_ACTUAL_WIRE,
                    saturatedAdd(preferences.getLong(KEY_TOTAL_ACTUAL_WIRE, 0L), actualWireDelta)
                )
                .apply()
        }
    }

    private fun saturatedAdd(a: Long, b: Long): Long =
        if (b > 0L && a > Long.MAX_VALUE - b) Long.MAX_VALUE else a + b

    override fun close() {
        val shouldClose = synchronized(lifecycleLock) {
            closeStarted.compareAndSet(false, true)
        }
        if (!shouldClose) return
        stop()

        val currentRunner = runner
        if (currentRunner != null && currentRunner !== Thread.currentThread()) {
            joinWithoutLosingInterrupt(currentRunner)
        }

        persistenceLoopActive = false
        persistenceThread?.interrupt()
        val currentPersistenceThread = persistenceThread
        if (currentPersistenceThread != null && currentPersistenceThread !== Thread.currentThread()) {
            joinWithoutLosingInterrupt(currentPersistenceThread)
        }

        persistCurrentStats()
        synchronized(nativeHandleLock) {
            val currentHandle = handle
            if (currentHandle != 0L) {
                handle = 0L
                nativeDestroy(currentHandle)
            }
        }
    }

    private fun joinWithoutLosingInterrupt(thread: Thread) {
        var interrupted = false
        while (thread.isAlive) {
            try {
                thread.join()
            } catch (_: InterruptedException) {
                interrupted = true
            }
        }
        if (interrupted) Thread.currentThread().interrupt()
    }

    private external fun nativeCreate(
        compressionLevel: Int,
        maxBatchBytes: Int,
        flushTimeoutMs: Int,
        connectTimeoutMs: Int,
        compressionEnabled: Boolean,
        logTag: String,
        verboseLogs: Boolean
    ): Long

    private external fun nativeRun(
        handle: Long,
        vpnService: VpnService,
        tunFd: Int,
        serverHost: String,
        serverPort: Int
    ): Int

    private external fun nativeStop(handle: Long)

    private external fun nativeDestroy(handle: Long)

    private external fun nativeGetStats(handle: Long): LongArray?
}
