/*
 * zvpn_jni.c -- Android VPN packet batching + Zstandard TCP tunnel (C only)
 *
 * JNI owner class expected:
 *   package ir.andy.zvpn
 *   class NativeProxyEngine { ... }
 *
 * Native methods expected on that class:
 *   private external fun nativeCreate(
 *       compressionLevel: Int, maxBatchBytes: Int,
 *       flushTimeoutMs: Int, connectTimeoutMs: Int,
 *       compressionEnabled: Boolean, logTag: String, verboseLogs: Boolean
 *   ): Long
 *
 *   private external fun nativeRun(
 *       handle: Long, vpnService: android.net.VpnService,
 *       tunFd: Int, serverHost: String, serverPort: Int
 *   ): Int
 *
 *   private external fun nativeStop(handle: Long)
 *   private external fun nativeDestroy(handle: Long)
 *   private external fun nativeGetStats(handle: Long): LongArray
 *
 * Stats array order (16 values; Kotlin accepts legacy 15-value snapshots):
 *   [0] raw TUN bytes read
 *   [1] raw TUN bytes written
 *   [2] transport bytes sent (frame headers included)
 *   [3] transport bytes received (frame headers included)
 *   [4] batches sent
 *   [5] batches received
 *   [6] compressed batches sent
 *   [7] IP packets sent
 *   [8] IP packets written to TUN
 *   [9] outgoing uncompressed payload bytes
 *   [10] outgoing encoded payload bytes actually selected for transmission
 *   [11] outgoing payload bytes saved
 *   [12] incoming decoded/original payload bytes
 *   [13] incoming encoded payload bytes received
 *   [14] incoming payload bytes saved
 *   [15] compressed incoming batches received
 *
 * Stats remain cumulative across nativeRun reconnect attempts on the same Engine.
 * Payload counters include packet-length prefixes but exclude the constant 16-byte frame header.
 *
 * Wire protocol (network byte order):
 *   16-byte header: "ZVPN", version(1), flags(bit 0 = Zstd), reserved(2),
 *                   uncompressed batch size(u32), payload size(u32)
 *   payload: repeated [packet length(u32)][raw IP packet bytes]
 *
 * WARNING: This transport is plain TCP and has no authentication/encryption.
 * Add TLS or another authenticated transport before using over untrusted networks.
 */

#define _POSIX_C_SOURCE 200809L

#include <jni.h>
#include <zstd.h>
#include <android/log.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define ZVPN_HEADER_SIZE       16u
#define ZVPN_VERSION           1u
#define ZVPN_FLAG_ZSTD         0x01u
#define ZVPN_MIN_BATCH_BYTES   (4u * 1024u)
#define ZVPN_MAX_BATCH_BYTES   (4u * 1024u * 1024u)
#define ZVPN_MAX_IP_PACKET     65575u
#define ZVPN_POLL_SLICE_MS     100
#define ZVPN_STATS_COUNT       16

struct Engine {
    pthread_mutex_t mutex;
    pthread_cond_t condition;

    int stop_requested;
    int user_stop_requested;
    int running;
    int tun_fd;       /* duplicated TUN descriptor owned by this engine run */
    int socket_fd;    /* owned by this engine run */

    int compression_level;
    size_t max_batch_bytes;
    int flush_timeout_ms;
    int connect_timeout_ms;
    int compression_enabled;
    int verbose_logs;
    char log_tag[64];

    uint64_t stats[ZVPN_STATS_COUNT];
    int last_error;
};

typedef struct Engine Engine;

#define ZVPN_DEFAULT_LOG_TAG "ZVPN"

static void log_message(Engine *e, int priority, const char *format, ...) {
    if (e != NULL && priority <= ANDROID_LOG_DEBUG && !e->verbose_logs)
        return;

    char message[1024];
    va_list args;
    va_start(args, format);
    (void)vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    const char *tag = (e != NULL && e->log_tag[0] != '\0')
        ? e->log_tag : ZVPN_DEFAULT_LOG_TAG;
    __android_log_print(priority, tag, "%s", message);
}

#define LOGE(e, ...) log_message((e), ANDROID_LOG_ERROR, __VA_ARGS__)
#define LOGW(e, ...) log_message((e), ANDROID_LOG_WARN, __VA_ARGS__)
#define LOGI(e, ...) log_message((e), ANDROID_LOG_INFO, __VA_ARGS__)
#define LOGD(e, ...) log_message((e), ANDROID_LOG_DEBUG, __VA_ARGS__)
#define LOGV(e, ...) log_message((e), ANDROID_LOG_VERBOSE, __VA_ARGS__)

static void log_errno(Engine *e, const char *operation, int error_code) {
    if (error_code == 0)
        error_code = EIO;
    LOGE(e, "[ERR] %s failed | errno=%d (%s)", operation, error_code,
         strerror(error_code));
    /* Logging helpers must not accidentally replace the error returned to callers. */
    errno = error_code;
}

static Engine *engine_from_handle(jlong handle) {
    return (Engine *)(intptr_t)handle;
}

static int is_stopping(Engine *e) {
    int result;
    pthread_mutex_lock(&e->mutex);
    result = e->stop_requested;
    pthread_mutex_unlock(&e->mutex);
    return result;
}

static void stats_add(Engine *e, int index, uint64_t amount) {
    pthread_mutex_lock(&e->mutex);
    e->stats[index] += amount;
    pthread_mutex_unlock(&e->mutex);
}

static void set_error(Engine *e, int error_code) {
    if (error_code == 0)
        error_code = EIO;
    pthread_mutex_lock(&e->mutex);
    if (e->last_error == 0)
        e->last_error = error_code;
    pthread_mutex_unlock(&e->mutex);
}

static void request_stop(Engine *e) {
    pthread_mutex_lock(&e->mutex);
    e->stop_requested = 1;
    if (e->socket_fd >= 0)
        (void)shutdown(e->socket_fd, SHUT_RDWR);
    pthread_cond_broadcast(&e->condition);
    pthread_mutex_unlock(&e->mutex);
}

static int publish_socket(Engine *e, int fd) {
    int accepted = 0;
    pthread_mutex_lock(&e->mutex);
    if (!e->stop_requested) {
        e->socket_fd = fd;
        accepted = 1;
    }
    pthread_mutex_unlock(&e->mutex);
    return accepted;
}

/* Caller must have published fd in e->socket_fd. */
static void discard_socket(Engine *e, int fd) {
    pthread_mutex_lock(&e->mutex);
    if (e->socket_fd == fd)
        e->socket_fd = -1;
    (void)shutdown(fd, SHUT_RDWR);
    (void)close(fd);
    pthread_mutex_unlock(&e->mutex);
}

static uint64_t monotonic_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void put_u32(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

static uint32_t get_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static int get_last_error(Engine *e) {
    int result;
    pthread_mutex_lock(&e->mutex);
    result = e->last_error;
    pthread_mutex_unlock(&e->mutex);
    return result;
}

static const char *ip_protocol_name(unsigned int protocol) {
    switch (protocol) {
        case IPPROTO_ICMP: return "ICMP";
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
#ifdef IPPROTO_ICMPV6
        case IPPROTO_ICMPV6: return "ICMPv6";
#endif
        default: return "other";
    }
}

/* Validate packet boundaries before framing or injecting packets into TUN. */
static int validate_ip_packet(Engine *e, const uint8_t *packet,
                              size_t packet_len, const char *direction) {
    if (packet == NULL || packet_len == 0) {
        LOGE(e, "[PKT] %s rejected | empty IP packet", direction);
        errno = EPROTO;
        return -1;
    }

    unsigned int version = (unsigned int)(packet[0] >> 4);
    if (version == 4) {
        if (packet_len < 20u) {
            LOGE(e, "[PKT] %s rejected | IPv4 header too short (%zu B)",
                 direction, packet_len);
            errno = EPROTO;
            return -1;
        }
        size_t header_len = (size_t)(packet[0] & 0x0Fu) * 4u;
        size_t total_len = ((size_t)packet[2] << 8) | packet[3];
        if (header_len < 20u || header_len > packet_len ||
            total_len != packet_len || total_len < header_len) {
            LOGE(e, "[PKT] %s rejected | malformed IPv4 lengths | packet=%zu header=%zu total=%zu",
                 direction, packet_len, header_len, total_len);
            errno = EPROTO;
            return -1;
        }
        return 0;
    }

    if (version == 6) {
        if (packet_len < 40u) {
            LOGE(e, "[PKT] %s rejected | IPv6 header too short (%zu B)",
                 direction, packet_len);
            errno = EPROTO;
            return -1;
        }
        size_t payload_len = ((size_t)packet[4] << 8) | packet[5];
        /* The configured packet cap excludes IPv6 jumbograms. */
        if (payload_len + 40u != packet_len) {
            LOGE(e, "[PKT] %s rejected | malformed IPv6 lengths | packet=%zu payload=%zu",
                 direction, packet_len, payload_len);
            errno = EPROTO;
            return -1;
        }
        return 0;
    }

    LOGE(e, "[PKT] %s rejected | unsupported IP version=%u length=%zu",
         direction, version, packet_len);
    errno = EPROTO;
    return -1;
}

/* Enabled only with verboseLogs to avoid flooding normal Logcat output. */
static void log_packet_summary(Engine *e, const char *direction,
                               const uint8_t *packet, size_t packet_len) {
    if (e == NULL || !e->verbose_logs || packet == NULL || packet_len == 0)
        return;

    char source[INET6_ADDRSTRLEN] = "?";
    char destination[INET6_ADDRSTRLEN] = "?";
    unsigned int version = (unsigned int)(packet[0] >> 4);
    unsigned int protocol = 0;
    size_t transport_offset = 0;
    int address_family = AF_UNSPEC;

    if (version == 4 && packet_len >= 20u) {
        address_family = AF_INET;
        protocol = packet[9];
        transport_offset = (size_t)(packet[0] & 0x0Fu) * 4u;
        unsigned int fragment_offset =
            (((unsigned int)packet[6] & 0x1Fu) << 8) | packet[7];
        if (fragment_offset != 0)
            transport_offset = packet_len + 1u; /* Non-first fragment has no transport header. */
        (void)inet_ntop(AF_INET, packet + 12, source, sizeof(source));
        (void)inet_ntop(AF_INET, packet + 16, destination, sizeof(destination));
    } else if (version == 6 && packet_len >= 40u) {
        address_family = AF_INET6;
        protocol = packet[6];
        transport_offset = 40u;
        (void)inet_ntop(AF_INET6, packet + 8, source, sizeof(source));
        (void)inet_ntop(AF_INET6, packet + 24, destination, sizeof(destination));
    }

    if (address_family == AF_UNSPEC) {
        LOGV(e, "[PKT] %s | invalid/unparsed IP packet | bytes=%zu", direction, packet_len);
        return;
    }

    if ((protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) &&
        transport_offset <= packet_len && packet_len - transport_offset >= 4u) {
        unsigned int source_port = ((unsigned int)packet[transport_offset] << 8) |
                                   packet[transport_offset + 1];
        unsigned int destination_port = ((unsigned int)packet[transport_offset + 2] << 8) |
                                        packet[transport_offset + 3];
        LOGV(e, "[PKT] %s | IPv%u %s:%u -> %s:%u | %s | %zu B",
             direction, version, source, source_port, destination,
             destination_port, ip_protocol_name(protocol), packet_len);
    } else {
        LOGV(e, "[PKT] %s | IPv%u %s -> %s | %s(%u) | %zu B",
             direction, version, source, destination,
             ip_protocol_name(protocol), protocol, packet_len);
    }
}

/* Send one ZVPN frame using scatter/gather I/O. Header and payload are
 * normally offered to the kernel in the same syscall, avoiding the extra
 * header-only send that can otherwise create an unnecessary small TCP segment.
 * Partial writes are handled correctly; each accepted byte is counted once. */
static int send_frame(Engine *e, int fd,
                      const void *header, size_t header_len,
                      const void *payload, size_t payload_len) {
    struct iovec iov[2];
    iov[0].iov_base = (void *)header;
    iov[0].iov_len = header_len;
    iov[1].iov_base = (void *)payload;
    iov[1].iov_len = payload_len;

    int first = 0;
    while (first < 2) {
        struct msghdr message;
        memset(&message, 0, sizeof(message));
        message.msg_iov = &iov[first];
        message.msg_iovlen = (size_t)(2 - first);

        ssize_t n = sendmsg(fd, &message, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            int saved = n == 0 ? EPIPE : errno;
            log_errno(e, "sendmsg(frame)", saved);
            errno = saved;
            return -1;
        }

        stats_add(e, 2, (uint64_t)n);
        size_t consumed = (size_t)n;
        while (first < 2 && consumed >= iov[first].iov_len) {
            consumed -= iov[first].iov_len;
            first++;
        }
        if (first < 2 && consumed > 0) {
            iov[first].iov_base = (uint8_t *)iov[first].iov_base + consumed;
            iov[first].iov_len -= consumed;
        }
    }
    return 0;
}

static int recv_all(Engine *e, int fd, void *data, size_t len) {
    uint8_t *p = (uint8_t *)data;
    size_t requested = len;
    while (len > 0) {
        ssize_t n = recv(fd, p, len, 0);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            int saved = (n == 0) ? ECONNRESET : errno;
            log_errno(e, "recv", saved);
            errno = saved;
            return -1;
        }
        LOGV(e, "socket recv syscall read=%zd remaining_before=%zu", n, len);
        p += (size_t)n;
        len -= (size_t)n;
        stats_add(e, 3, (uint64_t)n);
    }
    LOGV(e, "recv_all complete requested=%zu", requested);
    return 0;
}

static int append_packet(Engine *e, uint8_t *batch, size_t *used,
                         const uint8_t *packet, size_t packet_len) {
    if (packet_len == 0 || packet_len > ZVPN_MAX_IP_PACKET) {
        LOGE(e, "rejecting invalid packet length=%zu", packet_len);
        errno = EMSGSIZE;
        return -1;
    }
    if (packet_len + 4u > e->max_batch_bytes) {
        LOGE(e, "packet does not fit configured max batch: packet=%zu max_batch=%zu", packet_len, e->max_batch_bytes);
        errno = EMSGSIZE;
        return -1;
    }
    if (*used > e->max_batch_bytes - packet_len - 4u)
        return 1; /* Flush previous batch, then retry packet. */

    size_t previous_used = *used;
    put_u32(batch + *used, (uint32_t)packet_len);
    *used += 4u;
    memcpy(batch + *used, packet, packet_len);
    *used += packet_len;
    LOGV(e, "packet appended bytes=%zu batch_before=%zu batch_after=%zu", packet_len, previous_used, *used);
    return 0;
}

static int count_packets(Engine *e, const uint8_t *batch, size_t batch_len,
                         uint64_t *count_out) {
    size_t offset = 0;
    uint64_t count = 0;
    while (offset < batch_len) {
        if (batch_len - offset < 4u) {
            LOGE(e, "malformed batch: only %zu bytes remain for packet length", batch_len - offset);
            errno = EPROTO;
            return -1;
        }
        uint32_t packet_len = get_u32(batch + offset);
        offset += 4u;
        if (packet_len == 0 || packet_len > batch_len - offset ||
            packet_len > ZVPN_MAX_IP_PACKET) {
            LOGE(e, "[BATCH] malformed packet entry | packet_len=%u remaining=%zu max_packet=%u",
                 packet_len, batch_len - offset, ZVPN_MAX_IP_PACKET);
            errno = EPROTO;
            return -1;
        }
        if (validate_ip_packet(e, batch + offset, packet_len, "batch") < 0)
            return -1;
        offset += packet_len;
        count++;
    }
    *count_out = count;
    return 0;
}

static int send_batch(Engine *e, int sock_fd,
                      const uint8_t *batch, size_t batch_len) {
    if (batch_len == 0 || batch_len > e->max_batch_bytes ||
        batch_len > UINT32_MAX) {
        LOGE(e, "send_batch invalid batch_len=%zu max_batch=%zu", batch_len, e->max_batch_bytes);
        errno = EINVAL;
        return -1;
    }

    uint64_t packet_count = 0;
    if (count_packets(e, batch, batch_len, &packet_count) < 0) {
        log_errno(e, "count_packets before send", errno);
        return -1;
    }

    LOGD(e, "[TX] preparing batch | packets=%llu | raw=%zu B | zstd=%s(level=%d)",
         (unsigned long long)packet_count, batch_len,
         e->compression_enabled ? "enabled" : "disabled", e->compression_level);
    const uint8_t *payload = batch;
    size_t payload_len = batch_len;
    uint8_t flags = 0;
    uint8_t *compressed = NULL;

    if (e->compression_enabled) {
        size_t bound = ZSTD_compressBound(batch_len);
        compressed = (uint8_t *)malloc(bound);
        if (!compressed) {
            /* Compression is an optimization: keep the tunnel alive by sending raw. */
            LOGW(e, "[ZSTD] output allocation failed | requested=%zu B | sending raw batch", bound);
        } else {
            uint64_t compress_started = monotonic_ms();
            size_t compressed_len = ZSTD_compress(compressed, bound, batch,
                                                  batch_len, e->compression_level);
            uint64_t compress_elapsed = monotonic_ms() - compress_started;
            if (ZSTD_isError(compressed_len)) {
                LOGW(e, "[ZSTD] compression failed | reason=%s | sending raw batch",
                     ZSTD_getErrorName(compressed_len));
            } else {
                LOGV(e, "[ZSTD] compression complete | input=%zu B | output=%zu B | elapsed=%llu ms",
                     batch_len, compressed_len,
                     (unsigned long long)compress_elapsed);
                if (compressed_len < batch_len) {
                    payload = compressed;
                    payload_len = compressed_len;
                    flags = ZVPN_FLAG_ZSTD;
                } else {
                    LOGD(e, "[ZSTD] no size benefit | raw=%zu B | compressed=%zu B | sending raw",
                         batch_len, compressed_len);
                }
            }
        }
        /* Allocation/compression failure or expansion safely falls back to raw. */
    } else {
        LOGV(e, "[ZSTD] disabled | sending raw batch | bytes=%zu", batch_len);
    }

    uint8_t header[ZVPN_HEADER_SIZE] = {0};
    memcpy(header, "ZVPN", 4);
    header[4] = ZVPN_VERSION;
    header[5] = flags;
    put_u32(header + 8, (uint32_t)batch_len);
    put_u32(header + 12, (uint32_t)payload_len);

    double ratio = batch_len ? ((double)payload_len * 100.0 / (double)batch_len) : 100.0;
    LOGI(e, "[TX] batch ready | packets=%llu | raw=%zu B | payload=%zu B | frame=%zu B | codec=%s | payload_ratio=%.1f%%",
         (unsigned long long)packet_count, batch_len, payload_len,
         ZVPN_HEADER_SIZE + payload_len,
         (flags & ZVPN_FLAG_ZSTD) ? "Zstd" : "raw", ratio);

    int result = send_frame(e, sock_fd, header, sizeof(header),
                            payload, payload_len);

    free(compressed);
    if (result < 0) {
        log_errno(e, "sending batch frame", errno);
        return -1;
    }

    LOGD(e, "[TX] batch sent | wire_bytes=%zu B", ZVPN_HEADER_SIZE + payload_len);
    /* Publish all per-frame counters atomically for consistent stats snapshots. */
    pthread_mutex_lock(&e->mutex);
    e->stats[4]++;
    e->stats[7] += packet_count;
    if (flags & ZVPN_FLAG_ZSTD)
        e->stats[6]++;
    e->stats[9] += (uint64_t)batch_len;
    e->stats[10] += (uint64_t)payload_len;
    if (batch_len > payload_len)
        e->stats[11] += (uint64_t)(batch_len - payload_len);
    pthread_mutex_unlock(&e->mutex);

    /* Successful outgoing frame: raw versus encoded payload accounting. */
    LOGD(e, "[SAVINGS][TX] raw_payload=%zu B | encoded_payload=%zu B | saved=%zu B | frame_raw=%zu B | frame_actual=%zu B",
         batch_len, payload_len, batch_len > payload_len ? batch_len - payload_len : 0,
         ZVPN_HEADER_SIZE + batch_len, ZVPN_HEADER_SIZE + payload_len);
    return 0;
}

static int receive_batch(Engine *e, int sock_fd,
                         uint8_t **out_batch, size_t *out_len) {
    uint8_t header[ZVPN_HEADER_SIZE];
    *out_batch = NULL;
    *out_len = 0;

    LOGV(e, "waiting for incoming frame header bytes=%u", ZVPN_HEADER_SIZE);
    if (recv_all(e, sock_fd, header, sizeof(header)) < 0) {
        log_errno(e, "receiving frame header", errno);
        return -1;
    }

    if (memcmp(header, "ZVPN", 4) != 0 ||
        header[4] != ZVPN_VERSION ||
        (header[5] & (uint8_t)~ZVPN_FLAG_ZSTD) != 0 ||
        header[6] != 0 || header[7] != 0) {
        LOGE(e, "invalid incoming frame header: magic=%.4s version=%u flags=0x%02x reserved=%02x%02x", header, header[4], header[5], header[6], header[7]);
        errno = EPROTO;
        return -1;
    }

    uint32_t original_len = get_u32(header + 8);
    uint32_t payload_len = get_u32(header + 12);
    size_t max_payload = ZSTD_compressBound(e->max_batch_bytes);

    LOGD(e, "[RX] frame header | flags=0x%02x | decoded=%u B | payload=%u B | max_batch=%zu B",
         header[5], original_len, payload_len, e->max_batch_bytes);
    if (original_len == 0 || original_len > e->max_batch_bytes ||
        payload_len == 0 || payload_len > max_payload) {
        LOGE(e, "incoming frame length rejected original=%u payload=%u", original_len, payload_len);
        errno = EMSGSIZE;
        return -1;
    }

    if (!(header[5] & ZVPN_FLAG_ZSTD) && payload_len != original_len) {
        LOGE(e, "raw frame size mismatch original=%u payload=%u", original_len, payload_len);
        errno = EPROTO;
        return -1;
    }

    uint8_t *payload = (uint8_t *)malloc(payload_len);
    if (!payload) {
        LOGE(e, "malloc failed for incoming payload=%u", payload_len);
        return -1;
    }
    if (recv_all(e, sock_fd, payload, payload_len) < 0) {
        log_errno(e, "receiving frame payload", errno);
        free(payload);
        return -1;
    }

    uint8_t *decoded = payload;
    size_t decoded_len = payload_len;

    if (header[5] & ZVPN_FLAG_ZSTD) {
        decoded = (uint8_t *)malloc(original_len);
        if (!decoded) {
            LOGE(e, "malloc failed for decoded batch=%u", original_len);
            free(payload);
            return -1;
        }
        uint64_t decompress_started = monotonic_ms();
        decoded_len = ZSTD_decompress(decoded, original_len,
                                      payload, payload_len);
        uint64_t decompress_elapsed = monotonic_ms() - decompress_started;
        free(payload);
        if (ZSTD_isError(decoded_len) || decoded_len != original_len) {
            LOGE(e, "Zstd decompression failed decoded=%zu expected=%u error=%s", decoded_len, original_len, ZSTD_isError(decoded_len) ? ZSTD_getErrorName(decoded_len) : "size mismatch");
            free(decoded);
            errno = EPROTO;
            return -1;
        }
        LOGD(e, "Zstd decompression complete input=%u output=%zu elapsed_ms=%llu", payload_len, decoded_len, (unsigned long long)decompress_elapsed);
    } else {
        LOGV(e, "received uncompressed batch bytes=%zu", decoded_len);
    }

    uint64_t count = 0;
    if (count_packets(e, decoded, decoded_len, &count) < 0) {
        log_errno(e, "validating decoded packet batch", errno);
        free(decoded);
        return -1;
    }

    LOGI(e, "[RX] batch decoded | packets=%llu | raw=%zu B | codec=%s",
         (unsigned long long)count, decoded_len,
         (header[5] & ZVPN_FLAG_ZSTD) ? "Zstd" : "raw");
    /* Publish incoming frame counters atomically for consistent stats snapshots. */
    pthread_mutex_lock(&e->mutex);
    e->stats[5]++;
    e->stats[12] += (uint64_t)original_len;
    e->stats[13] += (uint64_t)payload_len;
    if (original_len > payload_len)
        e->stats[14] += (uint64_t)(original_len - payload_len);
    if (header[5] & ZVPN_FLAG_ZSTD)
        e->stats[15]++;
    pthread_mutex_unlock(&e->mutex);

    /* Count both directions so client totals include server->client compression too. */
    LOGD(e, "[SAVINGS][RX] raw_payload=%u B | encoded_payload=%u B | saved=%u B | frame_raw=%u B | frame_actual=%u B",
         original_len, payload_len,
         original_len > payload_len ? original_len - payload_len : 0,
         (unsigned int)(ZVPN_HEADER_SIZE + original_len),
         (unsigned int)(ZVPN_HEADER_SIZE + payload_len));
    *out_batch = decoded;
    *out_len = decoded_len;
    return 0;
}

static int write_batch_to_tun(Engine *e, int tun_fd,
                              const uint8_t *batch, size_t batch_len) {
    size_t offset = 0;
    while (offset < batch_len) {
        if (batch_len - offset < 4u) {
            LOGE(e, "received malformed batch: %zu trailing bytes cannot contain packet length", batch_len - offset);
            errno = EPROTO;
            return -1;
        }
        uint32_t packet_len = get_u32(batch + offset);
        offset += 4u;
        if (packet_len == 0 || packet_len > batch_len - offset ||
            packet_len > ZVPN_MAX_IP_PACKET) {
            LOGE(e, "received invalid packet length=%u remaining=%zu max_packet=%u", packet_len, batch_len - offset, ZVPN_MAX_IP_PACKET);
            errno = EPROTO;
            return -1;
        }

        log_packet_summary(e, "NET->TUN", batch + offset, packet_len);
        LOGV(e, "[TUN] injecting packet | bytes=%u", packet_len);
        ssize_t n;
        for (;;) {
            n = write(tun_fd, batch + offset, packet_len);
            if (n < 0 && errno == EINTR)
                continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                if (is_stopping(e))
                    return 0;

                struct pollfd writable = { .fd = tun_fd, .events = POLLOUT };
                int ready = poll(&writable, 1, ZVPN_POLL_SLICE_MS);
                if (ready < 0 && errno == EINTR)
                    continue;
                if (ready < 0) {
                    int saved_error = errno;
                    log_errno(e, "poll waiting for writable TUN", saved_error);
                    return -1;
                }
                if (ready == 0)
                    continue;
                if (writable.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                    errno = EIO;
                    log_errno(e, "TUN became unwritable", errno);
                    return -1;
                }
                continue;
            }
            break;
        }

        if (n != (ssize_t)packet_len) {
            if (n >= 0)
                errno = EIO; /* A TUN write is one packet; never write a remainder as a second packet. */
            log_errno(e, "writing packet to TUN", errno);
            return -1;
        }

        LOGV(e, "[TUN] packet injected successfully | bytes=%u", packet_len);
        stats_add(e, 1, packet_len);
        stats_add(e, 8, 1);
        offset += packet_len;
    }
    return 0;
}

static int protect_socket(JNIEnv *env, jobject vpn_service, Engine *e, int sock_fd) {
    LOGD(e, "protecting proxy socket fd=%d from VPN routing", sock_fd);
    if (vpn_service == NULL) {
        LOGE(e, "VpnService object is null; cannot call protect() on socket fd=%d", sock_fd);
        errno = EINVAL;
        return -1;
    }

    jclass cls = (*env)->GetObjectClass(env, vpn_service);
    if (cls == NULL || (*env)->ExceptionCheck(env)) {
        LOGE(e, "JNI GetObjectClass failed while resolving VpnService.protect()");
        (*env)->ExceptionClear(env);
        errno = EFAULT;
        return -1;
    }

    jmethodID method = (*env)->GetMethodID(env, cls, "protect", "(I)Z");
    (*env)->DeleteLocalRef(env, cls);
    if (method == NULL || (*env)->ExceptionCheck(env)) {
        LOGE(e, "JNI could not resolve VpnService.protect(int)");
        (*env)->ExceptionClear(env);
        errno = ENOSYS;
        return -1;
    }

    jboolean protected_socket = (*env)->CallBooleanMethod(
        env, vpn_service, method, (jint)sock_fd);
    if ((*env)->ExceptionCheck(env)) {
        LOGE(e, "exception thrown by VpnService.protect(%d)", sock_fd);
        (*env)->ExceptionClear(env);
        errno = EFAULT;
        return -1;
    }
    if (protected_socket != JNI_TRUE) {
        LOGE(e, "VpnService.protect(%d) returned false", sock_fd);
        errno = EACCES;
        return -1;
    }
    LOGI(e, "proxy socket fd=%d successfully protected from VPN routing", sock_fd);
    return 0;
}

static int connect_one(JNIEnv *env, jobject vpn_service, Engine *e,
                       const struct addrinfo *ai) {
    int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) {
        log_errno(e, "creating proxy socket", errno);
        return -1;
    }
    LOGD(e, "[NET] socket created | fd=%d | family=%s | type=%d | protocol=%d", fd,
         ai->ai_family == AF_INET6 ? "IPv6" : (ai->ai_family == AF_INET ? "IPv4" : "other"),
         ai->ai_socktype, ai->ai_protocol);
    (void)fcntl(fd, F_SETFD, FD_CLOEXEC);

    if (ai->ai_socktype == SOCK_STREAM && ai->ai_protocol == IPPROTO_TCP) {
        int no_delay = 1;
        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                       &no_delay, sizeof(no_delay)) < 0) {
            LOGW(e, "[NET] could not enable TCP_NODELAY | errno=%d (%s)",
                 errno, strerror(errno));
        } else {
            LOGD(e, "[NET] TCP_NODELAY enabled | low-latency packet transport");
        }

        int keepalive = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
                       &keepalive, sizeof(keepalive)) < 0) {
            LOGW(e, "[NET] SO_KEEPALIVE unavailable | errno=%d (%s)",
                 errno, strerror(errno));
        } else {
            LOGD(e, "[NET] TCP keepalive enabled | best-effort dead-peer detection");
#ifdef TCP_KEEPIDLE
            int keepidle = 60;
            if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,
                           &keepidle, sizeof(keepidle)) < 0)
                LOGV(e, "[NET] TCP_KEEPIDLE not adjustable | errno=%d (%s)", errno, strerror(errno));
#endif
#ifdef TCP_KEEPINTVL
            int keepintvl = 15;
            if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL,
                           &keepintvl, sizeof(keepintvl)) < 0)
                LOGV(e, "[NET] TCP_KEEPINTVL not adjustable | errno=%d (%s)", errno, strerror(errno));
#endif
#ifdef TCP_KEEPCNT
            int keepcnt = 4;
            if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,
                           &keepcnt, sizeof(keepcnt)) < 0)
                LOGV(e, "[NET] TCP_KEEPCNT not adjustable | errno=%d (%s)", errno, strerror(errno));
#endif
        }
    }

    if (!publish_socket(e, fd)) {
        LOGW(e, "stopping requested before socket could be published; closing fd=%d", fd);
        close(fd);
        errno = ECANCELED;
        return -1;
    }

    if (protect_socket(env, vpn_service, e, fd) < 0) {
        int saved = errno;
        discard_socket(e, fd);
        errno = saved;
        return -1;
    }

    if (is_stopping(e)) {
        LOGI(e, "stop requested before connect; cancelling socket fd=%d", fd);
        discard_socket(e, fd);
        errno = ECANCELED;
        return -1;
    }

    int old_flags = fcntl(fd, F_GETFL, 0);
    if (old_flags < 0 || fcntl(fd, F_SETFL, old_flags | O_NONBLOCK) < 0) {
        int saved = errno;
        log_errno(e, "setting proxy socket non-blocking", saved);
        discard_socket(e, fd);
        errno = saved;
        return -1;
    }

    LOGI(e, "connecting to proxy address family=%s timeout_ms=%d",
         ai->ai_family == AF_INET6 ? "IPv6" : (ai->ai_family == AF_INET ? "IPv4" : "other"),
         e->connect_timeout_ms);
    int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
    if (rc < 0 && errno != EINPROGRESS) {
        int saved = errno;
        log_errno(e, "connect() to proxy address", saved);
        discard_socket(e, fd);
        errno = saved;
        return -1;
    }

    if (rc < 0) {
        uint64_t deadline = monotonic_ms() + (uint64_t)e->connect_timeout_ms;
        for (;;) {
            if (is_stopping(e)) {
                discard_socket(e, fd);
                errno = ECANCELED;
                return -1;
            }

            uint64_t now = monotonic_ms();
            if (now >= deadline) {
                LOGE(e, "proxy connect timed out after %d ms", e->connect_timeout_ms);
                discard_socket(e, fd);
                errno = ETIMEDOUT;
                return -1;
            }

            int remaining = (int)(deadline - now);
            if (remaining > ZVPN_POLL_SLICE_MS)
                remaining = ZVPN_POLL_SLICE_MS;

            struct pollfd pfd = { .fd = fd, .events = POLLOUT };
            int pr = poll(&pfd, 1, remaining);
            if (pr < 0 && errno == EINTR)
                continue;
            if (pr < 0) {
                int saved = errno;
                log_errno(e, "poll while connecting", saved);
                discard_socket(e, fd);
                errno = saved;
                return -1;
            }
            if (pr == 0)
                continue;

            int socket_error = 0;
            socklen_t error_len = sizeof(socket_error);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR,
                           &socket_error, &error_len) < 0) {
                int saved = errno;
                log_errno(e, "getsockopt(SO_ERROR) after connect", saved);
                discard_socket(e, fd);
                errno = saved;
                return -1;
            }
            if (socket_error != 0) {
                log_errno(e, "asynchronous connect", socket_error);
                discard_socket(e, fd);
                errno = socket_error;
                return -1;
            }
            break;
        }
    }

    if (fcntl(fd, F_SETFL, old_flags) < 0) {
        int saved = errno;
        log_errno(e, "restoring proxy socket flags", saved);
        discard_socket(e, fd);
        errno = saved;
        return -1;
    }
    LOGI(e, "[NET] TCP connection established | socket_fd=%d | TCP_NODELAY=on (when supported)", fd);
    return fd;
}

static int connect_proxy(JNIEnv *env, jobject vpn_service, Engine *e,
                         const char *host, int port) {
    char port_text[16];
    (void)snprintf(port_text, sizeof(port_text), "%d", port);
    LOGI(e, "[NET] resolving tunnel endpoint | host=%s | port=%d", host, port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo *addresses = NULL;
    uint64_t resolution_started = monotonic_ms();
    int gai = getaddrinfo(host, port_text, &hints, &addresses);
    uint64_t resolution_elapsed = monotonic_ms() - resolution_started;
    if (gai != 0) {
        LOGE(e, "getaddrinfo(%s:%s) failed after %llu ms: %s",
             host, port_text, (unsigned long long)resolution_elapsed, gai_strerror(gai));
        errno = EHOSTUNREACH;
        return -1;
    }

    int address_count = 0;
    for (struct addrinfo *tmp = addresses; tmp != NULL; tmp = tmp->ai_next) address_count++;
    LOGD(e, "[NET] endpoint resolution complete | candidates=%d | duration_ms=%llu",
         address_count, (unsigned long long)resolution_elapsed);
    if (resolution_elapsed > (uint64_t)e->connect_timeout_ms) {
        LOGW(e, "[NET] DNS resolution exceeded connect timeout | dns_ms=%llu | connect_timeout_ms=%d",
             (unsigned long long)resolution_elapsed, e->connect_timeout_ms);
    }

    int connected_fd = -1;
    int last_error = ECONNREFUSED;
    for (struct addrinfo *ai = addresses; ai != NULL; ai = ai->ai_next) {
        if (is_stopping(e)) {
            last_error = ECANCELED;
            break;
        }
        LOGD(e, "[NET] trying endpoint candidate | family=%s",
             ai->ai_family == AF_INET6 ? "IPv6" : (ai->ai_family == AF_INET ? "IPv4" : "other"));
        connected_fd = connect_one(env, vpn_service, e, ai);
        if (connected_fd >= 0)
            break;
        last_error = errno;
        LOGW(e, "address candidate failed: errno=%d (%s)", last_error, strerror(last_error));
        if (last_error == ECANCELED || last_error == EACCES ||
            last_error == ENOSYS || last_error == EFAULT)
            break;
    }

    freeaddrinfo(addresses);
    if (connected_fd < 0) {
        errno = last_error;
        LOGE(e, "unable to connect to proxy host=%s port=%d; final errno=%d (%s)", host, port, last_error, strerror(last_error));
    } else {
        LOGI(e, "[NET] tunnel connected | host=%s | port=%d | fd=%d", host, port, connected_fd);
    }
    return connected_fd;
}

static void log_stats_summary(Engine *e, const char *phase) {
    uint64_t stats[ZVPN_STATS_COUNT];
    int last_error;
    pthread_mutex_lock(&e->mutex);
    memcpy(stats, e->stats, sizeof(stats));
    last_error = e->last_error;
    pthread_mutex_unlock(&e->mutex);

    LOGI(e, "[STATS] %s | TUN read=%llu B (%llu packets sent) | TUN written=%llu B (%llu packets injected)",
         phase, (unsigned long long)stats[0], (unsigned long long)stats[7],
         (unsigned long long)stats[1], (unsigned long long)stats[8]);
    LOGI(e, "[STATS] %s | wire TX=%llu B | wire RX=%llu B | batches TX=%llu | batches RX=%llu | Zstd TX=%llu | Zstd RX=%llu | last_error=%d",
         phase, (unsigned long long)stats[2], (unsigned long long)stats[3],
         (unsigned long long)stats[4], (unsigned long long)stats[5],
         (unsigned long long)stats[6], (unsigned long long)stats[15], last_error);
    LOGI(e, "[SAVINGS] %s | raw_payload=%llu B | encoded_payload=%llu B | saved=%llu B",
         phase,
         (unsigned long long)(stats[9] + stats[12]),
         (unsigned long long)(stats[10] + stats[13]),
         (unsigned long long)(stats[11] + stats[14]));
}

struct WorkerArgs {
    Engine *engine;
    int tun_fd;
    int socket_fd;
};

static void *tun_to_socket_worker(void *opaque) {
    struct WorkerArgs *args = (struct WorkerArgs *)opaque;
    Engine *e = args->engine;
    int tun_fd = args->tun_fd;
    int sock_fd = args->socket_fd;
    free(args);

    uint8_t *batch = (uint8_t *)malloc(e->max_batch_bytes);
    uint8_t packet[ZVPN_MAX_IP_PACKET];
    if (!batch) {
        LOGE(e, "unable to allocate outgoing batch buffer bytes=%zu", e->max_batch_bytes);
        set_error(e, ENOMEM);
        request_stop(e);
        return NULL;
    }

    size_t used = 0;
    uint64_t batch_started = 0;
    LOGI(e, "[TX] worker started | tun_fd=%d | socket_fd=%d | max_batch=%zu B | flush_timeout=%d ms",
         tun_fd, sock_fd, e->max_batch_bytes, e->flush_timeout_ms);

    while (!is_stopping(e)) {
        /*
         * A continuously readable TUN can make poll() return immediately on
         * every iteration. Flush before polling so that traffic cannot starve
         * the batch deadline until max_batch_bytes is reached.
         */
        if (used > 0) {
            uint64_t now = monotonic_ms();
            int deadline_reached = e->flush_timeout_ms == 0 ||
                now >= batch_started + (uint64_t)e->flush_timeout_ms;
            if (deadline_reached) {
                LOGD(e, "[BATCH] flush | reason=timeout | bytes=%zu | age=%llu ms",
                     used, (unsigned long long)(now - batch_started));
                if (send_batch(e, sock_fd, batch, used) < 0) {
                    int saved_error = errno ? errno : EIO;
                    set_error(e, saved_error);
                    /* Never retry a partially written frame on the same TCP stream. */
                    request_stop(e);
                    break;
                }
                used = 0;
                batch_started = 0;
                continue;
            }
        }

        int timeout = ZVPN_POLL_SLICE_MS;
        if (used > 0 && e->flush_timeout_ms > 0) {
            uint64_t now = monotonic_ms();
            uint64_t deadline = batch_started + (uint64_t)e->flush_timeout_ms;
            uint64_t remaining = deadline > now ? deadline - now : 0;
            timeout = remaining > ZVPN_POLL_SLICE_MS
                ? ZVPN_POLL_SLICE_MS : (int)remaining;
        }

        struct pollfd pfd = { .fd = tun_fd, .events = POLLIN };
        int ready = poll(&pfd, 1, timeout);
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready < 0) {
            log_errno(e, "poll on TUN fd", errno);
            set_error(e, errno);
            break;
        }

        if (ready == 0) {
            /* Deadline is rechecked at the top of the loop. */
            continue;
        }

        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            LOGW(e, "TUN poll returned event flags=0x%x", pfd.revents);
            if (is_stopping(e))
                break;
            set_error(e, EIO);
            break;
        }
        if (!(pfd.revents & POLLIN))
            continue;

        ssize_t n = read(tun_fd, packet, sizeof(packet));
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
            continue;
        if (n < 0) {
            log_errno(e, "reading packet from TUN", errno);
            set_error(e, errno);
            break;
        }
        if (n == 0)
            continue;

        stats_add(e, 0, (uint64_t)n);
        if ((size_t)n > ZVPN_MAX_IP_PACKET ||
            validate_ip_packet(e, packet, (size_t)n, "TUN->NET") < 0) {
            if ((size_t)n > ZVPN_MAX_IP_PACKET)
                errno = EMSGSIZE;
            set_error(e, errno ? errno : EPROTO);
            break;
        }
        log_packet_summary(e, "TUN->NET", packet, (size_t)n);
        LOGV(e, "[TUN] packet read | bytes=%zd", n);
        size_t needed = 4u + (size_t)n;

        if (needed > e->max_batch_bytes) {
            LOGE(e, "[BATCH] packet cannot fit | packet=%zd B | framed=%zu B | max_batch=%zu B", n, needed, e->max_batch_bytes);
            set_error(e, EMSGSIZE);
            break;
        }

        if (used > 0 && needed > e->max_batch_bytes - used) {
            LOGD(e, "[BATCH] flush | reason=capacity-before-append | bytes=%zu | next_packet=%zd B", used, n);
            if (send_batch(e, sock_fd, batch, used) < 0) {
                int saved_error = errno ? errno : EIO;
                set_error(e, saved_error);
                /* A failed frame may already be partially on the wire; stop instead of retrying it. */
                request_stop(e);
                break;
            }
            used = 0;
            batch_started = 0;
        }

        if (used == 0)
            batch_started = monotonic_ms();

        int append_result = append_packet(e, batch, &used,
                                          packet, (size_t)n);
        if (append_result == 1 && used > 0) {
            LOGD(e, "[BATCH] flush | reason=capacity-before-append | bytes=%zu | next_packet=%zd B",
                 used, n);
            if (send_batch(e, sock_fd, batch, used) < 0) {
                int saved_error = errno ? errno : EIO;
                set_error(e, saved_error);
                /* A failed frame may already be partially on the wire; stop instead of retrying it. */
                request_stop(e);
                break;
            }
            used = 0;
            batch_started = monotonic_ms();
            append_result = append_packet(e, batch, &used,
                                          packet, (size_t)n);
        }
        if (append_result < 0) {
            set_error(e, errno ? errno : EMSGSIZE);
            break;
        }
        if (append_result == 1) {
            LOGE(e, "[BATCH] append retry still does not fit | packet=%zd B | max_batch=%zu B",
                 n, e->max_batch_bytes);
            set_error(e, EMSGSIZE);
            break;
        }

        if (used >= e->max_batch_bytes || e->flush_timeout_ms == 0) {
            LOGD(e, "[BATCH] flush | reason=%s | bytes=%zu",
                 e->flush_timeout_ms == 0 ? "timeout-disabled" : "capacity",
                 used);
            if (send_batch(e, sock_fd, batch, used) < 0) {
                int saved_error = errno ? errno : EIO;
                set_error(e, saved_error);
                /* A failed frame may already be partially on the wire; stop instead of retrying it. */
                request_stop(e);
                break;
            }
            used = 0;
            batch_started = 0;
        }
    }

    /* On stop/error, best-effort flush the remaining batch only if socket is live. */
    if (used > 0 && !is_stopping(e)) {
        if (send_batch(e, sock_fd, batch, used) < 0)
            set_error(e, errno);
    }

    free(batch);
    LOGI(e, "[TX] worker stopped | stop_requested=%d | last_error=%d",
         is_stopping(e), get_last_error(e));
    if (!is_stopping(e))
        request_stop(e);
    return NULL;
}

static int socket_to_tun(Engine *e, int sock_fd, int tun_fd) {
    LOGI(e, "[RX] worker started | socket_fd=%d | tun_fd=%d", sock_fd, tun_fd);
    for (;;) {
        if (is_stopping(e))
            return 0;

        uint8_t *batch = NULL;
        size_t batch_len = 0;
        if (receive_batch(e, sock_fd, &batch, &batch_len) < 0) {
            if (is_stopping(e)) {
                LOGI(e, "proxy->TUN worker stopping because shutdown was requested");
                return 0;
            }
            log_errno(e, "receiving batch from proxy", errno);
            return -1;
        }

        int rc = write_batch_to_tun(e, tun_fd, batch, batch_len);
        free(batch);
        if (rc < 0) {
            log_errno(e, "writing received batch to TUN", errno);
            return -1;
        }
    }
}

JNIEXPORT jlong JNICALL
Java_ir_andy_zvpn_NativeProxyEngine_nativeCreate(
    JNIEnv *env, jobject thiz,
    jint compression_level, jint max_batch_bytes,
    jint flush_timeout_ms, jint connect_timeout_ms,
    jboolean compression_enabled, jstring log_tag, jboolean verbose_logs) {
    (void)thiz;

    char requested_tag[64] = ZVPN_DEFAULT_LOG_TAG;
    if (log_tag != NULL) {
        const char *tag_chars = (*env)->GetStringUTFChars(env, log_tag, NULL);
        if (tag_chars == NULL) {
            __android_log_print(ANDROID_LOG_ERROR, ZVPN_DEFAULT_LOG_TAG, "nativeCreate could not read logTag string");
            return 0;
        }
        (void)snprintf(requested_tag, sizeof(requested_tag), "%s", tag_chars);
        (*env)->ReleaseStringUTFChars(env, log_tag, tag_chars);
    }

    if (compression_level < 1 || compression_level > ZSTD_maxCLevel() ||
        max_batch_bytes < (jint)ZVPN_MIN_BATCH_BYTES ||
        max_batch_bytes > (jint)ZVPN_MAX_BATCH_BYTES ||
        flush_timeout_ms < 0 || flush_timeout_ms > 60000 ||
        connect_timeout_ms < 1 || connect_timeout_ms > 120000) {
        __android_log_print(ANDROID_LOG_ERROR, requested_tag,
            "nativeCreate invalid config level=%d maxBatch=%d flushTimeoutMs=%d connectTimeoutMs=%d",
            compression_level, max_batch_bytes, flush_timeout_ms, connect_timeout_ms);
        errno = EINVAL;
        return 0;
    }

    Engine *e = (Engine *)calloc(1, sizeof(*e));
    if (!e) {
        __android_log_print(ANDROID_LOG_ERROR, requested_tag, "nativeCreate allocation failed");
        return 0;
    }

    int mutex_rc = pthread_mutex_init(&e->mutex, NULL);
    if (mutex_rc != 0) {
        __android_log_print(ANDROID_LOG_ERROR, requested_tag, "pthread_mutex_init failed rc=%d (%s)", mutex_rc, strerror(mutex_rc));
        free(e);
        return 0;
    }
    int cond_rc = pthread_cond_init(&e->condition, NULL);
    if (cond_rc != 0) {
        __android_log_print(ANDROID_LOG_ERROR, requested_tag, "pthread_cond_init failed rc=%d (%s)", cond_rc, strerror(cond_rc));
        pthread_mutex_destroy(&e->mutex);
        free(e);
        return 0;
    }

    e->tun_fd = -1;
    e->socket_fd = -1;
    e->compression_level = compression_level;
    e->max_batch_bytes = (size_t)max_batch_bytes;
    e->flush_timeout_ms = flush_timeout_ms;
    e->connect_timeout_ms = connect_timeout_ms;
    e->compression_enabled = compression_enabled == JNI_TRUE;
    e->verbose_logs = verbose_logs == JNI_TRUE;
    (void)snprintf(e->log_tag, sizeof(e->log_tag), "%s", requested_tag[0] ? requested_tag : ZVPN_DEFAULT_LOG_TAG);
    e->stop_requested = 0;
    e->user_stop_requested = 0;
    e->running = 0;
    LOGI(e, "[INIT] engine created | zstd=%s(level=%d) | max_batch=%zu B | flush_after=%d ms | connect_timeout=%d ms | verbose=%s",
         e->compression_enabled ? "enabled" : "disabled", e->compression_level,
         e->max_batch_bytes, e->flush_timeout_ms, e->connect_timeout_ms,
         e->verbose_logs ? "on" : "off");
    return (jlong)(intptr_t)e;
}

JNIEXPORT jint JNICALL
Java_ir_andy_zvpn_NativeProxyEngine_nativeRun(
    JNIEnv *env, jobject thiz, jlong handle,
    jobject vpn_service, jint tun_fd,
    jstring server_host, jint server_port) {
    (void)thiz;
    Engine *e = engine_from_handle(handle);
    if (!e) {
        __android_log_print(ANDROID_LOG_ERROR, ZVPN_DEFAULT_LOG_TAG, "nativeRun received null engine handle");
        return EINVAL;
    }
    if (tun_fd < 0 || server_host == NULL || server_port < 1 || server_port > 65535) {
        LOGE(e, "nativeRun invalid arguments tun_fd=%d host_is_null=%d port=%d", tun_fd, server_host == NULL, server_port);
        return EINVAL;
    }
    LOGI(e, "[LIFECYCLE] nativeRun starting | tun_fd=%d | server_port=%d", tun_fd, server_port);

    pthread_mutex_lock(&e->mutex);
    if (e->running || e->user_stop_requested) {
        int running_now = e->running;
        int user_stopped_now = e->user_stop_requested;
        LOGE(e, "nativeRun rejected: running=%d user_stop_requested=%d",
             running_now, user_stopped_now);
        pthread_mutex_unlock(&e->mutex);
        return EALREADY;
    }
    /* Permit another nativeRun on this same Engine after a transport drop.
       Stats stay cumulative; an explicit nativeStop permanently blocks retries. */
    e->stop_requested = 0;
    e->last_error = 0;
    e->running = 1;
    pthread_mutex_unlock(&e->mutex);

    int result_code = 0;
    int local_tun = dup(tun_fd);
    if (local_tun < 0) {
        result_code = errno;
        log_errno(e, "duplicating TUN descriptor", result_code);
        goto finish_without_fds;
    }
    (void)fcntl(local_tun, F_SETFD, FD_CLOEXEC);
    LOGI(e, "duplicated TUN fd original=%d native_fd=%d", tun_fd, local_tun);

    pthread_mutex_lock(&e->mutex);
    e->tun_fd = local_tun;
    pthread_mutex_unlock(&e->mutex);

    const char *host = (*env)->GetStringUTFChars(env, server_host, NULL);
    if (host == NULL) {
        result_code = ENOMEM;
        LOGE(e, "GetStringUTFChars failed for server host");
        goto finish;
    }
    LOGI(e, "[NET] tunnel target | host=%s | port=%d", host, server_port);

    int sock_fd = connect_proxy(env, vpn_service, e, host, server_port);
    (*env)->ReleaseStringUTFChars(env, server_host, host);
    if (sock_fd < 0) {
        result_code = errno ? errno : ECONNREFUSED;
        log_errno(e, "connecting to proxy", result_code);
        goto finish;
    }
    LOGI(e, "[LIFECYCLE] transport ready | socket_fd=%d | starting packet workers", sock_fd);

    struct WorkerArgs *args = (struct WorkerArgs *)malloc(sizeof(*args));
    if (!args) {
        LOGE(e, "failed allocating worker arguments");
        result_code = ENOMEM;
        goto finish;
    }
    args->engine = e;
    args->tun_fd = local_tun;
    args->socket_fd = sock_fd;

    pthread_t writer_thread;
    int thread_rc = pthread_create(&writer_thread, NULL,
                                   tun_to_socket_worker, args);
    if (thread_rc != 0) {
        LOGE(e, "pthread_create for TUN->proxy worker failed rc=%d (%s)", thread_rc, strerror(thread_rc));
        free(args);
        result_code = thread_rc;
        goto finish;
    }
    LOGI(e, "[LIFECYCLE] TX worker started | RX loop running on nativeRun thread");

    if (socket_to_tun(e, sock_fd, local_tun) < 0) {
        result_code = errno ? errno : EIO;
        set_error(e, result_code);
    }

    if (result_code != 0)
        log_errno(e, "proxy->TUN receive loop", result_code);
    request_stop(e);
    LOGD(e, "waiting for TUN->proxy worker to exit");
    (void)pthread_join(writer_thread, NULL);
    LOGD(e, "TUN->proxy worker joined");

finish:
    log_stats_summary(e, "session end");
    pthread_mutex_lock(&e->mutex);
    if (e->socket_fd >= 0) {
        int fd = e->socket_fd;
        e->socket_fd = -1;
        (void)shutdown(fd, SHUT_RDWR);
        (void)close(fd);
    }
    if (e->tun_fd >= 0) {
        int fd = e->tun_fd;
        e->tun_fd = -1;
        (void)close(fd);
    }
    if (result_code == 0 && e->last_error != 0 && !e->user_stop_requested)
        result_code = e->last_error;
    int user_stopped = e->user_stop_requested;
    /* Log before publishing running=0, so nativeDestroy cannot free e first. */
    LOGI(e, "[LIFECYCLE] nativeRun finished | result=%d (%s) | user_stopped=%d",
         result_code, result_code ? strerror(result_code) : "success", user_stopped);
    e->running = 0;
    pthread_cond_broadcast(&e->condition);
    pthread_mutex_unlock(&e->mutex);

    /* Do not access e after running becomes false: nativeDestroy may now free it. */
    if (user_stopped)
        return 0;
    return (jint)result_code;

finish_without_fds:
    pthread_mutex_lock(&e->mutex);
    LOGI(e, "nativeRun finished before sockets initialized result=%d (%s)", result_code, strerror(result_code));
    e->running = 0;
    pthread_cond_broadcast(&e->condition);
    pthread_mutex_unlock(&e->mutex);
    return (jint)result_code;
}

JNIEXPORT void JNICALL
Java_ir_andy_zvpn_NativeProxyEngine_nativeStop(
    JNIEnv *env, jobject thiz, jlong handle) {
    (void)env;
    (void)thiz;
    Engine *e = engine_from_handle(handle);
    if (e) {
        LOGI(e, "[LIFECYCLE] nativeStop requested");
        pthread_mutex_lock(&e->mutex);
        e->user_stop_requested = 1;
        pthread_mutex_unlock(&e->mutex);
        request_stop(e);
    }
}

JNIEXPORT void JNICALL
Java_ir_andy_zvpn_NativeProxyEngine_nativeDestroy(
    JNIEnv *env, jobject thiz, jlong handle) {
    (void)env;
    (void)thiz;
    Engine *e = engine_from_handle(handle);
    if (!e)
        return;

    LOGI(e, "[LIFECYCLE] nativeDestroy requested | waiting for engine stop");
    pthread_mutex_lock(&e->mutex);
    e->user_stop_requested = 1;
    pthread_mutex_unlock(&e->mutex);
    request_stop(e);
    pthread_mutex_lock(&e->mutex);
    while (e->running)
        pthread_cond_wait(&e->condition, &e->mutex);
    pthread_mutex_unlock(&e->mutex);

    LOGI(e, "[LIFECYCLE] destroying engine instance");
    pthread_cond_destroy(&e->condition);
    pthread_mutex_destroy(&e->mutex);
    free(e);
}

JNIEXPORT jlongArray JNICALL
Java_ir_andy_zvpn_NativeProxyEngine_nativeGetStats(
    JNIEnv *env, jobject thiz, jlong handle) {
    (void)thiz;
    Engine *e = engine_from_handle(handle);
    if (!e)
        return NULL;

    jlong values[ZVPN_STATS_COUNT];
    pthread_mutex_lock(&e->mutex);
    for (int i = 0; i < ZVPN_STATS_COUNT; i++)
        values[i] = (jlong)e->stats[i];
    pthread_mutex_unlock(&e->mutex);
    LOGD(e, "stats tun_read=%lld tun_written=%lld transport_sent=%lld transport_received=%lld batches_sent=%lld batches_received=%lld compressed_batches_sent=%lld packets_sent=%lld packets_written=%lld tx_raw_payload=%lld tx_encoded_payload=%lld tx_saved=%lld rx_raw_payload=%lld rx_encoded_payload=%lld rx_saved=%lld compressed_batches_received=%lld",
         (long long)values[0], (long long)values[1], (long long)values[2],
         (long long)values[3], (long long)values[4], (long long)values[5],
         (long long)values[6], (long long)values[7], (long long)values[8],
         (long long)values[9], (long long)values[10], (long long)values[11],
         (long long)values[12], (long long)values[13], (long long)values[14],
         (long long)values[15]);

    jlongArray array = (*env)->NewLongArray(env, ZVPN_STATS_COUNT);
    if (!array)
        return NULL;
    (*env)->SetLongArrayRegion(env, array, 0, ZVPN_STATS_COUNT, values);
    return array;
}
