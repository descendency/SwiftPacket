#ifndef SWIFTPACKET_CLINUXPACKET_H
#define SWIFTPACKET_CLINUXPACKET_H

// Native AF_PACKET capture helpers, Linux only. On other platforms this
// header (and the module it defines) is intentionally empty; the Swift code
// that calls it is guarded by `#if os(Linux)`.
//
// The struct-heavy kernel interface (sockaddr_ll, packet_mreq, sock_fprog,
// cmsg walking) lives here in C, where the compiler checks it against the
// real kernel headers, instead of in blind Swift imports.

#ifdef __linux__

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/// A packet arrival time, from SO_TIMESTAMPNS when available.
typedef struct {
    int64_t seconds;
    int64_t nanoseconds;
} swiftpacket_timestamp;

/// Opens an AF_PACKET/SOCK_RAW socket bound to `interface_name`, optionally
/// joining promiscuous mode, with nanosecond receive timestamps enabled.
/// On success returns the file descriptor (>= 0) and stores the interface's
/// ARPHRD_* hardware type in `hardware_type_out`. On failure returns
/// -errno.
int swiftpacket_afpacket_open(const char *interface_name,
                              int promiscuous,
                              int *hardware_type_out);

/// Joins fanout group `group_id` with hash (flow-affine) load balancing, so
/// multiple sockets can share one interface's traffic across cores.
/// Returns 0 on success, -errno on failure.
int swiftpacket_afpacket_set_fanout(int fd, uint16_t group_id);

/// Attaches a classic-BPF filter. `insns` points to `count` instructions in
/// libpcap's `struct bpf_insn` layout (u16 code, u8 jt, u8 jf, u32 k), which
/// is bit-identical to the kernel's `struct sock_filter`. Returns 0 or
/// -errno.
int swiftpacket_afpacket_attach_filter(int fd, const void *insns, uint16_t count);

/// Waits up to `timeout_milliseconds` for a packet, then reads one.
/// Returns the packet's ORIGINAL wire length (which may exceed `capacity`;
/// only `capacity` bytes are stored — MSG_TRUNC semantics), 0 on timeout,
/// or -errno on failure. Fills `timestamp` from SO_TIMESTAMPNS, falling
/// back to the current clock.
ssize_t swiftpacket_afpacket_recv(int fd,
                                  uint8_t *buffer,
                                  size_t capacity,
                                  int timeout_milliseconds,
                                  swiftpacket_timestamp *timestamp);

/// Sends `length` bytes as a raw frame on the socket. Returns the number of
/// bytes written, or -errno.
ssize_t swiftpacket_afpacket_send(int fd, const uint8_t *buffer, size_t length);

/// Kernel capture counters (`PACKET_STATISTICS`).
typedef struct {
    uint64_t packets;
    uint64_t drops;
} swiftpacket_stats;

/// Reads and *resets* the socket's packet/drop counters. Returns 0 or -errno.
int swiftpacket_afpacket_stats(int fd, swiftpacket_stats *stats_out);

/// Closes the socket.
void swiftpacket_afpacket_close(int fd);

// MARK: - TPACKET_V3 receive ring

/// An opaque handle to a memory-mapped TPACKET_V3 RX ring.
typedef struct swiftpacket_ring swiftpacket_ring;

/// Sets `fd` to TPACKET_V3 and installs a mmap'd RX ring.
///
/// `block_size` (page-aligned) × `block_count` is the total ring memory;
/// `frame_size` bounds one packet's slot; `timeout_milliseconds` is the
/// kernel's block-retire timeout. Returns a ring handle, or NULL with -errno
/// stored in `error_out`.
swiftpacket_ring *swiftpacket_ring_setup(int fd,
                                         unsigned int block_size,
                                         unsigned int block_count,
                                         unsigned int frame_size,
                                         int timeout_milliseconds,
                                         int *error_out);

/// Returns the next packet from the ring, waiting up to `timeout_milliseconds`.
///
/// On success returns 1 and points `data_out` into the mmap (valid only until
/// the next call — copy before then), with `capture_length_out` /
/// `original_length_out` / `timestamp` filled. Returns 0 on timeout, or
/// -errno on error. Block ownership is handed back to the kernel lazily on the
/// following call, so the returned pointer stays valid across exactly one
/// consumer step.
int swiftpacket_ring_next(swiftpacket_ring *ring,
                          int fd,
                          const uint8_t **data_out,
                          uint32_t *capture_length_out,
                          uint32_t *original_length_out,
                          swiftpacket_timestamp *timestamp,
                          int timeout_milliseconds);

/// Unmaps and frees the ring. Does not close `fd`.
void swiftpacket_ring_close(swiftpacket_ring *ring);

#endif /* __linux__ */

#endif /* SWIFTPACKET_CLINUXPACKET_H */
