#include "include/clinuxpacket.h"

#ifdef __linux__

#include <arpa/inet.h>  // htons / ntohs
#include <errno.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

int swiftpacket_afpacket_open(const char *interface_name,
                              int promiscuous,
                              int *hardware_type_out) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        return -errno;
    }

    unsigned int ifindex = if_nametoindex(interface_name);
    if (ifindex == 0) {
        int err = -errno;
        close(fd);
        return err;
    }

    struct sockaddr_ll address;
    memset(&address, 0, sizeof(address));
    address.sll_family = AF_PACKET;
    address.sll_protocol = htons(ETH_P_ALL);
    address.sll_ifindex = (int)ifindex;
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        int err = -errno;
        close(fd);
        return err;
    }

    if (promiscuous) {
        struct packet_mreq mreq;
        memset(&mreq, 0, sizeof(mreq));
        mreq.mr_ifindex = (int)ifindex;
        mreq.mr_type = PACKET_MR_PROMISC;
        if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
            int err = -errno;
            close(fd);
            return err;
        }
    }

    int enable = 1;
    // Best effort: without it, recv falls back to the wall clock.
    (void)setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPNS, &enable, sizeof(enable));

    if (hardware_type_out != NULL) {
        struct ifreq request;
        memset(&request, 0, sizeof(request));
        strncpy(request.ifr_name, interface_name, IFNAMSIZ - 1);
        if (ioctl(fd, SIOCGIFHWADDR, &request) == 0) {
            *hardware_type_out = request.ifr_hwaddr.sa_family;
        } else {
            *hardware_type_out = -1;
        }
    }

    return fd;
}

int swiftpacket_afpacket_set_fanout(int fd, uint16_t group_id) {
    int argument = (int)group_id | (PACKET_FANOUT_HASH << 16);
    if (setsockopt(fd, SOL_PACKET, PACKET_FANOUT, &argument, sizeof(argument)) < 0) {
        return -errno;
    }
    return 0;
}

int swiftpacket_afpacket_attach_filter(int fd, const void *insns, uint16_t count) {
    // libpcap's bpf_insn and the kernel's sock_filter share one layout:
    // { u16 code; u8 jt; u8 jf; u32 k; }.
    struct sock_fprog program;
    program.len = count;
    program.filter = (struct sock_filter *)(uintptr_t)insns;
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof(program)) < 0) {
        return -errno;
    }
    return 0;
}

ssize_t swiftpacket_afpacket_recv(int fd,
                                  uint8_t *buffer,
                                  size_t capacity,
                                  int timeout_milliseconds,
                                  swiftpacket_timestamp *timestamp) {
    struct pollfd descriptor = {.fd = fd, .events = POLLIN, .revents = 0};
    int ready = poll(&descriptor, 1, timeout_milliseconds);
    if (ready < 0) {
        return (errno == EINTR) ? 0 : -errno;  // treat EINTR as a timeout tick
    }
    if (ready == 0) {
        return 0;  // timeout: no packet
    }

    struct iovec iov = {.iov_base = buffer, .iov_len = capacity};
    uint8_t control[512];
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);

    // MSG_TRUNC makes the return value the packet's original wire length
    // even when it exceeded `capacity` — exactly pcap's caplen/len split.
    ssize_t received = recvmsg(fd, &message, MSG_TRUNC | MSG_DONTWAIT);
    if (received < 0) {
        return (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) ? 0 : -errno;
    }

    if (timestamp != NULL) {
        timestamp->seconds = 0;
        timestamp->nanoseconds = 0;
        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message); cmsg != NULL;
             cmsg = CMSG_NXTHDR(&message, cmsg)) {
            if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMPNS) {
                struct timespec spec;
                memcpy(&spec, CMSG_DATA(cmsg), sizeof(spec));
                timestamp->seconds = (int64_t)spec.tv_sec;
                timestamp->nanoseconds = (int64_t)spec.tv_nsec;
                break;
            }
        }
        if (timestamp->seconds == 0 && timestamp->nanoseconds == 0) {
            struct timespec now;
            clock_gettime(CLOCK_REALTIME, &now);
            timestamp->seconds = (int64_t)now.tv_sec;
            timestamp->nanoseconds = (int64_t)now.tv_nsec;
        }
    }

    return received;
}

ssize_t swiftpacket_afpacket_send(int fd, const uint8_t *buffer, size_t length) {
    ssize_t sent = send(fd, buffer, length, 0);
    return (sent < 0) ? -errno : sent;
}

int swiftpacket_afpacket_stats(int fd, swiftpacket_stats *stats_out) {
    struct tpacket_stats_v3 kernel;
    socklen_t size = sizeof(kernel);
    memset(&kernel, 0, sizeof(kernel));
    // PACKET_STATISTICS is read-and-reset: each call reports the deltas since
    // the previous one.
    if (getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &kernel, &size) < 0) {
        return -errno;
    }
    if (stats_out != NULL) {
        stats_out->packets = kernel.tp_packets;
        stats_out->drops = kernel.tp_drops;
    }
    return 0;
}

void swiftpacket_afpacket_close(int fd) {
    close(fd);
}

// MARK: - TPACKET_V3 receive ring

#include <sys/mman.h>

struct swiftpacket_ring {
    uint8_t *map;
    size_t map_size;
    unsigned int block_size;
    unsigned int block_count;
    unsigned int current_block;
    struct tpacket3_hdr *current_frame;
    unsigned int frames_left;
    int release_pending;  // the current block owes a hand-back to the kernel
};

static struct tpacket_block_desc *ring_block(const swiftpacket_ring *ring,
                                             unsigned int index) {
    return (struct tpacket_block_desc *)(ring->map + (size_t)index * ring->block_size);
}

swiftpacket_ring *swiftpacket_ring_setup(int fd,
                                         unsigned int block_size,
                                         unsigned int block_count,
                                         unsigned int frame_size,
                                         int timeout_milliseconds,
                                         int *error_out) {
    int version = TPACKET_V3;
    if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) < 0) {
        if (error_out) *error_out = -errno;
        return NULL;
    }

    struct tpacket_req3 request;
    memset(&request, 0, sizeof(request));
    request.tp_block_size = block_size;
    request.tp_block_nr = block_count;
    request.tp_frame_size = frame_size;
    request.tp_frame_nr = (block_size / frame_size) * block_count;
    request.tp_retire_blk_tov = timeout_milliseconds > 0 ? timeout_milliseconds : 100;
    request.tp_feature_req_word = 0;
    if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &request, sizeof(request)) < 0) {
        if (error_out) *error_out = -errno;
        return NULL;
    }

    size_t map_size = (size_t)block_size * block_count;
    uint8_t *map = mmap(NULL, map_size, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_LOCKED, fd, 0);
    if (map == MAP_FAILED) {
        // MAP_LOCKED can fail on RLIMIT_MEMLOCK; retry without it.
        map = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    }
    if (map == MAP_FAILED) {
        if (error_out) *error_out = -errno;
        return NULL;
    }

    swiftpacket_ring *ring = calloc(1, sizeof(swiftpacket_ring));
    if (ring == NULL) {
        munmap(map, map_size);
        if (error_out) *error_out = -ENOMEM;
        return NULL;
    }
    ring->map = map;
    ring->map_size = map_size;
    ring->block_size = block_size;
    ring->block_count = block_count;
    ring->current_block = 0;
    ring->current_frame = NULL;
    ring->frames_left = 0;
    ring->release_pending = 0;
    return ring;
}

int swiftpacket_ring_next(swiftpacket_ring *ring,
                          int fd,
                          const uint8_t **data_out,
                          uint32_t *capture_length_out,
                          uint32_t *original_length_out,
                          swiftpacket_timestamp *timestamp,
                          int timeout_milliseconds) {
    // Advance within the block we already hold.
    if (ring->frames_left > 0 && ring->current_frame != NULL) {
        ring->current_frame = (struct tpacket3_hdr *)((uint8_t *)ring->current_frame
                                                      + ring->current_frame->tp_next_offset);
    } else {
        // The previous block is fully consumed; hand it back now that the
        // caller has copied its last frame out.
        if (ring->release_pending) {
            struct tpacket_block_desc *done = ring_block(ring, ring->current_block);
            __atomic_store_n(&done->hdr.bh1.block_status, TP_STATUS_KERNEL, __ATOMIC_RELEASE);
            ring->current_block = (ring->current_block + 1) % ring->block_count;
            ring->release_pending = 0;
        }

        // Acquire the next ready block.
        for (;;) {
            struct tpacket_block_desc *block = ring_block(ring, ring->current_block);
            uint32_t status = __atomic_load_n(&block->hdr.bh1.block_status, __ATOMIC_ACQUIRE);
            if ((status & TP_STATUS_USER) == 0) {
                struct pollfd descriptor = {.fd = fd, .events = POLLIN, .revents = 0};
                int ready = poll(&descriptor, 1, timeout_milliseconds);
                if (ready < 0) {
                    return (errno == EINTR) ? 0 : -errno;
                }
                if (ready == 0) {
                    return 0;  // timeout
                }
                status = __atomic_load_n(&block->hdr.bh1.block_status, __ATOMIC_ACQUIRE);
                if ((status & TP_STATUS_USER) == 0) {
                    return 0;  // woke for another reason; let the caller re-poll
                }
            }

            unsigned int packets = block->hdr.bh1.num_pkts;
            if (packets == 0) {
                // An empty retired block: recycle it and try the next.
                __atomic_store_n(&block->hdr.bh1.block_status, TP_STATUS_KERNEL, __ATOMIC_RELEASE);
                ring->current_block = (ring->current_block + 1) % ring->block_count;
                continue;
            }

            ring->current_frame = (struct tpacket3_hdr *)((uint8_t *)block
                                    + block->hdr.bh1.offset_to_first_pkt);
            ring->frames_left = packets;
            ring->release_pending = 1;
            break;
        }
    }

    struct tpacket3_hdr *frame = ring->current_frame;
    ring->frames_left -= 1;

    if (data_out) *data_out = (const uint8_t *)frame + frame->tp_mac;
    if (capture_length_out) *capture_length_out = frame->tp_snaplen;
    if (original_length_out) *original_length_out = frame->tp_len;
    if (timestamp) {
        timestamp->seconds = (int64_t)frame->tp_sec;
        timestamp->nanoseconds = (int64_t)frame->tp_nsec;
    }
    return 1;
}

void swiftpacket_ring_close(swiftpacket_ring *ring) {
    if (ring == NULL) {
        return;
    }
    if (ring->map != NULL && ring->map != MAP_FAILED) {
        munmap(ring->map, ring->map_size);
    }
    free(ring);
}

#endif /* __linux__ */
