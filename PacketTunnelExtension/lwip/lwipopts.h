/**
 * lwIP options for iOS Packet Tunnel Extension
 * Based on Potatso/tun2socks-iOS proven configuration
 *
 * Key settings:
 * - NO_SYS=1: No OS threads, we drive everything from GCD
 * - MEM_LIBC_MALLOC=1: Use system malloc (iOS has plenty of memory)
 * - LWIP_CALLBACK_API=1: Raw callback API (no sequential/socket API needed)
 * - TCP_MSS: Controls maximum segment size for fragmentation
 */

#ifndef LWIPOPTS_H
#define LWIPOPTS_H

/* === System === */
#define NO_SYS                      1
#define SYS_LIGHTWEIGHT_PROT        0
#define MEM_ALIGNMENT               4       /* ARM alignment */

/* === Memory (use system malloc) === */
#define MEM_LIBC_MALLOC             1
#define MEMP_MEM_MALLOC             1
#define MEM_SIZE                    (2 * 1024 * 1024)  /* 2 MiB heap */

/* === Pool sizes === */
#define MEMP_NUM_PBUF               256
#define MEMP_NUM_TCP_PCB            128
#define MEMP_NUM_TCP_PCB_LISTEN     128
#define MEMP_NUM_TCP_SEG            256
#define MEMP_NUM_REASSDATA          64
#define MEMP_NUM_FRAG_PBUF          64
#define MEMP_NUM_UDP_PCB            32
#define PBUF_POOL_SIZE              256
#define PBUF_POOL_BUFSIZE           1600

/* === TCP Configuration === */
#define LWIP_TCP                    1
#define TCP_MSS                     1460    /* Standard MSS */
#define TCP_WND                     (16 * TCP_MSS)
#define TCP_SND_BUF                 (16 * TCP_MSS)
#define TCP_SND_QUEUELEN            ((4 * (TCP_SND_BUF) + (TCP_MSS - 1))/(TCP_MSS))
#define TCP_OVERSIZE                TCP_MSS
#define TCP_LISTEN_BACKLOG          1
#define LWIP_TCP_TIMESTAMPS         0
#define LWIP_TCP_SACK_OUT           0
#define LWIP_WND_SCALE              0
#define TCP_CALCULATE_EFF_SEND_MSS  1

/* === UDP Configuration === */
#define LWIP_UDP                    1

/* === IP Configuration === */
#define IP_FORWARD                  0
#define IP_FRAG                     1
#define IP_REASSEMBLY               1
#define IP_DEFAULT_TTL              64
#define LWIP_IPV4                   1
#define LWIP_IPV6                   0       /* IPv4 only for now */

/* === Disable unused features === */
#define LWIP_ARP                    0
#define ARP_QUEUEING                0
#define LWIP_ICMP                   1       /* Keep for diagnostics */
#define LWIP_RAW                    0
#define LWIP_DHCP                   0
#define LWIP_AUTOIP                 0
#define LWIP_SNMP                   0
#define LWIP_IGMP                   0
#define LWIP_DNS                    0
#define LWIP_UDPLITE                0
#define LWIP_HAVE_LOOPIF            0
#define LWIP_NETIF_LOOPBACK         0
#define PPP_SUPPORT                 0

/* === API Configuration === */
#define LWIP_CALLBACK_API           1
#define LWIP_NETCONN                0       /* No sequential API */
#define LWIP_SOCKET                 0       /* No socket API */
#define LWIP_NETIF_API              0

/* === Checksum === */
#define LWIP_CHECKSUM_ON_COPY       1
#define CHECKSUM_GEN_IP             1
#define CHECKSUM_GEN_TCP            1
#define CHECKSUM_GEN_UDP            1
#define CHECKSUM_CHECK_IP           1
#define CHECKSUM_CHECK_TCP          1
#define CHECKSUM_CHECK_UDP          1

/* === Debug (disable in release) === */
#define LWIP_DEBUG                  0
#define TCP_DEBUG                   LWIP_DBG_OFF
#define IP_DEBUG                    LWIP_DBG_OFF

/* === Timers === */
#define LWIP_TIMERS                 1

#endif /* LWIPOPTS_H */
