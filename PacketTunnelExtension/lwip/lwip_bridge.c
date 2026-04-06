/**
 * lwIP C Bridge for Swift interop
 * FULL IMPLEMENTATION — connects lwIP stack to NEPacketTunnelProvider
 */

#include "lwip/init.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/ip.h"
#include "lwip/pbuf.h"
#include "lwip/netif.h"
#include "lwip/timeouts.h"
#include "lwip/ip4_frag.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// ============================================================================
// Callback types (C → Swift)
// ============================================================================

typedef void (*lwip_output_callback_t)(const void *data, int len);
typedef void (*lwip_tcp_recv_callback_t)(const char *src_ip, int src_port,
                                         const char *dst_ip, int dst_port,
                                         const void *data, int len);
typedef void (*lwip_tcp_accept_callback_t)(const char *src_ip, int src_port,
                                            const char *dst_ip, int dst_port);

// ============================================================================
// Globals
// ============================================================================

static lwip_output_callback_t g_output_callback = NULL;
static lwip_tcp_recv_callback_t g_tcp_recv_callback = NULL;
static lwip_tcp_accept_callback_t g_tcp_accept_callback = NULL;

static struct netif g_netif;

// Connection tracking (simple array, max 256 connections)
#define MAX_CONNECTIONS 256

struct connection {
    struct tcp_pcb *pcb;
    int id;
    int active;
};

static struct connection g_connections[MAX_CONNECTIONS];
static int g_next_id = 1;

// ============================================================================
// Internal: netif callbacks
// ============================================================================

static err_t netif_output_func(struct netif *netif, struct pbuf *buf, const ip4_addr_t *ipaddr) {
    (void)netif;
    (void)ipaddr;

    if (g_output_callback && buf) {
        // Flatten pbuf chain into contiguous buffer
        u16_t total = buf->tot_len;
        void *data = malloc(total);
        if (data) {
            pbuf_copy_partial(buf, data, total, 0);
            g_output_callback(data, (int)total);
            free(data);
        }
    }
    return ERR_OK;
}

static err_t netif_init_func(struct netif *netif) {
    netif->name[0] = 't';
    netif->name[1] = 'n';
    netif->output = netif_output_func;
    netif->mtu = 1500;
    netif->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;
    return ERR_OK;
}

// ============================================================================
// Internal: TCP callbacks
// ============================================================================

static int find_connection_by_pcb(struct tcp_pcb *pcb) {
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (g_connections[i].active && g_connections[i].pcb == pcb) {
            return i;
        }
    }
    return -1;
}

static int find_connection_by_id(int id) {
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (g_connections[i].active && g_connections[i].id == id) {
            return i;
        }
    }
    return -1;
}

static int add_connection(struct tcp_pcb *pcb) {
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (!g_connections[i].active) {
            g_connections[i].pcb = pcb;
            g_connections[i].id = g_next_id++;
            g_connections[i].active = 1;
            return i;
        }
    }
    return -1; // full
}

static void remove_connection_by_pcb(struct tcp_pcb *pcb) {
    int idx = find_connection_by_pcb(pcb);
    if (idx >= 0) {
        g_connections[idx].active = 0;
        g_connections[idx].pcb = NULL;
    }
}

static void ip4_to_str(const ip4_addr_t *addr, char *buf, size_t buflen) {
    u32_t ip = ip4_addr_get_u32(addr);
    snprintf(buf, buflen, "%u.%u.%u.%u",
             (unsigned)(ip & 0xFF),
             (unsigned)((ip >> 8) & 0xFF),
             (unsigned)((ip >> 16) & 0xFF),
             (unsigned)((ip >> 24) & 0xFF));
}

static err_t tcp_recv_func(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    (void)arg;
    (void)err;

    if (!tpcb) return ERR_VAL;

    if (!p) {
        // Connection closed by remote
        remove_connection_by_pcb(tpcb);
        tcp_close(tpcb);
        return ERR_OK;
    }

    if (g_tcp_recv_callback) {
        char src_ip[16], dst_ip[16];
        ip4_to_str(&tpcb->remote_ip, src_ip, sizeof(src_ip));
        ip4_to_str(&tpcb->local_ip, dst_ip, sizeof(dst_ip));

        // Flatten pbuf
        void *data = malloc(p->tot_len);
        if (data) {
            pbuf_copy_partial(p, data, p->tot_len, 0);
            g_tcp_recv_callback(src_ip, tpcb->remote_port, dst_ip, tpcb->local_port,
                                data, (int)p->tot_len);
            free(data);
        }
    }

    tcp_recved(tpcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

static void tcp_err_func(void *arg, err_t err) {
    (void)arg;
    (void)err;
    // PCB is already freed by lwIP when this is called
}

static err_t tcp_accept_func(void *arg, struct tcp_pcb *newpcb, err_t err) {
    (void)arg;
    (void)err;

    if (!newpcb) return ERR_VAL;

    int idx = add_connection(newpcb);
    if (idx < 0) {
        tcp_abort(newpcb);
        return ERR_ABRT;
    }

    tcp_recv(newpcb, tcp_recv_func);
    tcp_err(newpcb, tcp_err_func);

    if (g_tcp_accept_callback) {
        char src_ip[16], dst_ip[16];
        ip4_to_str(&newpcb->remote_ip, src_ip, sizeof(src_ip));
        ip4_to_str(&newpcb->local_ip, dst_ip, sizeof(dst_ip));
        g_tcp_accept_callback(src_ip, newpcb->remote_port, dst_ip, newpcb->local_port);
    }

    return ERR_OK;
}

// ============================================================================
// Public API (called from Swift)
// ============================================================================

void lwip_bridge_init(void) {
    lwip_init();

    memset(g_connections, 0, sizeof(g_connections));

    // Setup virtual network interface
    ip4_addr_t addr, mask, gw;
    IP4_ADDR(&addr, 10, 0, 0, 2);   // TUN IP
    IP4_ADDR(&mask, 255, 255, 255, 0);
    IP4_ADDR(&gw, 10, 0, 0, 1);

    netif_add(&g_netif, &addr, &mask, &gw, NULL, netif_init_func, ip_input);
    netif_set_default(&g_netif);
    netif_set_up(&g_netif);

    // Listen for all incoming TCP connections
    struct tcp_pcb *listen_pcb = tcp_new();
    if (listen_pcb) {
        tcp_bind(listen_pcb, IP_ADDR_ANY, 0); // Bind to all ports
        listen_pcb = tcp_listen(listen_pcb);
        if (listen_pcb) {
            tcp_accept(listen_pcb, tcp_accept_func);
        }
    }
}

void lwip_bridge_set_output_callback(lwip_output_callback_t callback) {
    g_output_callback = callback;
}

void lwip_bridge_set_tcp_recv_callback(lwip_tcp_recv_callback_t callback) {
    g_tcp_recv_callback = callback;
}

void lwip_bridge_set_tcp_accept_callback(lwip_tcp_accept_callback_t callback) {
    g_tcp_accept_callback = callback;
}

void lwip_bridge_input(const void *data, int len) {
    if (!data || len <= 0) return;

    struct pbuf *buf = pbuf_alloc(PBUF_RAW, (u16_t)len, PBUF_RAM);
    if (buf) {
        pbuf_take(buf, data, (u16_t)len);
        if (g_netif.input) {
            g_netif.input(buf, &g_netif);
        } else {
            pbuf_free(buf);
        }
    }
}

void lwip_bridge_tcp_write(int connection_id, const void *data, int len) {
    if (!data || len <= 0) return;

    int idx = find_connection_by_id(connection_id);
    if (idx < 0) return;

    struct tcp_pcb *pcb = g_connections[idx].pcb;
    if (!pcb) return;

    err_t err = tcp_write(pcb, data, (u16_t)len, TCP_WRITE_FLAG_COPY);
    if (err == ERR_OK) {
        tcp_output(pcb);
    }
}

void lwip_bridge_tcp_write_fragmented(int connection_id,
                                       const void *data, int len,
                                       int split_point) {
    if (!data || len <= 0 || split_point <= 0 || split_point >= len) {
        lwip_bridge_tcp_write(connection_id, data, len);
        return;
    }

    int idx = find_connection_by_id(connection_id);
    if (idx < 0) return;

    struct tcp_pcb *pcb = g_connections[idx].pcb;
    if (!pcb) return;

    // Fragment 1
    err_t err1 = tcp_write(pcb, data, (u16_t)split_point, TCP_WRITE_FLAG_COPY);
    if (err1 == ERR_OK) {
        tcp_output(pcb); // Force flush — creates first TCP segment
    }

    // Fragment 2
    err_t err2 = tcp_write(pcb, (const char *)data + split_point,
                           (u16_t)(len - split_point), TCP_WRITE_FLAG_COPY);
    if (err2 == ERR_OK) {
        tcp_output(pcb); // Force flush — creates second TCP segment
    }
}

void lwip_bridge_check_timeouts(void) {
    sys_check_timeouts();
}

void lwip_bridge_set_window_size(int connection_id, int window_size) {
    int idx = find_connection_by_id(connection_id);
    if (idx < 0) return;

    struct tcp_pcb *pcb = g_connections[idx].pcb;
    if (pcb) {
        pcb->rcv_wnd = (tcpwnd_size_t)window_size;
        pcb->rcv_ann_wnd = (tcpwnd_size_t)window_size;
    }
}

void lwip_bridge_set_ignore_rst(int connection_id, int ignore) {
    // RST filtering is handled at the Swift level (RSTDropper.swift)
    // before packets reach lwIP. This function is a no-op placeholder
    // in case we want to add lwIP-level RST filtering later.
    (void)connection_id;
    (void)ignore;
}
