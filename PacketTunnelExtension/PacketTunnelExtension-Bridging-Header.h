//
//  PacketTunnelExtension-Bridging-Header.h
//  Exposes C functions from lwip_bridge.c to Swift
//

#ifndef PacketTunnelExtension_Bridging_Header_h
#define PacketTunnelExtension_Bridging_Header_h

#include <stdint.h>

// lwIP C bridge functions (defined in lwip/lwip_bridge.c)

typedef void (*lwip_output_callback_t)(const void *data, int len);
typedef void (*lwip_tcp_recv_callback_t)(const char *src_ip, int src_port,
                                         const char *dst_ip, int dst_port,
                                         const void *data, int len);
typedef void (*lwip_tcp_accept_callback_t)(const char *src_ip, int src_port,
                                            const char *dst_ip, int dst_port);

void lwip_bridge_init(void);
void lwip_bridge_set_output_callback(lwip_output_callback_t callback);
void lwip_bridge_set_tcp_recv_callback(lwip_tcp_recv_callback_t callback);
void lwip_bridge_set_tcp_accept_callback(lwip_tcp_accept_callback_t callback);
void lwip_bridge_input(const void *data, int len);
void lwip_bridge_tcp_write(int connection_id, const void *data, int len);
void lwip_bridge_tcp_write_fragmented(int connection_id, const void *data, int len, int split_point);
void lwip_bridge_check_timeouts(void);
void lwip_bridge_set_window_size(int connection_id, int window_size);
void lwip_bridge_set_ignore_rst(int connection_id, int ignore);

#endif
