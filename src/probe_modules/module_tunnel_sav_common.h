#ifndef MODULE_TUNNEL_SAV_COMMON_H
#define MODULE_TUNNEL_SAV_COMMON_H

#include <stdbool.h>
#include "probe_modules.h"

typedef enum {
	TUN_SAV_MODE_ISAV = 0,
	TUN_SAV_MODE_OSAV = 1,
} tun_sav_mode_t;

typedef enum {
	TUN_SAV_PROTO_IPIP = 0,
	TUN_SAV_PROTO_GRE = 1,
	TUN_SAV_PROTO_IP6IP6 = 2,
	TUN_SAV_PROTO_GRE6 = 3,
	TUN_SAV_PROTO_4IN6 = 4,
	TUN_SAV_PROTO_6TO4 = 5,
} tun_sav_proto_t;

typedef struct {
	tun_sav_mode_t mode;
	tun_sav_proto_t proto;
	bool outer_ipv6;
	bool inner_ipv6;
	const char *module_name;
	const char *module_desc;
	struct in_addr scanner_inner4;
	struct in_addr osav_spoof4;
	struct in6_addr scanner_inner6;
	struct in6_addr osav_spoof6;
	bool have_inner6;
	bool have_osav_spoof6;
} tunnel_sav_profile_t;

int tunnel_sav_common_global_initialize(tunnel_sav_profile_t *profile,
					probe_module_t *module,
					struct state_conf *conf);
int tunnel_sav_common_prepare_packet(tunnel_sav_profile_t *profile, void *buf,
				     macaddr_t *src, macaddr_t *gw,
				     void *arg_ptr);
int tunnel_sav_common_make_packet(tunnel_sav_profile_t *profile, void *buf,
				  size_t *buf_len, ipaddr_n_t src_ip,
				  ipaddr_n_t dst_ip, port_n_t dst_port,
				  uint8_t ttl, uint32_t *validation,
				  int probe_num, uint16_t ip_id, void *arg);
int tunnel_sav_common_validate_packet(tunnel_sav_profile_t *profile,
				      const struct ip *ip_hdr,
				      uint32_t len, uint32_t *src_ip,
				      uint32_t *validation,
				      const struct port_conf *ports);
void tunnel_sav_common_process_packet(tunnel_sav_profile_t *profile,
				      const u_char *packet,
				      uint32_t len, fieldset_t *fs,
				      uint32_t *validation,
				      const struct timespec ts);

#endif
