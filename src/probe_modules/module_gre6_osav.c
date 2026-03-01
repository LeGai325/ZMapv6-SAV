#include <stdlib.h>

#include "module_tunnel_sav_common.h"

#define UNUSED __attribute__((unused))

static tunnel_sav_profile_t profile = {
	.mode = TUN_SAV_MODE_OSAV,
	.proto = TUN_SAV_PROTO_GRE6,
	.outer_ipv6 = true,
	.inner_ipv6 = true,
	.module_name = "gre6_osav",
	.module_desc = "gre6 osav source-address validation scan module",
};

probe_module_t module_gre6_osav;

static int global_initialize(struct state_conf *conf)
{
	return tunnel_sav_common_global_initialize(&profile, &module_gre6_osav, conf);
}

static int prepare_packet(void *buf, macaddr_t *src, macaddr_t *gw, void *arg_ptr)
{
	return tunnel_sav_common_prepare_packet(&profile, buf, src, gw, arg_ptr);
}

static int make_packet(void *buf, size_t *buf_len, ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
			port_n_t dst_port, uint8_t ttl, uint32_t *validation,
			int probe_num, uint16_t ip_id, void *arg)
{
	return tunnel_sav_common_make_packet(&profile, buf, buf_len, src_ip, dst_ip,
					 dst_port, ttl, validation, probe_num, ip_id, arg);
}

static int validate_packet(const struct ip *ip_hdr, uint32_t len, uint32_t *src_ip,
			   uint32_t *validation, const struct port_conf *ports)
{
	return tunnel_sav_common_validate_packet(&profile, ip_hdr, len, src_ip, validation, ports);
}

static void process_packet(const u_char *packet, uint32_t len, fieldset_t *fs,
			   uint32_t *validation, const struct timespec ts)
{
	tunnel_sav_common_process_packet(&profile, packet, len, fs, validation, ts);
}

static fielddef_t fields[] = {
	{.name = "classification", .type = "string", .desc = "response classification"},
	{.name = "success", .type = "bool", .desc = "whether response indicates SAV weakness"},
	{.name = "mode", .type = "string", .desc = "scan mode"},
	{.name = "proto", .type = "string", .desc = "module protocol"},
	{.name = "response_src", .type = "string", .desc = "response source address"},
};

probe_module_t module_gre6_osav = {
	.name = "gre6_osav",
	.max_packet_length = sizeof(struct ether_header) + sizeof(struct ip6_hdr) + 4 + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + 8,
	.pcap_filter = "icmp or icmp6",
	.pcap_snaplen = 256,
	.port_args = 0,
	.global_initialize = &global_initialize,
	.prepare_packet = &prepare_packet,
	.make_packet = &make_packet,
	.process_packet = &process_packet,
	.validate_packet = &validate_packet,
	.close = NULL,
	.fields = fields,
	.numfields = sizeof(fields) / sizeof(fields[0]),
	.helptext = "gre6 osav SAV scanning module. Optional --probe-args inner_dst4=,inner_dst6=,inner_src4=,inner_src6=",
};
