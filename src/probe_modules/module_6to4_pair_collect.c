#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../lib/includes.h"
#include "../../lib/logger.h"
#include "probe_modules.h"
#include "packet.h"

#define UNUSED __attribute__((unused))

typedef struct {
	struct in6_addr inner_dst6;
	int have_inner_dst6;
} pair_conf_t;

typedef struct __attribute__((packed)) {
	uint32_t marker;
	uint32_t v4_target;
	uint32_t v0;
	uint32_t v1;
} pair_payload_t;

static pair_conf_t conf;
probe_module_t module_6to4_pair_collect;

static void parse_probe_args(const char *args)
{
	if (!args || !*args) {
		return;
	}
	char *dup = strdup(args);
	if (!dup) {
		return;
	}
	char *save = NULL;
	for (char *tok = strtok_r(dup, ",", &save); tok;
	     tok = strtok_r(NULL, ",", &save)) {
		char *eq = strchr(tok, '=');
		if (!eq) {
			continue;
		}
		*eq = '\0';
		if (!strcmp(tok, "inner_dst6") || !strcmp(tok, "ipv6_other")) {
			if (inet_pton(AF_INET6, eq + 1, &conf.inner_dst6) == 1) {
				conf.have_inner_dst6 = 1;
			}
		}
	}
	free(dup);
}

int module_6to4_pair_collect_global_init(struct state_conf *zconf_local)
{
	memset(&conf, 0, sizeof(conf));
	if (zconf_local->probe_args) {
		parse_probe_args(zconf_local->probe_args);
	}
	if (!conf.have_inner_dst6 &&
	    inet_pton(AF_INET6, "2001:db8::1", &conf.inner_dst6) != 1) {
		return EXIT_FAILURE;
	}
	if (!zconf_local->ipv6_source_ip) {
		log_fatal("6to4_pair_collect",
			  "--ipv6-source-ip is required for 6to4 pair collection");
	}
	if (asprintf((char **)&module_6to4_pair_collect.pcap_filter,
		     "icmp6 and ip6 dst host %s and ip6[40] == 3", zconf_local->ipv6_source_ip) ==
	    -1) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int module_6to4_pair_collect_prepare(void *buf, macaddr_t *src, macaddr_t *gw,
				      UNUSED void *arg)
{
	memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth = (struct ether_header *)buf;
	make_eth_header_ethertype(eth, src, gw, ETHERTYPE_IP);

	struct ip *outer = (struct ip *)(&eth[1]);
	uint16_t inner_payload = sizeof(struct icmp6_hdr) + sizeof(pair_payload_t);
	uint16_t inner_len = sizeof(struct ip6_hdr) + inner_payload;
	make_ip_header(outer, IPPROTO_IPV6, htons(sizeof(struct ip) + inner_len));

	struct ip6_hdr *inner6 = (struct ip6_hdr *)(&outer[1]);
	make_ip6_header(inner6, IPPROTO_ICMPV6, inner_payload);

	struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)(&inner6[1]);
	make_icmp6_header(icmp6);
	return EXIT_SUCCESS;
}

int module_6to4_pair_collect_make(void *buf, size_t *buf_len, ipaddr_n_t src_ip,
				   ipaddr_n_t dst_ip, UNUSED port_n_t dst_port,
				   UNUSED uint8_t ttl, uint32_t *validation,
				   UNUSED int probe_num, uint16_t ip_id,
				   UNUSED void *arg)
{
	struct ether_header *eth = (struct ether_header *)buf;
	struct ip *outer = (struct ip *)(&eth[1]);
	struct ip6_hdr *inner6 = (struct ip6_hdr *)(&outer[1]);
	struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)(&inner6[1]);
	pair_payload_t *payload = (pair_payload_t *)(&icmp6[1]);

	outer->ip_src.s_addr = src_ip;
	outer->ip_dst.s_addr = dst_ip;
	outer->ip_id = ip_id;
	outer->ip_ttl = MAXTTL;

	if (inet_pton(AF_INET6, zconf.ipv6_source_ip, &inner6->ip6_src) != 1) {
		return EXIT_FAILURE;
	}
	inner6->ip6_dst = conf.inner_dst6;
	inner6->ip6_ctlun.ip6_un1.ip6_un1_hlim = 1;

	icmp6->icmp6_id = htons(validation[2] & 0xFFFF);
	icmp6->icmp6_seq = htons(1);

	payload->marker = htonl(0x36345450); /* 6TTP */
	payload->v4_target = dst_ip;
	payload->v0 = htonl(validation[0]);
	payload->v1 = htonl(validation[1]);

	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = ipv6_payload_checksum(
		sizeof(struct icmp6_hdr) + sizeof(pair_payload_t), &inner6->ip6_src,
		&inner6->ip6_dst, (unsigned short *)icmp6, IPPROTO_ICMPV6);

	outer->ip_sum = 0;
	outer->ip_sum = zmap_ip_checksum((unsigned short *)outer);

	*buf_len = sizeof(struct ether_header) + sizeof(struct ip) +
		   sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) +
		   sizeof(pair_payload_t);
	return EXIT_SUCCESS;
}

int module_6to4_pair_collect_validate(const struct ip *ip_hdr, uint32_t len,
				       UNUSED uint32_t *src_ip,
				       UNUSED uint32_t *validation,
				       UNUSED const struct port_conf *ports)
{
	struct ip6_hdr *ip6 = (struct ip6_hdr *)ip_hdr;
	if (len < sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)) {
		return PACKET_INVALID;
	}
	if (ip6->ip6_nxt != IPPROTO_ICMPV6) {
		return PACKET_INVALID;
	}
	struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)(&ip6[1]);
	if (icmp6->icmp6_type != ICMP6_TIME_EXCEEDED) {
		return PACKET_INVALID;
	}
	if (len < sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) +
		      sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) +
		      sizeof(pair_payload_t)) {
		return PACKET_INVALID;
	}
	struct ip6_hdr *quoted_ip6 = (struct ip6_hdr *)(&icmp6[1]);
	struct icmp6_hdr *quoted_icmp6 = (struct icmp6_hdr *)(&quoted_ip6[1]);
	pair_payload_t *payload = (pair_payload_t *)(&quoted_icmp6[1]);
	if (payload->marker != htonl(0x36345450)) {
		return PACKET_INVALID;
	}
	return PACKET_VALID;
}

void module_6to4_pair_collect_process(const u_char *packet, UNUSED uint32_t len,
				      fieldset_t *fs,
				      UNUSED uint32_t *validation,
				      UNUSED const struct timespec ts)
{
	struct ip6_hdr *ip6 = (struct ip6_hdr *)&packet[sizeof(struct ether_header)];
	struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)(&ip6[1]);
	struct ip6_hdr *quoted_ip6 = (struct ip6_hdr *)(&icmp6[1]);
	struct icmp6_hdr *quoted_icmp6 = (struct icmp6_hdr *)(&quoted_ip6[1]);
	pair_payload_t *payload = (pair_payload_t *)(&quoted_icmp6[1]);

	fs_add_string(fs, "classification", (char *)"6to4-pair", 0);
	fs_add_bool(fs, "success", 1);
	fs_add_string(fs, "ipv6_target", make_ipv6_str(&ip6->ip6_src), 1);
	fs_add_string(fs, "ipv4_target", make_ip_str(payload->v4_target), 1);
}

static fielddef_t fields[] = {
	{.name = "classification", .type = "string", .desc = "classification"},
	{.name = "success", .type = "bool", .desc = "success"},
	{.name = "ipv4_target", .type = "string", .desc = "discovered tunnel endpoint IPv4"},
	{.name = "ipv6_target", .type = "string", .desc = "discovered tunnel endpoint IPv6"},
};

probe_module_t module_6to4_pair_collect = {
	.name = "6to4_pair_collect",
	.max_packet_length = sizeof(struct ether_header) + sizeof(struct ip) +
			     sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) +
			     sizeof(pair_payload_t),
	.pcap_filter = "icmp6 and ip6[40] == 3",
	.pcap_snaplen = 256,
	.port_args = 0,
	.global_initialize = &module_6to4_pair_collect_global_init,
	.prepare_packet = &module_6to4_pair_collect_prepare,
	.make_packet = &module_6to4_pair_collect_make,
	.print_packet = NULL,
	.validate_packet = &module_6to4_pair_collect_validate,
	.process_packet = &module_6to4_pair_collect_process,
	.close = NULL,
	.helptext = "Collect 6to4 IPv4-IPv6 tunnel pairs. Use --ipv6-source-ip and optional --probe-args=inner_dst6=<pure IPv6 target>",
	.fields = fields,
	.numfields = sizeof(fields) / sizeof(fields[0]),
};
