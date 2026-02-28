#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../lib/includes.h"
#include "packet.h"
#include "module_tunnel_sav_common.h"

#define UNUSED __attribute__((unused))
#define GRE_HEADER_LEN 4

static void parse_args(tunnel_sav_profile_t *p, const char *args)
{
	if (!args || !*args) {
		return;
	}
	char *dup = strdup(args);
	if (!dup) {
		return;
	}
	char *save = NULL;
	for (char *tok = strtok_r(dup, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
		char *eq = strchr(tok, '=');
		if (!eq) {
			continue;
		}
		*eq = '\0';
		char *k = tok;
		char *v = eq + 1;
		if (!strcmp(k, "inner_dst4")) {
			inet_pton(AF_INET, v, &p->scanner_inner4);
		} else if (!strcmp(k, "inner_src4") || !strcmp(k, "spoof_inner4")) {
			inet_pton(AF_INET, v, &p->osav_spoof4);
		} else if (!strcmp(k, "inner_dst6")) {
			if (inet_pton(AF_INET6, v, &p->scanner_inner6) == 1) {
				p->have_inner6 = true;
			}
		} else if (!strcmp(k, "inner_src6") || !strcmp(k, "spoof_inner6")) {
			if (inet_pton(AF_INET6, v, &p->osav_spoof6) == 1) {
				p->have_osav_spoof6 = true;
			}
		}
	}
	free(dup);
}

static void make_isav_spoof_v4(struct in_addr dst, struct in_addr *out)
{
	*out = dst;
	uint32_t host = ntohl(out->s_addr);
	host = (host & 0xFFFFFF00U) | (((host & 0xFFU) + 1U) & 0xFFU);
	out->s_addr = htonl(host);
}

static void make_isav_spoof_v6(struct in6_addr dst, struct in6_addr *out)
{
	*out = dst;
	out->s6_addr[15]++;
}

static void build_inner_ipv4(uint8_t *buf, struct in_addr src, struct in_addr dst,
			     uint32_t *validation)
{
	struct ip *inner = (struct ip *)buf;
	make_ip_header(inner, IPPROTO_ICMP,
		       htons(sizeof(struct ip) + sizeof(struct icmp) + sizeof(uint32_t) * 2));
	inner->ip_src = src;
	inner->ip_dst = dst;
	inner->ip_sum = 0;
	inner->ip_sum = zmap_ip_checksum((unsigned short *)inner);
	struct icmp *icmp = (struct icmp *)&inner[1];
	make_icmp_header(icmp);
	icmp->icmp_id = htons(validation[2] & 0xFFFF);
	uint32_t *payload = (uint32_t *)(&icmp[1]);
	payload[0] = validation[0];
	payload[1] = validation[1];
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = icmp_checksum((unsigned short *)icmp,
					 sizeof(struct icmp) + sizeof(uint32_t) * 2);
}

static void build_inner_ipv6(uint8_t *buf, struct in6_addr src, struct in6_addr dst,
			     uint32_t *validation)
{
	struct ip6_hdr *inner = (struct ip6_hdr *)buf;
	make_ip6_header(inner, IPPROTO_ICMPV6,
			sizeof(struct icmp6_hdr) + sizeof(uint32_t) * 2);
	inner->ip6_src = src;
	inner->ip6_dst = dst;
	struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)&inner[1];
	make_icmp6_header(icmp6);
	icmp6->icmp6_id = htons(validation[2] & 0xFFFF);
	icmp6->icmp6_data32[1] = validation[0];
	icmp6->icmp6_data32[2] = validation[1];
	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = ipv6_payload_checksum(sizeof(struct icmp6_hdr) + sizeof(uint32_t) * 2,
					     &inner->ip6_src, &inner->ip6_dst,
					     (unsigned short *)icmp6, IPPROTO_ICMPV6);
}

int tunnel_sav_common_global_initialize(tunnel_sav_profile_t *p,
					probe_module_t *module,
					struct state_conf *conf)
{
	if (conf->number_source_ips > 0 && p->scanner_inner4.s_addr == 0) {
		p->scanner_inner4.s_addr = conf->source_ip_addresses[0];
	}
	if (p->osav_spoof4.s_addr == 0) {
		inet_pton(AF_INET, "198.51.100.9", &p->osav_spoof4);
	}
	if (conf->ipv6_source_ip && !p->have_inner6 &&
	    inet_pton(AF_INET6, conf->ipv6_source_ip, &p->scanner_inner6) == 1) {
		p->have_inner6 = true;
	}
	parse_args(p, conf->probe_args);

	if (!p->outer_ipv6) {
		if (p->mode == TUN_SAV_MODE_OSAV) {
			char ipbuf[INET_ADDRSTRLEN] = {0};
			inet_ntop(AF_INET, &p->osav_spoof4, ipbuf, sizeof(ipbuf));
			asprintf((char **)&module->pcap_filter, "icmp and src host %s", ipbuf);
		} else {
			asprintf((char **)&module->pcap_filter, "icmp");
		}
	} else {
		if (p->mode == TUN_SAV_MODE_OSAV && p->have_osav_spoof6) {
			char ip6buf[INET6_ADDRSTRLEN] = {0};
			inet_ntop(AF_INET6, &p->osav_spoof6, ip6buf, sizeof(ip6buf));
			asprintf((char **)&module->pcap_filter, "icmp6 and src host %s", ip6buf);
		} else {
			asprintf((char **)&module->pcap_filter, "icmp6");
		}
	}
	return EXIT_SUCCESS;
}

int tunnel_sav_common_prepare_packet(tunnel_sav_profile_t *profile, void *buf,
				     macaddr_t *src, macaddr_t *gw,
				     UNUSED void *arg_ptr)
{
	memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth = (struct ether_header *)buf;
	make_eth_header_ethertype(eth, src, gw,
				  profile->outer_ipv6 ? ETHERTYPE_IPV6 : ETHERTYPE_IP);
	return EXIT_SUCCESS;
}

int tunnel_sav_common_make_packet(tunnel_sav_profile_t *p, void *buf,
				  size_t *buf_len, ipaddr_n_t src_ip,
				  ipaddr_n_t dst_ip, UNUSED port_n_t dst_port,
				  uint8_t ttl, uint32_t *validation,
				  UNUSED int probe_num, uint16_t ip_id, void *arg)
{
	struct ether_header *eth = (struct ether_header *)buf;
	uint8_t *cursor = (uint8_t *)&eth[1];
	if (!p->outer_ipv6) {
		uint16_t inner_len = p->inner_ipv6 ? (sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + 8)
						       : (sizeof(struct ip) + sizeof(struct icmp) + 8);
		uint16_t total_outer_payload = inner_len +
			((p->proto == TUN_SAV_PROTO_GRE) ? GRE_HEADER_LEN : 0);
		struct ip *outer = (struct ip *)cursor;
		make_ip_header(outer,
			       (p->proto == TUN_SAV_PROTO_GRE) ? IPPROTO_GRE :
			       ((p->proto == TUN_SAV_PROTO_6TO4) ? IPPROTO_IPV6 : IPPROTO_IPIP),
			       htons(sizeof(struct ip) + total_outer_payload));
		outer->ip_ttl = ttl;
		outer->ip_dst.s_addr = dst_ip;
		outer->ip_id = ip_id;
		if (p->mode == TUN_SAV_MODE_ISAV) {
			make_isav_spoof_v4(outer->ip_dst, &outer->ip_src);
		} else {
			outer->ip_src.s_addr = src_ip;
		}
		cursor = (uint8_t *)&outer[1];
		if (p->proto == TUN_SAV_PROTO_GRE) {
			cursor[0] = 0; cursor[1] = 0; cursor[2] = 0x08; cursor[3] = 0x00;
			cursor += GRE_HEADER_LEN;
		}
		if (p->inner_ipv6) {
			struct in6_addr src6 = (p->mode == TUN_SAV_MODE_OSAV && p->have_osav_spoof6) ? p->osav_spoof6 : p->scanner_inner6;
			build_inner_ipv6(cursor, src6, p->scanner_inner6, validation);
		} else {
			struct in_addr src4 = (p->mode == TUN_SAV_MODE_OSAV) ? p->osav_spoof4 : p->scanner_inner4;
			build_inner_ipv4(cursor, src4, p->scanner_inner4, validation);
		}
		outer->ip_sum = 0;
		outer->ip_sum = zmap_ip_checksum((unsigned short *)outer);
		*buf_len = sizeof(struct ether_header) + sizeof(struct ip) + total_outer_payload;
	} else {
		uint16_t inner_len = p->inner_ipv6 ? (sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + 8)
						       : (sizeof(struct ip) + sizeof(struct icmp) + 8);
		uint16_t payload_len = inner_len +
			((p->proto == TUN_SAV_PROTO_GRE6) ? GRE_HEADER_LEN : 0);
		struct ip6_hdr *outer = (struct ip6_hdr *)cursor;
		make_ip6_header(outer,
				(p->proto == TUN_SAV_PROTO_GRE6) ? IPPROTO_GRE :
				((p->proto == TUN_SAV_PROTO_4IN6) ? IPPROTO_IPIP : IPPROTO_IPV6),
				payload_len);
		outer->ip6_ctlun.ip6_un1.ip6_un1_hlim = ttl;
		struct in6_addr *pair = (struct in6_addr *)arg;
		outer->ip6_dst = pair[1];
		if (p->mode == TUN_SAV_MODE_ISAV) {
			make_isav_spoof_v6(pair[1], &outer->ip6_src);
		} else {
			outer->ip6_src = pair[0];
		}
		cursor = (uint8_t *)&outer[1];
		if (p->proto == TUN_SAV_PROTO_GRE6) {
			cursor[0] = 0; cursor[1] = 0;
			cursor[2] = p->inner_ipv6 ? 0x86 : 0x08;
			cursor[3] = p->inner_ipv6 ? 0xDD : 0x00;
			cursor += GRE_HEADER_LEN;
		}
		if (p->inner_ipv6) {
			struct in6_addr src6 = (p->mode == TUN_SAV_MODE_OSAV && p->have_osav_spoof6) ? p->osav_spoof6 : p->scanner_inner6;
			build_inner_ipv6(cursor, src6, p->scanner_inner6, validation);
		} else {
			struct in_addr src4 = (p->mode == TUN_SAV_MODE_OSAV) ? p->osav_spoof4 : p->scanner_inner4;
			build_inner_ipv4(cursor, src4, p->scanner_inner4, validation);
		}
		*buf_len = sizeof(struct ether_header) + sizeof(struct ip6_hdr) + payload_len;
	}
	return EXIT_SUCCESS;
}

int tunnel_sav_common_validate_packet(tunnel_sav_profile_t *p,
				      const struct ip *ip_hdr,
				      uint32_t len, UNUSED uint32_t *src_ip,
				      uint32_t *validation,
				      UNUSED const struct port_conf *ports)
{
	if (p->inner_ipv6) {
		if (len < sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)) {
			return PACKET_INVALID;
		}
		struct ip6_hdr *ip6 = (struct ip6_hdr *)ip_hdr;
		if (ip6->ip6_nxt != IPPROTO_ICMPV6) {
			return PACKET_INVALID;
		}
		struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)&ip6[1];
		if (icmp6->icmp6_id != htons(validation[2] & 0xFFFF)) {
			return PACKET_INVALID;
		}
		return PACKET_VALID;
	}
	if (len < sizeof(struct ip) + sizeof(struct icmp)) {
		return PACKET_INVALID;
	}
	if (ip_hdr->ip_p != IPPROTO_ICMP) {
		return PACKET_INVALID;
	}
	struct icmp *icmp = (struct icmp *)((char *)ip_hdr + ip_hdr->ip_hl * 4);
	if (icmp->icmp_id != htons(validation[2] & 0xFFFF)) {
		return PACKET_INVALID;
	}
	return PACKET_VALID;
}

void tunnel_sav_common_process_packet(tunnel_sav_profile_t *p,
				      const u_char *packet,
				      UNUSED uint32_t len, fieldset_t *fs,
				      UNUSED uint32_t *validation,
				      UNUSED const struct timespec ts)
{
	fs_add_string(fs, "classification", (char *)"tunnel-response", 0);
	fs_add_uint64(fs, "success", 1);
	fs_add_string(fs, "mode", (char *)(p->mode == TUN_SAV_MODE_ISAV ? "isav" : "osav"), 0);
	fs_add_string(fs, "proto", (char *)p->module_name, 0);
	if (p->inner_ipv6) {
		struct ip6_hdr *ip6 = (struct ip6_hdr *)&packet[sizeof(struct ether_header)];
		fs_add_string(fs, "response_src", make_ipv6_str(&ip6->ip6_src), 1);
	} else {
		struct ip *ip4 = (struct ip *)&packet[sizeof(struct ether_header)];
		fs_add_string(fs, "response_src", make_ip_str(ip4->ip_src.s_addr), 1);
	}
}
