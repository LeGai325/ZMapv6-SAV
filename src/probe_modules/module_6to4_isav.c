#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "module_tunnel_sav_common.h"
#include "packet.h"

#define UNUSED __attribute__((unused))

typedef struct {
	struct in6_addr src6;
	struct in6_addr dst6;
	struct in_addr dst4;
	uint8_t has_dst4;
} ipv6_probe_arg_t;

static tunnel_sav_profile_t profile = {
	.mode = TUN_SAV_MODE_ISAV,
	.proto = TUN_SAV_PROTO_6TO4,
	.outer_ipv6 = false,
	.inner_ipv6 = true,
	.module_name = "6to4_isav",
	.module_desc = "6to4 isav source-address validation scan module",
};

probe_module_t module_6to4_isav;

static void make_isav_spoof_v4(struct in_addr dst, struct in_addr *out)
{
	*out = dst;
	uint32_t host = ntohl(out->s_addr);
	uint32_t d = host & 0xFFU;
	uint32_t e = (d + 1U) % 255U;
	if (e == 0) {
		e = 1;
	}
	host = (host & 0xFFFFFF00U) | e;
	out->s_addr = htonl(host);
}

static struct in6_addr make_6to4_addr(struct in_addr v4, int iid_mode)
{
	struct in6_addr out = IN6ADDR_ANY_INIT;
	const uint8_t *b = (const uint8_t *)&v4.s_addr;
	out.s6_addr[0] = 0x20;
	out.s6_addr[1] = 0x02;
	out.s6_addr[2] = b[0];
	out.s6_addr[3] = b[1];
	out.s6_addr[4] = b[2];
	out.s6_addr[5] = b[3];
	if (iid_mode == 1) {
		out.s6_addr[15] = 0x01;
	} else if (iid_mode == 2) {
		out.s6_addr[12] = b[0];
		out.s6_addr[13] = b[1];
		out.s6_addr[14] = b[2];
		out.s6_addr[15] = b[3];
	}
	return out;
}

static int global_initialize(struct state_conf *conf)
{
	int rc = tunnel_sav_common_global_initialize(&profile, &module_6to4_isav, conf);
	if (rc != EXIT_SUCCESS) {
		return rc;
	}
	if (module_6to4_isav.pcap_filter) {
		free((void *)module_6to4_isav.pcap_filter);
	}
	char local6buf[INET6_ADDRSTRLEN] = {0};
	inet_ntop(AF_INET6, &profile.scanner_inner6, local6buf, sizeof(local6buf));
	const char *fmt = "icmp6 and dst host %s";
	size_t filter_len = strlen(fmt) + strlen(local6buf) + 1;
	char *filter = malloc(filter_len);
	if (!filter) {
		return EXIT_FAILURE;
	}
	snprintf(filter, filter_len, fmt, local6buf);
	module_6to4_isav.pcap_filter = filter;
	return EXIT_SUCCESS;
}

static int prepare_packet(void *buf, macaddr_t *src, macaddr_t *gw, void *arg_ptr)
{
	return tunnel_sav_common_prepare_packet(&profile, buf, src, gw, arg_ptr);
}

static int make_packet(void *buf, size_t *buf_len, UNUSED ipaddr_n_t src_ip,
			ipaddr_n_t dst_ip, UNUSED port_n_t dst_port, uint8_t ttl,
			UNUSED uint32_t *validation, int probe_num, uint16_t ip_id,
			void *arg)
{
	if (dst_ip == 0) {
		return EXIT_FAILURE;
	}
	ipv6_probe_arg_t *pair = (ipv6_probe_arg_t *)arg;
	struct in_addr dst4 = {.s_addr = dst_ip};
	struct in_addr spoof4 = {0};
	make_isav_spoof_v4(dst4, &spoof4);

	struct ether_header *eth = (struct ether_header *)buf;
	uint8_t *cursor = (uint8_t *)&eth[1];
	struct ip *outer = (struct ip *)cursor;

	char dst4buf[INET_ADDRSTRLEN] = {0};
	inet_ntop(AF_INET, &dst4, dst4buf, sizeof(dst4buf));

	char payload[96] = {0};
	struct in6_addr inner_src = profile.scanner_inner6;
	struct in6_addr inner_dst = IN6ADDR_ANY_INIT;
	uint16_t seq = htons(1);

	int phase = probe_num % 4;
	if (phase == 0) {
		inner_dst = make_6to4_addr(dst4, 1);
		snprintf(payload, sizeof(payload), "PROBE_REF_%s_IID_1#", dst4buf);
	} else if (phase == 1) {
		inner_dst = make_6to4_addr(dst4, 0);
		snprintf(payload, sizeof(payload), "PROBE_REF_%s_IID_0#", dst4buf);
	} else if (phase == 2) {
		inner_dst = make_6to4_addr(dst4, 2);
		snprintf(payload, sizeof(payload), "PROBE_REF_%s_IID_V4#", dst4buf);
	} else {
		inner_src = profile.have_osav_spoof6 ? profile.osav_spoof6 : (pair ? pair->src6 : profile.scanner_inner6);
		inner_dst = profile.scanner_inner6;
		seq = htons(2);
		snprintf(payload, sizeof(payload), "PROBE_FWD_%s#", dst4buf);
	}

	uint16_t payload_len = (uint16_t)strlen(payload);
	uint16_t inner_len = sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + payload_len;

	make_ip_header(outer, IPPROTO_IPV6, htons(sizeof(struct ip) + inner_len));
	outer->ip_ttl = ttl;
	outer->ip_id = ip_id;
	outer->ip_src = spoof4;
	outer->ip_dst = dst4;

	struct ip6_hdr *inner6 = (struct ip6_hdr *)&outer[1];
	make_ip6_header(inner6, IPPROTO_ICMPV6,
			sizeof(struct icmp6_hdr) + payload_len);
	inner6->ip6_src = inner_src;
	inner6->ip6_dst = inner_dst;

	struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)&inner6[1];
	make_icmp6_header(icmp6);
	icmp6->icmp6_seq = seq;
	memcpy(&icmp6[1], payload, payload_len);
	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = ipv6_payload_checksum(
		sizeof(struct icmp6_hdr) + payload_len, &inner6->ip6_src,
		&inner6->ip6_dst, (unsigned short *)icmp6, IPPROTO_ICMPV6);

	outer->ip_sum = 0;
	outer->ip_sum = zmap_ip_checksum((unsigned short *)outer);

	*buf_len = sizeof(struct ether_header) + sizeof(struct ip) + inner_len;
	return EXIT_SUCCESS;
}

static const char *extract_probe_marker(const uint8_t *ptr, size_t len,
					char *out, size_t out_len)
{
	const char *m1 = "PROBE_REF_";
	const char *m2 = "PROBE_FWD_";
	for (size_t i = 0; i + 10 < len; i++) {
		const uint8_t *p = ptr + i;
		if (memcmp(p, m1, 10) != 0 && memcmp(p, m2, 10) != 0) {
			continue;
		}
		size_t j = 0;
		while (i + j < len && j + 1 < out_len) {
			char c = (char)ptr[i + j];
			if (c == '#') {
				break;
			}
			out[j++] = c;
		}
		out[j] = '\0';
		return out;
	}
	return NULL;
}

static int validate_packet(const struct ip *ip_hdr, uint32_t len, UNUSED uint32_t *src_ip,
			   UNUSED uint32_t *validation, UNUSED const struct port_conf *ports)
{
	if (ip_hdr->ip_v != 6 || len < sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)) {
		return PACKET_INVALID;
	}
	const struct ip6_hdr *ip6 = (const struct ip6_hdr *)ip_hdr;
	if (ip6->ip6_nxt != IPPROTO_ICMPV6) {
		return PACKET_INVALID;
	}
	if (memcmp(&ip6->ip6_dst, &profile.scanner_inner6, sizeof(struct in6_addr)) != 0) {
		return PACKET_INVALID;
	}
	const struct icmp6_hdr *icmp6 = (const struct icmp6_hdr *)&ip6[1];
	char payload_info[64] = {0};
	const uint8_t *payload = (const uint8_t *)(&icmp6[1]);
	size_t payload_len = len - sizeof(struct ip6_hdr) - sizeof(struct icmp6_hdr);
	if (!extract_probe_marker(payload, payload_len, payload_info, sizeof(payload_info))) {
		return PACKET_INVALID;
	}
	return PACKET_VALID;
}

static void process_packet(const u_char *packet, uint32_t len, fieldset_t *fs,
			   UNUSED uint32_t *validation, UNUSED const struct timespec ts)
{
	const struct ip6_hdr *ip6 = (const struct ip6_hdr *)&packet[sizeof(struct ether_header)];
	const struct icmp6_hdr *icmp6 = (const struct icmp6_hdr *)&ip6[1];
	const uint8_t *payload = (const uint8_t *)(&icmp6[1]);
	size_t payload_len = len > sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)
				 ? len - (sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr))
				 : 0;
	char payload_info[64] = {0};
	const char *marker = extract_probe_marker(payload, payload_len, payload_info,
					      sizeof(payload_info));
	const char *scheme = "UNKNOWN";
	char classification[] = "tunnel-reply";
	char empty_info[] = "";
	if (marker && strncmp(marker, "PROBE_REF_", 10) == 0) {
		scheme = "Reflection";
	} else if (marker && strncmp(marker, "PROBE_FWD_", 10) == 0) {
		scheme = "Forwarding";
	}

	if (fs->len >= fs->fds->len) {
		return;
	}
	if (strcmp(fs->fds->fielddefs[fs->len].name, "classification") == 0) {
		fs_add_string(fs, "classification", classification, 0);
	}
	if (fs->len < fs->fds->len && strcmp(fs->fds->fielddefs[fs->len].name, "success") == 0) {
		fs_add_uint64(fs, "success", 1);
	}
	if (fs->len < fs->fds->len && strcmp(fs->fds->fielddefs[fs->len].name, "scheme_type") == 0) {
		fs_add_string(fs, "scheme_type", (char *)scheme, 0);
	}
	if (fs->len < fs->fds->len && strcmp(fs->fds->fielddefs[fs->len].name, "payload_info") == 0) {
		fs_add_string(fs, "payload_info", marker ? payload_info : empty_info, 0);
	}
	if (fs->len < fs->fds->len && strcmp(fs->fds->fielddefs[fs->len].name, "replied_v6_src") == 0) {
		fs_add_string(fs, "replied_v6_src", make_ipv6_str((struct in6_addr *)&ip6->ip6_src), 1);
	}
}

static int module_close(UNUSED struct state_conf *conf, UNUSED struct state_send *s,
			UNUSED struct state_recv *r)
{
	tunnel_sav_common_close(&profile);
	return EXIT_SUCCESS;
}

static fielddef_t fields[] = {
	{.name = "classification", .type = "string", .desc = "response classification"},
	{.name = "success", .type = "bool", .desc = "whether response indicates SAV weakness"},
	{.name = "scheme_type", .type = "string", .desc = "Reflection or Forwarding"},
	{.name = "payload_info", .type = "string", .desc = "payload marker content"},
	{.name = "replied_v6_src", .type = "string", .desc = "captured IPv6 source"},
};

probe_module_t module_6to4_isav = {
	.name = "6to4_isav",
	.max_packet_length = 256,
	.pcap_filter = "icmp6",
	.pcap_snaplen = 256,
	.port_args = 0,
	.global_initialize = &global_initialize,
	.prepare_packet = &prepare_packet,
	.make_packet = &make_packet,
	.process_packet = &process_packet,
	.validate_packet = &validate_packet,
	.close = &module_close,
	.fields = fields,
	.numfields = sizeof(fields) / sizeof(fields[0]),
	.helptext = "6to4 isav module with dual-track probing (3 reflection IID variants + 1 forwarding) per target. Use IPv4 target input (e.g. -w targets.txt), --probes=4, and --probe-args inner_dst6=<IPv6_prober>,spoofing-address-v6=<IPv6_other>.",
};
