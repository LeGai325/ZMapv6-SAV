#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "../../lib/includes.h"
#include "../../lib/logger.h"
#include "packet.h"
#include "module_tunnel_sav_common.h"

#define UNUSED __attribute__((unused))
#define GRE_HEADER_LEN 4
#define TUN_SAV_MARKER 0x54534156U

typedef struct __attribute__((packed)) {
	uint32_t marker;
	uint32_t outer_dst4;
	struct in6_addr outer_dst6;
	uint32_t inner_src4;
	uint32_t inner_dst4;
	struct in6_addr inner_src6;
	struct in6_addr inner_dst6;
	uint32_t validation0;
	uint32_t validation1;
} tunnel_sav_payload_t;

typedef struct {
	struct in6_addr src6;
	struct in6_addr dst6;
	struct in_addr dst4;
	uint8_t has_dst4;
} tunnel_sav_send_arg_t;

typedef struct tunnel_sav_pair_entry {
	uint32_t v4_addr;
	struct in6_addr v6_addr;
	uint8_t matched;
} tunnel_sav_pair_entry_t;

static int use_osav_pair_text_payload(const tunnel_sav_profile_t *p)
{
	return p->mode == TUN_SAV_MODE_OSAV &&
	       (p->proto == TUN_SAV_PROTO_4IN6 || p->proto == TUN_SAV_PROTO_6TO4);
}

static int use_4in6_isav_pair_tracking(const tunnel_sav_profile_t *p)
{
	return p->mode == TUN_SAV_MODE_ISAV && p->proto == TUN_SAV_PROTO_4IN6 &&
	       p->outer_ipv6 && !p->inner_ipv6;
}

static int use_6to4_isav_probe_markers(const tunnel_sav_profile_t *p)
{
	return p->mode == TUN_SAV_MODE_ISAV && p->proto == TUN_SAV_PROTO_6TO4 &&
	       !p->outer_ipv6 && p->inner_ipv6;
}

static int use_6to4_osav_probe_marker(const tunnel_sav_profile_t *p)
{
	return p->mode == TUN_SAV_MODE_OSAV && p->proto == TUN_SAV_PROTO_6TO4 &&
	       !p->outer_ipv6 && p->inner_ipv6;
}

static int use_6to4_probe_marker_mode(const tunnel_sav_profile_t *p)
{
	return use_6to4_isav_probe_markers(p) || use_6to4_osav_probe_marker(p);
}

static int use_gre6_osav_minimal_payload(const tunnel_sav_profile_t *p)
{
	return p->mode == TUN_SAV_MODE_OSAV && p->proto == TUN_SAV_PROTO_GRE6 &&
	       p->outer_ipv6 && p->inner_ipv6;
}

static int use_gre_ipip_osav_minimal_payload(const tunnel_sav_profile_t *p)
{
	return p->mode == TUN_SAV_MODE_OSAV &&
	       (p->proto == TUN_SAV_PROTO_GRE || p->proto == TUN_SAV_PROTO_IPIP) &&
	       !p->outer_ipv6 && !p->inner_ipv6;
}

static uint16_t get_osav_minimal_payload_len(const tunnel_sav_profile_t *p)
{
	if (use_osav_pair_text_payload(p)) {
		return 0;
	}
	if (p->mode != TUN_SAV_MODE_OSAV) {
		return 0;
	}
	if (use_gre6_osav_minimal_payload(p) ||
	    p->proto == TUN_SAV_PROTO_IP6IP6) {
		return sizeof(struct in6_addr);
	}
	if (use_gre_ipip_osav_minimal_payload(p)) {
		return sizeof(struct in_addr);
	}
	return 0;
}


static void close_result_csv(tunnel_sav_profile_t *p)
{
	if (p->result_csv_fp) {
		fclose(p->result_csv_fp);
		p->result_csv_fp = NULL;
	}
	if (p->result_csv_lock_initialized) {
		pthread_mutex_destroy(&p->result_csv_lock);
		p->result_csv_lock_initialized = false;
	}
	if (p->result_csv_path) {
		free(p->result_csv_path);
		p->result_csv_path = NULL;
	}
}

static void close_isav_pair_table(tunnel_sav_profile_t *p)
{
	if (p->isav_pairs) {
		free(p->isav_pairs);
		p->isav_pairs = NULL;
	}
	p->isav_pair_count = 0;
	p->isav_pair_capacity = 0;
	if (p->isav_pair_lock_initialized) {
		pthread_mutex_destroy(&p->isav_pair_lock);
		p->isav_pair_lock_initialized = false;
	}
}

static void ensure_isav_pair_lock(tunnel_sav_profile_t *p)
{
	if (p->isav_pair_lock_initialized) {
		return;
	}
	if (pthread_mutex_init(&p->isav_pair_lock, NULL) != 0) {
		log_fatal(p->module_name, "unable to initialize isav pair mutex");
	}
	p->isav_pair_lock_initialized = true;
}

static long find_isav_pair_index(const tunnel_sav_profile_t *p, uint32_t v4_addr)
{
	for (size_t i = 0; i < p->isav_pair_count; i++) {
		if (p->isav_pairs[i].v4_addr == v4_addr) {
			return (long)i;
		}
	}
	return -1;
}

static void register_isav_pair(tunnel_sav_profile_t *p, struct in_addr v4,
			       struct in6_addr v6)
{
	if (!use_4in6_isav_pair_tracking(p)) {
		return;
	}
	ensure_isav_pair_lock(p);
	pthread_mutex_lock(&p->isav_pair_lock);
	if (find_isav_pair_index(p, v4.s_addr) >= 0) {
		pthread_mutex_unlock(&p->isav_pair_lock);
		return;
	}
	if (p->isav_pair_count == p->isav_pair_capacity) {
		size_t new_cap = p->isav_pair_capacity ? p->isav_pair_capacity * 2 : 1024;
		tunnel_sav_pair_entry_t *new_pairs =
			realloc(p->isav_pairs, new_cap * sizeof(*new_pairs));
		if (!new_pairs) {
			pthread_mutex_unlock(&p->isav_pair_lock);
			log_fatal(p->module_name, "unable to grow 4in6 isav pair table");
		}
		p->isav_pairs = new_pairs;
		p->isav_pair_capacity = new_cap;
	}
	p->isav_pairs[p->isav_pair_count++] = (tunnel_sav_pair_entry_t){
		.v4_addr = v4.s_addr,
		.v6_addr = v6,
		.matched = 0,
	};
	pthread_mutex_unlock(&p->isav_pair_lock);
}

static int consume_isav_pair_match(tunnel_sav_profile_t *p, uint32_t v4_addr,
				   struct in6_addr *out_v6)
{
	if (!use_4in6_isav_pair_tracking(p)) {
		return 0;
	}
	ensure_isav_pair_lock(p);
	pthread_mutex_lock(&p->isav_pair_lock);
	long idx = find_isav_pair_index(p, v4_addr);
	if (idx < 0 || p->isav_pairs[idx].matched) {
		pthread_mutex_unlock(&p->isav_pair_lock);
		return 0;
	}
	p->isav_pairs[idx].matched = 1;
	if (out_v6) {
		*out_v6 = p->isav_pairs[idx].v6_addr;
	}
	pthread_mutex_unlock(&p->isav_pair_lock);
	return 1;
}

static int is_known_isav_pair_v4(tunnel_sav_profile_t *p, uint32_t v4_addr)
{
	if (!use_4in6_isav_pair_tracking(p)) {
		return 0;
	}
	ensure_isav_pair_lock(p);
	pthread_mutex_lock(&p->isav_pair_lock);
	int known = find_isav_pair_index(p, v4_addr) >= 0;
	pthread_mutex_unlock(&p->isav_pair_lock);
	return known;
}

static int payload_to_csv_pair(const uint8_t *data, size_t data_len,
			       struct in_addr *out_v4,
			       struct in6_addr *out_v6)
{
	if (!data || !out_v4 || !out_v6 || data_len == 0 || data_len >= 256) {
		return 0;
	}
	char payload[256] = {0};
	memcpy(payload, data, data_len);
	payload[data_len] = '\0';
	char *comma = strchr(payload, ',');
	if (!comma) {
		return 0;
	}
	*comma = '\0';
	const char *v4 = payload;
	const char *v6 = comma + 1;
	if (*v4 == '\0' || *v6 == '\0') {
		return 0;
	}
	if (inet_pton(AF_INET, v4, out_v4) != 1) {
		return 0;
	}
	if (inet_pton(AF_INET6, v6, out_v6) != 1) {
		return 0;
	}
	return 1;
}

static int in6addr_is_zero(const struct in6_addr *addr);

static uint16_t build_csv_pair_payload(const tunnel_sav_send_arg_t *pair,
			       uint8_t *buf, size_t buf_len)
{
	if (!pair || !pair->has_dst4 || in6addr_is_zero(&pair->dst6) || !buf) {
		return 0;
	}
	char v4buf[INET_ADDRSTRLEN] = {0};
	char v6buf[INET6_ADDRSTRLEN] = {0};
	inet_ntop(AF_INET, &pair->dst4, v4buf, sizeof(v4buf));
	inet_ntop(AF_INET6, &pair->dst6, v6buf, sizeof(v6buf));
	int written = snprintf((char *)buf, buf_len, "%s,%s", v4buf, v6buf);
	if (written <= 0 || (size_t)written >= buf_len) {
		return 0;
	}
	return (uint16_t)written;
}

static void parse_result_csv_arg(tunnel_sav_profile_t *p, const char *key, const char *value)
{
	if (!strcmp(key, "result_csv") || !strcmp(key, "result-csv")) {
		if (p->result_csv_path) {
			free(p->result_csv_path);
		}
		p->result_csv_path = strdup(value);
	}
}

static int fs_next_is(fieldset_t *fs, const char *name)
{
	if (!fs->fds || fs->len >= fs->fds->len) {
		return 0;
	}
	return strcmp(fs->fds->fielddefs[fs->len].name, name) == 0;
}

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
	for (char *tok = strtok_r(dup, ",", &save); tok;
	     tok = strtok_r(NULL, ",", &save)) {
		char *eq = strchr(tok, '=');
		if (!eq) {
			continue;
		}
		*eq = '\0';
		char *k = tok;
		char *v = eq + 1;
		parse_result_csv_arg(p, k, v);
		if (!strcmp(k, "inner_dst4")) {
			inet_pton(AF_INET, v, &p->scanner_inner4);
		} else if (!strcmp(k, "inner_src4") || !strcmp(k, "spoof_inner4")) {
			inet_pton(AF_INET, v, &p->osav_spoof4);
		} else if (!strcmp(k, "inner_dst6")) {
			if (inet_pton(AF_INET6, v, &p->scanner_inner6) == 1) {
				p->have_inner6 = true;
			}
		} else if (!strcmp(k, "inner_src6") || !strcmp(k, "spoof_inner6") ||
			   !strcmp(k, "spoofing-address-v6")) {
			if (inet_pton(AF_INET6, v, &p->osav_spoof6) == 1) {
				p->have_osav_spoof6 = true;
			}
		}
	}
	free(dup);
}

static void fill_payload(tunnel_sav_payload_t *payload, struct in_addr outer_dst4,
			 struct in6_addr outer_dst6, struct in_addr inner_src4,
			 struct in_addr inner_dst4, struct in6_addr inner_src6,
			 struct in6_addr inner_dst6, uint32_t *validation)
{
	payload->marker = htonl(TUN_SAV_MARKER);
	payload->outer_dst4 = outer_dst4.s_addr;
	payload->outer_dst6 = outer_dst6;
	payload->inner_src4 = inner_src4.s_addr;
	payload->inner_dst4 = inner_dst4.s_addr;
	payload->inner_src6 = inner_src6;
	payload->inner_dst6 = inner_dst6;
	payload->validation0 = htonl(validation[0]);
	payload->validation1 = htonl(validation[1]);
}

static int payload_has_marker(const tunnel_sav_payload_t *payload);

static int payload_matches(const tunnel_sav_payload_t *payload, uint32_t *validation)
{
	if (!payload_has_marker(payload)) {
		return 0;
	}
	if (payload->validation0 != htonl(validation[0]) ||
	    payload->validation1 != htonl(validation[1])) {
		return 0;
	}
	return 1;
}


static int payload_has_marker(const tunnel_sav_payload_t *payload)
{
	return payload->marker == htonl(TUN_SAV_MARKER);
}

static int extract_payload_by_marker(const uint8_t *data, size_t data_len,
			   tunnel_sav_payload_t *out)
{
	if (data_len < sizeof(tunnel_sav_payload_t)) {
		return 0;
	}
	for (size_t i = 0; i + sizeof(tunnel_sav_payload_t) <= data_len; i++) {
		const tunnel_sav_payload_t *candidate =
			(const tunnel_sav_payload_t *)(data + i);
		if (payload_has_marker(candidate)) {
			memcpy(out, candidate, sizeof(*out));
			return 1;
		}
	}
	return 0;
}

static int parse_minimal_payload_v4(const struct ip *ip_hdr, uint32_t len,
				    struct in_addr *out)
{
	uint16_t ip_hl_bytes = (uint16_t)(ip_hdr->ip_hl * 4);
	if (ip_hl_bytes < sizeof(struct ip) ||
	    len < ip_hl_bytes + sizeof(struct icmp) + sizeof(struct in_addr)) {
		return 0;
	}
	const uint8_t *payload = (const uint8_t *)ip_hdr + ip_hl_bytes +
				 sizeof(struct icmp);
	memcpy(out, payload, sizeof(*out));
	return out->s_addr != 0;
}

static void make_isav_spoof_v4(struct in_addr dst, struct in_addr *out)
{
	*out = dst;
	uint32_t host = ntohl(out->s_addr);
	uint32_t d = host & 0xFFU;
	uint32_t e = (d + 1U) % 255U;
	host = (host & 0xFFFFFF00U) | e;
	out->s_addr = htonl(host);
}

static void make_isav_spoof_v6(struct in6_addr dst, struct in6_addr *out)
{
	*out = dst;
	out->s6_addr[15] = (uint8_t)((out->s6_addr[15] + 1U) % 255U);
}

static struct in_addr extract_v4_from_v6_tail(struct in6_addr v6)
{
	struct in_addr out = {0};
	memcpy(&out.s_addr, &v6.s6_addr[12], sizeof(out.s_addr));
	return out;
}

static int in6addr_is_zero(const struct in6_addr *addr)
{
	static const struct in6_addr zero = IN6ADDR_ANY_INIT;
	return memcmp(addr, &zero, sizeof(zero)) == 0;
}

static struct in6_addr make_6to4_v6_from_v4(struct in_addr dst4)
{
	struct in6_addr out = IN6ADDR_ANY_INIT;
	uint8_t *b = (uint8_t *)&dst4.s_addr;
	out.s6_addr[0] = 0x20;
	out.s6_addr[1] = 0x02;
	out.s6_addr[2] = b[0];
	out.s6_addr[3] = b[1];
	out.s6_addr[4] = b[2];
	out.s6_addr[5] = b[3];
	return out;
}

static struct in6_addr make_6to4_v6_with_iid(struct in_addr dst4, int variant)
{
	struct in6_addr out = make_6to4_v6_from_v4(dst4);
	if (variant == 0) {
		out.s6_addr[15] = 0x01; /* IID_1 */
	} else if (variant == 2) {
		uint8_t *b = (uint8_t *)&dst4.s_addr;
		out.s6_addr[12] = b[0];
		out.s6_addr[13] = b[1];
		out.s6_addr[14] = b[2];
		out.s6_addr[15] = b[3];
	}
	/* variant 1 keeps IID_0 (::) */
	return out;
}

static uint16_t build_6to4_probe_payload(const tunnel_sav_profile_t *p,
					 struct in_addr target_v4, int probe_num,
					 uint8_t *buf, size_t buf_len)
{
	if (!buf || buf_len == 0 || !use_6to4_probe_marker_mode(p)) {
		return 0;
	}
	char v4buf[INET_ADDRSTRLEN] = {0};
	inet_ntop(AF_INET, &target_v4, v4buf, sizeof(v4buf));

	int n = 0;
	if (use_6to4_isav_probe_markers(p)) {
		const int variant = ((probe_num % 4) + 4) % 4;
		if (variant == 0) {
			n = snprintf((char *)buf, buf_len, "PROBE_REF_%s_IID_1#", v4buf);
		} else if (variant == 1) {
			n = snprintf((char *)buf, buf_len, "PROBE_REF_%s_IID_0#", v4buf);
		} else if (variant == 2) {
			n = snprintf((char *)buf, buf_len, "PROBE_REF_%s_IID_V4#", v4buf);
		} else {
			n = snprintf((char *)buf, buf_len, "PROBE_FWD_%s#", v4buf);
		}
	} else if (use_6to4_osav_probe_marker(p)) {
		n = snprintf((char *)buf, buf_len, "PROBE_OSAV_%s#", v4buf);
	}
	if (n <= 0 || (size_t)n >= buf_len) {
		return 0;
	}
	return (uint16_t)n;
}

static int parse_6to4_probe_payload(const uint8_t *data, size_t len, char *out,
				    size_t out_len)
{
	if (!data || !out || out_len < 8 || len == 0) {
		return 0;
	}
	size_t i = 0;
	while (i < len && i + 1 < out_len) {
		out[i] = (char)data[i];
		if (out[i] == '#') {
			out[i + 1] = '\0';
			break;
		}
		i++;
	}
	if (i == 0 || out[0] == '\0') {
		return 0;
	}
	if (out[i] != '#') {
		out[i] = '\0';
	}
	return strncmp(out, "PROBE_REF_", 10) == 0 ||
	       strncmp(out, "PROBE_FWD_", 10) == 0 ||
	       strncmp(out, "PROBE_OSAV_", 11) == 0;
}

static void build_inner_ipv4(uint8_t *buf, struct in_addr src, struct in_addr dst,
			     struct in_addr outer_dst4,
			     struct in6_addr outer_dst6,
			     uint32_t *validation,
			     uint16_t minimal_payload_len,
			     const uint8_t *custom_payload,
			     uint16_t custom_payload_len)
{
	struct ip *inner = (struct ip *)buf;
	uint16_t icmp_payload_len = custom_payload_len
					   ? custom_payload_len
					   : (minimal_payload_len
					      ? minimal_payload_len
					      : sizeof(tunnel_sav_payload_t));
	make_ip_header(inner, IPPROTO_ICMP,
		       htons(sizeof(struct ip) + sizeof(struct icmp) +
			     icmp_payload_len));
	inner->ip_src = src;
	inner->ip_dst = dst;
	inner->ip_sum = 0;
	inner->ip_sum = zmap_ip_checksum((unsigned short *)inner);

	struct icmp *icmp = (struct icmp *)&inner[1];
	make_icmp_header(icmp);
	if (custom_payload_len) {
		icmp->icmp_id = htons(1234);
		icmp->icmp_seq = htons(1);
		memcpy(&icmp[1], custom_payload, custom_payload_len);
	} else if (minimal_payload_len) {
		icmp->icmp_id = htons(1234);
		icmp->icmp_seq = htons(1);
		if (minimal_payload_len == sizeof(struct in6_addr)) {
			struct in6_addr *payload6 = (struct in6_addr *)(&icmp[1]);
			*payload6 = outer_dst6;
		} else {
			struct in_addr *payload4 = (struct in_addr *)(&icmp[1]);
			*payload4 = outer_dst4;
		}
	} else {
		icmp->icmp_id = htons(validation[2] & 0xFFFF);

		tunnel_sav_payload_t *payload = (tunnel_sav_payload_t *)(&icmp[1]);
		fill_payload(payload, outer_dst4, outer_dst6, src,
			     dst, (struct in6_addr)IN6ADDR_ANY_INIT,
			     (struct in6_addr)IN6ADDR_ANY_INIT, validation);
	}

	icmp->icmp_cksum = 0;
	icmp->icmp_cksum =
		icmp_checksum((unsigned short *)icmp,
			      sizeof(struct icmp) + icmp_payload_len);
}

static void build_inner_ipv6(uint8_t *buf, struct in6_addr src,
			     struct in6_addr dst,
			     struct in_addr outer_dst4,
			     struct in6_addr outer_dst6,
			     struct in_addr payload_inner_src4,
			     struct in_addr payload_inner_dst4,
			     uint32_t *validation,
			     uint16_t minimal_payload_len,
			     const uint8_t *custom_payload,
			     uint16_t custom_payload_len)
{
	struct ip6_hdr *inner = (struct ip6_hdr *)buf;
	uint16_t icmp_payload_len = custom_payload_len
					   ? custom_payload_len
					   : (minimal_payload_len
					      ? minimal_payload_len
					      : sizeof(tunnel_sav_payload_t));
	make_ip6_header(inner, IPPROTO_ICMPV6,
			sizeof(struct icmp6_hdr) + icmp_payload_len);
	inner->ip6_src = src;
	inner->ip6_dst = dst;

	struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)&inner[1];
	make_icmp6_header(icmp6);
	if (custom_payload_len) {
		icmp6->icmp6_id = 0;
		icmp6->icmp6_seq = 0;
		memcpy(&icmp6[1], custom_payload, custom_payload_len);
	} else if (minimal_payload_len) {
		icmp6->icmp6_id = 0;
		icmp6->icmp6_seq = 0;
		if (minimal_payload_len == sizeof(struct in6_addr)) {
			struct in6_addr *payload6 = (struct in6_addr *)(&icmp6[1]);
			*payload6 = outer_dst6;
		} else {
			struct in_addr *payload4 = (struct in_addr *)(&icmp6[1]);
			*payload4 = outer_dst4;
		}
	} else {
		icmp6->icmp6_id = htons(validation[2] & 0xFFFF);

		tunnel_sav_payload_t *payload = (tunnel_sav_payload_t *)(&icmp6[1]);
		fill_payload(payload, outer_dst4, outer_dst6, payload_inner_src4,
			     payload_inner_dst4, src, dst, validation);
	}

	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = ipv6_payload_checksum(
		sizeof(struct icmp6_hdr) + icmp_payload_len, &inner->ip6_src,
		&inner->ip6_dst, (unsigned short *)icmp6, IPPROTO_ICMPV6);
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
	p->spoof_match_count = 0;
	p->csv_write_count = 0;
	if (p->result_csv_path && !p->result_csv_fp) {
		p->result_csv_fp = fopen(p->result_csv_path, "a+");
		if (!p->result_csv_fp) {
			log_fatal(p->module_name, "unable to open result csv %s: %s",
				  p->result_csv_path, strerror(errno));
		}
		if (pthread_mutex_init(&p->result_csv_lock, NULL) != 0) {
			log_fatal(p->module_name, "unable to initialize result csv mutex");
		}
		p->result_csv_lock_initialized = true;
		if (fseek(p->result_csv_fp, 0, SEEK_END) == 0 && ftell(p->result_csv_fp) == 0) {
			if (use_6to4_probe_marker_mode(p)) {
				fprintf(p->result_csv_fp, "scheme_type,payload_info,captured_v6_src\n");
			} else {
				fprintf(p->result_csv_fp, "ipv4,ipv6\n");
			}
			fflush(p->result_csv_fp);
		}
	}

	if (use_4in6_isav_pair_tracking(p)) {
		char local4buf[INET_ADDRSTRLEN] = {0};
		inet_ntop(AF_INET, &p->scanner_inner4, local4buf, sizeof(local4buf));
		asprintf((char **)&module->pcap_filter, "icmp and dst host %s", local4buf);
		return EXIT_SUCCESS;
	}

	if (use_6to4_probe_marker_mode(p)) {
		char dst6buf[INET6_ADDRSTRLEN] = {0};
		inet_ntop(AF_INET6, &p->scanner_inner6, dst6buf, sizeof(dst6buf));
		if (use_6to4_osav_probe_marker(p) && p->have_osav_spoof6) {
			char src6buf[INET6_ADDRSTRLEN] = {0};
			inet_ntop(AF_INET6, &p->osav_spoof6, src6buf, sizeof(src6buf));
			asprintf((char **)&module->pcap_filter,
				 "icmp6 and dst host %s and src host %s", dst6buf, src6buf);
		} else {
			asprintf((char **)&module->pcap_filter, "icmp6 and dst host %s",
				 dst6buf);
		}
		return EXIT_SUCCESS;
	}

	if (use_osav_pair_text_payload(p)) {
		if (p->proto == TUN_SAV_PROTO_4IN6) {
			char spoof4buf[INET_ADDRSTRLEN] = {0};
			char local4buf[INET_ADDRSTRLEN] = {0};
			inet_ntop(AF_INET, &p->osav_spoof4, spoof4buf, sizeof(spoof4buf));
			inet_ntop(AF_INET, &p->scanner_inner4, local4buf, sizeof(local4buf));
			asprintf((char **)&module->pcap_filter,
				 "icmp and src host %s and dst host %s", spoof4buf, local4buf);
		} else {
			char local6buf[INET6_ADDRSTRLEN] = {0};
			inet_ntop(AF_INET6, &p->scanner_inner6, local6buf, sizeof(local6buf));
			if (p->have_osav_spoof6) {
				char spoof6buf[INET6_ADDRSTRLEN] = {0};
				inet_ntop(AF_INET6, &p->osav_spoof6, spoof6buf, sizeof(spoof6buf));
				asprintf((char **)&module->pcap_filter,
					 "icmp6 and src host %s and dst host %s", spoof6buf,
					 local6buf);
			} else {
				asprintf((char **)&module->pcap_filter,
					 "icmp6 and dst host %s", local6buf);
			}
		}
		return EXIT_SUCCESS;
	}

	if (!p->outer_ipv6) {
		if (p->mode == TUN_SAV_MODE_OSAV) {
			char ipbuf[INET_ADDRSTRLEN] = {0};
			inet_ntop(AF_INET, &p->osav_spoof4, ipbuf, sizeof(ipbuf));
			asprintf((char **)&module->pcap_filter,
				 "icmp and src host %s", ipbuf);
		} else {
			asprintf((char **)&module->pcap_filter, "icmp");
		}
	} else {
		if (p->mode == TUN_SAV_MODE_OSAV && p->have_osav_spoof6) {
			char ip6buf[INET6_ADDRSTRLEN] = {0};
			inet_ntop(AF_INET6, &p->osav_spoof6, ip6buf, sizeof(ip6buf));
			asprintf((char **)&module->pcap_filter,
				 "icmp6 and src host %s", ip6buf);
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
				  int probe_num, uint16_t ip_id,
				  void *arg)
{
	struct ether_header *eth = (struct ether_header *)buf;
	uint8_t *cursor = (uint8_t *)&eth[1];
	struct in6_addr any6 = IN6ADDR_ANY_INIT;
	tunnel_sav_send_arg_t *pair = (tunnel_sav_send_arg_t *)arg;
	uint8_t csv_pair_payload[256] = {0};
	uint16_t csv_pair_payload_len = 0;
	uint8_t marker_payload[256] = {0};
	uint16_t marker_payload_len = 0;
	uint16_t minimal_payload_len = get_osav_minimal_payload_len(p);
	if (use_6to4_probe_marker_mode(p)) {
		struct in_addr target_v4 = {.s_addr = dst_ip};
		marker_payload_len = build_6to4_probe_payload(
			p, target_v4, probe_num, marker_payload, sizeof(marker_payload));
	}
	if (use_osav_pair_text_payload(p)) {
		csv_pair_payload_len =
			build_csv_pair_payload(pair, csv_pair_payload, sizeof(csv_pair_payload));
	}
	uint16_t payload_data_len =
		marker_payload_len
			? marker_payload_len
			: (csv_pair_payload_len
			? csv_pair_payload_len
			: (minimal_payload_len ? minimal_payload_len : sizeof(tunnel_sav_payload_t)));
	const uint8_t *custom_payload = marker_payload_len ? marker_payload : csv_pair_payload;
	uint16_t custom_payload_len = marker_payload_len ? marker_payload_len : csv_pair_payload_len;
	if (!p->outer_ipv6) {
		if (p->proto == TUN_SAV_PROTO_6TO4 && dst_ip == 0) {
			return EXIT_FAILURE;
		}
		uint16_t inner_len =
			p->inner_ipv6
				? (sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) +
				   payload_data_len)
				: (sizeof(struct ip) + sizeof(struct icmp) +
				   payload_data_len);
		uint16_t total_outer_payload =
			inner_len +
			((p->proto == TUN_SAV_PROTO_GRE) ? GRE_HEADER_LEN : 0);
		struct ip *outer = (struct ip *)cursor;
		make_ip_header(outer,
			       (p->proto == TUN_SAV_PROTO_GRE)
				       ? IPPROTO_GRE
				       : ((p->proto == TUN_SAV_PROTO_6TO4) ? IPPROTO_IPV6
								     : IPPROTO_IPIP),
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
			cursor[0] = 0;
			cursor[1] = 0;
			cursor[2] = 0x08;
			cursor[3] = 0x00;
			cursor += GRE_HEADER_LEN;
		}
		if (p->inner_ipv6) {
			struct in6_addr src6 = p->scanner_inner6;
			struct in6_addr dst6 = p->scanner_inner6;
			if (use_6to4_isav_probe_markers(p)) {
				int variant = ((probe_num % 4) + 4) % 4;
				if (variant == 3) {
					src6 = p->have_osav_spoof6 ? p->osav_spoof6 : p->scanner_inner6;
					dst6 = p->scanner_inner6;
				} else {
					src6 = p->scanner_inner6;
					dst6 = make_6to4_v6_with_iid(outer->ip_dst, variant);
				}
			} else if (p->mode == TUN_SAV_MODE_ISAV && p->proto == TUN_SAV_PROTO_6TO4) {
				if (pair && !in6addr_is_zero(&pair->dst6)) {
					src6 = pair->dst6;
				} else {
					src6 = make_6to4_v6_from_v4(outer->ip_dst);
				}
			} else if (p->mode == TUN_SAV_MODE_OSAV && p->have_osav_spoof6) {
				src6 = p->osav_spoof6;
			}
			if (use_6to4_osav_probe_marker(p)) {
				dst6 = p->scanner_inner6;
			} else if (p->proto == TUN_SAV_PROTO_6TO4) {
				dst6 = p->scanner_inner6;
			}
			struct in6_addr payload_dst6 = any6;
			if (p->proto == TUN_SAV_PROTO_6TO4 && pair) {
				payload_dst6 = pair->dst6;
			}
			build_inner_ipv6(cursor, src6, dst6, outer->ip_dst,
					 payload_dst6, p->osav_spoof4,
					 p->scanner_inner4, validation,
					 minimal_payload_len, custom_payload,
					 custom_payload_len);
		} else {
			struct in_addr src4;
			struct in_addr dst4 = p->scanner_inner4;
			if (p->mode == TUN_SAV_MODE_ISAV &&
			    (p->proto == TUN_SAV_PROTO_IPIP ||
			     p->proto == TUN_SAV_PROTO_GRE)) {
				src4 = outer->ip_dst;
			} else {
				src4 = p->osav_spoof4;
			}
			if (minimal_payload_len) {
				dst4 = outer->ip_src;
			} else if (p->mode == TUN_SAV_MODE_OSAV) {
				dst4 = outer->ip_dst;
			}
			build_inner_ipv4(cursor, src4, dst4, outer->ip_dst,
					 any6, validation, minimal_payload_len,
					 custom_payload, custom_payload_len);
		}
		outer->ip_sum = 0;
		outer->ip_sum = zmap_ip_checksum((unsigned short *)outer);
		*buf_len = sizeof(struct ether_header) + sizeof(struct ip) +
			   total_outer_payload;
	} else {
		int minimal_payload = use_gre6_osav_minimal_payload(p);
		uint16_t inner_len =
			p->inner_ipv6
				? (sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) +
				   payload_data_len)
				: (sizeof(struct ip) + sizeof(struct icmp) +
				   payload_data_len);
		uint16_t payload_len =
			inner_len +
			((p->proto == TUN_SAV_PROTO_GRE6) ? GRE_HEADER_LEN : 0);
		struct ip6_hdr *outer = (struct ip6_hdr *)cursor;
		make_ip6_header(outer,
				(p->proto == TUN_SAV_PROTO_GRE6)
					? IPPROTO_GRE
					: ((p->proto == TUN_SAV_PROTO_4IN6)
						   ? IPPROTO_IPIP
						   : IPPROTO_IPV6),
				payload_len);
		outer->ip6_ctlun.ip6_un1.ip6_un1_hlim = ttl;
		outer->ip6_dst = pair->dst6;
		if (p->mode == TUN_SAV_MODE_ISAV) {
			make_isav_spoof_v6(pair->dst6, &outer->ip6_src);
		} else {
			outer->ip6_src = pair->src6;
		}
		cursor = (uint8_t *)&outer[1];
		if (p->proto == TUN_SAV_PROTO_GRE6) {
			cursor[0] = 0;
			cursor[1] = 0;
			cursor[2] = p->inner_ipv6 ? 0x86 : 0x08;
			cursor[3] = p->inner_ipv6 ? 0xDD : 0x00;
			cursor += GRE_HEADER_LEN;
		}
		if (p->inner_ipv6) {
			struct in6_addr src6 = p->scanner_inner6;
			struct in6_addr dst6 = p->scanner_inner6;
			if (p->mode == TUN_SAV_MODE_ISAV &&
			    (p->proto == TUN_SAV_PROTO_IP6IP6 ||
			     p->proto == TUN_SAV_PROTO_GRE6)) {
				src6 = outer->ip6_dst;
			} else if (p->mode == TUN_SAV_MODE_OSAV && p->have_osav_spoof6) {
				src6 = p->osav_spoof6;
			}
			if (minimal_payload_len) {
				dst6 = outer->ip6_src;
			} else if (p->mode == TUN_SAV_MODE_OSAV) {
				dst6 = outer->ip6_dst;
			}
			build_inner_ipv6(cursor, src6, dst6,
					 pair->has_dst4 ? pair->dst4 : (struct in_addr){0},
					 outer->ip6_dst, p->osav_spoof4,
					 p->scanner_inner4, validation,
					 minimal_payload_len, custom_payload,
					 custom_payload_len);
		} else {
			struct in_addr src4 = p->osav_spoof4;
			struct in_addr dst4 = p->scanner_inner4;
			if (p->mode == TUN_SAV_MODE_ISAV &&
			    p->proto == TUN_SAV_PROTO_4IN6) {
				if (pair && pair->has_dst4) {
					src4 = pair->dst4;
				} else {
					src4 = extract_v4_from_v6_tail(outer->ip6_dst);
				}
			}
			if (minimal_payload_len) {
				dst4 = extract_v4_from_v6_tail(outer->ip6_src);
			}
			build_inner_ipv4(cursor, src4, dst4,
					 pair->has_dst4 ? pair->dst4 : (struct in_addr){0},
					 outer->ip6_dst, validation, minimal_payload_len,
					 custom_payload, custom_payload_len);
			if (use_4in6_isav_pair_tracking(p) && pair && pair->has_dst4) {
				register_isav_pair(p, pair->dst4, pair->dst6);
				struct ip *inner4 = (struct ip *)cursor;
				struct icmp *inner_icmp = (struct icmp *)&inner4[1];
				inner_icmp->icmp_id = htons(1234);
				inner_icmp->icmp_seq = htons((uint16_t)(probe_num + 1));
				inner_icmp->icmp_cksum = 0;
				inner_icmp->icmp_cksum =
					icmp_checksum((unsigned short *)inner_icmp,
						      sizeof(struct icmp));
			}
		}
		*buf_len = sizeof(struct ether_header) + sizeof(struct ip6_hdr) +
			   payload_len;
	}
	return EXIT_SUCCESS;
}

int tunnel_sav_common_validate_packet(tunnel_sav_profile_t *p,
				      const struct ip *ip_hdr,
				      uint32_t len, uint32_t *src_ip,
				      uint32_t *validation,
				      UNUSED const struct port_conf *ports)
{
	if (p->inner_ipv6) {
		if (use_6to4_probe_marker_mode(p)) {
			if (len < sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) ||
			    ip_hdr->ip_v != 6) {
				return PACKET_INVALID;
			}
			const struct ip6_hdr *ip6 = (const struct ip6_hdr *)ip_hdr;
			if (ip6->ip6_nxt != IPPROTO_ICMPV6) {
				return PACKET_INVALID;
			}
			const struct icmp6_hdr *icmp6 = (const struct icmp6_hdr *)&ip6[1];
			if (icmp6->icmp6_type != ICMP6_ECHO_REQUEST) {
				return PACKET_INVALID;
			}
			size_t payload_off = sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr);
			if (len <= payload_off) {
				return PACKET_INVALID;
			}
			char payload_info[64] = {0};
			if (!parse_6to4_probe_payload((const uint8_t *)ip_hdr + payload_off,
						      len - payload_off, payload_info,
						      sizeof(payload_info))) {
				return PACKET_INVALID;
			}
			return PACKET_VALID;
		}
		if (use_osav_pair_text_payload(p)) {
			if (len < sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) ||
			    ip_hdr->ip_v != 6) {
				return PACKET_INVALID;
			}
			const struct ip6_hdr *ip6 = (const struct ip6_hdr *)ip_hdr;
			if (ip6->ip6_nxt != IPPROTO_ICMPV6) {
				return PACKET_INVALID;
			}
			const struct icmp6_hdr *icmp6 = (const struct icmp6_hdr *)&ip6[1];
			if (icmp6->icmp6_type != ICMP6_ECHO_REQUEST) {
				return PACKET_INVALID;
			}
			if (p->have_osav_spoof6 &&
			    memcmp(&ip6->ip6_src, &p->osav_spoof6, sizeof(struct in6_addr)) != 0) {
				return PACKET_INVALID;
			}
			return PACKET_VALID;
		}
		uint16_t minimal_payload_len = get_osav_minimal_payload_len(p);
		if (minimal_payload_len) {
			if (len < sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) +
					  minimal_payload_len) {
				return PACKET_INVALID;
			}
			struct ip6_hdr *ip6 = (struct ip6_hdr *)ip_hdr;
			if (ip6->ip6_nxt != IPPROTO_ICMPV6) {
				return PACKET_INVALID;
			}
			return PACKET_VALID;
		}
		if (len < sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) +
			      sizeof(tunnel_sav_payload_t)) {
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
		tunnel_sav_payload_t payload = {0};
		if (!extract_payload_by_marker((const uint8_t *)&icmp6[1],
				       len - (sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)),
				       &payload) ||
		    !payload_matches(&payload, validation)) {
			return PACKET_INVALID;
		}
		return PACKET_VALID;
	}

	uint16_t minimal_payload_len = get_osav_minimal_payload_len(p);
	if (use_4in6_isav_pair_tracking(p)) {
		uint16_t ip_hl_bytes = (uint16_t)(ip_hdr->ip_hl * 4);
		if (ip_hl_bytes < sizeof(struct ip) ||
		    len < ip_hl_bytes + sizeof(struct icmp) ||
		    ip_hdr->ip_p != IPPROTO_ICMP ||
		    ip_hdr->ip_dst.s_addr != p->scanner_inner4.s_addr) {
			return PACKET_INVALID;
		}
		const struct icmp *icmp =
			(const struct icmp *)((const char *)ip_hdr + ip_hl_bytes);
		if (icmp->icmp_type != ICMP_ECHO ||
		    !is_known_isav_pair_v4(p, ip_hdr->ip_src.s_addr)) {
			return PACKET_INVALID;
		}
		if (src_ip) {
			*src_ip = ip_hdr->ip_src.s_addr;
		}
		return PACKET_VALID;
	}
	if (use_osav_pair_text_payload(p)) {
		uint16_t ip_hl_bytes = (uint16_t)(ip_hdr->ip_hl * 4);
		if (ip_hl_bytes < sizeof(struct ip) ||
		    len < ip_hl_bytes + sizeof(struct icmp) ||
		    ip_hdr->ip_p != IPPROTO_ICMP ||
		    ip_hdr->ip_src.s_addr != p->osav_spoof4.s_addr ||
		    ip_hdr->ip_dst.s_addr != p->scanner_inner4.s_addr) {
			return PACKET_INVALID;
		}
		const struct icmp *icmp =
			(const struct icmp *)((const char *)ip_hdr + ip_hl_bytes);
		if (icmp->icmp_type != ICMP_ECHO) {
			return PACKET_INVALID;
		}
		return PACKET_VALID;
	}
	if (minimal_payload_len) {
		uint16_t ip_hl_bytes = (uint16_t)(ip_hdr->ip_hl * 4);
		if (ip_hl_bytes < sizeof(struct ip)) {
			return PACKET_INVALID;
		}
		if (len < ip_hl_bytes + sizeof(struct icmp) + minimal_payload_len) {
			return PACKET_INVALID;
		}
		if (ip_hdr->ip_p != IPPROTO_ICMP) {
			return PACKET_INVALID;
		}
		if (use_gre_ipip_osav_minimal_payload(p) &&
		    ip_hdr->ip_src.s_addr != p->osav_spoof4.s_addr) {
			return PACKET_INVALID;
		}
		if (use_gre_ipip_osav_minimal_payload(p)) {
			struct icmp *icmp =
				(struct icmp *)((char *)ip_hdr + ip_hl_bytes);
			if (icmp->icmp_id != htons(1234) ||
			    icmp->icmp_seq != htons(1)) {
				return PACKET_INVALID;
			}
			struct in_addr payload_v4 = {0};
			if (!parse_minimal_payload_v4(ip_hdr, len, &payload_v4)) {
				return PACKET_INVALID;
			}
			if (src_ip) {
				*src_ip = payload_v4.s_addr;
			}
		}
		return PACKET_VALID;
	}

	if (len < sizeof(struct ip) + sizeof(struct icmp) +
		      sizeof(tunnel_sav_payload_t)) {
		return PACKET_INVALID;
	}
	if (ip_hdr->ip_p != IPPROTO_ICMP) {
		return PACKET_INVALID;
	}
	struct icmp *icmp = (struct icmp *)((char *)ip_hdr + ip_hdr->ip_hl * 4);
	if (icmp->icmp_id != htons(validation[2] & 0xFFFF)) {
		return PACKET_INVALID;
	}
	tunnel_sav_payload_t payload = {0};
	if (!extract_payload_by_marker((const uint8_t *)&icmp[1],
			       len - (ip_hdr->ip_hl * 4 + sizeof(struct icmp)),
			       &payload) ||
	    !payload_matches(&payload, validation)) {
		return PACKET_INVALID;
	}
	return PACKET_VALID;
}


static int is_spoof_source_match(const tunnel_sav_profile_t *p, const u_char *packet)
{
	const uint8_t *ip_ptr = packet + sizeof(struct ether_header);
	if (p->outer_ipv6) {
		const struct ip6_hdr *ip6 = (const struct ip6_hdr *)ip_ptr;
		if (!p->have_osav_spoof6) {
			return 0;
		}
		return memcmp(&ip6->ip6_src, &p->osav_spoof6, sizeof(struct in6_addr)) == 0;
	}
	const struct ip *ip4 = (const struct ip *)ip_ptr;
	return ip4->ip_src.s_addr == p->osav_spoof4.s_addr;
}

static int payload_inner4_matches_profile(const tunnel_sav_profile_t *p,
					 const tunnel_sav_payload_t *payload)
{
	return payload->inner_src4 == p->osav_spoof4.s_addr &&
	       payload->inner_dst4 == p->scanner_inner4.s_addr;
}

static void maybe_record_payload_pair(tunnel_sav_profile_t *p,
				      const tunnel_sav_payload_t *payload,
				      int have_payload,
				      const u_char *packet)
{
	if (p->mode != TUN_SAV_MODE_OSAV || p->proto != TUN_SAV_PROTO_4IN6 && p->proto != TUN_SAV_PROTO_6TO4) {
		return;
	}
	if (!p->result_csv_fp || !have_payload) {
		return;
	}
	if (!is_spoof_source_match(p, packet)) {
		return;
	}
	if (!payload_inner4_matches_profile(p, payload)) {
		return;
	}
	char v4buf[INET_ADDRSTRLEN] = {0};
	char v6buf[INET6_ADDRSTRLEN] = {0};
	struct in_addr v4 = {.s_addr = payload->outer_dst4};
	inet_ntop(AF_INET, &v4, v4buf, sizeof(v4buf));
	inet_ntop(AF_INET6, &payload->outer_dst6, v6buf, sizeof(v6buf));

	pthread_mutex_lock(&p->result_csv_lock);
	if (fprintf(p->result_csv_fp, "%s,%s\n", v4buf, v6buf) > 0) {
		fflush(p->result_csv_fp);
		p->spoof_match_count++;
		p->csv_write_count++;
		log_info(p->module_name, "spoof_match_count=%" PRIu64 " csv_write_count=%" PRIu64 " wrote=%s,%s",
			 p->spoof_match_count, p->csv_write_count, v4buf, v6buf);
	} else {
		log_error(p->module_name, "failed writing result csv %s", p->result_csv_path ? p->result_csv_path : "(null)");
	}
	pthread_mutex_unlock(&p->result_csv_lock);
}

static void maybe_record_csv_payload_pair(tunnel_sav_profile_t *p,
					  const struct in_addr *payload_v4,
					  const struct in6_addr *payload_v6,
					  int have_pair,
					  const u_char *packet)
{
	if (!use_osav_pair_text_payload(p) || !have_pair || !is_spoof_source_match(p, packet)) {
		return;
	}
	p->spoof_match_count++;
	if (!p->result_csv_fp) {
		return;
	}
	char v4buf[INET_ADDRSTRLEN] = {0};
	char v6buf[INET6_ADDRSTRLEN] = {0};
	inet_ntop(AF_INET, payload_v4, v4buf, sizeof(v4buf));
	inet_ntop(AF_INET6, payload_v6, v6buf, sizeof(v6buf));

	pthread_mutex_lock(&p->result_csv_lock);
	if (fprintf(p->result_csv_fp, "%s,%s\n", v4buf, v6buf) > 0) {
		fflush(p->result_csv_fp);
		p->csv_write_count++;
		log_info(p->module_name,
			 "recv_count=%" PRIu64 " csv_write_count=%" PRIu64 " wrote=%s,%s",
			 p->spoof_match_count, p->csv_write_count, v4buf, v6buf);
	}
	pthread_mutex_unlock(&p->result_csv_lock);
}

static void maybe_record_4in6_isav_pair(tunnel_sav_profile_t *p, const u_char *packet)
{
	if (!use_4in6_isav_pair_tracking(p)) {
		return;
	}
	const struct ip *ip4 =
		(const struct ip *)(packet + sizeof(struct ether_header));
	if (ip4->ip_p != IPPROTO_ICMP ||
	    ip4->ip_dst.s_addr != p->scanner_inner4.s_addr) {
		return;
	}
	uint16_t ip_hl_bytes = (uint16_t)(ip4->ip_hl * 4);
	const struct icmp *icmp = (const struct icmp *)((const uint8_t *)ip4 + ip_hl_bytes);
	if (icmp->icmp_type != ICMP_ECHO) {
		return;
	}
	struct in6_addr matched_v6 = IN6ADDR_ANY_INIT;
	if (!consume_isav_pair_match(p, ip4->ip_src.s_addr, &matched_v6)) {
		return;
	}
	p->spoof_match_count++;
	if (!p->result_csv_fp) {
		return;
	}
	char v4buf[INET_ADDRSTRLEN] = {0};
	char v6buf[INET6_ADDRSTRLEN] = {0};
	struct in_addr v4 = {.s_addr = ip4->ip_src.s_addr};
	inet_ntop(AF_INET, &v4, v4buf, sizeof(v4buf));
	inet_ntop(AF_INET6, &matched_v6, v6buf, sizeof(v6buf));

	pthread_mutex_lock(&p->result_csv_lock);
	if (fprintf(p->result_csv_fp, "%s,%s\n", v4buf, v6buf) > 0) {
		fflush(p->result_csv_fp);
		p->csv_write_count++;
		log_info(p->module_name,
			 "recv_count=%" PRIu64 " csv_write_count=%" PRIu64 " wrote=%s,%s",
			 p->spoof_match_count, p->csv_write_count, v4buf, v6buf);
	}
	pthread_mutex_unlock(&p->result_csv_lock);
}

static void maybe_record_6to4_probe_marker(tunnel_sav_profile_t *p,
					   const u_char *packet, uint32_t len)
{
	if (!use_6to4_probe_marker_mode(p) || !p->result_csv_fp) {
		return;
	}
	if (len < sizeof(struct ether_header) + sizeof(struct ip6_hdr) +
		      sizeof(struct icmp6_hdr)) {
		return;
	}
	const struct ip6_hdr *ip6 =
		(const struct ip6_hdr *)(packet + sizeof(struct ether_header));
	const struct icmp6_hdr *icmp6 = (const struct icmp6_hdr *)&ip6[1];
	if (icmp6->icmp6_type != ICMP6_ECHO_REQUEST) {
		return;
	}
	size_t payload_off =
		sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr);
	char payload_info[64] = {0};
	if (!parse_6to4_probe_payload(packet + payload_off, len - payload_off, payload_info,
				      sizeof(payload_info))) {
		return;
	}
	const char *scheme_type = "UNKNOWN";
	if (strncmp(payload_info, "PROBE_REF_", 10) == 0) {
		scheme_type = "Reflection";
	} else if (strncmp(payload_info, "PROBE_FWD_", 10) == 0) {
		scheme_type = "Forwarding";
	} else if (strncmp(payload_info, "PROBE_OSAV_", 11) == 0) {
		scheme_type = "OSAV";
	}

	char v6_src[INET6_ADDRSTRLEN] = {0};
	inet_ntop(AF_INET6, &ip6->ip6_src, v6_src, sizeof(v6_src));

	pthread_mutex_lock(&p->result_csv_lock);
	if (fprintf(p->result_csv_fp, "%s,%s,%s\n", scheme_type, payload_info, v6_src) > 0) {
		fflush(p->result_csv_fp);
		p->spoof_match_count++;
		p->csv_write_count++;
	}
	pthread_mutex_unlock(&p->result_csv_lock);
}

void tunnel_sav_common_process_packet(tunnel_sav_profile_t *p,
				      const u_char *packet,
				      uint32_t len, fieldset_t *fs,
				      UNUSED uint32_t *validation,
				      UNUSED const struct timespec ts)
{
	const char *cls = "tunnel-request";
	char *response_src = NULL;
	char *original_target = NULL;
	uint64_t icmp_type = 0;
	int have_icmp_type = 0;
	uint16_t minimal_payload_len = get_osav_minimal_payload_len(p);
	tunnel_sav_payload_t payload = {0};
	int have_payload = 0;
	struct in_addr csv_payload_v4 = {0};
	struct in6_addr csv_payload_v6 = IN6ADDR_ANY_INIT;
	int have_csv_pair = 0;
	if (p->inner_ipv6) {
		struct ip6_hdr *ip6 =
			(struct ip6_hdr *)&packet[sizeof(struct ether_header)];
		struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)&ip6[1];
		have_icmp_type = 1;
		icmp_type = icmp6->icmp6_type;
		if (icmp6->icmp6_type == ICMP6_ECHO_REPLY) {
			cls = "tunnel-reply";
		} else if (icmp6->icmp6_type == ICMP6_TIME_EXCEEDED) {
			cls = "tunnel-timxceed";
		}
		response_src = make_ipv6_str(&ip6->ip6_src);
		if (use_osav_pair_text_payload(p)) {
			size_t offset = sizeof(struct ether_header) + sizeof(struct ip6_hdr) +
				       sizeof(struct icmp6_hdr);
			if (len > offset) {
				have_csv_pair = payload_to_csv_pair(&packet[offset], len - offset,
							    &csv_payload_v4,
							    &csv_payload_v6);
				if (have_csv_pair) {
					have_payload = 1;
					payload.outer_dst4 = csv_payload_v4.s_addr;
					payload.outer_dst6 = csv_payload_v6;
				}
			}
		} else if (minimal_payload_len) {
			size_t offset = sizeof(struct ether_header) + sizeof(struct ip6_hdr) +
				       sizeof(struct icmp6_hdr);
			if (len >= offset + minimal_payload_len) {
				if (p->outer_ipv6) {
					struct in6_addr original_target6 = {0};
					memcpy(&original_target6, &packet[offset],
					       sizeof(original_target6));
					original_target = make_ipv6_str(&original_target6);
				} else {
					struct in_addr original_target4 = {0};
					memcpy(&original_target4, &packet[offset],
					       sizeof(original_target4));
					original_target = make_ip_str(original_target4.s_addr);
				}
			}
		} else {
			have_payload = extract_payload_by_marker((const uint8_t *)&icmp6[1],
						       len > sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)
							       ? len - (sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr))
							       : 0,
						       &payload);
		}
	} else {
		struct ip *ip4 = (struct ip *)&packet[sizeof(struct ether_header)];
		struct icmp *icmp = (struct icmp *)((char *)ip4 + ip4->ip_hl * 4);
		int use_minimal_v4 = use_gre_ipip_osav_minimal_payload(p);
		have_icmp_type = 1;
		icmp_type = icmp->icmp_type;
		if (icmp->icmp_type == ICMP_ECHOREPLY) {
			cls = "tunnel-reply";
		} else if (icmp->icmp_type == ICMP_TIMXCEED) {
			cls = "tunnel-timxceed";
		}
		response_src = make_ip_str(ip4->ip_src.s_addr);
		if (use_osav_pair_text_payload(p)) {
			size_t offset = sizeof(struct ether_header) + ip4->ip_hl * 4 +
				       sizeof(struct icmp);
			if (len > offset) {
				have_csv_pair = payload_to_csv_pair(&packet[offset], len - offset,
							    &csv_payload_v4,
							    &csv_payload_v6);
				if (have_csv_pair) {
					have_payload = 1;
					payload.outer_dst4 = csv_payload_v4.s_addr;
					payload.outer_dst6 = csv_payload_v6;
					original_target = p->outer_ipv6
						? make_ipv6_str(&csv_payload_v6)
						: make_ip_str(csv_payload_v4.s_addr);
				}
			}
		} else if (minimal_payload_len &&
		    (!use_minimal_v4 || ip4->ip_src.s_addr == p->osav_spoof4.s_addr)) {
			size_t offset = sizeof(struct ether_header) + ip4->ip_hl * 4 +
				       sizeof(struct icmp);
			if (len >= offset + minimal_payload_len) {
				if (p->outer_ipv6) {
					struct in6_addr original_target6 = {0};
					memcpy(&original_target6, &packet[offset],
					       sizeof(original_target6));
					original_target = make_ipv6_str(&original_target6);
				} else {
					struct in_addr original_target4 = {0};
					memcpy(&original_target4, &packet[offset],
					       sizeof(original_target4));
					original_target = make_ip_str(original_target4.s_addr);
					if (use_minimal_v4) {
						have_payload = 1;
						payload.outer_dst4 = original_target4.s_addr;
					}
				}
			}
		} else {
			have_payload = extract_payload_by_marker((const uint8_t *)&icmp[1],
						       len > sizeof(struct ether_header) + ip4->ip_hl * 4 + sizeof(struct icmp)
							       ? len - (sizeof(struct ether_header) + ip4->ip_hl * 4 + sizeof(struct icmp))
							       : 0,
						       &payload);
		}
	}
	if (have_payload) {
		if (!original_target) {
			if (p->outer_ipv6) {
				original_target = make_ipv6_str(&payload.outer_dst6);
			} else {
				original_target = make_ip_str(payload.outer_dst4);
			}
		}
	}

	maybe_record_payload_pair(p, &payload, have_payload, packet);
	maybe_record_csv_payload_pair(p, &csv_payload_v4, &csv_payload_v6,
				      have_csv_pair, packet);
	maybe_record_4in6_isav_pair(p, packet);
	maybe_record_6to4_probe_marker(p, packet, len);

	if (fs_next_is(fs, "classification")) {
		fs_add_string(fs, "classification", (char *)cls, 0);
	}
	if (fs_next_is(fs, "success")) {
		fs_add_uint64(fs, "success", 1);
	}
	if (fs_next_is(fs, "original_target")) {
		fs_chkadd_string(fs, "original_target", original_target, 1);
		original_target = NULL;
	}
	if (fs_next_is(fs, "icmp_type")) {
		fs_add_uint64(fs, "icmp_type", have_icmp_type ? icmp_type : 0);
	}
	if (fs_next_is(fs, "mode")) {
		fs_add_string(fs, "mode",
			      (char *)(p->mode == TUN_SAV_MODE_ISAV ? "isav" : "osav"),
			      0);
	}
	if (fs_next_is(fs, "proto")) {
		fs_add_string(fs, "proto", (char *)p->module_name, 0);
	}
	if (fs_next_is(fs, "response_src")) {
		fs_chkadd_string(fs, "response_src", response_src, 1);
		response_src = NULL;
	}
	if (fs_next_is(fs, "payload_outer_dst4")) {
		fs_chkadd_string(fs, "payload_outer_dst4",
				 have_payload ? make_ip_str(payload.outer_dst4) : NULL, 1);
	}
	if (fs_next_is(fs, "payload_outer_dst6")) {
		fs_chkadd_string(fs, "payload_outer_dst6",
				 have_payload ? make_ipv6_str(&payload.outer_dst6) : NULL, 1);
	}
	if (fs_next_is(fs, "payload_inner_src4")) {
		fs_chkadd_string(fs, "payload_inner_src4",
				 have_payload ? make_ip_str(payload.inner_src4) : NULL, 1);
	}
	if (fs_next_is(fs, "payload_inner_dst4")) {
		fs_chkadd_string(fs, "payload_inner_dst4",
				 have_payload ? make_ip_str(payload.inner_dst4) : NULL, 1);
	}
	if (fs_next_is(fs, "payload_inner_src6")) {
		fs_chkadd_string(fs, "payload_inner_src6",
				 have_payload ? make_ipv6_str(&payload.inner_src6) : NULL, 1);
	}
	if (fs_next_is(fs, "payload_inner_dst6")) {
		fs_chkadd_string(fs, "payload_inner_dst6",
				 have_payload ? make_ipv6_str(&payload.inner_dst6) : NULL, 1);
	}

	if (response_src) {
		free(response_src);
	}
	if (original_target) {
		free(original_target);
	}
}


void tunnel_sav_common_close(tunnel_sav_profile_t *p)
{
	close_result_csv(p);
	close_isav_pair_table(p);
}
