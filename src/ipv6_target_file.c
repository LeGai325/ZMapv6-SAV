/*
 * ZMapv6 Copyright 2016 Chair of Network Architectures and Services
 * Technical University of Munich
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <arpa/inet.h>
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <strings.h>

#include "../lib/logger.h"

#define LOGGER_NAME "ipv6_target_file"

static FILE *fp;

static char *trim(char *s)
{
	while (*s == ' ' || *s == '\t' || *s == '\r') {
		s++;
	}
	char *end = s + strlen(s);
	while (end > s && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r')) {
		*--end = '\0';
	}
	return s;
}

int ipv6_target_file_init(char *file)
{
	if (strcmp(file, "-") == 0) {
		fp = stdin;
	} else {
		fp = fopen(file, "r");
	}
	if (fp == NULL) {
		log_fatal(LOGGER_NAME, "unable to open %s file: %s: %s",
				LOGGER_NAME, file, strerror(errno));
		return 1;
	}

	return 0;
}

int ipv6_target_file_get_target(struct in_addr *dst4, bool *has_dst4,
			      struct in6_addr *dst6)
{
	// ipv6_target_file_init() needs to be called before ipv6_target_file_get_target()
	assert(fp);

	char line[256];

	while (fgets(line, sizeof(line), fp) != NULL) {
		// Remove newline
		char *pos;
		if ((pos = strchr(line, '\n')) != NULL) {
			*pos = '\0';
		}
		if (line[0] == '\0' || line[0] == '#') {
			continue;
		}
		char *line_trimmed = trim(line);
		if (strcasecmp(line_trimmed, "ipv4,ipv6") == 0) {
			continue;
		}

		char *comma = strchr(line_trimmed, ',');
		if (comma) {
			*comma = '\0';
			char *ipv4_str = trim(line_trimmed);
			char *ipv6_str = trim(comma + 1);
			if (ipv4_str[0] == '\0' || ipv6_str[0] == '\0') {
				log_warn(LOGGER_NAME,
					 "skipping malformed IPv4/IPv6 pair line (empty field): %s,%s",
					 ipv4_str, ipv6_str);
				continue;
			}
			int rc4 = inet_pton(AF_INET, ipv4_str, dst4);
			int rc6 = inet_pton(AF_INET6, ipv6_str, dst6);
			if (rc4 != 1 || rc6 != 1) {
				log_warn(LOGGER_NAME,
					 "skipping malformed IPv4/IPv6 pair line: %s,%s",
					 ipv4_str, ipv6_str);
				continue;
			}
			*has_dst4 = true;
		} else {
			char *ipv6_str = trim(line_trimmed);
			int rc6 = inet_pton(AF_INET6, ipv6_str, dst6);
			if (rc6 != 1) {
				log_warn(LOGGER_NAME,
					 "skipping malformed IPv6 address line: %s",
					 ipv6_str);
				continue;
			}
			dst4->s_addr = 0;
			*has_dst4 = false;
		}
		return 0;
	}

	return 1;
}

int ipv6_target_file_deinit()
{
	fclose(fp);
	fp = NULL;

	return 0;
}
