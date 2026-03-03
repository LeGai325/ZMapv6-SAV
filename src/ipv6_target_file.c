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

#include "../lib/logger.h"

#define LOGGER_NAME "ipv6_target_file"

static FILE *fp;

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
		if (strcmp(line, "ipv4,ipv6") == 0) {
			continue;
		}

		char *comma = strchr(line, ',');
		if (comma) {
			*comma = '\0';
			char *ipv4_str = line;
			char *ipv6_str = comma + 1;
			int rc4 = inet_pton(AF_INET, ipv4_str, dst4);
			int rc6 = inet_pton(AF_INET6, ipv6_str, dst6);
			if (rc4 != 1 || rc6 != 1) {
				log_fatal(LOGGER_NAME,
					  "could not parse IPv4/IPv6 pair from line: %s,%s",
					  ipv4_str, ipv6_str);
				return 1;
			}
			*has_dst4 = true;
		} else {
			int rc6 = inet_pton(AF_INET6, line, dst6);
			if (rc6 != 1) {
				log_fatal(LOGGER_NAME,
					  "could not parse IPv6 address from line: %s",
					  line);
				return 1;
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
