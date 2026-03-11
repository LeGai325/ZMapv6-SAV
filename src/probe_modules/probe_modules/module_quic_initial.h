/*
 * Philippe Buschmann 2020
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* 
 * Defined QUIC versions according to IETF Draft: 
 * https://github.com/quicwg/base-drafts/wiki/QUIC-Versions 
 * 
 * 0x?a?a?a?a should not be accepted by IETF standard
 * Therefore we use 0x1a1a1a1a to force a version negotiation
 */
#define QUIC_VERSION_FORCE_NEGOTIATION 0x1a1a1a1a

/*
 * A client MUST expand the payload of all UDP datagrams carrying
 * Initial packets to at least the smallest allowed maximum datagram
 * size of 1200 bytes by adding PADDING frames to the Initial packet
 * https://tools.ietf.org/html/draft-ietf-quic-transport-32#section-14.1
 *
 * We are sending an Initial packet and have to set the size to 1200 bytes
 */
#define QUIC_PACKET_LENGTH 1200

/*
 * QUIC Long Header
 * 
 * Usually the four least-significant bits of the header_flags and the packet_number should
 * be protected by the header protection. However, to achieve a version negotiation response
 * from the server, this is not necessary
 */
typedef struct {
	uint8_t header_flags;
#define HEADER_FLAG_FORM_LONG_HEADER 0x1 << 7 // 1 = LONG HEADER
#define HEADER_FLAG_FIXED_BIT 0x1 << 6
#define HEADER_FLAG_TYPE_INITIAL 0x00 << 4 // 0x00 = INITIAL
#define HEADER_FLAG_RESERVED_BITS 0x00 << 2
#define HEADER_FLAG_PACKET_NUMBER_LENGTH 0x01 // 1 = 2 bytes
	uint32_t version;
	uint8_t dst_conn_id_length;
#define HEADER_CONNECTION_ID_LENGTH                                            \
	0x08 // since we use 64 bits for the connection id
	uint64_t dst_conn_id;
	uint8_t src_conn_id_length; // should be 0 without source connection id
	uint8_t token_length;	    // should be 0 without a token
	uint16_t length;	    // in bytes
	uint32_t packet_number;
} __attribute__((__packed__)) quic_long_hdr;

/*
 * QUIC Version Negotiation Packet
 * 
 * 
 */
typedef struct {
	uint8_t header_flags;
	uint32_t version; // must be set to 0x00000000
#define QUIC_VERSION_VERSION_NEGOTIATION 0x00000000
	uint8_t dst_conn_id_length; // should be 0 in response to our packet
	uint8_t
	    src_conn_id_length; // must be 0x08 (our dst_conn_id_length from before)
	uint64_t src_conn_id; // must be our dst_conn_id from before
			      // next fields should be supported versions
} __attribute__((__packed__)) quic_version_negotiation_hdr;
