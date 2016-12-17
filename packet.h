/*
 * packet.h
 *
 * Author: Shiyu Zhang <1181856726@qq.com>
 *
 */

#ifndef _PACKET_H_
#define _PACKET_H_

#include "bt_parse.h"
#include "chunk_helper.h"

#include <stdint.h>

#define HDR_SIZE 16

enum packet_type {
    WHOHAS, // 0
    IHAVE,  // 1
    GET,    // 2
    DATA,   // 3
    ACK,    // 4
    DENIED, // 5
};

typedef struct {
    uint16_t magic;
    uint8_t version;
    uint8_t type;
    uint16_t hdr_len;
    uint16_t tot_len;
    uint32_t seq;
    uint32_t ack;
    uint8_t payload[0];
} __attribute__((__packed__)) packet;

int send_packet(int sock, bt_peer_t *peers, uint8_t type, uint32_t seq_ack, uint8_t *payload);
int do_send_packet(int sock, bt_peer_t *peers, packet *pkt);
void process_get(bt_config_t *config, chunk_info_t *ckinfo);
int process_packet(uint8_t *msg, struct sockaddr_in *from, bt_config_t *config, chunk_table_t cktbl, chunk_info_t *ckinfo);

#endif /* _PACKET_H_ */
