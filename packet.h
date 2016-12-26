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
#define MAGIC 15441
#define VERSION 1

#define BM_CLR(bm, num) { \
    for(int i = 0; i <= (num / 32); ++i) \
        bm[i] &= 0; \
}
#define BIT_SET(bm, id) (bm[id / 32] |= (1 << (id % 32)))
#define BIT_CLR(bm, id) (bm[id / 32] &= ~(1 << (id % 32)))
#define BIT_ISSET(bm, id) ((bm[id / 32] & (1 << (id % 32))) != 0)

typedef enum {
    PKT_WHOHAS, // 0
    PKT_IHAVE,  // 1
    PKT_GET,    // 2
    PKT_DATA,   // 3
    PKT_ACK,    // 4
    PKT_DENIED, // 5
} packet_type;

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

typedef struct {
    uint8_t start;
    uint16_t conn_num;
    uint16_t peer_num;
    uint32_t *bitmap;
} get_info_t;

void send_packet(int sock, bt_peer_t *peers, uint8_t type, uint32_t seq_ack, uint8_t *payload, uint32_t len);
void do_send_packet(int sock, bt_peer_t *peers, packet *pkt);
void process_packet(uint8_t *msg, struct sockaddr_in *from, bt_config_t *config, chunk_table_t cktbl, chunk_array_t *ckarr, get_info_t *getinfo);
void process_whohas(uint8_t *payload, uint16_t len, int sock, struct sockaddr_in *from, chunk_table_t cktbl);
void process_ihave(uint8_t *payload, uint16_t len, struct sockaddr_in *from, bt_config_t *config, chunk_array_t *ckarr, get_info_t *getinfo);
void process_get(uint8_t *payload, uint16_t len, struct sockaddr_in *from);
void send_get(bt_config_t *config, chunk_array_t *ckarr, get_info_t *getinfo);
void print_packet(int type, const struct sockaddr_in *addr, packet *pkt);

#endif /* _PACKET_H_ */
