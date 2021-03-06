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
#include <time.h>

#define WIN_SIZE_FN "win_size.txt"

#define WIN_SIZE 1
#define SSTHRESH 64
#define UPDATE_SSTHRESH(win_size) (win_size / 2 > 2 ? win_size / 2 : 2)
#define TIMEOUT 5
#define RETRANSMIT_TIMES 5
#define DUP_ACK_NUM 3

#define UDP_SIZE 1500
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

#define define_list(type) \
    typedef struct list_##type { \
        type data; \
        struct list_##type *next; \
    } list_##type;
#define list(type) list_##type
#define free_list(type, list) { \
    list_##type *tmp; \
    while(list != NULL) \
    { \
        tmp = list; \
        list = list->next; \
        free(tmp); \
    } \
}

define_list(uint32_t);

#define ESTIMATE_RTT(ertt, srtt) (0.875 * ertt, 0.125 * srtt)

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
    uint8_t used;
    uint32_t ack;
    time_t timeout;
    uint8_t re_times;
    uint32_t ckarr_id;
    packet *pre_pkt;
} server_info_t;

typedef struct {
    uint8_t used;
    uint32_t win_size;
    uint16_t ssthresh;
    uint8_t stage;
    float rtt;
    uint32_t ckid;
    uint32_t seq, ack;
    uint8_t dup;
    time_t timeout;
    time_t timer;
    time_t rtt_timer;
    uint8_t re_times;
} client_info_t;

typedef struct {
    uint8_t start;
    uint8_t done;
    uint16_t srv_conn, cli_conn;
    uint16_t peer_num;
    server_info_t *srv_info;
    client_info_t *cli_info;
} get_info_t;


void do_send_packet(int sock, bt_peer_t *peers, packet *pkt);
void send_packet(int sock, bt_peer_t *peers, uint8_t type, uint32_t seq_ack, uint8_t *payload, uint32_t len, packet **pkt);
void send_whohas(int sock, bt_peer_t *peers, chunk_array_t *ckarr, list(uint32_t) *list);
void send_ihave(int sock, bt_peer_t *peers, uint8_t *payload, uint32_t len);
void send_get(bt_config_t *config, chunk_array_t *ckarr, get_info_t *getinfo);
void send_data(bt_config_t *config, bt_peer_t *peers, client_info_t *cli);
void send_ack(int sock, bt_peer_t *peers, server_info_t *srv);

void process_packet(uint8_t *msg, struct sockaddr_in *from, bt_config_t *config, chunk_table_t cktbl, chunk_array_t *ckarr, get_info_t *getinfo);
void process_whohas(uint8_t *payload, uint16_t len, int sock, struct sockaddr_in *from, chunk_table_t cktbl);
void process_ihave(uint8_t *payload, uint16_t len, struct sockaddr_in *from, bt_config_t *config, chunk_array_t *ckarr, get_info_t *getinfo);
void process_get(bt_config_t *config, chunk_table_t cktbl, get_info_t *getinfo, uint8_t *payload, uint16_t len, struct sockaddr_in *from);
void process_data(uint32_t seq, uint8_t *payload, uint16_t len, struct sockaddr_in *from, bt_config_t *config, get_info_t *getinfo, chunk_array_t *ckarr);
void process_ack(uint32_t ack, struct sockaddr_in *from, bt_config_t *config, get_info_t *getinfo);

void check_retransmit(get_info_t *getinfo, bt_config_t *config, chunk_array_t *ckarr);

void print_packet(int type, const struct sockaddr_in *addr, packet *pkt);
void record_winsize(char *fn, int srv_id, int cli_id, uint32_t win_size);

#endif /* _PACKET_H_ */
