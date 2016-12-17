/*
 * packet.c
 *
 * Author: Shiyu Zhang <1181856726@qq.com>
 *
 */

#include "packet.h"
#include "spiffy.h"
#include "chunk.h"

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

int send_packet(int sock, bt_peer_t *peers, uint8_t type, uint32_t seq_ack, uint8_t *payload)
{
    int size = sizeof(payload) / sizeof(uint8_t);
    packet *pkt = (packet *)malloc(sizeof(packet) + size);

    pkt->magic = htons(15441);
    pkt->version = 1;
    pkt->type = type;
    pkt->hdr_len = htons(HDR_SIZE);
    pkt->tot_len = htons(HDR_SIZE + size);
    pkt->seq = 0;
    pkt->ack = 0;
    switch(type)
    {
        case WHOHAS:
        case IHAVE:
            break;
        default:
            break;
    }
    memcpy(pkt->payload, payload, size); 

    do_send_packet(sock, peers, pkt);

    free(pkt);

    return 0;
}

int do_send_packet(int sock, bt_peer_t *peers, packet *pkt)
{
    while(peers != NULL)
    {
        spiffy_sendto(sock, pkt, pkt->tot_len, 0, (struct sockaddr *)&peers->addr, sizeof(peers->addr));
        peers = peers->next;
    }

    return 0;
}

int parse_packet(uint8_t *msg)
{

    return 0;
}

void process_get(bt_config_t *config, chunk_info_t *ckinfo)
{
    uint8_t i = 0, num = sizeof(ckinfo) / sizeof(chunk_info_t);
    uint8_t *payload = (uint8_t *)malloc(sizeof(uint8_t) * (4 + HASH_BINARY_SIZE * num));
    uint8_t bin_hash[HASH_BINARY_SIZE] = { 0 };

    bzero(payload, sizeof(payload));

    payload[0] = num;
    for(i = 0; i < num - 1; ++i)
    {
        hex2binary(ckinfo[i].row.hash, HASH_ASCII_SIZE, bin_hash);
        memcpy(payload + 4 + HASH_BINARY_SIZE * i, bin_hash, HASH_BINARY_SIZE);
    }

    send_packet(config->sock, config->peers, WHOHAS, 0, payload);
}

int process_packet(uint8_t *msg, struct sockaddr_in *from, bt_config_t *config, chunk_table_t cktbl, chunk_info_t *ckinfo)
{
    return 0;
}
