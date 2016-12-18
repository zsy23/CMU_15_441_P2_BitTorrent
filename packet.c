/*
 * packet.c
 *
 * Author: Shiyu Zhang <1181856726@qq.com>
 *
 */

#include "packet.h"
#include "spiffy.h"
#include "chunk.h"
#include "chunk_helper.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
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

void process_get(bt_config_t *config, chunk_info_t *ckinfo)
{
    uint8_t i = 0, num = sizeof(ckinfo) / sizeof(chunk_info_t);
    uint8_t *payload = (uint8_t *)malloc(sizeof(uint8_t) * (4 + HASH_BINARY_SIZE * num));

    bzero(payload, sizeof(payload));

    payload[0] = num;
    for(i = 0; i < num - 1; ++i)
        memcpy(payload + 4 + HASH_BINARY_SIZE * i, ckinfo[i].row.hash, HASH_BINARY_SIZE);

    send_packet(config->sock, config->peers, WHOHAS, 0, payload);

    free(payload);
}

int process_packet(uint8_t *msg, struct sockaddr_in *from, bt_config_t *config, chunk_table_t cktbl, chunk_info_t *ckinfo)
{
    packet *pkt = (packet *)msg; 

    assert(ntohs(pkt->magic) == 15441);
    assert(pkt->version == 1);
    assert(pkt->type >= 0 && pkt->type <=5);
    assert(ntohs(pkt->hdr_len) == HDR_SIZE);
    pkt->tot_len = ntohs(pkt->tot_len);
    pkt->seq = ntohl(pkt->seq);
    pkt->ack = ntohl(pkt->ack);

    switch(pkt->type)
    {
        case WHOHAS:
            process_whohas(pkt->payload, pkt->tot_len - HDR_SIZE, config->sock, from, cktbl);
            break;
        case IHAVE:
            process_ihave(pkt->payload, pkt->tot_len - HDR_SIZE, from, ckinfo);
            break;
        default:
            break;
    }

    return 0;
}

int process_whohas(const uint8_t *payload, uint16_t len, int sock, struct sockaddr_in *from, chunk_table_t cktbl)
{
    uint8_t i = 0, num_recv = payload[0], num_send = 0, id = -1;
    chunk_entry_t *head = NULL, *cur = NULL;

    assert(len == (4 + HASH_BINARY_SIZE * num_recv));

    for(i = 0; i < num_recv; i++)
        if((id = search_cktbl(cktbl, payload + 4 + HASH_BINARY_SIZE * i)) >= 0)
        {
            ++num_send;
            chunk_entry_t *item = (chunk_entry_t *)malloc(sizeof(chunk_entry_t));
            memcpy(item->row.hash, payload + 4 + HASH_BINARY_SIZE * i, HASH_BINARY_SIZE);
            item->row.id = id;
            item->next = NULL;
            if(head == NULL)
                head = item;
            else
                cur->next = item;
            cur = item;
        }

    if(num_send > 0)
    {
        bt_peer_t peer;
        uint8_t *payload_send = (uint8_t *)malloc(4 + HASH_BINARY_SIZE * num_send);
        
        peer.addr = *from;
        payload_send[0] = num_send;
        cur = head;
        for(i = 0; i < num_send; ++i)
        {
            assert(cur != NULL);
            memcpy(payload_send + 4 + HASH_BINARY_SIZE * i, cur->row.hash, HASH_BINARY_SIZE);
            cur = cur->next;
        }

        send_packet(sock, &peer, IHAVE, 0, payload_send);

        free(payload_send);
    }

    free_entry(head);

    return 0;
}

int process_ihave(const uint8_t *payload, uint16_t len, struct sockaddr_in *from, chunk_info_t *ckinfo)
{
    uint8_t i = 0, j = 0, num = payload[0], num_info = sizeof(ckinfo), left = payload[0];
    chunk_row_t *rows = (chunk_row_t *)malloc(sizeof(chunk_row_t) * num);

    assert(num > 0);
    assert(len == (4 + HASH_BINARY_SIZE * num));

    for(i = 0; i < num; ++i)
    {
        rows[i].id = 1;
        memcpy(rows[i].hash, payload + 4 + HASH_BINARY_SIZE * i, HASH_BINARY_SIZE);
    }

    for(i = 0; i < num_info; ++i)
    {
        if(left == 0)
            break;

        for(j = 0; j < num; ++j)
            if(rows[j].id == 1)
                if(strncmp((const char *)ckinfo[i].row.hash, (const char *)rows[j].hash, HASH_BINARY_SIZE) == 0)
                {
                    bt_peer_t *peer = (bt_peer_t *)malloc(sizeof(bt_peer_t));
                    peer->addr = *from;
                    peer->next = ckinfo[i].candidates;
                    ckinfo[i].candidates = peer;

                    rows[j].id = 0;
                    --left;
                }
    }

    free(rows);

    return 0;
}
