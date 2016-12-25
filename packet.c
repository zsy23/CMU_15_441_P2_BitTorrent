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
#include <assert.h>
#include <arpa/inet.h>

const char *pkt_type_strings[] = {
    "WHOHAS",
    "IHAVE",
    "GET",
    "DATA",
    "ACK",
    "DENIED",
    0,
};

void send_packet(int sock, bt_peer_t *peers, uint8_t type, uint32_t seq_ack, uint8_t *payload, uint32_t len)
{
    packet *pkt = (packet *)malloc(sizeof(packet) + len);

    pkt->magic = htons(MAGIC);
    pkt->version = VERSION;
    pkt->type = type;
    pkt->hdr_len = htons(HDR_SIZE);
    pkt->tot_len = htons(HDR_SIZE + len);
    pkt->seq = 0;
    pkt->ack = 0;
    switch(type)
    {
        case PKT_WHOHAS:
        case PKT_IHAVE:
        case PKT_GET:
            break;
        default:
            break;
    }
    memcpy(pkt->payload, payload, len); 

    do_send_packet(sock, peers, pkt);

    free(pkt);
}

void do_send_packet(int sock, bt_peer_t *peers, packet *pkt)
{
    while(peers != NULL)
    {
        spiffy_sendto(sock, pkt, ntohs(pkt->tot_len), 0, (struct sockaddr *)&peers->addr, sizeof(peers->addr));

        print_packet(0, &peers->addr, pkt);

        peers = peers->next;
    }
}

void process_packet(uint8_t *msg, struct sockaddr_in *from, bt_config_t *config, chunk_table_t cktbl, chunk_array_t *ckarr, get_info_t *getinfo)
{
    assert(bt_peer_id(config, from) >= 0);

    packet *pkt = (packet *)msg; 

    assert(ntohs(pkt->magic) == MAGIC);
    assert(pkt->version == VERSION);
    assert(pkt->type >= 0 && pkt->type <=5);
    assert(ntohs(pkt->hdr_len) == HDR_SIZE);

    print_packet(1, from, pkt);

    switch(pkt->type)
    {
        case PKT_WHOHAS:
            process_whohas(pkt->payload, ntohs(pkt->tot_len) - HDR_SIZE, config->sock, from, cktbl);
            break;
        case PKT_IHAVE:
            process_ihave(pkt->payload, ntohs(pkt->tot_len) - HDR_SIZE, from, config, ckarr, getinfo);
            break;
        case PKT_GET:
            process_get(pkt->payload, ntohs(pkt->tot_len) - HDR_SIZE, from);
            break;
        default:
            break;
    }
}

void process_whohas(uint8_t *payload, uint16_t len, int sock, struct sockaddr_in *from, chunk_table_t cktbl)
{
    uint8_t i = 0, num_recv = payload[0], num_send = 0;
    int id = -1;
    chunk_entry_t *head = NULL, *cur = NULL;

    assert(len == (4 + HASH_BINARY_SIZE * num_recv));

    for(i = 0; i < num_recv; i++)
    {
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
    }

    if(num_send > 0)
    {
        bt_peer_t peer;
        uint8_t *payload_send = (uint8_t *)malloc(4 + HASH_BINARY_SIZE * num_send);
        
        peer.addr = *from;
        peer.next = NULL;
        payload_send[0] = num_send;
        cur = head;
        for(i = 0; i < num_send; ++i)
        {
            assert(cur != NULL);
            memcpy(payload_send + 4 + HASH_BINARY_SIZE * i, cur->row.hash, HASH_BINARY_SIZE);
            cur = cur->next;
        }

        send_packet(sock, &peer, PKT_IHAVE, 0, payload_send, 4 + HASH_BINARY_SIZE * num_send);

        free(payload_send);
        free_entry(head);
    }
}

void process_ihave(uint8_t *payload, uint16_t len, struct sockaddr_in *from, bt_config_t *config, chunk_array_t *ckarr, get_info_t *getinfo)
{
    uint8_t i = 0, j = 0, num = payload[0], num_info = ckarr->num, left = payload[0];
    chunk_row_t *rows = (chunk_row_t *)malloc(sizeof(chunk_row_t) * num);
    char ascii[HASH_ASCII_SIZE + 1] = { 0 };
    bt_peer_t *peer = NULL;

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
                if(strncmp((const char *)(ckarr->arr)[i].row.hash, (const char *)rows[j].hash, HASH_BINARY_SIZE) == 0)
                {
                    bt_peer_t *peer = (bt_peer_t *)malloc(sizeof(bt_peer_t));
                    peer->id = bt_peer_id(config, from);
                    peer->addr = *from;
                    peer->next = (ckarr->arr)[i].candidates;
                    (ckarr->arr)[i].candidates = peer;

                    rows[j].id = 0;
                    --left;

                    break;
                }
    }

    free(rows);

    if(getinfo->start == 0)
    {
        for(i = 0; i < num_info; ++i)
            if((ckarr->arr)[i].candidates == NULL)
                return;
    }
    
    DPRINTF(DEBUG_PROCESSES, "============================================\n");
    DPRINTF(DEBUG_PROCESSES, "Receive IHAVE for all chunks\n");
    for(i = 0; i < ckarr->num; ++i)
    {
        binary2hex((ckarr->arr)[i].row.hash, HASH_BINARY_SIZE, ascii);
        ascii[HASH_ASCII_SIZE] = 0;
        DPRINTF(DEBUG_PROCESSES, "hash %d: %s\n", (ckarr->arr)[i].row.id, ascii);
        peer = (ckarr->arr)[i].candidates;
        j = 1;
        while(peer != NULL)
        {
            DPRINTF(DEBUG_PROCESSES, "candidate %d: id: %d, addr: %s:%d\n", 
                    j, peer->id, inet_ntoa(peer->addr.sin_addr), ntohs(peer->addr.sin_port));
            ++j;
            peer = peer->next;
        }
    }
    
    if(getinfo->start == 0)
    {
        getinfo->start = 1;
        send_get(config, ckarr, getinfo);
    }
}

void process_get(uint8_t *payload, uint16_t len, struct sockaddr_in *from)
{
    assert(len == HASH_BINARY_SIZE);
}

void send_get(bt_config_t *config, chunk_array_t *ckarr, get_info_t *getinfo)
{
    int i;

    while(getinfo->conn_num < config->max_conn)
    {
        for(i = 0; i < getinfo->num; ++i)
            if(getinfo->conn[i].ckstt == CHUNK_UNGOT)
            {
                uint8_t payload[HASH_BINARY_SIZE]; 

                getinfo->conn[i].ckstt = CHUNK_PENDING;
                getinfo->conn[i].peer.id = ckarr->arr[i].candidates->id;
                getinfo->conn[i].peer.addr = ckarr->arr[i].candidates->addr;
                getinfo->conn[i].peer.next = NULL;

                memcpy(payload, ckarr->arr[i].row.hash, HASH_BINARY_SIZE);

                send_packet(config->sock, &getinfo->conn[i].peer, PKT_GET, 0, payload, HASH_BINARY_SIZE);

                ++getinfo->conn_num;
                break;
            }

        if(i >= getinfo->num)
            break;
    }
}

void print_packet(int type, const struct sockaddr_in *addr, packet *pkt)
{
    DPRINTF(DEBUG_PROCESSES, "============================================\n");
    DPRINTF(DEBUG_PROCESSES, "%s message to %s:%d\n",
            type == 0 ? "Send" : "Receive", 
            inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
    DPRINTF(DEBUG_PROCESSES, "Magic: %u, Version: %u, Type: %s, Header_Length: %u, Total_Length: %u, Seq: %u, Ack: %u\n", 
            ntohs(pkt->magic), pkt->version, pkt_type_strings[pkt->type], ntohs(pkt->hdr_len), ntohs(pkt->tot_len), ntohl(pkt->seq), ntohl(pkt->ack));
    int num = 0, i = 0;
    char hash[HASH_ASCII_SIZE + 1] = { 0 };
    switch(pkt->type)
    {
        case PKT_WHOHAS:
        case PKT_IHAVE:
            num = pkt->payload[0];
            DPRINTF(DEBUG_PROCESSES, "Hash_Num: %d\n", num);
            for(i = 0; i < num; ++i)
            {
                binary2hex(pkt->payload + 4 + HASH_BINARY_SIZE * i, HASH_BINARY_SIZE, hash);
                hash[HASH_ASCII_SIZE] = 0;
                DPRINTF(DEBUG_PROCESSES, "Hash %d: %s\n", i, hash);
            }
            break;
        case PKT_GET:
            binary2hex(pkt->payload, HASH_BINARY_SIZE, hash);
            hash[HASH_ASCII_SIZE] = 0;
            DPRINTF(DEBUG_PROCESSES, "Hash: %s\n", hash);
            break;
        default:
            break;
    }
}
