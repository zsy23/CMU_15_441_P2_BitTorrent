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

void send_packet(int sock, bt_peer_t *peers, uint8_t type, uint32_t seq_ack, uint8_t *payload, uint32_t len, packet **pkt_buf)
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

    if(pkt_buf != NULL)
        *pkt_buf = pkt;
    else
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
            process_get(config, cktbl, getinfo, pkt->payload, ntohs(pkt->tot_len) - HDR_SIZE, from);
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

        send_ihave(sock, &peer, payload_send, 4 + HASH_BINARY_SIZE * num_send);

        free(payload_send);
        free_entry(head);
    }
}

void process_ihave(uint8_t *payload, uint16_t len, struct sockaddr_in *from, bt_config_t *config, chunk_array_t *ckarr, get_info_t *getinfo)
{
    uint8_t i = 0, j = 0, num = payload[0], num_info = ckarr->num, left = payload[0];
    chunk_row_t *rows = (chunk_row_t *)malloc(sizeof(chunk_row_t) * num);
    char ascii[HASH_ASCII_SIZE + 1] = { 0 };
    bt_peer_t *peer = NULL, *p = NULL;

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
                    peer->next = NULL;
                    if(ckarr->arr[i].candidates == NULL)
                        ckarr->arr[i].candidates = peer;
                    else
                    {
                        p = ckarr->arr[i].candidates;
                        do {
                            if(strcmp(inet_ntoa(p->addr.sin_addr), inet_ntoa(peer->addr.sin_addr)) == 0 && ntohs(p->addr.sin_port) == ntohs(peer->addr.sin_port))
                            {
                                peer->id = 0;
                                break;
                            }
                        } while(p->next != NULL);
                        if(peer->id != 0)
                            p->next = peer;
                    }
                    (ckarr->arr)[i].candidates = peer;

                    rows[j].id = 0;
                    --left;

                    break;
                }
    }

    free(rows);

    for(i = 0; i < num_info; ++i)
        if((ckarr->arr)[i].candidates == NULL)
            return;
    
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
    
    send_get(config, ckarr, getinfo);
}

void process_get(bt_config_t *config, chunk_table_t cktbl, get_info_t *getinfo, uint8_t *payload, uint16_t len, struct sockaddr_in *from)
{
    assert(len == HASH_BINARY_SIZE);

    if(getinfo->cli_conn >= config->max_conn)
    {
        DPRINTF(DEBUG_PROCESSES, "TODO: DENIED\n");
        return;
    }

    int id = bt_peer_id(config, from);

    if(id >= 0)
    {
        if(getinfo->cli_info[id].used == 0)
        {
            getinfo->cli_info[id].used = 1;

            ++getinfo->cli_conn;
        }

        getinfo->cli_info[id].win_size = WIN_SIZE;
        getinfo->cli_info[id].ckid = search_cktbl(cktbl, payload);
        if(getinfo->cli_info[id].ckid == -1)
        {
            fprintf(stderr, "GET invalid chunk hash\n");
            return;
        }
    }
}

void send_whohas(int sock, bt_peer_t *peers, chunk_array_t *ckarr, list(uint32_t) *list)
{
    uint32_t i = 0, j = 0, tot_num = 0;
    uint16_t cum_num = 0, ck_num = (UDP_SIZE - HDR_SIZE - 4) / HASH_BINARY_SIZE;
    list(uint32_t) *tmp = NULL;
    uint8_t *payload = NULL;
    
    if(list == NULL)
        tot_num = ckarr->num;
    else
    {
        tmp = list;
        while(tmp != NULL)
        {
            ++tot_num;
            tmp = tmp->next;
        }
    }

    cum_num = ck_num < tot_num ? ck_num : tot_num;
    payload = (uint8_t *)malloc(sizeof(uint8_t) * (4 + HASH_BINARY_SIZE * cum_num));
    bzero(payload, sizeof(uint8_t) * (4 + HASH_BINARY_SIZE * cum_num));

    payload[0] = cum_num;

    if(list == NULL)
        for(i = 0, j = 0; i < tot_num; ++i)
        {
            if(i == cum_num)
            {
                send_packet(sock, peers, PKT_WHOHAS, 0, payload, 4 + HASH_BINARY_SIZE * payload[0], NULL);
                bzero(payload, sizeof(uint8_t) * (4 + HASH_BINARY_SIZE * cum_num));
                payload[0] = ck_num < (tot_num - cum_num) ? ck_num : (tot_num - cum_num);
                cum_num += payload[0];
                j = 0;
            }

            memcpy(payload + 4 + HASH_BINARY_SIZE * j, (ckarr->arr)[i].row.hash, HASH_BINARY_SIZE);

            ++j;
        }
    else
    {
        i = j = 0;
        tmp = list;
        while(tmp != NULL)
        {
            if(i == cum_num)
            {
                send_packet(sock, peers, PKT_WHOHAS, 0, payload, 4 + HASH_BINARY_SIZE * payload[0], NULL);
                bzero(payload, sizeof(uint8_t) * (4 + HASH_BINARY_SIZE * cum_num));
                payload[0] = ck_num < (tot_num - cum_num) ? ck_num : (tot_num - cum_num);
                cum_num += payload[0];
                j = 0;
            }

            memcpy(payload + 4 + HASH_BINARY_SIZE * j, (ckarr->arr)[tmp->data].row.hash, HASH_BINARY_SIZE);

            ++i, ++j;
            tmp = tmp->next;
        }
    }

    send_packet(sock, peers, PKT_WHOHAS, 0, payload, 4 + HASH_BINARY_SIZE * payload[0], NULL);

    free(payload);
}

void send_ihave(int sock, bt_peer_t *peers, uint8_t *payload, uint32_t len)
{
    send_packet(sock, peers, PKT_IHAVE, 0, payload, len, NULL);
}

void send_get(bt_config_t *config, chunk_array_t *ckarr, get_info_t *getinfo)
{
    int i;
    bt_peer_t *peer = NULL;

    for(i = 0; i < ckarr->num; ++i)
        if(ckarr->arr[i].state == CHUNK_UNGOT)
        {
            for(peer = ckarr->arr[i].candidates; peer != NULL && getinfo->srv_info[peer->id].used == 1; peer = peer->next);

            if(peer != NULL)
            {
                uint8_t payload[HASH_BINARY_SIZE]; 
                bt_peer_t p;
                packet pkt;

                getinfo->srv_info[peer->id].used = 1;
                getinfo->srv_info[peer->id].timeout = time(NULL) + TIMEOUT;
                getinfo->srv_info[peer->id].ckarr_id = i;
                getinfo->srv_info[peer->id].pre_pkt = &pkt;

                memcpy(payload, ckarr->arr[i].row.hash, HASH_BINARY_SIZE);
                p.id = peer->id;
                p.addr = peer->addr;
                p.next = NULL;

                send_packet(config->sock, &p, PKT_GET, 0, payload, HASH_BINARY_SIZE, &getinfo->srv_info[peer->id].pre_pkt);

                ckarr->arr[i].state = CHUNK_PENDING;

                if(++getinfo->srv_conn >= config->max_conn)
                    break;
            }
        }
}

void check_retransmit(get_info_t *getinfo, bt_config_t *config, chunk_array_t *ckarr)
{
    uint16_t i = 0, j = 0;
    bt_peer_t *pp = NULL, *tmpp = NULL;
    bt_peer_t p;
    list(uint32_t) list;

    for(i = 1, j = 0; i < (getinfo->peer_num + 1) && j < getinfo->srv_conn; ++i)
        if(getinfo->srv_info[i].used == 1)
        {
            if(time(NULL) >= getinfo->srv_info[i].timeout)
            {
                pp = bt_peer_info(config, i);
                p.id = pp->id;
                p.addr = pp->addr;
                p.next = NULL;

                if(getinfo->srv_info[i].re_times < RETRANSMIT_TIMES)
                {
                    do_send_packet(config->sock, &p, getinfo->srv_info[i].pre_pkt);
                    getinfo->srv_info[i].timeout = time(NULL) + TIMEOUT;
                    ++getinfo->srv_info[i].re_times;
                }
                else if(getinfo->srv_info[i].re_times == RETRANSMIT_TIMES)
                {
                    list.data = getinfo->srv_info[i].ckarr_id;
                    list.next = NULL;

                    ckarr->arr[list.data].state = CHUNK_UNGOT;
                    
                    pp = ckarr->arr[list.data].candidates;
                    tmpp = NULL;
                    while(pp != NULL)
                    {
                        if(strcmp(inet_ntoa(pp->addr.sin_addr), inet_ntoa(p.addr.sin_addr)) == 0 && ntohs(pp->addr.sin_port) == ntohs(p.addr.sin_port))
                        {
                            if(tmpp == NULL)
                                ckarr->arr[list.data].candidates = pp->next;
                            else
                                tmpp->next = pp->next;

                            break;
                        }

                        tmpp = pp;
                        pp = pp->next;
                    }

                    send_whohas(config->sock, config->peers, ckarr, &list);

                    free(getinfo->srv_info[i].pre_pkt);
                    bzero(&getinfo->srv_info[i], sizeof(server_info_t));
                    --getinfo->srv_conn;

                    continue;
                }
            }

            ++j;
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
