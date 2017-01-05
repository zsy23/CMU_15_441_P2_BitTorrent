/*
 * packet.c
 *
 * Author: Shiyu Zhang <1181856726@qq.com>
 *
 */

#include "packet.h"
#include "spiffy.h"
#include "chunk.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
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

void do_send_packet(int sock, bt_peer_t *peers, packet *pkt)
{
    while(peers != NULL)
    {
        spiffy_sendto(sock, pkt, ntohs(pkt->tot_len), 0, (struct sockaddr *)&peers->addr, sizeof(peers->addr));

        print_packet(0, &peers->addr, pkt);

        peers = peers->next;
    }
}

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
        case PKT_DATA:
            pkt->seq = htonl(seq_ack);
            break;
        case PKT_ACK:
            pkt->ack = htonl(seq_ack);
            break;
        default:
            break;
    }

    if(payload != NULL)
        memcpy(pkt->payload, payload, len); 

    do_send_packet(sock, peers, pkt);

    if(pkt_buf != NULL)
        *pkt_buf = pkt;
    else
        free(pkt);
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
                getinfo->srv_info[peer->id].re_times = 0;
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

void send_data(bt_config_t *config, bt_peer_t *peers, client_info_t *cli)
{
    FILE *fp = NULL;
    uint8_t payload[UDP_SIZE - HDR_SIZE] = { 0 };
    uint32_t len = 0, send_len = 0;

    fp = fopen(config->share_file, "rb");
    if(fp == NULL)
    {
        DPRINTF(DEBUG_PROCESSES, "Error open master data file %s: %s\n", 
                config->share_file, strerror(errno));
        return;
    }

    fseek(fp, BT_CHUNK_SIZE * cli->ckid + (UDP_SIZE - HDR_SIZE) * cli->seq, SEEK_SET);

    while(cli->seq < (BT_CHUNK_SIZE + UDP_SIZE - HDR_SIZE - 1) / (UDP_SIZE - HDR_SIZE) && cli->seq - cli->ack < cli->win_size)
    {
        send_len = (BT_CHUNK_SIZE - (UDP_SIZE - HDR_SIZE) * cli->seq) < (UDP_SIZE - HDR_SIZE) ? (BT_CHUNK_SIZE - (UDP_SIZE - HDR_SIZE) *cli->seq) : (UDP_SIZE - HDR_SIZE);
        
        len = fread(payload, 1, send_len, fp);

        ++cli->seq;

        send_packet(config->sock, peers, PKT_DATA, cli->seq, payload, len, NULL);
    }

    fclose(fp);

    cli->timeout = time(NULL) + TIMEOUT;
}

void send_ack(int sock, bt_peer_t *peers, server_info_t *srv)
{
    srv->timeout = time(NULL) + TIMEOUT;
    srv->re_times = 0;

    send_packet(sock, peers, PKT_ACK, srv->ack, NULL, 0, &srv->pre_pkt);
}

void process_packet(uint8_t *msg, struct sockaddr_in *from, bt_config_t *config, chunk_table_t cktbl, chunk_array_t *ckarr, get_info_t *getinfo)
{
    if(bt_peer_id(config, from) < 0)
    {
        DPRINTF(DEBUG_PROCESSES, "Packet from invalid peer %s:%u\n", 
                inet_ntoa(from->sin_addr), ntohs(from->sin_port));
        return;
    }

    packet *pkt = (packet *)msg; 

    if(ntohs(pkt->magic) != MAGIC)
    {
        DPRINTF(DEBUG_PROCESSES, "Packet with invalid magic from %s:%u\n", 
                inet_ntoa(from->sin_addr), ntohs(from->sin_port));
        return;
    }

    if(pkt->version != VERSION)
    {
        DPRINTF(DEBUG_PROCESSES, "Packet with invalid version from %s:%u\n", 
                inet_ntoa(from->sin_addr), ntohs(from->sin_port));
        return;
    }

    if(pkt->type < 0 || pkt->type > 5)
    {
        DPRINTF(DEBUG_PROCESSES, "Packet with invalid type from %s:%u\n", 
                inet_ntoa(from->sin_addr), ntohs(from->sin_port));
        return;
    }

    if(ntohs(pkt->hdr_len) != HDR_SIZE)
    {
        DPRINTF(DEBUG_PROCESSES, "Packet with invalid header from %s:%u\n", 
                inet_ntoa(from->sin_addr), ntohs(from->sin_port));
        return;
    }

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
        case PKT_DATA:
            process_data(ntohl(pkt->seq), pkt->payload, ntohs(pkt->tot_len) - HDR_SIZE, from, config, getinfo, ckarr);
            break;
        case PKT_ACK:
            process_ack(ntohl(pkt->ack), from, config, getinfo);
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

    if(len != (4 + HASH_BINARY_SIZE * num_recv))
    {
        DPRINTF(DEBUG_PROCESSES, "WHOHAS packet with invalid payload len form %s:%u\n", 
                inet_ntoa(from->sin_addr), ntohs(from->sin_port));
        return;
    }

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

    if(num <= 0)
    {
        DPRINTF(DEBUG_PROCESSES, "IHAVE packet with zero or negative legnth payload from %s:%u\n", 
                inet_ntoa(from->sin_addr), ntohs(from->sin_port));
        return;
    }
    
    if(len != (4 + HASH_BINARY_SIZE * num))
    {
        DPRINTF(DEBUG_PROCESSES, "IHAVE packet with invalid payload len form %s:%u\n", 
                inet_ntoa(from->sin_addr), ntohs(from->sin_port));
        return;
    }

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
                        } while(p->next != NULL && (p = p->next));

                        if(peer->id != 0)
                            p->next = peer;
                    }

                    rows[j].id = 0;
                    --left;

                    break;
                }
    }

    free(rows);

    for(i = 0; i < num_info; ++i)
        if(ckarr->arr[i].candidates == NULL)
            return;

    DPRINTF(DEBUG_PROCESSES, "============================================\n");
    DPRINTF(DEBUG_PROCESSES, "Receive IHAVE for all chunks\n");
    for(i = 0; i < ckarr->num; ++i)
    {
        binary2hex(ckarr->arr[i].row.hash, HASH_BINARY_SIZE, ascii);
        ascii[HASH_ASCII_SIZE] = 0;
        DPRINTF(DEBUG_PROCESSES, "hash %d: %s\n", ckarr->arr[i].row.id, ascii);
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
    if(len != HASH_BINARY_SIZE)
    {
        DPRINTF(DEBUG_PROCESSES, "GET packet with invalid payload length from %s:%u\n", 
                inet_ntoa(from->sin_addr), ntohs(from->sin_port));
        return;
    }

    int id = bt_peer_id(config, from);
    bt_peer_t peer;

    if(id >= 0)
    {
        if(getinfo->cli_info[id].used == 0 && getinfo->cli_conn >= config->max_conn)
        {
            DPRINTF(DEBUG_PROCESSES, "TODO: DENIED\n");
            return;
        }

        peer.addr = *from;
        peer.id = id;
        peer.next = NULL;

        if(getinfo->cli_info[id].used == 0)
        {
            getinfo->cli_info[id].used = 1;

            ++getinfo->cli_conn;
        }

        getinfo->cli_info[id].win_size = WIN_SIZE;
        getinfo->cli_info[id].ckid = search_cktbl(cktbl, payload);
        if(getinfo->cli_info[id].ckid == -1)
        {
            DPRINTF(DEBUG_PROCESSES, "GET packet with invalid chunk hash from %s:%u\n", 
                    inet_ntoa(from->sin_addr), ntohs(from->sin_port));
            return;
        }

        getinfo->cli_info[id].seq = 0;
        getinfo->cli_info[id].ack = 0;
        getinfo->cli_info[id].dup = 0;

        getinfo->cli_info[id].re_times = 0;
        send_data(config, &peer, &getinfo->cli_info[id]);
    }
}

void process_data(uint32_t seq, uint8_t *payload, uint16_t len, struct sockaddr_in *from, bt_config_t *config, get_info_t *getinfo, chunk_array_t *ckarr)
{
    int id = bt_peer_id(config, from);

    if(id < 0)
    {
        DPRINTF(DEBUG_PROCESSES, "DATA packet from invalid peer %s:%u\n", 
                inet_ntoa(from->sin_addr), ntohs(from->sin_port));
        return;
    }

    int i = 0;
    bt_peer_t peer;
    FILE *fp = NULL;
    char fn[CHUNK_FILENAME_SIZE] = { 0 };
    packet pkt;

    peer.id = id;
    peer.addr = *from;
    peer.next = NULL;

    if(getinfo->srv_info[id].ack + 1 == seq)
    {
        sprintf(fn, "%s/ck%u.bin", TMP_FOLDER, getinfo->srv_info[id].ckarr_id);
        if(getinfo->srv_info[id].ack == 0)
            fp = fopen(fn, "wb");
        else
            fp = fopen(fn, "ab");

        fwrite(payload, 1, len, fp); 

        fclose(fp);

        ++getinfo->srv_info[id].ack;
        getinfo->srv_info[id].pre_pkt = &pkt;

        send_ack(config->sock, &peer, &getinfo->srv_info[id]);

        if(getinfo->srv_info[id].ack == (BT_CHUNK_SIZE + UDP_SIZE - HDR_SIZE - 1) / (UDP_SIZE - HDR_SIZE))
        {
            if(check_chunk(fn, getinfo->srv_info[id].ckarr_id, ckarr) == 1)
            {
                DPRINTF(DEBUG_PROCESSES, "DATA chunk %d from %s:%u done\n", 
                        getinfo->srv_info[id].ckarr_id, inet_ntoa(from->sin_addr), ntohs(from->sin_port));

                for(i = 0; i < ckarr->num; ++i)
                    if(ckarr->arr[i].state < CHUNK_GOT)
                        break;

                if(i >= ckarr->num)  
                    getinfo->done = 1;
                else
                {
                    bzero(&getinfo->srv_info[id], sizeof(server_info_t));
                    send_get(config, ckarr, getinfo);
                }
            }
            else
                DPRINTF(DEBUG_PROCESSES, "DATA invalid from %s:%u\n", 
                        inet_ntoa(from->sin_addr), ntohs(from->sin_port));
        }
    }
}

void process_ack(uint32_t ack, struct sockaddr_in *from, bt_config_t *config, get_info_t *getinfo)
{
    int id = bt_peer_id(config, from);

    if(id < 0)
    {
        DPRINTF(DEBUG_PROCESSES, "ACK packet from invalid peer %s:%u\n", 
                inet_ntoa(from->sin_addr), ntohs(from->sin_port));
        return;
    }

    bt_peer_t peer;

    peer.id = id;
    peer.addr = *from;
    peer.next = NULL;

    if(getinfo->cli_info[id].ack < ack)
    {
        getinfo->cli_info[id].ack = ack;
        getinfo->cli_info[id].dup = 0;

        if(getinfo->cli_info[id].ack == (BT_CHUNK_SIZE + UDP_SIZE - HDR_SIZE - 1) / (UDP_SIZE - HDR_SIZE))
        {
            DPRINTF(DEBUG_PROCESSES, "Send chunk %u to peer %s:%u done\n", 
                    getinfo->cli_info[id].ckid, inet_ntoa(from->sin_addr), ntohs(from->sin_port));

            bzero(&getinfo->cli_info[id], sizeof(client_info_t));
        }
        else
        {
            getinfo->cli_info[id].re_times = 0;

            send_data(config, &peer, &getinfo->cli_info[id]);
        }
    }
    else
    {
        ++getinfo->cli_info[id].dup;
        DPRINTF(DEBUG_PROCESSES, "TODO: Duplicate ACK\n");
    }
}

void check_retransmit(get_info_t *getinfo, bt_config_t *config, chunk_array_t *ckarr)
{
    uint16_t i = 0, j = 0;
    bt_peer_t *pp = NULL, *tmpp = NULL;
    bt_peer_t p;
    list(uint32_t) list;

    // client check server
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
                else if(getinfo->srv_info[i].re_times >= RETRANSMIT_TIMES)
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

                    free(pp);

                    send_whohas(config->sock, config->peers, ckarr, &list);

                    free(getinfo->srv_info[i].pre_pkt);
                    bzero(&getinfo->srv_info[i], sizeof(server_info_t));
                    --getinfo->srv_conn;

                    continue;
                }
            }

            ++j;
        }

    // server check client
    for(i = 1, j = 0; i < (getinfo->peer_num + 1) && j < getinfo->cli_conn; ++i)
        if(getinfo->cli_info[i].used == 1)
        {
            if(time(NULL) >= getinfo->cli_info[i].timeout)
            {
                pp = bt_peer_info(config, i);
                p.id = pp->id;
                p.addr = pp->addr;
                p.next = NULL;

                if(getinfo->cli_info[i].re_times < RETRANSMIT_TIMES)
                {    
                    getinfo->cli_info[i].seq = getinfo->cli_info[i].ack;
                    send_data(config, &p, &getinfo->cli_info[i]);

                    ++getinfo->cli_info[i].re_times;
                }
                else if(getinfo->cli_info[i].re_times >= RETRANSMIT_TIMES)
                {
                    bzero(&getinfo->cli_info[i], sizeof(client_info_t));
                    --getinfo->cli_conn;

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
