/*
 * peer.c
 *
 * Initial Authors: Ed Bardsley <ebardsle+441@andrew.cmu.edu>,
 *          Dave Andersen
 * Class: 15-441 (Spring 2005)
 *
 * Skeleton for 15-441 Project 2.
 *
 * Author: Shiyu Zhang <1181856726@qq.com>
 *
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "debug.h"
#include "spiffy.h"
#include "bt_parse.h"
#include "input_buffer.h"
#include "chunk.h"
#include "chunk_helper.h"
#include "packet.h"

void peer_run(bt_config_t *config);

int main(int argc, char **argv)
{
    bt_config_t config;

    bt_init(&config, argc, argv);

    DPRINTF(DEBUG_INIT, "peer.c main beginning\n");

#ifdef TESTING
    config.identity = 1; // your group number here
    strcpy(config.chunk_file, "chunkfile");
    strcpy(config.has_chunk_file, "haschunks");
#endif

    bt_parse_command_line(&config);

#ifdef DEBUG
    if (debug & DEBUG_INIT)
        bt_dump_config(&config);
#endif

    if(access(TMP_FOLDER, F_OK) == 0)
    {
        char cmd[128] = { 0 };
        sprintf(cmd, "rm -rf %s", TMP_FOLDER);
        system(cmd);
    }
        
    if(mkdir(TMP_FOLDER, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) < 0)
    {
        DPRINTF(DEBUG_INIT, "Error mkdir: %s\n", strerror(errno));
        return 1;
    }

    // check if has_chunk consistent with master_chunk
    if(check_has_chunk(config.has_chunk_file, config.chunk_file) != 0)
    {
        DPRINTF(DEBUG_INIT, "has_chunk not consistent with master_chunk\n");
        exit(-1);
    }
  
    peer_run(&config);

    free_peer_list(config.peers);

    return 0;
}

void process_inbound_udp(int sock, bt_config_t *config, chunk_table_t cktbl, chunk_array_t *ckarr, get_info_t *getinfo)
{
    #define BUFLEN 1500
    struct sockaddr_in from;
    socklen_t fromlen;
    char buf[BUFLEN];

    fromlen = sizeof(from);
    spiffy_recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *) &from, &fromlen);

    process_packet((uint8_t *)buf, &from, config, cktbl, ckarr, getinfo);    
}

void handle_user_input(char *line, void *cbdata)
{
    char chunkf[128], outf[128];
    bt_config_t *config;

    bzero(chunkf, sizeof(chunkf));
    bzero(outf, sizeof(outf));
    config = (bt_config_t *)cbdata;

    if (sscanf(line, "GET %120s %120s", chunkf, outf))
        if (strlen(outf) > 0)
        {
            strcpy(config->output_file, outf);
            strcpy(config->get_chunk_file, chunkf);
        }
}

void process_get_cmd(bt_config_t *config, chunk_array_t *ckarr)
{
    send_whohas(config->sock, config->peers, ckarr, NULL);
}

void peer_run(bt_config_t *config)
{
    int sock, nready, i;
    struct sockaddr_in myaddr;
    fd_set allset, rset;
    struct user_iobuf *userbuf;
    struct timeval timeout;
    chunk_table_t cktbl;
    chunk_array_t ckarr;
    get_info_t getinfo;
  
    bzero(cktbl, sizeof(chunk_table_t)); 
    build_has_cktbl(config->has_chunk_file, cktbl);

    ckarr.num = 0;
    ckarr.arr = NULL;

    getinfo.start = 0;
    getinfo.done = 0;
    getinfo.srv_conn = getinfo.cli_conn = 0;
    getinfo.peer_num = 0;
    for(bt_peer_t *peer = config->peers; peer != NULL; peer = peer->next, ++getinfo.peer_num);
    getinfo.srv_info = (server_info_t *)malloc(sizeof(server_info_t) * (getinfo.peer_num + 1));
    bzero(getinfo.srv_info, sizeof(server_info_t) * (getinfo.peer_num + 1));
    getinfo.cli_info = (client_info_t *)malloc(sizeof(client_info_t) * (getinfo.peer_num + 1));
    bzero(getinfo.cli_info, sizeof(client_info_t) * (getinfo.peer_num + 1));
    for(i = 0; i < getinfo.peer_num + 1; ++i) getinfo.cli_info[i].ssthresh = SSTHRESH;

    if ((userbuf = create_userbuf()) == NULL)
    {
        perror("peer_run could not allocate userbuf");
        exit(-1);
    }
  
    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1)
    {
        perror("peer_run could not create socket");
        exit(-1);
    }
  
    bzero(&myaddr, sizeof(myaddr));
    myaddr.sin_family = AF_INET;
    myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    myaddr.sin_port = htons(config->myport);
  
    if (bind(sock, (struct sockaddr *) &myaddr, sizeof(myaddr)) == -1)
    {
        perror("peer_run could not bind socket");
        exit(-1);
    }
  
    config->sock = sock;

    spiffy_init(config->identity, (struct sockaddr *)&myaddr, sizeof(myaddr));

    timeout.tv_sec = TIMEOUT;
    timeout.tv_usec = 0;

    FD_ZERO(&allset);
    FD_SET(STDIN_FILENO, &allset);
    FD_SET(sock, &allset);
  
    while (1)
    {
        if(getinfo.done == 1)
        {
            assemble_chunk(config->output_file, &ckarr);

            fprintf(stdout, "GOT %s\n", config->get_chunk_file);
            free_ckarr(&ckarr);

            getinfo.start = 0;
            getinfo.done = 0;
            getinfo.srv_conn = getinfo.cli_conn = 0;
            bzero(getinfo.srv_info, sizeof(server_info_t) * (getinfo.peer_num + 1));
            bzero(getinfo.cli_info, sizeof(client_info_t) * (getinfo.peer_num + 1));
            for(i = 0; i < getinfo.peer_num + 1; ++i) getinfo.cli_info[i].ssthresh = SSTHRESH;
        }

        rset = allset;
    
        nready = select(sock + 1, &rset, NULL, NULL, &timeout);
    
        if(nready == 0 && (getinfo.srv_conn > 0 || getinfo.cli_conn > 0))
            check_retransmit(&getinfo, config, &ckarr);
        if (nready > 0)
        {
            if (FD_ISSET(sock, &rset))
	            process_inbound_udp(sock, config, cktbl, &ckarr, &getinfo);
      
            if (FD_ISSET(STDIN_FILENO, &rset))
            {
                process_user_input(STDIN_FILENO, userbuf, handle_user_input, config);
                build_get_ckarr(config->get_chunk_file, &ckarr);
                process_get_cmd(config, &ckarr);
            }

            check_retransmit(&getinfo, config, &ckarr);
        }
    }

    free(userbuf->buf);
    free(userbuf);
    free_cktbl(cktbl);
    free_ckarr(&ckarr);
    free(getinfo.srv_info);
    free(getinfo.cli_info);
}
