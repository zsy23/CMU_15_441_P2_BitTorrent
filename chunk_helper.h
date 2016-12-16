/*
 * chunk_helper.h
 *
 * Author: Shiyu Zhang <1181856726@qq.com>
 *
 */

#ifndef _CHUNK_HELPER_H_
#define _CHUNK_HELPER_H_

#include <stdio.h>
#include <netinet/in.h>

#define LINE_SIZE 256
#define HASH_ASCII_SIZE 40
#define HASH_TABLE_SIZE 6

typedef struct sockaddr_list_s {
    struct sockaddr_in addr;
    struct sockaddr_list_s *next;
} sockaddr_list_t;

typedef struct {
    int id;
    char hash[HASH_ASCII_SIZE + 1];
} chunk_row_t;

typedef struct chunk_entry_s {
    chunk_row_t row;
    struct chunk_entry_s *next;
} chunk_entry_t;

typedef struct {
    chunk_row_t row;
    sockaddr_list_t addr_list;
} chunk_info_t;

typedef struct {
    int id;
    chunk_info_t *chunks;
} chunk_get_t;

typedef chunk_entry_t *chunk_table_t[HASH_TABLE_SIZE];

int get_chunk_row(FILE **f, chunk_row_t *row);
void build_cktbl(FILE **f, chunk_table_t *cktbl);
int search_cktbl(const chunk_table_t *cktbl, const char *hash);
int check_has_chunk(const char *has_chunk, const char *master_chunk);

#endif /* _CHUNK_HELPER_H_ */
