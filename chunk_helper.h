/*
 * chunk_helper.h
 *
 * Author: Shiyu Zhang <1181856726@qq.com>
 *
 */

#ifndef _CHUNK_HELPER_H_
#define _CHUNK_HELPER_H_

#include "bt_parse.h"

#include <stdio.h>
#include <netinet/in.h>

#define LINE_SIZE 256
#define HASH_ASCII_SIZE 40
#define HASH_BINARY_SIZE (HASH_ASCII_SIZE / 2)
#define HASH_TABLE_SIZE 6

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
    bt_peer_t *candidates;
} chunk_info_t;

typedef chunk_entry_t *chunk_table_t[HASH_TABLE_SIZE];

int get_chunk_row(FILE *f, chunk_row_t *row);
void build_cktbl(FILE *f, chunk_table_t cktbl);
int search_cktbl(const chunk_table_t cktbl, const char *hash);
int check_has_chunk(const char *has_chunk, const char *master_chunk);
void build_has_cktbl(const char *has_file, chunk_table_t cktbl);
void build_get_ckinfo(const char *get_file, chunk_info_t **ckinfo);
void free_entry(chunk_entry_t *head);
#endif /* _CHUNK_HELPER_H_ */
