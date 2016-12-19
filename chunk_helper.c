/*
 * chunk_helper.c
 *
 * Author: Shiyu Zhang <1181856726@qq.com>
 *
 */

#include "chunk_helper.h"
#include "super_fast_hash.h"
#include "chunk.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>

int get_chunk_row(FILE *f, chunk_row_t *row)
{
    char line[LINE_SIZE] = { 0 };
    char hash[HASH_ASCII_SIZE + 1] = { 0 };

    assert(f != NULL);

    if(fgets(line, LINE_SIZE, f) == NULL)
        return -1;
    
    assert(sscanf(line, "%d %s", &row->id, hash) != 0);
    hex2binary(hash, HASH_ASCII_SIZE, row->hash);

    return 0;
}

void build_cktbl(FILE *f, chunk_table_t cktbl)
{
    int i = -1;
    chunk_row_t row;

    assert(f != NULL);

    while(get_chunk_row(f, &row) == 0)
    {
        chunk_entry_t *entry = (chunk_entry_t *)malloc(sizeof(chunk_entry_t));
        entry->row = row;
        entry->next = NULL;

        i = super_fast_hash((const char *)entry->row.hash, HASH_BINARY_SIZE, HASH_BINARY_SIZE) % HASH_TABLE_SIZE;
        entry->next = cktbl[i];
        cktbl[i] = entry;
    }
}

int search_cktbl(const chunk_table_t cktbl, uint8_t *hash)
{
    int i = -1;
    chunk_entry_t *entry;

    i = super_fast_hash((const char *)hash, HASH_BINARY_SIZE, HASH_BINARY_SIZE) % HASH_TABLE_SIZE;

    entry = cktbl[i];
    while(entry != NULL)
    {
        if(strncmp((const char *)hash, (const char *)entry->row.hash, HASH_BINARY_SIZE) == 0)
            return entry->row.id;

        entry = entry->next;
    }

    return -1;
}

int check_has_chunk(const char *has_chunk, const char *master_chunk)
{
    FILE *f = NULL;
    char line[LINE_SIZE] = { 0 };
    chunk_table_t cktbl = { 0 };
    chunk_row_t row;

    f = fopen(master_chunk, "r");
    assert(f != NULL);
    
    fgets(line, LINE_SIZE, f);
    fgets(line, LINE_SIZE, f);
    build_cktbl(f, cktbl);
    fclose(f);

    f = fopen(has_chunk, "r");
    assert(f != NULL);

    while(get_chunk_row(f, &row) == 0)
        if(search_cktbl(cktbl, row.hash) != row.id)
            return -1;

    free_cktbl(cktbl);

    return 0;
}

void build_has_cktbl(const char *has_file, chunk_table_t cktbl)
{
    FILE *f = NULL;

    f = fopen(has_file, "r");
    assert(f != NULL);

    build_cktbl(f, cktbl);
    
    fclose(f);
}

void build_get_ckarr(const char *get_file, chunk_array_t *ckarr)
{
    int num = 0, i = 0;
    FILE *f = NULL;
    chunk_entry_t *head = NULL, *cur = NULL;
    chunk_row_t row;

    f = fopen(get_file, "r");
    while(get_chunk_row(f, &row) == 0)
    {
        ++num;
        chunk_entry_t *item = (chunk_entry_t *)malloc(sizeof(chunk_entry_t));
        item->row = row;
        item->next = NULL;
        if(head == NULL)
            head = item;
        else
            cur->next = item;
        cur = item;
    }
    fclose(f);

    cur = head;
    ckarr->num = num;
    ckarr->arr = (chunk_info_t *)malloc(sizeof(chunk_info_t) * num);
    for(i = 0; i < num; ++i)
    {
        assert(cur != NULL);

        (ckarr->arr)[i].row = cur->row;
        (ckarr->arr)[i].candidates = NULL;
        cur = cur->next;
    }

    free_entry(head);
}

void free_entry(chunk_entry_t *head)
{
    chunk_entry_t *tmp;

    while(head != NULL)
    {
        tmp = head;
        head = head->next;
        free(tmp);
    }
}

void free_cktbl(chunk_table_t cktbl)
{
    int i = 0;
    chunk_entry_t *tmp = NULL, *cur = NULL;

    for(i = 0; i < HASH_TABLE_SIZE; ++i)
    {
        cur = cktbl[i];
        while(cur != NULL)
        {
            tmp = cur;
            cur = cur->next;
            free(tmp);
        }
    }
}

void free_ckarr(chunk_array_t *ckarr)
{
    int i = 0;
    bt_peer_t *peer = NULL, *tmp = NULL;

    for(i = 0; i < ckarr->num; ++i)
    {
        peer = (ckarr->arr)[i].candidates;
        while(peer != NULL)
        {
            tmp = peer;
            peer = peer->next;
            free(tmp);
        }
    }
}
