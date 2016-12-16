/*
 * chunk_helper.c
 *
 * Author: Shiyu Zhang <1181856726@qq.com>
 *
 */

#include "chunk_helper.h"
#include "super_fast_hash.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>

int get_chunk_row(FILE **f, chunk_row_t *row)
{
    char line[LINE_SIZE] = { 0 };

    if(fgets(line, LINE_SIZE, *f) == NULL)
        return -1;
    
    assert(sscanf(line, "%d %s", &row->id, row->hash) != 0);

    return 0;
}

void build_cktbl(FILE **f, chunk_table_t *cktbl)
{
    int i = -1;
    chunk_row_t row;

    assert(f != NULL);

    while(get_chunk_row(f, &row) == 0)
    {
        chunk_entry_t *entry = (chunk_entry_t *)malloc(sizeof(chunk_entry_t));
        entry->row = row;
        entry->next = NULL;

        i = super_fast_hash(entry->row.hash, HASH_ASCII_SIZE, HASH_ASCII_SIZE) % HASH_TABLE_SIZE;
        entry->next = (*cktbl)[i]->next;
        (*cktbl)[i] = entry;
    }
}

int search_cktbl(const chunk_table_t *cktbl, const char *hash)
{
    int i = -1;
    chunk_entry_t *entry;

    i = super_fast_hash(hash, HASH_ASCII_SIZE, HASH_ASCII_SIZE) % HASH_TABLE_SIZE;

    entry = (*cktbl)[i];
    while(entry != NULL)
    {
        if(strncmp(hash, entry->row.hash, HASH_ASCII_SIZE) == 0)
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
    build_cktbl(&f, &cktbl);
    fclose(f);

    f = fopen(has_chunk, "r");
    assert(f != NULL);

    while(get_chunk_row(&f, &row) == 0)
        if(search_cktbl(&cktbl, row.hash) != row.id)
            return -1;

    return 0;
}
