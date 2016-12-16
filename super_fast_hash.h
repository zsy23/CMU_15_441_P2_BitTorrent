/*
 * super_fast_hash.h
 *
 * Referenced from <http://www.azillionmonkeys.com/qed/hash.html>
 * Under the LGPL 2.1 license
 *
 */

#ifndef _SUPER_FAST_HASH_H_
#define _SUPER_FAST_HASH_H_

#include <stdint.h>

uint32_t super_fast_hash (const char * data, int len, uint32_t hash);

#endif /* SUPER_FAST_HASH_H_ */
