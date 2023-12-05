#ifndef TTYRIS_LIBRARY_H
#define TTYRIS_LIBRARY_H

#include <stddef.h>

// the key used to encrypt the flag in ttyriscrypt.
// 31337 is an impossible score for sure.
// [ord(x) ^ 31337 for x in "65143f1845aed0ff60146bc4de9fc9e0"]
static const int FLAG[] = {
        31327, 31324, 31320, 31325, 31322, 31247, 31320,
        31313, 31325, 31324, 31240, 31244, 31245, 31321,
        31247, 31247, 31327, 31321, 31320, 31325, 31327,
        31243, 31242, 31325, 31245, 31244, 31312, 31247,
        31242, 31312, 31244, 31321
};

size_t flag_size();

void flag_key(int key, char *answer, int answer_len);

#endif //TTYRIS_LIBRARY_H
