#ifndef TTYRIS_LIBRARY_H
#define TTYRIS_LIBRARY_H

#include <stddef.h>

// the key used to encrypt the flag in ttyriscrypt.
// score 9197, and you get the flag
// [ord(x) ^ 9197 for x in "65143f1845aed0ff60146bc4de9fc9e0"]
static const int FLAG[] = {
        9179, 9176, 9180, 9177, 9182, 9099, 9180, 9173, 9177,
        9176, 9100, 9096, 9097, 9181, 9099, 9099, 9179,
        9181, 9180, 9177, 9179, 9103, 9102, 9177, 9097,
        9096, 9172, 9099, 9102, 9172, 9096, 9181
};

size_t flag_size();

void flag_key(int key, char *answer, int answer_len);

#endif //TTYRIS_LIBRARY_H
