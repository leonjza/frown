#ifndef TTYRIS_LIBRARY_H
#define TTYRIS_LIBRARY_H

#include <stddef.h>

// the key used to encrypt the flag in ttyriscrypt.
// score 9179, and you get the flag
// [ord(x) ^ 9179 for x in "e4abd17d8629082edc2c9dd38cd16a5c"]
static const int FLAG[] = {
        9150, 9199, 9146, 9145, 9151, 9194, 9196, 9151, 9187, 9197,
        9193, 9186, 9195, 9187, 9193, 9150, 9151, 9144, 9193,
        9144, 9186, 9151, 9151, 9192, 9187, 9144, 9151, 9194,
        9197, 9146, 9198, 9144
};

size_t flag_size();

void flag_key(int key, char *answer, int answer_len);

#endif //TTYRIS_LIBRARY_H
