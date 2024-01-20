#ifndef TTYRIS_LIBRARY_H
#define TTYRIS_LIBRARY_H

#include <stddef.h>

// the key used to encrypt the flag in ttyriscrypt.
// score 19981, and you get the flag
// [ord(x) ^ 19981 for x in "e4abd17d8629082edc2c9dd38cd16a5c"]
static const int FLAG[] = {
        20072, 20025, 20076, 20079, 20073, 20028, 20026, 20073, 20021,
        20027, 20031, 20020, 20029, 20021, 20031, 20072, 20073, 20078,
        20031, 20078, 20020, 20073, 20073, 20030, 20021, 20078,
        20073, 20028, 20027, 20076, 20024, 20078
};

size_t flag_size();

void flag_key(int key, char *answer, int answer_len);

#endif //TTYRIS_LIBRARY_H
