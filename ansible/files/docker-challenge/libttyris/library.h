#ifndef TTYRIS_LIBRARY_H
#define TTYRIS_LIBRARY_H

#include <stddef.h>

// [ord(x) ^ 1337 for x in "flag{y0u_c4nt_h1d3_fr0m_fr33da}"]
static const int FLAG[] = {
        1375, 1365, 1368, 1374, 1346, 1344, 1289, 1356, 1382, 1370,
        1293, 1367, 1357, 1382, 1361, 1288, 1373, 1290, 1382,
        1375, 1355, 1289, 1364, 1382, 1375, 1355, 1290, 1290,
        1373, 1368, 1348
};

// [ord(x) for x in string.ascii_letters + string.digits + string.punctuation]
static const int safe[] = {
        97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107,
        108, 109, 110, 111, 112, 113, 114, 115, 116, 117,
        118, 119, 120, 121, 122, 65, 66, 67, 68, 69,
        70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
        81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 48,
        49, 50, 51, 52, 53, 54, 55, 56, 57, 33, 34,
        35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
        46, 47, 58, 59, 60, 61, 62, 63, 64, 91, 92,
        93, 94, 95, 96, 123, 124, 125, 126
};

size_t flag_size();

size_t safe_size();

void get_flag(int key, char *answer);

#endif //TTYRIS_LIBRARY_H
