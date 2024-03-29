#include "library.h"

#include <stdio.h>


size_t flag_size() {
    return sizeof(FLAG) / sizeof(FLAG[0]);
}

void flag_key(int key, char *answer, int answer_len) {
    for (size_t i = 0; ((i < flag_size()) && (i < answer_len)); i++) {
        int t = FLAG[i] ^ key;

        if ((t > 0) && (t < 255)) {
            answer[i] = (char) t;
        } else {
            answer[i] = 0;
        }
    }
}
