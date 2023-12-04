#include "library.h"

#include <stdio.h>


size_t flag_size() {
    return sizeof(FLAG) / sizeof(FLAG[0]);
}

size_t safe_size() {
    return sizeof(safe) / sizeof(safe[0]);
}

void get_flag(int key, char *answer) {
    for (size_t i = 0; i < flag_size(); i++) {
        int t = FLAG[i] ^ key;
//            int t = FLAG[i] ^ 0x539;

        // filter to safe, ascii printable only
        for (size_t si = 0; si < safe_size(); si++) {
            if (t == safe[si]) {
                answer[i] = (char) t;
                break;
            } else {
                answer[i] = (char) 42; // * character
            }
        }
    }
}
