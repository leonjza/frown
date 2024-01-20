#!/usr/bin/env python3

def xor_with_key(secret, key):
    return [(ord(char) ^ ord(key[i % len(key)])) for i, char in enumerate(secret)]

secret = "INS{f1rst_yoU_try_AND_hide_AnD_s0m3t1m3s_You_ARE_lucky}"
key = "e4abd17d8629082edc2c9dd38cd16a5c"
xored = xor_with_key(secret, key)

print("[]int{", end="")
for x in xored:
    print(x, end=", ")
print("}")
