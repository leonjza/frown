#!/usr/bin/env python3

def xor_with_key(secret, key):
    return [(ord(char) ^ ord(key[i % len(key)])) for i, char in enumerate(secret)]

secret = "flag{y0u_c4nt_h1d3_fr0m_fr333da}"
key = "65143f1845aed0ff60146bc4de9fc9e0"
xored = xor_with_key(secret, key)

print("[]int{", end="")
for x in xored:
    print(x, end=", ")
print("}")
