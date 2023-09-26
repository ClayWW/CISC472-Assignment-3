from main import PRF, PRG
from drbg import *

def xor(X, Y):
    return "".join([chr(ord(a) ^ ord(b)) for (a, b) in zip(X, Y)])

def generate_round_keys(key, rounds):
    subkeys = []
    drbg = DRBG(key)
    prb = drbg.generate(rounds*16)
    for round_num in range(rounds):
        start = round_num*16
        end = start+16
        subkey = prb[start:end]
        subkeys.append(subkey)
    return subkeys

def bh_encrypt(plaintext, key, rounds):
    left,right = plaintext[:8],plaintext[8:]
    subkeys = generate_round_keys(key)
    for round in range(rounds):
        prf_r = PRF(subkeys[round],right)
        xored_left = xor(left, prf_r)
        left = right
        right = xored_left
    ciphertext = left+right
    return ciphertext, subkeys

def bh_decrypt(ciphertext, subkeys, rounds):
    left,right = ciphertext[:8],ciphertext[8:]
    for round in range(rounds -1, -1, -1):
        prf_r = PRF(subkeys[round],right)
        xored_left = xor(left, prf_r)
        left = right
        right = xored_left
    plaintext = left+right
    return plaintext

print(generate_round_keys())