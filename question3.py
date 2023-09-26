from main import PRF
from drbg import *
import secrets

def xor(X, Y):
    return bytes(a ^ b for a,b in zip(X,Y))

def generate_round_keys(key, rounds): #works
    subkeys = []
    drbg = DRBG(key)
    prb = drbg.generate(rounds*8)
    for round_num in range(rounds):
        start = round_num*8
        end = start+8
        subkey = prb[start:end]
        subkeys.append(subkey)
    return subkeys

def bh_encrypt(plaintext, key, rounds):
    left,right = plaintext[:8],plaintext[8:] #in english

    subkeys = generate_round_keys(key, rounds)
    left_bytes = left.encode('iso-8859-1')
    right_bytes = right.encode('iso-8859-1')

    for round in range(rounds):
        print(f"Round {round + 1} Key : {subkeys[round].hex()}")
        prf_r = PRF(subkeys[round],right_bytes) #feed the right side in bytes through the PRF
        print(f"Round {round + 1} PRF output: {prf_r.hex()}")
        xored_left = xor(left_bytes, prf_r) #pass the bytes in as strings of english for xor
        print(f"Round {round + 1} XOR output: {xored_left.hex()}")
        left_bytes = right_bytes #does not change
        right_bytes = xored_left
        print((left_bytes + right_bytes).hex())
    ciphertext = left_bytes+right_bytes
    return ciphertext, subkeys

def bh_decrypt(ciphertext, subkeys, rounds):
    left,right = ciphertext[:8],ciphertext[8:]
    for round in range(rounds-1, -1, -1): #working
        print(f"Round {round + 1} Key : {subkeys[round].hex()}")
        prf_r = PRF(subkeys[round],right)
        print(f"Round {round + 1} PRF output: {prf_r.hex()}")
        xored_left = xor(left, prf_r)
        print(f"Round {round + 1} XOR output: {xored_left.hex()}")
        left = right
        right = xored_left
        print((left+right).hex())
    plaintext = left+right
    return plaintext.decode('iso-8859-1')

plaintext = "Hello, World CWW"
key = bytes.fromhex("7bc6ac0dbe97d6e41cb440abd82b8dcf")
rounds = 5

ciphertext, subkeys = bh_encrypt(plaintext, key, rounds)
print(ciphertext.hex())
plaintext2 = bh_decrypt(ciphertext, subkeys, rounds)
print(plaintext2)