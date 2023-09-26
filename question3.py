from main import PRF
from drbg import *

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

def divide_blocks(plaintext, block_size):
    blocks = []
    num_blocks = len(plaintext)//block_size
    for i in range(num_blocks):
        block_start = i*block_size
        block_end = block_start+block_size
        block = plaintext[block_start:block_end]
        blocks.append(block)
    if len(plaintext) % block_size != 0:
        remaining_block = plaintext[num_blocks*block_size:]
        padding_length = block_size - len(remaining_block)%block_size
        #padding = bytes([padding_length]*padding_length)
        #padded_block = remaining_block + padding
        #blocks.append(padded_block)
    else:
        padding_length = 0
    return blocks, padding_length

def remove_padding(block):
    padding_length = block[-1]
    if padding_length <= 0 or padding_length > len(block):
        return block
    unpadded_block = block[:-padding_length]
    return unpadded_block

def bh_encrypt(plaintext, key, rounds):
    encrypted_blocks = []
    blocks, padding_length = divide_blocks(plaintext)
    for block in enumerate(blocks):
        
        left,right = plaintext[:8],plaintext[8:]  #correctly splits
        subkeys = generate_round_keys(key, rounds) #correctly generates keys, wrong size maybe?
        left_bytes = left.encode('iso-8859-1')
        right_bytes = right.encode('iso-8859-1') #correctly encodes

        for round in range(rounds):
            #print(subkeys[round].hex())
            #print(f"Round {round + 1} Key : {subkeys[round].hex()}")
            prf_r = PRF(subkeys[round],right_bytes) #feed the right side in bytes through the PRF
            #print(f"Round {round + 1} PRF output: {prf_r.hex()}")
            xored_left = xor(left_bytes, prf_r) #pass the bytes in as strings of english for xor
            #print(f"Round {round + 1} XOR output: {xored_left.hex()}")
            left_bytes = right_bytes #does not change
            right_bytes = xored_left
            #print((left_bytes + right_bytes).hex())

        ciphertext = left_bytes+right_bytes
        encrypted_blocks.append(ciphertext)

        if(block == len(blocks)-1):
            block = block[:-padding_length]

    concat_blocks = " ".join(encrypted_blocks)
    return concat_blocks, subkeys


def bh_decrypt(ciphertext, subkeys, rounds):
    left,right = ciphertext[:8],ciphertext[8:]
    for round in range(rounds-1, -1, -1): #working
        #print(f"Round {round + 1} Key : {subkeys[round].hex()}")
        prf_r = PRF(subkeys[round],right)
        #print(f"Round {round + 1} PRF output: {prf_r.hex()}")
        xored_left = xor(left, prf_r)
        #print(f"Round {round + 1} XOR output: {xored_left.hex()}")
        left = right
        right = xored_left
        #print((left+right).hex())
    plaintext = left+right
    return plaintext.decode('iso-8859-1')



def bh_ctr_decryption(ciphertext_blocks, key, nonce, rounds):
    decrypted_blocks = []
    for i,block in enumerate(ciphertext_blocks):
        input = str(nonce)+str(i)
        encrypted = bh_encrypt(input, key, rounds)
        message = xor(block, encrypted)
        decrypted_blocks.append(message)
    concat_plain = " ".join(decrypted_blocks)
    return concat_plain

plaintext = "Hello, World CWW"
key = bytes.fromhex("7bc6ac0dbe97d6e41cb440abd82b8dcf")
rounds = 5

ciphertext, subkeys = bh_encrypt(plaintext, key, rounds)
print(ciphertext.hex())
decrypted_plaintext = bh_decrypt(ciphertext, subkeys, rounds)
print(decrypted_plaintext)