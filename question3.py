from main import PRF
from drbg import *

def xor(X, Y):
    try:
        return bytes(a ^ b for a,b in zip(X,Y))
    except TypeError:
        print(f"Error XOR-ing: {X=} {Y=}")
        raise

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
'''
def divide_blocks(plaintext, block_size):
    blocks = []
    num_blocks = len(plaintext)//block_size + 1
    for i in range(num_blocks):
        block_start = i*block_size
        block_end = block_start+block_size
        block = plaintext[block_start:block_end]
        blocks.append(block)
    if len(plaintext) % block_size != 0:
        remaining_block = plaintext[num_blocks*block_size:]
        padding_length = block_size - len(remaining_block)%block_size
    else:
        padding_length = 0
    return blocks, padding_length
'''
def divide_blocks(plaintext, block_size_bits: int):
    block_size_bytes = block_size_bits // 8
    if isinstance(plaintext, str):
        plaintext_bytes = plaintext.encode('iso-8859-1')
    elif isinstance(plaintext, bytes):
        plaintext_bytes = plaintext
    else:
        raise ValueError("input needs to be a string or bytes")
    
    blocks = [plaintext_bytes[i:i+block_size_bytes] for i in range(0, len(plaintext_bytes), block_size_bytes)]
    last_block_len = len(blocks[-1])
    if(last_block_len < block_size_bytes):
        padding_length = block_size_bytes - last_block_len
        padding = bytes([padding_length]) * padding_length
        blocks[-1] += padding
    elif last_block_len == block_size_bytes:
        padding = bytes([block_size_bytes])*block_size_bytes
        blocks.append(padding)
        padding_length = block_size_bytes
    else:
        padding_length = 0
    return blocks, padding_length

def remove_padding(block):
    padding_length = block[-1]
    if padding_length <= 0 or padding_length > len(block):
        return block
    unpadded_block = block[:-padding_length]
    return unpadded_block

def bh_encrypt(plaintext: str, key: bytes, rounds: int): #will finish with all blocks being full
    encrypted_blocks = []
    subkeys = []
    blocks, padding_length = divide_blocks(plaintext, 128)
    block: bytes
    for block in blocks:
        left_bytes,right_bytes = block[:8],block[8:]  #correctly splits
        if not isinstance(right_bytes, bytes):
            right_bytes = right_bytes.encode('iso-8859-1')
        if not isinstance(left_bytes, bytes):
            left_bytes = left_bytes.encode('iso-8859-1')
        subkeys = generate_round_keys(key, rounds) #correctly generates keys, wrong size maybe?

        for round in range(rounds):
            prf_r = PRF(subkeys[round],right_bytes) #feed the right side in bytes through the PRF
            xored_left = xor(left_bytes, prf_r) #pass the bytes in as strings of english for xor
            left_bytes = right_bytes #does not change
            right_bytes = xored_left

        ciphertext = left_bytes+right_bytes
        encrypted_blocks.append(ciphertext)

    concat_blocks = b"".join(encrypted_blocks)
    return concat_blocks, subkeys, padding_length


def bh_decrypt(ciphertext, subkeys, rounds, padding_length):
    decrypted_blocks = []
    blocks, padding_length = divide_blocks(ciphertext, 128)
    for block in blocks:
        left,right = block[:8],block[8:]
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
        if block == len(blocks)-1:
            plaintext = plaintext[:-padding_length]
        decrypted_blocks.append(plaintext)
    concat_blocks = b"".join(decrypted_blocks)
    return concat_blocks.decode('iso-8859-1')

def bh_ctr_encryption(message_bytes, key, nonce, rounds):
    encrypted_blocks = []
    blocks, _ = divide_blocks(message_bytes, 128)
    for i,block in enumerate(blocks):
        if(i > 256):
            print("Out of counter, need a new nonce!")
            return
        input = nonce+i.to_bytes(8,'big')
        encrypted,_,_ = bh_encrypt(input, key, rounds)
        ciphertext = xor(block, encrypted)
        encrypted_blocks.append(ciphertext)
    concat_ciphertext = b"".join(encrypted_blocks)
    return concat_ciphertext


def bh_ctr_decryption(ciphertext, key, nonce, rounds, padding_length): 
    decrypted_blocks = []
    blocks, _ = divide_blocks(ciphertext, 128) #correctly divides
    for i,block in enumerate(blocks): 
        if(i > 256):
            print("Out of counter, Need a new nonce!")
            return
        input = nonce+i.to_bytes(8,'big')
        encrypted, _, _ = bh_encrypt(input, key, rounds)
        message = xor(block, encrypted)
        if(i == len(blocks)-1):
            message = message[:-padding_length]
        decrypted_blocks.append(message)
    concat_plain = b"".join(decrypted_blocks) #empty when it shouldn't be
    return concat_plain.decode('iso-8859-1')

#testing feistel
plaintext = "Hello, World CWW"
key = bytes.fromhex("7bc6ac0dbe97d6e41cb440abd82b8dcf")
rounds = 5
ciphertext, subkeys, padding_length = bh_encrypt(plaintext, key, rounds)
print(ciphertext.hex())
decrypted_plaintext = bh_decrypt(ciphertext, subkeys, rounds, padding_length)
print(decrypted_plaintext)

#testing bh_ctr_decryption
message = "0123456789ABCDEF0123456789ABCDEF"
message_bytes = message.encode('iso-8859-1')
nonce = bytes.fromhex("59733285e8d82615")
ciphertext_ctr = bh_ctr_encryption(message_bytes, key, nonce, rounds)

concat_plain = bh_ctr_decryption(ciphertext_ctr, key, nonce, rounds, padding_length)
#print(message)
#print(concat_plain)

#blocks, _ = divide_blocks(message, 128)
#print("Output: ",blocks)