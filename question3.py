from main import PRF
from drbg import *

#our xor function but this time for bits instead of ascii characters
def xor(X, Y):
    try:
        return bytes(a ^ b for a,b in zip(X,Y))
    except TypeError:
        print(f"Error XOR-ing: {X=} {Y=}")
        raise

#takes in a key and uses it to generate a specified amount of round keys
#we know that we are passing 8 bytes into the PRF so we make our subkeys 8 bytes long
def generate_round_keys(key, rounds): #works
    subkeys = []
    drbg = DRBG(key)
    prb = drbg.generate(rounds*8) #generates an exact amount of psuedorandom bytes
    for round_num in range(rounds): #divides up the keys
        start = round_num*8
        end = start+8
        subkey = prb[start:end]
        subkeys.append(subkey)
    return subkeys #return the array of subkeys

#divides the blocks based on a specified size and adds padding if necessary
def divide_blocks(plaintext, block_size_bits: int):
    block_size_bytes = block_size_bits // 8 #bits to bytes
    if isinstance(plaintext, str): #ensure that plaintext is in bytes
        plaintext_bytes = plaintext.encode('iso-8859-1')
    elif isinstance(plaintext, bytes):
        plaintext_bytes = plaintext
    else:
        raise ValueError("input needs to be a string or bytes") #in case incorrect input
    
    blocks = [plaintext_bytes[i:i+block_size_bytes] for i in range(0, len(plaintext_bytes), block_size_bytes)] #divide the blocks and store in array
    last_block_len = len(blocks[-1]) 
    if(last_block_len < block_size_bytes): #pads the final block if necessary, adds more than necessary padding in some cases
        padding_length = block_size_bytes - last_block_len
        padding = bytes([padding_length]) * padding_length
        blocks[-1] += padding
    elif last_block_len == block_size_bytes:
        padding = bytes([block_size_bytes])*block_size_bytes
        blocks.append(padding)
        padding_length = block_size_bytes
    else:
        padding_length = 0
    return blocks, padding_length #returns the array of blocks and the amount of padding on the final block

#takes in a block and removes additional padding
def remove_padding(block):
    padding_length = block[-1] #specify how many bytes to delete
    if padding_length == len(block): # if final block is full padding just delete the block
        return b""
    return block[:-padding_length] #return the unpadded block

#encrypts a plaintext through a feistel network using an inputted key and inputted amount of rounds
def bh_encrypt(plaintext: str, key: bytes, rounds: int): 
    encrypted_blocks = []
    subkeys = []
    blocks, padding_length = divide_blocks(plaintext, 128) #divide plaintext into blocks
    block: bytes #suggest block as type bytes
    for block in blocks: #for each block
        left_bytes,right_bytes = block[:8],block[8:]  #divide block in half
        if not isinstance(right_bytes, bytes): #ensure left half is in bytes
            right_bytes = right_bytes.encode('iso-8859-1')
        if not isinstance(left_bytes, bytes): #ensure right half is in bytes
            left_bytes = left_bytes.encode('iso-8859-1')
        subkeys = generate_round_keys(key, rounds) #generate subkey for each round

        for round in range(rounds): #perform feistel scheme for amount of rounds specifed (0,1,2,3,4)
            prf_r = PRF(subkeys[round],right_bytes) #feed the right side in bytes through the PRF with unique subkey
            xored_left = xor(left_bytes, prf_r) #xor the left bytes with the results of the PRF
            left_bytes = right_bytes #the bytes that were once the left half become the right
            right_bytes = xored_left #the bytes that were once the right half become the result of XOR operation between left bytes and PRF output

        ciphertext = left_bytes+right_bytes #combine left and right into the final block
        encrypted_blocks.append(ciphertext) #add the encrypted block into the encrypted blocks array

    concat_blocks = b"".join(encrypted_blocks) #combine all of the encrypted blocks and return
    return concat_blocks, subkeys, padding_length #return ciphertext, the subkeys used in all the rounds, and any padding the final block of ciphertext may have

#decrypts ciphertext through a feistel network by passing the ciphertext through for the same amount of rounds as encryption but subkeys are applied in reverse order
#I believe my problem lies here, I think the encryption algorithm is performing as intended, but there has to be something wrong with decryption
#If I had to guess, the problem is something obvious that I am overlooking, I believe I am following the algorithm correctly in terms of the splitting, the PRF, the swapping, and
#the recombination, so the problem likely lies with in either the padding or maybe the application of subkeys (but I think I have that right?)
def bh_decrypt(ciphertext, subkeys, rounds, padding_length):
    decrypted_blocks = []
    blocks, padding_length = divide_blocks(ciphertext, 128) #divide ciphertext into blocks
    for block in blocks: #for every block
        left,right = block[:8],block[8:] #divide the block into left and right
        for round in range(rounds-1, -1, -1): #loop through in reverse order (4,3,2,1,0)
            prf_r = PRF(subkeys[round],right) #apply inverse subkey for the PRF
            xored_left = xor(left, prf_r) #perform the same xor operation between left bytes and the output of the prf
            left = right #left bytes are now the right bytes
            right = xored_left #right bytes are now the ouput of the xor operation
        plaintext = left+right #recombine block
        if block == len(blocks)-1: #check for padding and remove
            plaintext = plaintext[:-padding_length]
        decrypted_blocks.append(plaintext) #add back decrypted block to array
    concat_blocks = b"".join(decrypted_blocks) #combine decrypted blocks and return decrypted ciphertext
    return concat_blocks

#performs ctr encryption using the bh_encryption scheme above.
#Takes in a message in bytes format, a key, the nonce used, and the amount of rounds executed in the fesitel network
def bh_ctr_encryption(message_bytes, key, nonce, rounds):
    encrypted_blocks = []
    blocks, _ = divide_blocks(message_bytes, 128) #divide message into blocks
    for i,block in enumerate(blocks): #i acts as the counter, increments with every block
        if(i > 256): #if counter is maxed out indicate the need for a new nonce
            print("Out of counter, need a new nonce!")
            return
        input = nonce+i.to_bytes(8,'big') #concatenate the nonce and counter
        encrypted,_,_ = bh_encrypt(input, key, rounds) #encrypt the nonce+counter using the bh_encrypt function
        ciphertext = xor(block, encrypted) #xor the encrypted nonce+counter with the block of the message
        encrypted_blocks.append(ciphertext) #add the encrypted block to the array
    concat_ciphertext = b"".join(encrypted_blocks) #combine all encrypted blocks and return the ciphertext
    return concat_ciphertext

#I also implemented ctr decryption so i could make sure the ctr encryption worked properly (FEEL FREE TO IGNORE)
#Takes in the ciphertext from the encryption, the key used, the nonce used, the amount fo rounds in bh_encrypt, and the potential padding on the last block
#Pretty much the same as encryption with a couple changes
def bh_ctr_decryption(ciphertext, key, nonce, rounds, padding_length): 
    decrypted_blocks = []
    blocks, _ = divide_blocks(ciphertext, 128) #correctly divides ciphertext
    for i,block in enumerate(blocks): 
        if(i > 256):
            print("Out of counter, Need a new nonce!")
            return
        input = nonce+i.to_bytes(8,'big')
        encrypted, _, _ = bh_encrypt(input, key, rounds)
        message = xor(block, encrypted) #xor the ciphertext and the encrypted nonce+counter
        if(i == len(blocks)-1): #check for padding on the final block and remove
            message = message[:-padding_length]
        decrypted_blocks.append(message)
    concat_plain = b"".join(decrypted_blocks)
    return concat_plain.decode('iso-8859-1')

#CBC encryption, takes in the plaintext to be encrypted, the key used, the IV, and the amount of rounds used in bh_encrypt
def bh_cbc_encryption(plaintext, key, IV, rounds):
    encrypted_blocks = []
    blocks,_ = divide_blocks(plaintext,128) #divide the plaintext into blocks
    prev_cipher_block = IV #establish the IV as the first previous block to start out
    for block in blocks: #for every block
        xor_block = xor(block, prev_cipher_block) #xor the block with the previously encrypted block
        encrypted_block,_,_ = bh_encrypt(xor_block, key, rounds) #pass the new xored block into the encryption algorithm
        encrypted_blocks.append(encrypted_block) #append this new ciphertext to the array of encrypted blocks
        prev_cipher_block = encrypted_block #the newly encrypted block is now the previous block for the next iteration
    concat_ciphertext = b"".join(encrypted_blocks) #concatenate all of the encrypted blocks together and return
    return concat_ciphertext

    
#testing feistel
#3a Questions
#Each subkey should be 8 bytes, or half the length of the block
#You need a different subkey for each round, so we will generate 5 subkeys

plaintext = "Hello, World CWW"
plaintext2 = "This is an attempt to see if a longer plaintext yields better results"

key = bytes.fromhex("7bc6ac0dbe97d6e41cb440abd82b8dcf")
rounds = 5

print("Plaintext 1: ", plaintext)
ciphertext, subkeys, padding_length = bh_encrypt(plaintext, key, rounds)
print("Ciphertext 1: ",ciphertext.hex())
decrypted_plaintext = bh_decrypt(ciphertext, subkeys, rounds, padding_length)
print("Decrypted Ciphertext 1: ",decrypted_plaintext.decode('iso-8859-1'))

print("Plaintext 2: ", plaintext2)
ciphertext2, subkeys2, padding_length2 = bh_encrypt(plaintext2, key, rounds)
print("Ciphertext 2: ",ciphertext2.hex())
decrypted_plaintext2 = bh_decrypt(ciphertext2, subkeys2, rounds, padding_length2)
print("Decrypted Ciphertext 2: ", decrypted_plaintext2.decode('iso-8859-1'))
print("\n")

#testing bh_ctr_decryption
#Questions for 3b
#When you are using the same key, you need to change the nonce for every message
#The decryption algorithm needs the ciphertext, the key, the IV, and in our case the amount of rounds used in the feistel scheme
#You do not need to add padding for this mode of operation
message = "This is my attempt to encrypt a string that is four blocks long!"
message_bytes = message.encode('iso-8859-1')
nonce = bytes.fromhex("59733285e8d82615")
print("Plaintext: ",message)
ciphertext_ctr = bh_ctr_encryption(message_bytes, key, nonce, rounds)
print("Ciphertext: ",ciphertext_ctr.hex())
concat_plain = bh_ctr_decryption(ciphertext_ctr, key, nonce, rounds, padding_length)
print("Should match with plaintext: ",concat_plain)
print("\n")

#testing cbc encryption
#Questions for 3c
#For CBC decryption, you need the ciphertext, the key, the IV, and because we are using a feistel scheme for encryption we need to also provide the amount of rounds used
plaintext = "Attempting to encrypt three blocks of data now!!"
IV = bytes.fromhex("1218a9f78bf8bedff5013407dc712544")
cipher = bh_cbc_encryption(plaintext, key, IV, rounds)
print("Plaintext: ",plaintext)
print("Ciphertext: ", cipher.hex())
print("\n")



