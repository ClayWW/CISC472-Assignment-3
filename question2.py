from Crypto.Cipher import AES

#our two initial ciphertexts that were intercepted
ctxt1_hex = "3012e00127813d5a563f775e0906d081"
ctxt2_hex = "79789673ec9cf766126751c0d7486604"

#ciphertexts in bytes
ctxt1_bytes = bytes.fromhex(ctxt1_hex)
ctxt2_bytes = bytes.fromhex(ctxt2_hex)

#double for loop that each go from 0-256 so that we cover all 2^16 possibilites for the two bytes that are repeated in the key
for byte1_val in range(256):
    for byte2_val in range(256):
        byte1_bytes = bytes([byte1_val]) #turns the values into bytes
        byte2_bytes = bytes([byte2_val])

        key_bytes = (byte1_bytes + byte2_bytes)*8 #creates the key based on the bytes, just two bytes repeated 8 times

        cipher = AES.new(key_bytes, AES.MODE_ECB) #create the AES cipher utilized in encryption and pass in a key 

        try:
            plaintext1_bytes = cipher.decrypt(ctxt1_bytes) #decrypt both ciphertexts 
            plaintext2_bytes = cipher.decrypt(ctxt2_bytes)

            plaintext1 = plaintext1_bytes.decode('iso-8859-1') #turn the bytes back into plaintext
            plaintext2 = plaintext2_bytes.decode('iso-8859-1')

            if(plaintext1.isprintable() and plaintext2.isprintable()): #if the bytes are printable (not gibberish), print them out and see if they make sense
                print("Potential Key Found: ", key_bytes.hex()) #fully print out everything, both plaintexts need to make sense in order for the key to possibly be correct
                print("Decrypted Plainext 1: ",plaintext1)
                print("Decrypted Plaintext 2: ", plaintext2)
                print("\n")
                break
        except Exception as e: #in case of any errors involving the cipher or decryption
            pass

#RESULTS
#Key: 1c4d1c4d1c4d1c4d1c4d1c4d1c4d1c4d
#Plaintext 1: my key is weak!!
#Plaintext 2: Eve cant read it