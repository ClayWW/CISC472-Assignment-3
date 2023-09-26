from Crypto.Cipher import AES

ctxt1_hex = "3012e00127813d5a563f775e0906d081"
ctxt2_hex = "79789673ec9cf766126751c0d7486604"

ctxt1_bytes = bytes.fromhex(ctxt1_hex)
ctxt2_bytes = bytes.fromhex(ctxt2_hex)

for byte1_val in range(256):
    for byte2_val in range(256):
        byte1_bytes = bytes([byte1_val])
        byte2_bytes = bytes([byte2_val])

        key_bytes = (byte1_bytes + byte2_bytes)*8

        cipher = AES.new(key_bytes, AES.MODE_ECB)

        try:
            plaintext1_bytes = cipher.decrypt(ctxt1_bytes)
            plaintext2_bytes = cipher.decrypt(ctxt2_bytes)

            plaintext1 = plaintext1_bytes.decode('iso-8859-1')
            plaintext2 = plaintext2_bytes.decode('iso-8859-1')

            if(plaintext1.isprintable() and plaintext2.isprintable()):
                print("Potential Key Found: ", key_bytes.hex())
                print("Decrypted Plainext 1: ",plaintext1)
                print("Decrypted Plaintext 2: ", plaintext2)
                print("\n")
                break
        except Exception as e:
            pass

#Key: 1c4d1c4d1c4d1c4d1c4d1c4d1c4d1c4d
#Plaintext 1: my key is weak!!
#Plaintext 2: Eve cant read it