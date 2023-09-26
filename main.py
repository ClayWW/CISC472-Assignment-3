from drbg import *

# Generate twice the amount of pseudorandom 
# data as the byte size of the given seed
# break the output in two parts: left, right
def PRG(seed):
  assert isinstance(seed, bytes)
  drbg = DRBG(seed)
  rnd = drbg.generate(2*len(seed))
  return rnd[:len(seed)], rnd[len(seed):]

def PRF(key, msg):
  assert isinstance(key, bytes)
  assert isinstance(msg, bytes)
  # convert data into sequence of bits
  msgBits = "".join(format(byte, '08b') for byte in msg)
  seed = key # initialize the seed with the key
  for b in msgBits:
    rnd = PRG(seed)[int(b)]
    seed = rnd
  return rnd

#print(PRF(b'\x00'*5,b'\x00'*5))