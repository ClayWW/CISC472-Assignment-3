# needs pycrypto installed

from hw3_helper import olivia
hex_data = 'd3ee35544bff6e54f5dc559a98aa8b8558eb674f0825046e6395136a25f92af3'
hex_iv = '61616161616161616161616161616161'
print(olivia(hex_data, hex_iv))
