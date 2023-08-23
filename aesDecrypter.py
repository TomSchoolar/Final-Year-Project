from binascii import a2b_hex, b2a_hex
from Crypto.Cipher import AES
import sys

""" some test data
key: d0f8a6a4b479e611a684d4003ce126de
nonce: 00acf8cc662d23000000000003
data: 38
"""

# pulling arguments from the command line call
key = a2b_hex(sys.argv[1])
Mac = sys.argv[2]
IV = sys.argv[3]
IVPadded = ('0'*(12-len(IV))) + IV

nonce = a2b_hex('00'+Mac+IVPadded) # pad the nonce

# making sure the ciphertext is an even length otherwise the cipher wont run
if (len(sys.argv[4]) % 2) != 0: 
	cipherdata = a2b_hex(sys.argv[4] + '0') # pad with 0 to make the data even length
else:
	cipherdata = a2b_hex(sys.argv[4])

# run the cipher suite with CCM mode
cipher = AES.new(key, AES.MODE_CCM, nonce, mac_len=8, msg_len=len(cipherdata))
data = cipher.decrypt(cipherdata)

# convert to hex bytes
data = b2a_hex(data)

string = ''

for byte in data:
	string = string + chr(byte) # convert bytes to chars for printing

print(string)
