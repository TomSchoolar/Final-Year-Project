import zlib
import sys

# convert the input into byte form
inputValue = bytes.fromhex(sys.argv[1])

# return the hex value of the calculated crc32 given the input
print(hex(zlib.crc32(inputValue))[2:10])
