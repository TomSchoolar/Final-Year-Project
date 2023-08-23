import sys

# get argument from command line
data = sys.argv[1]

# convert hex character in ascii representation into a int value in base 16
def hexToDen(num):
    if num == 'a':
        return 10
    if num == 'b':
        return 11
    if num == 'c':
        return 12
    if num == 'd':
        return 13
    if num == 'e':
        return 14
    if num == 'f':
        return 15
    else:
        return int(num)

# convert int in base 16 to the hex value in ascii representation
def denToHex(num):
    if num == 10:
        return 'a'
    if num == 11:
        return 'b'
    if num == 12:
        return 'c'
    if num == 13:
        return 'd'
    if num == 14:
        return 'e'
    if num == 15:
        return 'f'
    else:
        return str(num)

# converts hex string and turns into the binary representation
def binary(inputNumber):
    finalBinaryRepresentation = []
    
    for char in inputNumber:
        number = hexToDen(char)
        
        binaryRepresentation = [0,0,0,0]
        if(number >= 8):
            binaryRepresentation[0] = 1
            number = number - 8
        if(number >= 4):
            binaryRepresentation[1] = 1
            number = number - 4
        if(number >= 2):
            binaryRepresentation[2] = 1
            number = number - 2
        if(number >= 1):
            binaryRepresentation[3] = 1
            number = number - 1
            
        finalBinaryRepresentation = finalBinaryRepresentation + binaryRepresentation # append this binary number to the end of the other numbers
    return finalBinaryRepresentation # a 16 bit long binary number


# adds 2 binary numbers together returning the result and any carried bits
def binaryAdd(num1, num2):
    index = 15
    finalBinary = num1;
    carry = 0

    while index >= 0: # loop through every bit adding the values up and scaling by the place value
        count = num1[index] + num2[index] + carry

        if count == 1:
            carry = 0
            finalBinary[index] = 1
        elif count == 2:
            carry = 1
            finalBinary[index] = 0
        elif count == 3:
            carry = 1
            finalBinary[index] = 1

        index = index - 1

    return (carry, finalBinary) # returns a pair of the carried bit and the final binary number
        

# summed will be the value of all the bytes added together including any carry bits
summed = binary(data[0:4]) # set it to the first byte

# loop through all the bytes adding them to summed while keeping track of the carried bits
start = 0
end = start + 4
carry = 0

for i in range (1, int(len(data) / 4)):
    start = i*4
    end = start + 4
    newBinary = binary(data[start:end])
    (newCarry, summed) = binaryAdd(newBinary, summed)
    carry = carry + newCarry

# scale the carry bit into a binary number and add this to the summed value
(carry, summed) = binaryAdd(binary("000"+str(carry)), summed)


# convert the binary numbers back into denary and store them in this list
nums = [0,0,0,0]

index = 15
power = 0
while index >= 0:
    if summed[index] == 1:
        summed[index] = 0
    else:
        summed[index] = 1

    if index > 11:
        nums[3] = nums[3] + (2**power * summed[index])
    elif index > 7:
        nums[2] = nums[2] + (2**power * summed[index])
    elif index > 3:
        nums[1] = nums[1] + (2**power * summed[index])
    else:
        nums[0] = nums[0] + (2**power * summed[index])
    index = index - 1
    power = power + 1
    if power > 3:
        power = 0

# convert each denary number to hex and store the value as a string for printing
final = denToHex(nums[0]) + denToHex(nums[1]) + denToHex(nums[2]) + denToHex(nums[3])

print(final)


