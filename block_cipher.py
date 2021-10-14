myStudentNum = [2,5,0,9,4,8,4,7,9]
codebook = [162, 127, 100, 71, 3, 114, 178, 130, 122, 189, 23, 214, 83, 153, 231, 145, 47, 128, 224, 60, 115, 255, 137, 248, 96, 81, 249, 45, 93, 213, 161, 136, 191, 244, 142, 174, 194, 167, 172, 141, 5, 242, 91, 225, 31, 37, 75, 61, 82, 226, 26, 105, 230, 15, 209, 109, 246, 144, 27, 29, 24, 40, 175, 158, 103, 0, 73, 199, 120, 33, 180, 32, 121, 211, 156, 79, 54, 185, 76, 43, 239, 234, 222, 250, 63, 57, 6, 116, 99, 132, 14, 232, 77, 62, 240, 183, 208, 126, 148, 106, 66, 165, 52, 107, 147, 41, 123, 186, 55, 200, 237, 151, 30, 129, 215, 69, 25, 152, 117, 160, 212, 125, 150, 97, 188, 166, 48, 217, 2, 8, 84, 124, 190, 28, 18, 49, 210, 140, 184, 139, 227, 98, 95, 197, 235, 170, 198, 205, 202, 241, 203, 169, 85, 207, 134, 10, 110, 135, 87, 78, 181, 16, 253, 90, 70, 146, 236, 176, 80, 72, 36, 113, 21, 164, 68, 12, 182, 59, 157, 187, 159, 13, 46, 50, 119, 56, 17, 254, 19, 65, 223, 58, 138, 177, 168, 131, 220, 39, 155, 245, 74, 38, 111, 252, 179, 20, 67, 112, 64, 243, 94, 206, 35, 163, 204, 11, 171, 195, 149, 247, 104, 218, 221, 4, 89, 201, 251, 143, 51, 92, 216, 7, 229, 102, 228, 9, 118, 53, 193, 173, 22, 219, 233, 1, 44, 101, 154, 86, 196, 238, 133, 88, 42, 192, 34, 108]

def cbc_encrypt(plaintext, initVector):

    # empty array for ciphertext
    ciphertext = [0]*len(plaintext)

    # loop through plaintext
    for i in range (len(plaintext)):

        # xor first with init vector
        if i == 0:
            xor = plaintext[0] ^ initVector
            ciphertext[0] = codebook[xor]

        else: # xor with previous ciphertext
            xor = plaintext[i] ^ ciphertext[i-1]
            ciphertext[i] = codebook[xor]

    return ciphertext

def ctr_encrypt(plaintext, initVector):

    # empty array for ciphertext
    ciphertext = [0]*len(plaintext)

    for i in range (len(plaintext)):

        #encrpt the counter
        temp = codebook[initVector]

        # xor with plaintext, increase counter
        ciphertext[i] = temp ^ plaintext[i]
        initVector += 1
        
        # wrap init vector back to zero
        if initVector == 256:
            initVector = 0
            
    return ciphertext

print('CBC Encryption:', cbc_encrypt(myStudentNum, 23))
print('CTR Encryption:', ctr_encrypt(myStudentNum, 51))

def generate_codebook(plaintext, ciphertext, initVector):

    newCodebook = [0]*255

    # loop through plaintext
    for i in range (len(plaintext)):

        # xor first with init vector
        if i == 0:
            
            # xor'd value is the index of the ciphertext in the codebook 
            index = plaintext[0] ^ initVector
            newCodebook[index] = ciphertext[i]

        else: 

            index = plaintext[i] ^ ciphertext[i-1]
            newCodebook[index] = ciphertext[i]

    return newCodebook

pt = 'melody'
ptAscii = [ord(c) for c in pt]
print (ptAscii)

ct = [56, 16, 139, 19, 243, 149]

print('Test codebook gen: ', generate_codebook(ptAscii,ct,111))

