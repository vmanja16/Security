__author__ = 'Vikram'

########################################################
# Advanced Encryption Standard (128 bit) by Vikram Manja
########################################################
from BitVector import *

INPUT_FILE = "plaintext.txt"
DECRYPTION_FILE = "decrypted.txt"
ENCRYPTION_FILE = "encrypted.txt"

KEY = "yayboilermakers!"

AES_modulus = BitVector(bitstring='100011011')
subBytesTable = [ 99, 124, 119, 123, 242, 107, 111, 197,  48,   1, 103,  43, 254, 215, 171, 118,
                 202, 130, 201, 125, 250,  89,  71, 240, 173, 212, 162, 175, 156, 164, 114, 192,
                 183, 253, 147,  38,  54,  63, 247, 204,  52, 165, 229, 241, 113, 216,  49,  21,
                   4, 199,  35, 195,  24, 150,   5, 154,   7,  18, 128, 226, 235,  39, 178, 117,
                   9, 131,  44,  26,  27, 110,  90, 160,  82,  59, 214, 179,  41, 227,  47, 132,
                  83, 209,   0, 237,  32, 252, 177,  91, 106, 203, 190,  57,  74,  76,  88, 207,
                 208, 239, 170, 251,  67,  77,  51, 133,  69, 249,   2, 127,  80,  60, 159, 168,
                  81, 163,  64, 143, 146, 157,  56, 245, 188, 182, 218,  33,  16, 255, 243, 210,
                 205,  12,  19, 236,  95, 151,  68,  23, 196, 167, 126,  61, 100,  93,  25, 115,
                  96, 129,  79, 220,  34,  42, 144, 136,  70, 238, 184,  20, 222,  94,  11, 219,
                 224,  50,  58,  10,  73,   6,  36,  92, 194, 211, 172,  98, 145, 149, 228, 121,
                 231, 200,  55, 109, 141, 213,  78, 169, 108,  86, 244, 234, 101, 122, 174,   8,
                 186, 120,  37,  46,  28, 166, 180, 198, 232, 221, 116,  31,  75, 189, 139, 138,
                 112,  62, 181, 102,  72,   3, 246,  14,  97,  53,  87, 185, 134, 193,  29, 158,
                 225, 248, 152,  17, 105, 217, 142, 148, 155,  30, 135, 233, 206,  85,  40, 223,
                 140, 161, 137,  13, 191, 230,  66, 104,  65, 153,  45,  15, 176,  84, 187,  22]
invSubBytesTable = [
                  82,   9, 106, 213,  48,  54, 165,  56, 191,  64, 163, 158, 129, 243, 215, 251,
                 124, 227,  57, 130, 155,  47, 255, 135,  52, 142,  67,  68, 196, 222, 233, 203,
                  84, 123, 148,  50, 166, 194,  35,  61, 238,  76, 149,  11,  66, 250, 195,  78,
                   8,  46, 161, 102,  40, 217,  36, 178, 118,  91, 162,  73, 109, 139, 209,  37,
                 114, 248, 246, 100, 134, 104, 152,  22, 212, 164,  92, 204,  93, 101, 182, 146,
                 108, 112,  72,  80, 253, 237, 185, 218,  94,  21,  70,  87, 167, 141, 157, 132,
                 144, 216, 171,   0, 140, 188, 211,  10, 247, 228,  88,   5, 184, 179,  69,   6,
                 208,  44,  30, 143, 202,  63,  15,   2, 193, 175, 189,   3,   1,  19, 138, 107,
                  58, 145,  17,  65,  79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115,
                 150, 172, 116,  34, 231, 173,  53, 133, 226, 249,  55, 232,  28, 117, 223, 110,
                  71, 241,  26, 113,  29,  41, 197, 137, 111, 183,  98,  14, 170,  24, 190,  27,
                 252,  86,  62,  75, 198, 210, 121,  32, 154, 219, 192, 254, 120, 205,  90, 244,
                  31, 221, 168,  51, 136,   7, 199,  49, 177,  18,  16,  89,  39, 128, 236,  95,
                  96,  81, 127, 169,  25, 181,  74,  13,  45, 229, 122, 159, 147, 201, 156, 239,
                 160, 224,  59,  77, 174,  42, 245, 176, 200, 235, 187,  60, 131,  83, 153,  97,
                  23,  43,   4, 126, 186, 119, 214,  38, 225, 105,  20,  99,  85,  33,  12, 125]

def g(keyword, round_constant, byte_sub_table):
    '''
    Mostly taken from lectures notes by Avi Kak
    '''
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size = 0)
    for i in range(4):
        newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
    newword[:8] ^= round_constant
    round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8)
    return newword, round_constant

def gen_key_schedule_128(key_bv):
    '''
    Mostly taken from lectures notes by Avi Kak
    '''
    byte_sub_table = subBytesTable

    key_words = [None for i in range(44)]
    round_constant = BitVector(intVal = 0x01, size=8)
    for i in range(4):
        key_words[i] = key_bv[i*32 : i*32 + 32]
    for i in range(4,44):
        if i%4 == 0:
            kwd, round_constant = g(key_words[i-1], round_constant, byte_sub_table)
            key_words[i] = key_words[i-4] ^ kwd
        else:
            key_words[i] = key_words[i-4] ^ key_words[i-1]
    return key_words

def get_round_keys():
    """
    Mostly adapted from lecture files by Avi Kak
    """
    key_bv =  BitVector( textstring = KEY )
    key_words = gen_key_schedule_128(key_bv)
    key_schedule = []

    for word in (key_words):
        keyword_in_ints = []
        for i in range(4):
            keyword_in_ints.append(word[i*8:i*8+8].intValue())
        key_schedule.append(keyword_in_ints)

    round_keys = [None for i in range(11)]
    for i in range(11):
        round_keys[i] = (key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] +
                                                       key_words[i*4+3])
    return round_keys

def mult(bitvect, number):
    return bitvect.deep_copy().gf_multiply_modular(BitVector(intVal=number,size=8), AES_modulus, 8)

def createStateArray(linear_bv):
    stateArray =  [[0 for x in range(4)] for y in range(4)]
    for i in range(4):
        for j in range(4):
            stateArray[j][i] = linear_bv[32*i + 8*j:32*i + 8*(j+1)]
    return stateArray

def encrypt():
    round_keys = get_round_keys()

    bv = BitVector( filename=INPUT_FILE )

    bv_out = BitVector(size=0)

    while (bv.more_to_read):
        bitvec = bv.read_bits_from_file( 128 )
        # PAD if Necessary
        if len(bitvec) < 128:
            bitvec += BitVector(size = (128 - len(bitvec)))
        # Initialize stateArray and Round_Key
        state = createStateArray(bitvec)
        # XOR state with round_key 0
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_keys[0][(32*i+8*j):(32*i+8*j+8)]
        # Begin 10 round encryption
        for round, round_key in enumerate(round_keys[1:]):
            # 1) Substitute Bytes
            for row_ind, row in enumerate(state):
                for col_ind, byte in enumerate(row):
                    state[row_ind][col_ind] = BitVector(intVal=subBytesTable[int(byte)], size=8)

            # 2) Shift Rows
            state[1] = [state[1][i].deep_copy() for i in [1,2,3,0]]
            state[2] = [state[2][i].deep_copy() for i in [2,3,0,1]]
            state[3] = [state[3][i].deep_copy() for i in [3,0,1,2]]

            # 3) Mix Columns (not on last round)
            if round != 9:
                new_state = [[None for i in range(4)] for j in range(4)]
                new_state[0] = [ mult(state[0][i],0x02) ^ mult(state[1][i],0x03) ^ mult(state[2][i],0x01) ^ mult(state[3][i],0x01) for i in range(4)]
                new_state[1] = [ mult(state[0][i],0x01) ^ mult(state[1][i],0x02) ^ mult(state[2][i],0x03) ^ mult(state[3][i],0x01) for i in range(4)]
                new_state[2] = [ mult(state[0][i],0x01) ^ mult(state[1][i],0x01) ^ mult(state[2][i],0x02) ^ mult(state[3][i],0x03) for i in range(4)]
                new_state[3] = [ mult(state[0][i],0x03) ^ mult(state[1][i],0x01) ^ mult(state[2][i],0x01) ^ mult(state[3][i],0x02) for i in range(4)]
                state = new_state

            # 4) Add roundkey
            for i in range(4):
                for j in range(4):
                    state[i][j] ^= round_key[(32*i+8*j):(32*i+8*j+8)]
        # Convert state to cipherText
        for i in range(4):
            for j in range(4):
                bv_out += state[j][i]
    return bv_out

def decrypt():

    bv_out = BitVector(size=0)

    f = open(ENCRYPTION_FILE, "r")
    bv = BitVector(hexstring=f.read().strip())
    f.close()

    round_keys = get_round_keys()
    round_keys.reverse()

    bit_ind = 0
    while bit_ind < len(bv):
        # assume it's been padded during encryption
        bitvec = bv[bit_ind:bit_ind+128].deep_copy()
        state = createStateArray(bitvec)

        # XOR state with round_key 0
        for i in range(4):
            for j in range(4):
                #state[i][j] ^= subkeys[i][j]
                state[i][j] ^= round_keys[0][(32*i+8*j):(32*i+8*j+8)]

        for round, round_key in enumerate(round_keys[1:]):

            #1) Inverse shift rows

            state[1] = [state[1][i].deep_copy() for i in [3,0,1,2]]
            state[2] = [state[2][i].deep_copy() for i in [2,3,0,1]]
            state[3] = [state[3][i].deep_copy() for i in [1,2,3,0]]

            # 2) Inverse Substitute Bytes

            for row_ind, row in enumerate(state):
                for col_ind, byte in enumerate(row):
                    state[row_ind][col_ind] = BitVector(intVal=invSubBytesTable[int(byte)], size=8)

            #3) Add round key

            for i in range(4):
                for j in range(4):
                    state[i][j] ^= round_key[(32*i+8*j):(32*i+8*j+8)]

            #4) Inverse mix columns (not on last round)

            if round != 9:
                new_state = [[None for i in range(4)] for j in range(4)]
                new_state[0] = [ mult(state[0][i], 0x0E) ^ mult(state[1][i], 0x0B) ^ mult(state[2][i],0x0D) ^ mult(state[3][i],0x09) for i in range(4)]
                new_state[1] = [ mult(state[0][i], 0x09) ^ mult(state[1][i], 0x0E) ^ mult(state[2][i],0x0B) ^ mult(state[3][i],0x0D) for i in range(4)]
                new_state[2] = [ mult(state[0][i], 0x0D) ^ mult(state[1][i], 0x09) ^ mult(state[2][i],0x0E) ^ mult(state[3][i],0x0B) for i in range(4)]
                new_state[3] = [ mult(state[0][i], 0x0B) ^ mult(state[1][i], 0x0D) ^ mult(state[2][i],0x09) ^ mult(state[3][i],0x0E) for i in range(4)]
                state = new_state

    # Convert state to plainText
        for i in range(4):
            for j in range(4):
                bv_out += state[j][i]
        bit_ind += 128
    return bv_out

if __name__ == '__main__':
    # encrypt
    e = encrypt()
    # Write encrypted text as HEX string
    with open("encrypted.txt","w") as en:
        en.write(e.get_bitvector_in_hex())
    # decrypt!
    d = decrypt()
    # Write decrypted bytes to text
    with open("decrypted.txt", "wb") as dec:
        d.write_to_file(dec)
