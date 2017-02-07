__author__ = 'Vikram'

from BitVector import *
import copy

INPUT_FILE = "plaintext.txt"
KEY = "yayboilermakers!"

AES_modulus = BitVector(bitstring='100011011')
subBytesTable = []
invSubBytesTable = []

def generateTables():
    """
    Alternatively could just hard code...
    """
    c = BitVector(bitstring='01100011') #0x63
    d = BitVector(bitstring='00000101') #0x05
    for i in range(0, 256):
        # For the encryption SBox
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        # For bit scrambling for the encryption SBox entries:
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
        # For the decryption Sbox:
        b = BitVector(intVal = i, size=8)
        # For bit scrambling for the decryption SBox entries:
        b1,b2,b3 = [b.deep_copy() for x in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        check = b.gf_MI(AES_modulus, 8)
        b = check if isinstance(check, BitVector) else 0
        invSubBytesTable.append(int(b))
def getSubstitute(bitvec_in):
    return subBytesTable[bitvec_in]

def gee(keyword, round_constant, byte_sub_table):
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

def gen_subbytes_table():
    subBytesTable = []
    c = BitVector(bitstring='01100011')
    for i in range(0, 256):
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
    return subBytesTable

def gen_key_schedule_128(key_bv):
    byte_sub_table = gen_subbytes_table()

    key_words = [None for i in range(44)]
    round_constant = BitVector(intVal = 0x01, size=8)
    for i in range(4):
        key_words[i] = key_bv[i*32 : i*32 + 32]
    for i in range(4,44):
        if i%4 == 0:
            kwd, round_constant = gee(key_words[i-1], round_constant, byte_sub_table)
            key_words[i] = key_words[i-4] ^ kwd
        else:
            key_words[i] = key_words[i-4] ^ key_words[i-1]
    return key_words

def get_round_keys():
    """
    --Generates round keys
    Mostly adapted from lecture files by Avi Kak
    """
    keysize, key_bv = 128, BitVector( textstring = KEY )
    key_words = gen_key_schedule_128(key_bv)
    key_schedule = []

    for index, word in enumerate(key_words):
        keyword_in_ints = []
        for i in range(4):
            keyword_in_ints.append(word[i*8:i*8+8].intValue())
        key_schedule.append(keyword_in_ints)

    round_keys = [None for i in range(11)]
    for i in range(11):
        round_keys[i] = (key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] +
                                                       key_words[i*4+3])
    return round_keys

def mult_2(bitvect):
    return bitvect.deep_copy().gf_multiply_modular(BitVector(intVal=0x02,size=8), AES_modulus, 8)

def mult_3(bitvect):
    return bitvect.deep_copy().gf_multiply_modular(BitVector(intVal=0x03,size=8), AES_modulus, 8)

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
        subkeys = createStateArray(round_keys[0]) # need to ask if word needs to become a state....
        # XOR state with round_key 0
        for i in range(4):
            for j in range(4):
                state[i][j] ^= subkeys[i][j]

        # Begin 10 round encryption
        for round, round_key in enumerate(round_keys[1:]):
            # 1) Substitute Bytes
            for row_ind, row in enumerate(state):
                for col_ind, byte in enumerate(row):
                    state[row_ind][col_ind] = BitVector(intVal=subBytesTable[int(byte)], size=8)
            # 2) Shift Rows
            state[1] = [state[1][i] for i in [1,2,3,0]]
            state[2] = [state[2][i] for i in [2,3,0,1]]
            state[3] = [state[3][i] for i in [3,0,1,2]]

            # 3) Mix Columns (not on last round)
            state[0] = [ mult_2(state[0][i]) ^ mult_3(state[1][i]) ^ state[2][i].deep_copy() ^ state[3][i].deep_copy() for i in range(4)]
            state[1] = [ state[0][i].deep_copy() ^ mult_2(state[1][i]) ^ mult_3(state[2][i]) ^ state[3][i].deep_copy() for i in range(4)]
            state[2] = [ state[0][i].deep_copy() ^ state[1][i].deep_copy() ^ mult_2(state[2][i]) ^ mult_3(state[3][i]) for i in range(4)]
            state[3] = [ mult_3(state[0][i]) ^ state[1][i].deep_copy() ^ state[2][i].deep_copy() ^ mult_2(state[3][i]) for i in range(4)]

            # 4) Add roundkey
            subkeys = createStateArray(round_key)
            for i in range(4):
                for j in range(4):
                    state[i][j] ^= subkeys[i][j]
        # Convert state to cipherText
        for i in range(4):
            for j in range(4):
                bv_out += state[i][j]
    return bv_out

def decrypt():

    bv_out = BitVector(size=0)

    f = open("encrypted.txt", "r")
    bv = BitVector(hexstring=f.read().strip())
    f.close()

    round_keys = get_round_keys()
    round_keys.reverse()

    bit_ind = 0
    while bit_ind < len(bv):
        # assume it's been padded during encryption
        bitvec = bv[bit_ind:bit_ind+128]
        state = createStateArray(bitvec)
        subkeys = createStateArray(round_keys[0]) # need to ask if word needs to become a state....

        # XOR state with round_key 0
        for i in range(4):
            for j in range(4):
                state[i][j] ^= subkeys[i][j]

        for round, round_key in enumerate(round_keys[1:]):

            #1) Inverse shift rows

            state[1] = [state[1][i] for i in [3,0,1,2]]
            state[2] = [state[2][i] for i in [2,3,0,1]]
            state[3] = [state[3][i] for i in [1,2,3,0]]

            # 2) Inverse Substitute Bytes

            for row_ind, row in enumerate(state):
                for col_ind, byte in enumerate(row):
                    state[row_ind][col_ind] = BitVector(intVal=invSubBytesTable[int(byte)], size=8)

            #3) Add round key

            subkeys = createStateArray(round_key)
            for i in range(4):
                for j in range(4):
                    state[i][j] ^= subkeys[i][j]

            #4) Inverse mix columns (not on last round)

            if round != 10:
                state[0] = [ mult(state[0][i], 0x0E) ^ mult(state[1][i], 0x0B) ^ mult(state[2][i],0x0D) ^ mult(state[3][i],0x09) for i in range(4)]
                state[1] = [ mult(state[0][i], 0x09) ^ mult(state[1][i], 0x0E) ^ mult(state[2][i],0x0B) ^ mult(state[3][i],0x0D) for i in range(4)]
                state[2] = [ mult(state[0][i], 0x0D) ^ mult(state[1][i], 0x09) ^ mult(state[2][i],0x0E) ^ mult(state[3][i],0x0B) for i in range(4)]
                state[3] = [ mult(state[0][i], 0x0B) ^ mult(state[1][i], 0x0D) ^ mult(state[2][i],0x09) ^ mult(state[3][i],0x0E) for i in range(4)]

    # Convert state to plainText
        for i in range(4):
            for j in range(4):
                bv_out += state[i][j]
        bit_ind += 128
    return bv_out





if __name__ == '__main__':
    # Generate substitution tables
    generateTables()
    # encrypt!
    e = encrypt()
    print(e.get_bitvector_in_hex())
    with open("encrypted.txt","w") as en:
        en.write(e.get_bitvector_in_hex())
    # decrypt!
    d = decrypt()
    print(d.get_bit_vector_in_hex())
    with open("decrypted.txt", "wb") as dec:
        d.write_to_file(dec)
