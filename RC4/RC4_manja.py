__author__ = 'Vikram Manja'

######################################
# RC4 Image Encryption by Vikram Manja
######################################

ENCRYPTED_FILE = "encrypted.ppm"
DECRYPTED_FILE = "decrypted.ppm"

from BitVector import *
from copy import deepcopy
class RC4:
    def __init__(self, key):
        self.key = key
        self.keylen = len(key)
        self.ksa()
    def ksa(self):
        """
        Key Scheduling Algorithm
        """
        self.state_vector = [i for i in range(256)]
        T_vector = [ord(self.key[i%self.keylen]) for i in range(256)]
        j = 0
        for i in range(256):
            j = (j + self.state_vector[i] + T_vector[i]) % 256
            self.swap(i,j)
    def encrypt(self, originalImage):
        out = open(ENCRYPTED_FILE, "wb")
        bv = BitVector(filename=originalImage)
        i,j = 0,0
        while(bv.more_to_read):
            bitvector = bv.read_bits_from_file(8)
            i = (i+1) % 256
            j = (j+self.state_vector[i]) % 256
            self.swap(i,j)
            k = (self.state_vector[i] + self.state_vector[j]) % 256
            bv_out=BitVector(intVal=self.state_vector[k])
            bv_out ^= bitvector
            bv_out.write_to_file(out)
        out.close()
    def decrypt(self, encryptedImage):
        pass
    def swap(self, i, j):
        temp = self.state_vector[i]
        self.state_vector[i] = self.state_vector[j]
        self.state_vector[j] = temp


#f = open("boxes_2.ppm", "rb")
#r = RC4("abcdefghijlmnopq")
#r.encrypt(INPUT_FILE)

#j = BitVector(fp = f)
#j.read_bits_from_fileobject(f)
#print(j.get_bitvector_in_hex())
