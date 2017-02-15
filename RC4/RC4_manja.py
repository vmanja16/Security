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
    def encrypt(self, originalImage, encrypt=True):
        # Run the Key scheduler
        self.ksa()
        # Have to deal with unknown file object/mode
        name = originalImage.name
        originalImage.close()
        # Choose Encryption Decryption
        if (encrypt):
            out = open("encrypted.ppm", "wb")
        else:
            out = open("decrypted.ppm", "wb")
        bv = BitVector(filename=name)
        # Standard RC4 byte-by-byte encryption
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
        return out
    def decrypt(self, encryptedImage):
        return self.encrypt(encryptedImage, encrypt=False)
    def swap(self, i, j):
        temp = self.state_vector[i]
        self.state_vector[i] = self.state_vector[j]
        self.state_vector[j] = temp

if __name__ == "__main__":
    rc4Cipher = RC4("abcdefghijklmnop")
    originalImage = open("winterTown.ppm", "r")
    encryptedImage = rc4Cipher.encrypt(originalImage)
    print("image has been encrypted as 'encrypted.ppm'")
    decryptedImage = rc4Cipher.decrypt(encryptedImage)
    decryptedImage.close()
    print("image has been decrypted as 'decrypted.ppm'")
    import filecmp
    # Check if Equal
    print(filecmp.cmp("winterTown.ppm", "decrypted.ppm"))
    # Rc4 is easy to do if given files, harder w/ file objects...
