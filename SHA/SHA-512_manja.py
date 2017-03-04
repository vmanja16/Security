#!/usr/bin/env python3
__author__ = 'Vikram Manja'
################################################################
# SHA-512 Secure Hashing Algorithm implmentation by Vikram Manja
################################################################
import sys
import BitVector

def sha512(string_to_be_hashed):

    bv = BitVector(textsring=message)
    # Get Length
    length = bv.length()
    bv_length = BitVector(intVal=length, size=128)

    # Add Padding
    bv += BitVector(bitstring="1")
    length1 = bv.len()
    howmanyzeros = (1024 - 128 - length1) % 1024
    bv += BitVector(size=howmanyzeros)
    # Add 128 bit length bv
    bv += bv_length

    # Initialize registers
    a = BitVector(hexstring="6a09e667f3bcc908")
    b = BitVector(hexstring="bb67ae8584caa73b")
    c = BitVector(hexstring="3c6ef372fe94f82b")
    d = BitVector(hexstring="a54ff53a5f1d36f1")
    e = BitVector(hexstring="510e527fade682d1")
    f = BitVector(hexstring="9b05688c2b3e6c1f")
    g = BitVector(hexstring="1f83d9abfb41bd6b")
    h = BitVector(hexstring="5be0cd19137e2179")


    words = [None] * 80

    for n in range(0,bv.length(),1024):
        block = bv[n:n+1024]
        words[0:16] = [block[i:i+64] for i in range(0,1024,64)]




if __name__ == "__main__":
    message = sys.argv[1]
    sha512(open(message, "r").read())
