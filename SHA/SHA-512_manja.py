#!/usr/bin/env python3
__author__ = 'Vikram Manja'
#################################
# SHA-512 by Vikram Manja
#################################
import sys
from BitVector import *
k_vals="\
428a2f98d728ae22 7137449123ef65cd b5c0fbcfec4d3b2f e9b5dba58189dbbc \
3956c25bf348b538 59f111f1b605d019 923f82a4af194f9b ab1c5ed5da6d8118 \
d807aa98a3030242 12835b0145706fbe 243185be4ee4b28c 550c7dc3d5ffb4e2 \
72be5d74f27b896f 80deb1fe3b1696b1 9bdc06a725c71235 c19bf174cf692694 \
e49b69c19ef14ad2 efbe4786384f25e3 0fc19dc68b8cd5b5 240ca1cc77ac9c65 \
2de92c6f592b0275 4a7484aa6ea6e483 5cb0a9dcbd41fbd4 76f988da831153b5 \
983e5152ee66dfab a831c66d2db43210 b00327c898fb213f bf597fc7beef0ee4 \
c6e00bf33da88fc2 d5a79147930aa725 06ca6351e003826f 142929670a0e6e70 \
27b70a8546d22ffc 2e1b21385c26c926 4d2c6dfc5ac42aed 53380d139d95b3df \
650a73548baf63de 766a0abb3c77b2a8 81c2c92e47edaee6 92722c851482353b \
a2bfe8a14cf10364 a81a664bbc423001 c24b8b70d0f89791 c76c51a30654be30 \
d192e819d6ef5218 d69906245565a910 f40e35855771202a 106aa07032bbd1b8 \
19a4c116b8d2d0c8 1e376c085141ab53 2748774cdf8eeb99 34b0bcb5e19b48a8 \
391c0cb3c5c95a63 4ed8aa4ae3418acb 5b9cca4f7763e373 682e6ff3d6b2b8a3 \
748f82ee5defb2fc 78a5636f43172f60 84c87814a1f0ab72 8cc702081a6439ec \
90befffa23631e28 a4506cebde82bde9 bef9a3f7b2c67915 c67178f2e372532b \
ca273eceea26619c d186b8c721c0c207 eada7dd6cde0eb1e f57d4f7fee6ed178 \
06f067aa72176fba 0a637dc5a2c898a6 113f9804bef90dae 1b710b35131c471b \
28db77f523047d84 32caab7b40c72493 3c9ebe0a15c9bebc 431d67c49c100d4c \
4cc5d4becb3e42b6 597f299cfc657e2a 5fcb6fab3ad6faec 6c44198c4a475817"

k = [BitVector(hexstring=i) for i in k_vals.split()]


MODULUS = 0xFFFFFFFFFFFFFFFF

def sigmaE(e):
    e1 = e.deep_copy() >> 14
    e2 = e.deep_copy() >> 18
    e3 = e.deep_copy() >> 41
    return (int(e1^e2^e3))

def sigmaA(a):
    a1 = a.deep_copy() >> 28
    a2 = a.deep_copy() >> 34
    a3 = a.deep_copy() >> 39
    return (int(a1^a2^a3))

def delta0(x):
    d1 = x.deep_copy() >> 1
    d2 = x.deep_copy() >> 8
    d3 = x.deep_copy().shift_right(7)
    return (int(d1^d2^d3))

def delta1(x):
    d1 = x.deep_copy() >> 19
    d2 = x.deep_copy() >> 61
    d3 = x.deep_copy().shift_right(6)
    return (int(d1^d2^d3))

def sha512(string_to_be_hashed):

    bv = BitVector(textstring=string_to_be_hashed)
    # Get Length
    length = bv.length()
    bv_length = BitVector(intVal=length, size=128)

    # Add Padding
    bv += BitVector(bitstring="1")
    length1 = bv.length()
    howmanyzeros = (1024 - 128 - length1) % 1024
    bv += BitVector(intVal=0,size=howmanyzeros)
    # Add 128 bit length bv
    bv += bv_length
    # Initialize registers
    h0 = BitVector(hexstring="6a09e667f3bcc908")
    h1 = BitVector(hexstring="bb67ae8584caa73b")
    h2 = BitVector(hexstring="3c6ef372fe94f82b")
    h3 = BitVector(hexstring="a54ff53a5f1d36f1")
    h4 = BitVector(hexstring="510e527fade682d1")
    h5 = BitVector(hexstring="9b05688c2b3e6c1f")
    h6 = BitVector(hexstring="1f83d9abfb41bd6b")
    h7 = BitVector(hexstring="5be0cd19137e2179")


    words = [None] * 80

    for n in range(0,bv.length(),1024):
        block = bv[n:n+1024]
        # Generate Message Schedule
        words[0:16] = [block[i:i+64] for i in range(0,1024,64)]
        for i in range(16,80):
            adder = int(words[i-16]) + delta0(words[i-15]) + int(words[i-7]) + delta1(words[i-2])
            words[i] = BitVector(intVal=(adder & MODULUS), size=64)
        # 80 rounds of processing
        a,b,c,d,e,f,g,h = h0,h1,h2,h3,h4,h5,h6,h7
        for i in range(80):

            T1 = (int(h) + int((e&f) ^ ((~e) & g)) + sigmaE(e) + int(words[i]) + int(k[i]) ) & MODULUS
            T2 = (sigmaA(a) + int((a&b)^(a&c)^(b&c))) & MODULUS
            h = g
            g = f
            f = e
            e = BitVector(intVal=((int(d) +  T1) & MODULUS), size=64)
            d = c
            c = b
            b = a
            a = BitVector(intVal=((T1 + T2) & MODULUS), size=64)

        h0 = BitVector( intVal = (int(h0) + int(a)) & MODULUS, size=64 )
        h1 = BitVector( intVal = (int(h1) + int(b)) & MODULUS, size=64 )
        h2 = BitVector( intVal = (int(h2) + int(c)) & MODULUS, size=64 )
        h3 = BitVector( intVal = (int(h3) + int(d)) & MODULUS, size=64 )
        h4 = BitVector( intVal = (int(h4) + int(e)) & MODULUS, size=64 )
        h5 = BitVector( intVal = (int(h5) + int(f)) & MODULUS, size=64 )
        h6 = BitVector( intVal = (int(h6) + int(g)) & MODULUS, size=64 )
        h7 = BitVector( intVal = (int(h7) + int(h)) & MODULUS, size=64 )

    message_hash = h0 + h1 + h2 + h3 + h4 + h5 + h6 + h7

    return message_hash

if __name__ == "__main__":

    message = sys.argv[1]
    msg = open(message, "r").read()
    Hash = sha512(msg)
    with open("output.txt", "w") as f:
        f.write(Hash.get_bitvector_in_hex())

# EXAMPLE:
# input:  bb
# output: 24b1a812d4e3535c06011c430aaba3f59d32f36263ddcb99541f998266c5e84a52fb33f951cec78656f598a004f83c771388b9a80404f7432b714f4dcae4a00f
