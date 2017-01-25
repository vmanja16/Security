__author__ = 'Vikram'

#######
# DES Diffusion/Confusion Analysis by Vikram Manja
######
from DES_manja import *
import copy


def flip_bit(msg, byte_number):
    lsb = (msg[byte_number] & 1)
    if(lsb == 1):
        msg[byte_number] &= 254
    else:
        msg[byte_number] |= 1
    with open("diffusion.txt", "wb") as diff:
        diff.write(msg)
# 1. CALCULATE DIFFUSION FROM PLAINTEXT CHANGES (5 different bits changed)
def calculateDiffusion():
    totalDiffusion = 0
    for pos in range(5):
        flip_bit(copy.deepcopy(message_bytes), pos*8)
        bv_changed = cipher(input_file="diffusion.txt")
        diffusion = sum([(a ^ b) for a,b in zip(bv_changed,BV_REF)])
        totalDiffusion += diffusion
    avgDiffusion = totalDiffusion/5
    print(avgDiffusion)
# 2. CALCULATE DIFFUSION FROM PLAINTEXT CHANGES with RANDOM S-Boxes (2 different bits changed)
def calculateDiffusionWithRandomness():
    totalDiffusion = 0
    for pos in range(2):
        r_sbox = [[ [random.randint(0, 15) for i in range(16)] for j in range(4)] for k in range(8)]
        bv_ref = cipher(key="ecepurdu", random_sbox=r_sbox)
        flip_bit(copy.deepcopy(message_bytes), pos*8)
        bv_changed = cipher(input_file="diffusion.txt", random_sbox=r_sbox)
        diffusion = sum([(a ^ b) for a,b in zip(bv_changed,bv_ref)])
        totalDiffusion += diffusion
    avgDiffusion = totalDiffusion/2
    print(avgDiffusion)
# 3. CALCULATE CONFUSION FROM KEY CHANGES (3 different bits changed)
def calculateConfusion():
    totalConfusion = 0
    bv_changed = cipher(key="gcepurdu")
    confusion = sum([(a ^ b) for a,b in zip(bv_changed,BV_REF)])
    totalConfusion += confusion
    bv_changed = cipher(key="eaepurdu")
    confusion = sum([(a ^ b) for a,b in zip(bv_changed,BV_REF)])
    totalConfusion += confusion
    bv_changed = cipher(key="ecgpurdu")
    confusion = sum([(a ^ b) for a,b in zip(bv_changed,BV_REF)])
    totalConfusion += confusion
    avgConfusion = totalConfusion/3
    print(avgConfusion)
if __name__ == "__main__":
    # Get Original message bytes
    bv = BitVector(filename="message.txt")
    message_bv = BitVector(size=0)
    while (bv.more_to_read):
        bitvec = bv.read_bits_from_file( 64 )
        # pad if needed
        message_bv += bitvec
    message_bytes = bytearray.fromhex(message_bv.get_bitvector_in_hex())
    # 1.
    BV_REF = cipher(key="ecepurdu")
    calculateDiffusion()
    # 2.
    calculateDiffusionWithRandomness()
    # 3.
    calculateConfusion()
# 1. Average Diffusion was 32.6    bits of cipher Text per Plain Text bit changed (Standard S-boxes)
# 2. Average Diffusion was 26.0    bits of cipher Text per Plain Text bit changed (Random S-boxes)
# 3. Average Confusion was 4232.33 bits of cipher Text per Key bit changed
