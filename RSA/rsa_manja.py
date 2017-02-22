#####################################
# 256 Bit RSA Cipher by Vikram Manja
#####################################

from BitVector import *
from PrimeGenerator import PrimeGenerator as PG
import sys

e = 65537

def chinese_remainder_theorem(c, d, p, q):
    """
    Returns c^d mod (p*q) using chinese remainders
    """
    vp = gme(int(c), int(d), p)
    vq = gme(int(c), int(d), q)
    xp = q * int(BitVector(intVal=q, size=128).multiplicative_inverse(BitVector(intVal=p)))
    xq = p * int(BitVector(intVal=p, size=128).multiplicative_inverse(BitVector(intVal=q)))

    return (vp*xp + vq*xq) % (p*q)

def coprime(a,b):
    if (b < a): a,b = b,a
    while b:
        a, b = b, a % b
    if (a==1):return True
    else: return False

def get_two_primes():
    generator = PG(bits=128)
    p = generator.findPrime()
    q = generator.findPrime()
    # check not equal
    if (p==q): return get_two_primes()
    # check coprime
    if not coprime(p,e): return get_two_primes()
    if not coprime(q,e): return get_two_primes()
    return p,q

def gme(a,b,n):
    """
    General Modular Exponentiation
    Returns a^b mod n
    """
    result = 1
    while b > 0:
        if b & 1:
            result = (result * a) % n
        b = b >> 1
        a = (a * a) % n
    return  int(result)

def encrypt(message_file, output_file):
    output = open(output_file, "w")
    p,q = get_two_primes()
    # SAVE p and q
    with open("pq.txt", "w") as pq:
        for i in [p, " ", q]: pq.write(str(i))
    n = p * q
    bv = BitVector(filename=message_file)
    while bv.more_to_read:
        # Read 128 bits
        bv_out = bv.read_bits_from_file(128)
        # Right pad with newlines (ascii=10)
        while(len(bv_out) < 128):
            bv_out += BitVector(intVal=10, size=8)
        # m^e mod n (e is small so 'gme' suffices --> gme is equivalent to 'pow')
        bv_out = BitVector(intVal=gme(int(bv_out), e, n))
        # Left pad with 0s
        if (len(bv_out)) < 256:
            bv_out = BitVector(size=256-len(bv_out)) + bv_out
        # Write crypt text
        output.write(bv_out.get_bitvector_in_hex())
    output.close()

def decrypt(encrypted_file, decrypted_file):
    dec = open(decrypted_file, "w")
    # GET p and q
    p,q = (int(i) for i in open("pq.txt", "r").read().split())
    totient = (p-1) * (q-1)
    d = BitVector(intVal=e).multiplicative_inverse(BitVector(intVal=totient))
    bv = BitVector(filename=encrypted_file)
    while bv.more_to_read:
        # Read & Translate Bitvector from hexstring
        bv_out = bv.read_bits_from_file(512)
        bv_out = BitVector(hexstring=bv_out.get_bitvector_in_ascii())
        # Use Chinese Remainder Theorem to get C^d
        bv_out = BitVector(intVal=chinese_remainder_theorem(bv_out, d, p, q),size=256)
        # Remove '0' padding
        bv_out = bv_out[128:]
        # Write Plain Text
        dec.write(bv_out.get_bitvector_in_ascii())
    dec.close()

if __name__ == "__main__":
    if(len(sys.argv) < 4):
        print("Error: requires 3 inputs")
        sys.exit()
    if(sys.argv[1] == "-e"):
        encrypt(sys.argv[2], sys.argv[3])
    if(sys.argv[1] == "-d"):
        decrypt(sys.argv[2], sys.argv[3])

# Example:
# pq.txt = 272521153320973396417630511022295649383 333191769576802382347215159520488131299
# d = 21192676109789010391262862485922983581960781531678874582696409324652745084161
# output.txt = 8dd329d0374a924f4a0ae76371f41cfa07e68c4a087f4c0ff29d41ddb25ae4d230c10225c3745a007708f1958a2ffaef2b39bf106203c8eca790cf5d609ddefa3e6b97da17c9267b996d26bab106cbc9915e4edb2453715424e9ff7d3b26902b2366d0b1b90df6a07f1bac51674fcfac24724aae765ff6681def9ae837217b1e08f30b1eefa7afdb82eb152e0252fc5ab6dfa47578aba3484e1cf5af5bb4ef6caceaf11993fb1b60325114cbef63ba8e11d604dda57e73f48cb85f7f564b452b1a098dc616d60f38c4edd94f90aa637aa57d0eb7049e83ddbba2f066f414378cc0854649028db78fb5a4b8308e52a37671dc61a8c42de24f94ee878f01056c3db63ba3ba9b22a3abd74e644119bea59c487dd825dfabfdfa0ae9ab1682d802d1464f5a807df29f3d7b5ee9089ba8b20a6b7e306eb6038eb44aee36b8e1337a73bbfed649a2665ec3ed6066e0805ced5a09eb575528f06f1f8bc5001bb4fe1cc1c03d1e4d3ab45abf40f02f158da7ca71e17411b2863c9fb8f53ba0ce0ef23936
# decrypted.txt = Life's but a walking shadow, a poor player that struts and frets his hour upon the stage and then is heard no more. It is a tale told by an idiot, full of sound and fury, signifying nothing.


# decrypted_hex: 4c69666527732062757420612077616c6b696e6720736861646f772c206120706f6f7220706c6179657220746861742073747275747320616e642066726574732068697320686f75722075706f6e2074686520737461676520616e64207468656e206973206865617264206e6f206d6f72652e20497420697320612074616c6520746f6c6420627920616e206964696f742c2066756c6c206f6620736f756e6420616e6420667572792c207369676e696679696e67206e6f7468696e672e0a0a
# (0a = newline added from padding)
