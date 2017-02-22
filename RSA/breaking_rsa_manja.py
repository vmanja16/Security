from rsa import *
from BitVector import *

def iroot(k, n):
    """
    Kth root script from StackOverflow
    http://stackoverflow.com/questions/15978781/how-to-find-integer-nth-roots
    """
    u, s = n, n+1
    while u < s:
        s = u
        t = (k-1) * s + n // pow(s, k-1)
        u = t // k
    return s


def break_RSA(m1,m2,m3, output_file):

    output = open(output_file, "wb")
    bv1 = BitVector(filename="e1.txt")
    bv2 = BitVector(filename="e2.txt")
    bv3 = BitVector(filename="e3.txt")
    # Calculate N
    N = m1 * m2 * m3

    while bv1.more_to_read:
        # Read 256 bits
        bitvec1 = bv1.read_bits_from_file(512)
        bitvec1 = BitVector(hexstring=bitvec1.get_bitvector_in_ascii())
        bitvec2 = bv2.read_bits_from_file(512)
        bitvec2 = BitVector(hexstring=bitvec2.get_bitvector_in_ascii())
        bitvec3 = bv3.read_bits_from_file(512)
        bitvec3 = BitVector(hexstring=bitvec3.get_bitvector_in_ascii())

        # Get a1, a2, a3
        a1 = int(bitvec1)
        a2 = int(bitvec2)
        a3 = int(bitvec3)

        # Get M1, M2, M3
        M1 = N/m1
        M2 = N/m2
        M3 = N/m3

        # Get c1, c2, c3
        c1 = M1 * int(BitVector(intVal=M1).multiplicative_inverse(BitVector(intVal=m1)))
        c2 = M2 * int(BitVector(intVal=M2).multiplicative_inverse(BitVector(intVal=m2)))
        c3 = M3 * int(BitVector(intVal=M3).multiplicative_inverse(BitVector(intVal=m3)))

        # Get M_cubed
        M_cubed = (a1*c1 + a2*c2 + a3*c3) % N

        # Get M
        M = iroot(3, M_cubed)

        #W Write M to output
        M_bv = BitVector(intVal=M, size=128)

        M_bv.write_to_file(output)

if __name__ == "__main__":
    if(len(sys.argv) < 3):
        print("Error: requires 2 inputs")
        sys.exit()

    break_exponent = 3

    message_file = sys.argv[1]

    n1 = encrypt(message_file, "e1.txt", exp=break_exponent)
    n2 = encrypt(message_file, "e2.txt", exp=break_exponent)
    n3 = encrypt(message_file, "e3.txt", exp=break_exponent)

    break_RSA(n1, n2, n3, sys.argv[2])

# EXAMPLE
# n1 = 89079961386244784480504345698119372254546070880657296266537686029213390047593
# n2 = 87542290131339196133296565547990034356852488624475813441015814204862641590421
# n3 = 95078872959474220184219460103199261322427070341457671262692029998840838018283
# e1.txt = 09a8e1415b3b4b0a805dedcb505eab4a9a13cd2876398df754ba04aa2f21edd6a9c01b6c92da4218fe671f94d71b8c5c5823581f19be3d6f43397ea9178bd3ee63c3bcf7b48c1ed43255a9bd426375fab63ec18849fbec43880e832de122c17eb82dba8bfc923ee829f0b69d09ffb274dfd174a4e312d91198fadafd5edd8d9c247088bb7e4cb15071613eac406ce82b441f9c79f6efc4d666486ebde1cb82bd6de48e32f453dd77dfc5fd5ef3b812cf3de18da0041b33aa56659db916f5e6208cd7edc35b9300bc253d814e94872d5407fd79afbf3180aea0a48648a9ff94171eaf8b4fdb518342651c1516e4117df584773680d62a0a3738307aa054c8f0a996ba1c0be240ef8a1658640b68fed3fe203b9febc0c24f0d63724a2d0f60d7e862faf3ecc915e77e3aa4b979c3a86e4fd10ed9399276b85f25d5b08ed4efdbaf0f8bc0665bf4b5c93f540082c3a83692c96e8a98ceb31a60eaf4a18b0bbc641192699eb737ffaa719577fea23c15ba11d1926ffd019d8af65cef679838936dfd
# e2.txt = 49d8061f246c335184c9bc88d28626de790d18f7c1b4f9d35ced36e50438a9b62387170e2a1cbd55c772175947243d843cf6ea917437cfbf736eccc9b6562d2e9f9635e7c0fb756ce98a0c583ba1168b5c3ae80b0aaf039a1b1d53b9ab5c53ec6a83f24d5c61379efe7647c7b101ebde929b603fcdfe0333146f0e58c703279a873c0d96b85820f92dda7ea31b6b8f90b4b36b2a719da9f0f19ff4032f54d5711ec295a0dc577e99072065b6b3105e96d8bdfb260c43d4b091b06f79611650a73bbb7416f1a06c9e63f0b332974a2ddd2dead870be6fd9d1d3a0e883fd1202659ee743a32709f7aa0df276f375cca148d17b558a10fd961403f361509bd1bc1e6a7aaae1b66ca545bb0b73be5284b6988a245c148dba09c33bbbe62a5f1f88791a6c0f1e558e3f7162582ad3b874b359c7d3bfa797be7d551a8c01e193ebd3af54a6de18296640b2e3563dd4df255ea5548ffa435f79c3c241fd19cbe0dffe17239feaa385d21251b4db3fbd93f9093fbb702ccdb5959f99947d444d85320b54
# e3.txt = a0220984957a2ea36a72baf520df46e107b3b2a670a95e83b2902577e35c30d30ddc360b983ef92386c2e64eb4a22fd418d021ffc982ecb95ef7393bc1c6a01ba544ad7d7ca5b998372b093a9f39658200dea17d8df78f4cb1d635b78416290265cd502a8009e51a318f7e4dda3eb0bdd60702c8cf3c12abc38b7a5141856ca2b093404712b2820d9527856d2ab34b85671eaa1bfc61656a63d2fde17003c46669d385678dbea5b1070ba7e6546f783e7ead852b2b265e8cce32770d7eae7480838e93e550b9b05f969b1be28d8dd5febffedcc738858f65870d496fcbffa27dc80fe82226d79e084734eaa30a7abcc31211c5e21ef0249db9ffa35c32670a8d8416e697c0712e0b9bf8c6d5da5d78578159e08e289f99b6b9fa626e664695194e2973e84d0dcf2eab3134d5c02951680a7d4a80e4894e28da20cbadc45267b45c1ed7d1bda31e2c0a99a1e18505100041a52ba1485df13b4f6c9ab2a8342568620ab657e4244c4dde5f406c4f3a638cada5c578db8ea6609e4062629755e625
# cracked.txt: Life's but a walking shadow, a poor player that struts and frets his hour upon the stage and then is heard no more. It is a tale told by an idiot, full of sound and fury, signifying nothing.
# decrypted hex: No difference









