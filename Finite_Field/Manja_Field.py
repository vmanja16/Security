__author__ = 'Vikram Manja'


modulus = input("Enter an integer n to check if Zn is a ring or field: ")

def prime(n):
    """
    RETURNS True IF input is PRIME
    """
    n = int(n)
    if (n <= 1):return False
    if (n % 2 == 0): return False
    i = 3
    n_sqrt = n** 0.5
    while (i < n_sqrt):
        if(n % i == 0):return False
        i +=2
    return True

with open("output.txt", "w") as f:
    if prime(modulus):
        f.write("field")
    else:
        f.write("ring")

