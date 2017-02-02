__author__ = 'Vikram Manja'

while(True):
    modulus = int(input("Enter an integer n > 1 to check if Zn is a ring or field: "))
    if(modulus > 1):break
def prime(n):
    """
    RETURNS True IF input is PRIME
    """
    n = int(n)
    if (n <= 1):return False
    if (n==2):return True
    if (n % 2 == 0): return False
    #Check odds for 3 +
    i = 3

    while (i < n):
        if(n % i == 0):return False
        i +=2
    return True

with open("output.txt", "w") as f:
    if prime(modulus):
        f.write("field")
    else:
        f.write("ring")

# Input: 7
# Output: field
