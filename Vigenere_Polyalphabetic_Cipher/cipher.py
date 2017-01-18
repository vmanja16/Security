__author__ = 'Vikram Manja'

##############################################################
# Vigenere Polyalphabetic Cipher
##############################################################

CHARACTERS = [char for char in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"]
CHAR_LEN = len(CHARACTERS)
KEY_FILE = "key.txt"
INPUT_FILE = "input.txt"
OUTPUT_FILE = "output.txt"

def getLineFromFile(filename):
    with open(filename, 'r') as file:
        return file.readline()

def getInputFromFile(filename):
    with open(filename, 'r') as file:
        return file.read()

def writeToFile(filename, output):
    with open(filename, 'w') as file:
        file.write(output)

# ENCRYPTION

def getCipherCharacter(plainChar, keyChar):
    plainIndex = CHARACTERS.index(plainChar)
    keyIndex = CHARACTERS.index(keyChar)
    return CHARACTERS[(plainIndex + keyIndex) % CHAR_LEN]

def encryptText(plainText, key):
    cypherChars = []
    for index, plainChar in enumerate(plainText):
        cypherChars.append(getCipherCharacter(plainChar, key[index % len(key)]))
    return "".join(cypherChars)

# DECRYPTION

def getPlainCharacter(cipherChar, keyChar):
    cipherIndex = CHARACTERS.index(cipherChar)
    keyIndex = CHARACTERS.index(keyChar)
    return CHARACTERS[(cipherIndex - keyIndex) % CHAR_LEN]

def decryptText(cipherText, key):
    plainChars = []
    for index, cipherChar in enumerate(cipherText):
        plainChars.append(getPlainCharacter(cipherChar, key[index % len(key)]))
    return "".join(plainChars)

if __name__ == "__main__":
    # get Key
    key = getLineFromFile(KEY_FILE).strip()
    # get Plain Text
    plainText = "".join(getInputFromFile(INPUT_FILE).split())
    # Generate Cipher Text
    cipherText = encryptText(plainText, key)
    # Write Cipher Text to Output File
    writeToFile(OUTPUT_FILE, cipherText)

# Example Below:
# Input::
# CanYouMeetMeAtMidnightIHaveTheGoods
# Key::
# abracadabrazABRACADABRAZabracadabra
# CipherText::
# CbEYquPefKMDaUDIFNLGIkiGawvTjeJopus
