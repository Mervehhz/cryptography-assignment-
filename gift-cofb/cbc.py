from bitarray import bitarray
import random
from giftcofb import *

def random_bits(n):
    iv = ""
    for h in range (0, n):
        iv += str((random.randint(0,1)))

    return iv

def xor(a, b):
    result = ""
    for i in range(0,len(a)):
        result += str(int(a[i])^int(b[i]))

    return result

def bitarray_to_str(arr):
    res = ""
    for i in range(0,len(arr)):
        res += str(arr[i])
    return res

def cbc_encryption(m, n):
    m_size = int(len(m) / 128)
    tag = ""
    M = [bitarray] * m_size

    j=0
    for i in range(0, m_size):
        M[i] = m[j:j+128]
        j += 128
    iv = random_bits(128)

    # associated data
    a = "1010111011110101011010"
    #key
    k = "10010100100101001001101011111000111100110100110010010111001011100011000010110000001111101100101010000100010101110010000100010101"

    first_xor = xor(iv, M[0])

    cipher_text = encrypt_gift_cofb(bitarray(n), bitarray(a), bitarray(first_xor), bitarray(k))
    tag += bitarray_to_str(cipher_text[1])
    result = ""
    result += bitarray_to_str(cipher_text[0])

    for i in range(1,m_size):
        temp_xor = xor(M[i], bitarray_to_str(cipher_text[0]))
        cipher_text = encrypt_gift_cofb(bitarray(n), bitarray(a), bitarray(temp_xor), bitarray(k))
        tag += ' '
        tag += bitarray_to_str(cipher_text[1])
        result += bitarray_to_str(cipher_text[0])
        
    t = tag.split(' ')
    return result, t, iv

def cbc_decryption(e, tag, n, iv):
    e_size = int(len(e) / 128)

    E = [bitarray] * e_size

    j=0
    for i in range(0, e_size):
        E[i] = e[j:j+128]
        j += 128

    # associated data
    a = "1010111011110101011010"
    #key
    k = "10010100100101001001101011111000111100110100110010010111001011100011000010110000001111101100101010000100010101110010000100010101"

    plain_text=decrypt_gift_cofb(bitarray(n), bitarray(a), bitarray(E[0]), bitarray(tag[0]), bitarray(k))
    first_xor = xor(iv, plain_text)
    result = ""
    result += first_xor

    for i in range(1,e_size):
        plain_text=decrypt_gift_cofb(bitarray(n), bitarray(a), bitarray(E[i]), bitarray(tag[i]), bitarray(k))
        temp_xor = xor(E[i-1], plain_text)
        result += temp_xor
        
    return result

if __name__ == '__main__':
    # nonce
    n = generate_nonce()
    m = "0000110110111010110010101011110111010001111011100111101011111000000101000000010101010111101010011001101110011101110000110111000100111000011000000001000010001100111101001110111011101010000101100111010011011001001111110100100000100000100001010110101000111111"
    enc, tag, iv = cbc_encryption(m, n)
    print("Message: ", m)
    print("\nEncrypted message with CBC mode", enc)
    dec = cbc_decryption(enc, tag, n, iv)
    print("\nDecrypted message with CBC mode", dec)
    print("\nMessage equal to decrypted message:", m==dec)