from giftcofb import *
from cbc import *

def ofb_encryption(m, n):
    m_size = int(len(m) / 128)
    tag = ""
    M = [bitarray] * m_size

    j=0
    for i in range(0, m_size):
        M[i] = m[j:j+128]
        j += 128
    iv2 = random_bits(128)

    # associated data
    a = "1010111011110101011010"
    #key
    k = "10010100100101001001101011111000111100110100110010010111001011100011000010110000001111101100101010000100010101110010000100010101"

    cipher_text = encrypt_gift_cofb(bitarray(n), bitarray(a), bitarray(iv2), bitarray(k))
    first_xor = xor(bitarray_to_str(cipher_text[0]), M[0])

    tag += bitarray_to_str(cipher_text[1])
    result = ""
    result += first_xor

    for i in range(1,m_size):
        cipher_text = encrypt_gift_cofb(bitarray(n), bitarray(a), bitarray(cipher_text[0]), bitarray(k))
        temp_xor = xor(M[i], bitarray_to_str(cipher_text[0]))
        tag += ' '
        tag += bitarray_to_str(cipher_text[1])
        result += temp_xor
        
    t = tag.split(' ')
    return result, t, iv2

def ofb_decryption(e, n, iv2):
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

    plain_text=encrypt_gift_cofb(bitarray(n), bitarray(a), bitarray(iv2), bitarray(k))
    first_xor = xor(E[0], plain_text[0])
    result = ""
    result += first_xor

    for i in range(1,e_size):
        plain_text=encrypt_gift_cofb(bitarray(n), bitarray(a), bitarray(plain_text[0]), bitarray(k))
        temp_xor = xor(E[i], plain_text[0])
        result += temp_xor
        
    return result

if __name__ == '__main__':
    # nonce
    n = generate_nonce()
    m = "0000110110111010110010101011110111010001111011100111101011111000000101000000010101010111101010011001101110011101110000110111000100111000011000000001000010001100111101001110111011101010000101100111010011011001001111110100100000100000100001010110101000111111"
    enc, tag, iv2 = ofb_encryption(m, n)
    print(enc)
    dec = ofb_decryption(enc, n, iv2)
    print(dec)