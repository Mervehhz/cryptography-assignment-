import numpy
from bitarray import bitarray
import random


pol_2 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]
pol_3 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1]
primitive_pol= [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1]


permutation = [
    [0, 4, 8, 12, 16, 20, 24, 28, 3, 7, 11, 15, 19, 23, 27, 31, 2, 6, 10, 14, 18, 22, 26, 30, 1, 5, 9, 13, 17, 21, 25,
    29],
    [1, 5, 9, 13, 17, 21, 25, 29, 0, 4, 8, 12, 16, 20, 24, 28, 3, 7, 11, 15, 19, 23, 27, 31, 2, 6, 10, 14, 18, 22, 26,
    30],
    [2, 6, 10, 14, 18, 22, 26, 30, 1, 5, 9, 13, 17, 21, 25, 29, 0, 4, 8, 12, 16, 20, 24, 28, 3, 7, 11, 15, 19, 23, 27,
    31],
    [3, 7, 11, 15, 19, 23, 27, 31, 2, 6, 10, 14, 18, 22, 26, 30, 1, 5, 9, 13, 17, 21, 25, 29, 0, 4, 8, 12, 16, 20, 24,
    28]]



round_constants = ["01", "03", "07", "0F", "1F", "3E", "3D", "3B", "37", "2F", "1E", "3C", "39", "33", "27", "0E", "1D", "3A", "35", "2B", 
                    "16", "2C", "18", "30", "21", "02", "05", "0B", "17", "2E", "1C", "38", "31", "23", "06", "0D","1B", "36", "2D", "1A"]


list = []

def generate_nonce():
    while True:
        nonce = random_bits(128)
        if nonce not in list:
            list.append(nonce)
            break

    return nonce


def random_bits(n):
    t = bitarray()
    for h in range (0, n):
        t.append(random.getrandbits(1))

    return t


def GIFT_box(plaintext, key):
    cipherstate = initialise_pt(plaintext)
    keystate = initialise_ks(key)

    for i in range(1, 41):
        cipherstate = subcells(cipherstate)
        cipherstate = permBits(cipherstate)
        AddRoundKey(cipherstate, keystate, i)
        keystateupdate(keystate)


    y = finalise(cipherstate)
    return y


def initialise_pt(plaintext):
    s0 = plaintext[0:32]
    s1 = plaintext[32:64]
    s2 = plaintext[64:96]
    s3 = plaintext[96:128]

    state  = []
    state.append(s0)
    state.append(s1)
    state.append(s2)
    state.append(s3)

    return state


def initialise_ks(keystate):
    ks0 = keystate[0:16]
    ks1 = keystate[16:32]
    ks2 = keystate[32:48]
    ks3 = keystate[48:64]
    ks4 = keystate[64:80]
    ks5 = keystate[80:96]
    ks6 = keystate[96:112]
    ks7 = keystate[112:128]

    state = []
    state.append(ks0)
    state.append(ks1)
    state.append(ks2)
    state.append(ks3)
    state.append(ks4)
    state.append(ks5)
    state.append(ks6)
    state.append(ks7)

    return state


def subcells(state):
    state[1] = state[1] ^ (state[0] & state[2])
    state[0] = state[0] ^ (state[1] & state[3])
    state[2] = state[2] ^ (state[0] | state[1])
    state[3] = state[3] ^ state[2]
    state[1] = state[1] ^ state[3]
    state[3] = ~state[3]
    state[2] = state[2] ^ (state[0] & state[1])

    list = []
    for i in range (0, 4):
        list.append(state[3 - i])

    return list


def permBits(state):
    tempstate = state
    for count1 in range(0, 4):
        for count2 in range(0, 32):
            tempstate[count1][count2] = state[count1][permutation[count1][count2]]

    return tempstate


def AddRoundKey(cipherstate, keystate, round):
    temp1 = keystate[6] + keystate[7]
    temp2 = keystate[2] + keystate[3]

    cipherstate[1] = cipherstate[1] ^ temp1
    cipherstate[2] = cipherstate[2] ^ temp2

    Const_round = "800000" + round_constants[round - 1]

    int_value = int(Const_round, base=16)

    binary_value = str(bin(int_value))[2:]

    binary = bitarray(binary_value)
    cipherstate[3] = cipherstate[3] ^ binary

    return


def keystateupdate(state):
    state[6] = rightrotate(state[6], 2)
    state[7] = rightrotate(state[7], 12)

    state[0] = state[6]
    state[1] = state[7]
    state[2] = state[0]
    state[3] = state[1]
    state[4] = state[2]
    state[5] = state[3]
    state[6] = state[4]
    state[7] = state[5]

    return


def finalise(ciphertext):
    list = []

    for count1 in range(0, 4):
        for count2 in range(0, 32):
            list.append(ciphertext[count1][count2])

    return bitarray(list)


def leftrotate(list, n):
    for h in range(0, n):
        last = list[0]
        for i in range(1, len(list)):
            list[i - 1] = list[i]
        list[len(list) - 1] = last

    return list


def rightrotate(list, n):
    for h in range(0, n):
        first = list[len(list) - 1]
        for i in range(len(list) - 2, -1, -1):
            list[i + 1] = list[i]
        list[0] = first

    return list

pad_seq = bitarray([0] * 64)


def pad(s):
    m = s
    if len(s) != 0 and len(s) % 128 == 0:
        return s

    else:
        m = m + "1"
        for num in range(0, 128 - len(s) % 128 ):
            m = m + "0"

    return m


def rand_key(p):
    key1 = ""

    for i in range(p):
        temp = str(random.randint(0, 1))
        key1 += temp

    return key1


def G(str):
    left = str[0:64]
    right = str[64:128]
    left = leftrotate(left, 1)
    state = right + left
    return state


def helper(two_or_three, L):
    if two_or_three == "two":
        quotient, remainder = numpy.polydiv(numpy.polynomial.polynomial.polymul(pol_2, numpy.poly1d(L.tolist())), primitive_pol)
    else:
        quotient, remainder = numpy.polydiv(numpy.polynomial.polynomial.polymul(pol_3, numpy.poly1d(L.tolist())), primitive_pol)

    r = []
    for f in range(0,len(remainder)):
        r.append(int(remainder[f]))

    for j in range(0, len(r)):
        r[j] = r[j] % 2

    if len(r) < 64 :
        for f in range(0, 64 - len(r)):
            r.insert(0,0)

    L = bitarray(r)
    return L


def encrypt_gift_cofb(n, a, m, k):
    a_temp = pad(a)

    associated_size = int(len(a_temp) / 128)
    message_size= 0

    A = [bitarray] * (associated_size)

    temp = 0
    for num in range(0, associated_size):
        A[num] = a_temp[temp:temp + 128]
        temp += 128

    if len(m) != 0:
        m_temp = pad(m)
        message_size = int(len(m_temp)/128)
        M = [bitarray] * (message_size)
        temp = 0
        for num in range(0, message_size):
            M[num] = m_temp[temp:temp + 128]
            temp += 128

    X = [bitarray()] * (associated_size + message_size + 1)
    Y = [bitarray()] * (associated_size + message_size + 1)
    C = [bitarray()] * (message_size + 1)


    Y[0] = GIFT_box(n, k)
    L = Y[0][0:64]


    for i in range(1, associated_size):
        L = helper("two", L)
        X[i] = A[i - 1] ^ G(Y[i - 1]) ^ (L + pad_seq)
        Y[i] = GIFT_box(X[i], k)


    if len(A) % 128 == 0 and len(A) != 0:
        L = helper("three", L)

    else:
        for n in range(0, 2):
            L = helper("three", L)

    if(len(m) == 0):
        for n in range(0, 2):
            L = helper("three", L)

    X[associated_size] = A[associated_size - 1] ^ G(Y[associated_size - 1]) ^ (L + pad_seq)
    Y[associated_size] = GIFT_box(X[associated_size], k)

    for i in range(1, message_size):
        L = helper("two", L)

        C[i] = M[i - 1] ^ Y[i + associated_size - 1]
        X[i + associated_size] = M[i - 1] ^ G(Y[i + associated_size - 1]) ^ (L + pad_seq)
        Y[i + associated_size] = GIFT_box(X[i + associated_size], k)


    if len(m) != 0:
        if len(m) % 128 == 0:
            L = helper("three", L)

        else:
            for n in range (0, 2):
                L = helper("three", L)

        C[message_size] = M[message_size - 1] ^ Y[associated_size + message_size - 1]
        X[associated_size + message_size] = M[message_size - 1] ^ G(Y[associated_size + message_size - 1] ^ (L + pad_seq))
        Y[message_size + associated_size] = GIFT_box(X[message_size + associated_size], k)
        c = bitarray()
        t = bitarray()

        for h in range(1, message_size + 1):
            c += C[h]
        c = c[0:len(m)]

        t = Y[associated_size + message_size][0:128]

    else:
        c = bitarray()
        t = bitarray()
        t = Y[associated_size][0:128]

    list = []
    list.append(c)
    list.append(t)
    return list


def decrypt_gift_cofb(n, a, c, t, k):
    a_temp = pad(a)

    associated_size = int(len(a_temp) / 128)
    c_size = 0

    A = [bitarray] * (associated_size)

    temp = 0
    for num in range(0, associated_size):
        A[num] = a_temp[temp:temp + 128]
        temp += 128

    if len(c) != 0:
        c_temp = pad(c)
        c_size = int(len(c_temp) / 128)
        C = [bitarray] * (c_size)
        temp = 0
        for num in range(0, c_size):
            C[num] = c_temp[temp:temp + 128]
            temp += 128

    X = [bitarray()] * (associated_size + c_size + 1)
    Y = [bitarray()] * (associated_size + c_size + 1)
    M = [bitarray()] * (c_size + 1)

    Y[0] = GIFT_box(n, k)
    L = Y[0][0:64]

    for i in range(1, associated_size):
        L = helper("two", L)
        X[i] = A[i - 1] ^ G(Y[i - 1]) ^ (L + pad_seq)
        Y[i] = GIFT_box(X[i], k)

    if len(A) % 128 == 0 and len(A) != 0:
        L = helper("three", L)

    else:
        for n in range(0, 2):
            L = helper("three", L)

    if (len(c) == 0):
        for n in range(0, 2):
            L = helper("three", L)

    X[associated_size] = A[associated_size - 1] ^ G(Y[associated_size - 1]) ^ (L + pad_seq)
    Y[associated_size] = GIFT_box(X[associated_size], k)


    for i in range(1, c_size):
        L = helper("two", L)

        M[i] = C[i - 1] ^ Y[i + associated_size - 1]
        X[i + associated_size] = M[i] ^ G(Y[i + associated_size - 1]) ^ (L + pad_seq)
        Y[i + associated_size] = GIFT_box(X[i + associated_size], k)

    if len(c) != 0:
        if len(c) % 128 == 0:
            L = helper("three", L)
            M[c_size] = C[c_size - 1] ^ Y[associated_size + c_size - 1]

        else:
            for n in range(0, 2):
                L = helper("three", L)

            c_dash = len(c) % 128

            sequence = bitarray()
            sequence.append(1)
            for num in range(1, 128 - c_dash):
                sequence.append(0)
            M[c_size] = (C[c_size - 1] ^ Y[associated_size + c_size - 1])[0: c_dash] + sequence

        X[associated_size + c_size] = M[c_size] ^ G(Y[associated_size + c_size - 1] ^ (L + pad_seq))
        Y[c_size + associated_size] = GIFT_box(X[c_size + associated_size], k)

        m = bitarray()


        for h in range(1, c_size + 1):
            m += M[h]

        m = m[0:len(c)]

        t_dash = bitarray()

        t_dash = Y[associated_size + c_size][0:128]

    else:
        m = bitarray()
        t_dash = bitarray()
        t_dash = Y[associated_size][0:128]

    if t_dash == t:
        return m

    else:
        return "Error"

# nonce
n = generate_nonce()
# associated data
a = "1010111011110101011010"
# message
m = "0000110110111010110010101011110111010001111011100111101011111000000101000000010101010111101010011001101110011101110000110111000100111000011000000001000010001100111101001110111011101010000101100111010011011001001111110100100000100000100001010110101000111111"

print("Message: ", m)
#key
k = "10010100100101001001101011111000111100110100110010010111001011100011000010110000001111101100101010000100010101110010000100010101"
#Encrypting- returns [ciphertext, tag]
t = encrypt_gift_cofb(bitarray(n), bitarray(a), bitarray(m), bitarray(k))

print("\nEncryted message: ", t[0])
#Decrypting
g  = decrypt_gift_cofb(bitarray(n), bitarray(a), t[0], t[1], bitarray(k))

print("\nDecrypted message: ", g)
#checking if the message recovered is equal to the original message
print("\nIs equal message and decrypted message: ", g == bitarray(m))
#passing wrong associated data gives error proving that authenticity is ensured
aa = "1010111011000001011000"
c  = decrypt_gift_cofb(bitarray(n), bitarray(aa), t[0], t[1], bitarray(k))
print("\nIs equal message and decrypted message(with wrong associated data): ", c)