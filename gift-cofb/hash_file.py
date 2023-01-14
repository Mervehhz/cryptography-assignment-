import os
from cbc import * 
import io

seperator = "~"
append_size = 16 + 1

def is_there_hash_value(file_name):
	size = os.stat(file_name).st_size
	doc = open(file_name, "rb")
	doc.seek(size - append_size, io.SEEK_SET)
	data = doc.read(1)
	if not (data.decode('utf-8') == seperator):
		return False
	else:
		return True

def add_hash_value(file_name,key, n, a):
	if is_there_hash_value(file_name):
		removve_hash_value(file_name)

	document= open(file_name, "rb+")
	value = bitarray()
	value.fromfile(document)
	encrypted = encrypt_gift_cofb(bitarray(n), bitarray(a), value, bitarray(key))
	hash_value = encrypted[0][-128:]
	document.write(seperator.encode() + hash_value)
	document.close()

def removve_hash_value(file_name):
	if is_there_hash_value(file_name):
		file_size = os.stat(file_name).st_size
		document= open(file_name, "rb+")
		document.truncate(file_size - append_size)
	else:
		print("hash value is not in the file!")
	document.close()


def check_file_change(file_name,key, n, a):
	if is_there_hash_value(file_name):
		document= open(file_name, "rb")
		document.seek(-16, io.SEEK_END)
		offset = document.tell() - 1
		hash_value = bitarray()
		hash_value.fromfile(document, 16)
		document.seek(0, io.SEEK_SET)
		value = bitarray()
		value.fromfile(document, offset)
		
		encrypted = encrypt_gift_cofb(bitarray(n), bitarray(a), value, bitarray(key))
		current_hash_value = encrypted[0][-128:]
		if current_hash_value != hash_value:
			print("hash values does not match..file has been changed.")
		else:
			print("hash values are same..file has not been changed")
		document.close()
	else:
		print("hash value is not in the file!")
	


def main():
    # nonce
    n = generate_nonce()
    # associated data
    a = "1010111011110101011010"
    k = "10010100100101001001101011111000111100110100110010010111001011100011000010110000001111101100101010000100010101110010000100010101"

    # add_hash_value("file.txt",k, n, a)
    check_file_change("file.txt",k, n, a)

if __name__ == "__main__":
    main()
