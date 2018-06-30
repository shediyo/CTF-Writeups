import socket
import base64
import hashlib

def xor_in_index(data, byte_to_xor, index):
	after_index = list(data[index + 1:])
	before_index = list(data[:index])
	in_byte = list([data[index] ^ ord(byte_to_xor)])
	lst = before_index + in_byte + after_index
	return bytes(lst)

def get_oracle_answer(send_data):
	s = socket.socket()
	s.connect(('dogestore.ctfcompetition.com' ,1337))
	s.send(send_data)
	sha3_encoded_ans = s.recv(8192)
	s.close()
	return base64.b64decode(sha3_encoded_ans)

def find_length_bytes(enc_data, value_bytes_xors, range_start=29, range_end=54):
	local_enc_data = enc_data[:]
	calculated_sizes = []

	for value_index in range(range_start, range_end):
		change_index = value_index * 2 + 2

		eq_byte = value_bytes_xors[value_index]
		final_xor = 0
		for check_bit in range(6):
			size_change = 2 ** check_bit

			first_send_data = xor_in_index(local_enc_data[:], chr(size_change), change_index - 1)
			first_send_data = xor_in_index(first_send_data, chr(eq_byte), change_index)
			sha3_data_first = get_oracle_answer(first_send_data)

			second_send_data = xor_in_index(local_enc_data[:], chr(size_change), change_index + 1)
			second_send_data = xor_in_index(second_send_data, chr(eq_byte), change_index)
			sha3_data_second = get_oracle_answer(second_send_data)

			if sha3_data_second != sha3_data_first:
				final_xor = final_xor ^ size_change

		calculated_sizes.append(final_xor)
		local_enc_data = xor_in_index(local_enc_data, chr(final_xor), change_index + 1)
		print(calculated_sizes)

	return calculated_sizes

def find_value_bytes_xors(enc_data):
	GOOD_SIZE_CHANGE = 0x80
	local_enc_data = enc_data[:]
	value_bytes_xors = []
	tests_num = (len(enc_data) // 2) - 1
	for value_index in range(tests_num):
		change_index = value_index * 2 + 2

		for byte in range(256):
			first_send_data = xor_in_index(local_enc_data[:], chr(GOOD_SIZE_CHANGE), change_index - 1)
			first_send_data = xor_in_index(first_send_data, chr(byte), change_index)
			sha3_data_first = get_oracle_answer(first_send_data)

			second_send_data = xor_in_index(local_enc_data[:], chr(GOOD_SIZE_CHANGE), change_index + 1)
			second_send_data = xor_in_index(second_send_data, chr(byte), change_index)
			sha3_data_second = get_oracle_answer(second_send_data)

			if sha3_data_second == sha3_data_first:
				print('Found xor of bytes ' + str(byte))
				value_bytes_xors.append(byte)
				found = True
				break

		if not found:
			print("Bummer, xor not found")
			return

		print(value_bytes_xors)

	return value_bytes_xors

flag_data = open('encrypted_secret', 'rb').read()
print(repr(flag_data))

xor_vals = find_value_bytes_xors(flag_data)
# xor_vals = [14, 14, 14, 14, 12, 12, 12, 12, 12, 23, 18, 32, 32, 2, 23, 18, 61, 40, 18, 5, 5, 18, 23, 23, 23, 7, 23, 18, 61, 55, 19, 26, 26, 13, 13, 16, 22, 6, 21, 15, 11,5, 2, 7, 29, 46, 60, 18, 23, 7, 23, 18, 61, 113]

for first_byte in range(256):
	curr_byte = chr(first_byte)
	whole_flag = curr_byte
	for xor_val in xor_vals:
		curr_byte = chr(ord(curr_byte) ^ xor_val)
		whole_flag += curr_byte
	if 'CTF{' in whole_flag:
		break

print(whole_flag)

FLAG_INDEX, END_INDEX = 20, 54
length_vals = find_length_bytes(flag_data, xor_vals, FLAG_INDEX, END_INDEX)
whole_flag_decoded = ''
for i in range(len(length_vals)):
	whole_flag_decoded += whole_flag[i + FLAG_INDEX + 1] * (length_vals[i] + 1)
print(whole_flag_decoded)



