import base64
import requests

def get_cookie_for(in_name):
	r = requests.get('http://95.85.51.183/?name='+in_name)
	# print r.headers
	cookie = r.headers['Set-Cookie'].split('"')[1]
	print cookie
	return cookie

def cookie_response(cookie):
	headers = {'Cookie': 'user_info=' + cookie}
	r = requests.get('http://95.85.51.183/', headers = headers)
	# print r.headers
	return r.content

def db64(wstr):
	return base64.b64decode(wstr)

def eb64(wstr):
	return base64.b64encode(wstr)

def show_db64(wstr):
	res = base64.b64decode(wstr)
	for i in range(0, len(res)/16):
		print repr(res[i * 16: (i+1) * 16])
	print '\n\n'
	return res

def change_in_split(z, sp, xor_with):
	return z[:sp] + chr(ord(z[sp]) ^ xor_with) + z[sp + 1:]

'''
z = db64(get_cookie_for('n'))
print len(z)
z = change_in_split(z, 3, ord('"') ^ ord('a'))
z = change_in_split(z, 4, ord(':') ^ ord('m'))
z = change_in_split(z, 7, ord(',') ^ ord(':'))
z = change_in_split(z, 11, ord('a') ^ ord('"'))
z = change_in_split(z, 12, ord('m') ^ ord(','))
z = change_in_split(z, 13, ord('e') ^ ord('"'))
print repr(z)
print eb64(z)
'''

made_cookie = db64(get_cookie_for('n'))
z = db64('u3DarlfTHIYEvpLMqjeAYMadahBBNzG8aRbRTkBhpnRZXZRAZ3PvnJIVYmFzMRLW3g86OIhu9XFm20Rr/V9eNQ==')
z = change_in_split(z, 16 + 11, ord('t') ^ ord('f'))
z = change_in_split(z, 16 + 12, ord('r') ^ ord('a'))
z = change_in_split(z, 16 + 13, ord('u') ^ ord('l'))
z = change_in_split(z, 16 + 14, ord('e') ^ ord('s'))
z = change_in_split(z, 16 + 15, ord(' ') ^ ord('e'))
z = change_in_split(z, 0, 0x80 ^ 0x8a ^ ord('{'))
z = change_in_split(z, 1, 0x00 ^ 0x97 ^ ord('"'))
z = change_in_split(z, 2, 0x80 ^ 0xc5 ^ ord("n"))
z = change_in_split(z, 3, 0x00 ^ 0xd8 ^ ord('a'))
z = change_in_split(z, 4, 0x80 ^ 0xcf ^ ord('m'))
z = change_in_split(z, 5, 0xc7 ^ ord('e'))
z = change_in_split(z, 6, 0x80 ^ 0xb6 ^ ord('"'))
z = change_in_split(z, 7, 0x80 ^ 0xc5 ^ ord(':'))
z = change_in_split(z, 8, 0xa2 ^ ord(' '))
z = change_in_split(z, 9, 0xc7 ^ ord('"'))
z = change_in_split(z, 10, 0x80 ^ 0xa8 ^ ord('a'))
z = change_in_split(z, 11, 0x80 ^ 0xaf ^ ord('"'))
z = change_in_split(z, 12, 0x80 ^ 0x9e ^ ord(','))
z = change_in_split(z, 13, 0x9d ^ ord(' '))
z = change_in_split(z, 14, 0x80 ^ 0x9f ^ ord('"'))
z = change_in_split(z, 15, 0xf2 ^ ord('s'))
print eb64(z)
resp = cookie_response(eb64(z))
print resp

'''
in_msg = ''
made_cookie = db64('u3DarlfTHIYEvpLMqjeAYMadahBBNzG8aRbRTkBhpnRZXZRAZ3PvnJIVYmFzMRLW3g86OIhu9XFm20Rr/V9eNQ==') # db64(get_cookie_for('a'))
for b in range(0, 16):
	for i in range(128, 256):
		z = made_cookie[16:]
		# z = change_in_split(z, 0, ord('a') ^ ord('{'))
		z = change_in_split(z, b, i)
		resp = cookie_response(eb64(z))
		if "decode byte" in resp:
			print resp
			print i
			byte_no_decode = resp.split("decode byte ")[1].split(' ')[0]
			print byte_no_decode
			in_msg += chr(i ^ int(byte_no_decode ,16))
			print in_msg
			break
		# print repr(z)
		# print eb64(z)
'''

# show_db64(get_cookie_for('a' * 80))
# show_db64(get_cookie_for('a' * 80))
# show_db64(get_cookie_for('a' * 80))