import base64
import requests
from HTMLParser import HTMLParser

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

def print_data(name_str, note_str, base64_cookie):
	cookie = base64.b64decode(base64_cookie)
	print("name = %s, note = %s, cookie = %s, len = %s" %(name_str, note_str, repr(cookie), len(cookie)))

def cookie_response(cookie):
	headers = {'Cookie': 'state="' + cookie + '"'}
	r = requests.get('http://silly-note.herokuapp.com/', headers = headers)
	# print r.headers
	return r.content

def change_in_split(z, sp, xor_with):
	return z[:sp] + chr(ord(z[sp]) ^ xor_with) + z[sp + 1:]

# print_data('a', '', 'ZZobmIbCoybHzPSIBNzuVKX3meAleMZ8ezeYl3CwHWBkNz6hkSr5XiBKCp8e9d+l')
# print_data('a', 'b', '"iscLXBIuEX/ObJu6+uYW8Q8wPvjVCR/q5AZjSmMh31tsivrfPl5qAqtftL726rS6"')
# print_data('a', 'abcdefghijklmnopqrstuvwxyz1234567890', '"jinGy+dKj53g72anYXdwYXc+zaG1KxtbH37kLjR5ykCD1Q/55LpJ5Ws+c460pgUIMkUZjkj7x/s1yvY1pVAGWmra+FxwKonsZxcJfTANSbE="')

# first_cookie = db64('ZZobmIbCoybHzPSIBNzuVKX3meAleMZ8ezeYl3CwHWBkNz6hkSr5XiBKCp8e9d+l')
# second_cookie = db64('"iscLXBIuEX/ObJu6+uYW8Q8wPvjVCR/q5AZjSmMh31tsivrfPl5qAqtftL726rS6"')
# third_cookie = db64('"jinGy+dKj53g72anYXdwYXc+zaG1KxtbH37kLjR5ykCD1Q/55LpJ5Ws+c460pgUIMkUZjkj7x/s1yvY1pVAGWmra+FxwKonsZxcJfTANSbE="')
# fourth_cookie = db64('"e6g/3Bao77p5sXShumm6xqbL1MAwdrAnUyd0gIY4Jy3tKw0PJoNyOuRgsDZCeWRXhUKZUxTPKV3DftqpogsSp9E8srS4Geoxc9H3GQ+GGJC9B2YP6aqMQCRlFVQNB1nedaa6zYHtGYySGVrkrJy1rA=="')

# a_cookie = db64('"e6g/3Bao77p5sXShumm6xqbL1MAwdrAnUyd0gIY4Jy3tKw0PJoNyOuRgsDZCeWRXhUKZUxTPKV3DftqpogsSp0ouW9Mckfus2uEzzINgBIqPlIBz3uqwFaphQdUxDHp+wMFU6n4qiGTJKEszXFGELA=="')
# b_cookie = db64('"xVfiTI7SYTnZrx7+rSm8xbKPxRC0e4BVxLBLaJWiJi7GyYf0g2vKO00DK02QJ+HfXRUg+EqDxDxDi2wKPweftWcXwb7cvZbnCJ1d0/lxb2ZXDTOs0ztnKfj5SNHz7CzDnQeHcYWgO5o8V5CjuQf8EQ=="')

# abcdef_cookie = db64("jinGy+dKj53g72anYXdwYaE8y8IJzYGUkfA54pCRDQIxqGpf8BWQjV79Wdp4KvMm")
known_cookie = db64("jinGy+dKj53g72anYXdwYaAaaDeK84JP7H2SEUJkAIgPj2pQCX1S+8jCIlRYo7fuHFsrvqscPf7bmPVNpXnNQA==")

# IDEA: get known cookiw in correct length, and xor with 0x1 to xor out the level and make it 0.
for i in range(40):
	print i
	new_cookie = change_in_split(known_cookie, i, 0x1)
	real_new_cookie = eb64(new_cookie)
	print real_new_cookie
	resp = cookie_response(real_new_cookie)
	if '<pre>' in resp:
		print resp.split('<pre>')[1].split('</pre>')[0]
	else:
		print resp
	print '\n\n\n'