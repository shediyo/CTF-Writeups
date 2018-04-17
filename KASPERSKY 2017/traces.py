Traceback (most recent call last):
File "/usr/local/lib/python2.7/dist-packages/flask/app.py", line 1612, in full_dispatch_request
rv = self.dispatch_request()
File "/usr/local/lib/python2.7/dist-packages/flask/app.py", line 1598, in dispatch_request
return self.view_functions[rule.endpoint](**req.view_args)
File "/var/www/FlaskApp/FlaskApp/__init__.py", line 53, in index
user_info_decrypted = json.loads(aes_decrypt(user_info).decode())
File "/var/www/FlaskApp/FlaskApp/__init__.py", line 34, in aes_decrypt
cipher = AES.new(base64.b64decode(hardcoded_key), AES.MODE_CBC, iv )
File "/usr/local/lib/python2.7/dist-packages/Crypto/Cipher/AES.py", line 95, in new
return AESCipher(key, *args, **kwargs)
File "/usr/local/lib/python2.7/dist-packages/Crypto/Cipher/AES.py", line 59, in __init__
blockalgo.BlockAlgo.__init__(self, _AES, key, *args, **kwargs)
File "/usr/local/lib/python2.7/dist-packages/Crypto/Cipher/blockalgo.py", line 141, in __init__
self._cipher = factory.new(key, *args, **kwargs)
ValueError: IV must be 16 bytes long

----------------------------------------
Traceback (most recent call last):
File "/usr/local/lib/python2.7/dist-packages/flask/app.py", line 1612, in full_dispatch_request
rv = self.dispatch_request()
File "/usr/local/lib/python2.7/dist-packages/flask/app.py", line 1598, in dispatch_request
return self.view_functions[rule.endpoint](**req.view_args)
File "/var/www/FlaskApp/FlaskApp/__init__.py", line 53, in index
user_info_decrypted = json.loads(aes_decrypt(user_info).decode())
File "/var/www/FlaskApp/FlaskApp/__init__.py", line 35, in aes_decrypt
return unpad(cipher.decrypt( enc[16:] ))
File "/var/www/FlaskApp/FlaskApp/__init__.py", line 23, in unpad
return s[:-ord(s[-1])]
IndexError: string index out of range

----------------------------------------
Traceback (most recent call last):
File "/usr/local/lib/python2.7/dist-packages/flask/app.py", line 1612, in full_dispatch_request
rv = self.dispatch_request()
File "/usr/local/lib/python2.7/dist-packages/flask/app.py", line 1598, in dispatch_request
return self.view_functions[rule.endpoint](**req.view_args)
File "/var/www/FlaskApp/FlaskApp/__init__.py", line 53, in index
user_info_decrypted = json.loads(aes_decrypt(user_info).decode())
File "/usr/lib/python2.7/json/__init__.py", line 339, in loads
return _default_decoder.decode(s)
File "/usr/lib/python2.7/json/decoder.py", line 364, in decode
obj, end = self.raw_decode(s, idx=_w(s, 0).end())
File "/usr/lib/python2.7/json/decoder.py", line 382, in raw_decode
raise ValueError("No JSON object could be decoded")
ValueError: No JSON object could be decoded