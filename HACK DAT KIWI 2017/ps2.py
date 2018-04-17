from ps_enc import ps, prep_ps2
prep_ps2()
from ps_enc import PBOX_TABLE, SBOX_TABLE

enc_msg = '9c 71 a3 5d 1f f6 12 53 d8 89 d0 27 c2 d1 67 7e d9 8a 5c 5d 94 33 df 55 6e 51 f7 27 df 08 28 94 d1 31 91 5a 1f f6 00 70 41 7c 4e f3 3b d1 91 d0 d9 e5 91 55 7a f0 df 55 c9 2f 4e 1c ea d1 de d0 31 71 5c 3c 7a f6 c2 0c 0a 60 69 28 a5 95 1f 87 6c 75 d1 c9 7a 0b 12 1b d8 64 f7 ee 41 02 9d 7c 50 07 bc f7 d1 6c 5d 55 fa a7 2c f3 72 1e 67 7e c0 8a f4 f7 cd 32 df c6 35 3b f5 90 c6 95 70 34 9c 65 af 9c eb 3f 06 52 fb 83 16 63 3b 5f 0e 8a 1f 7b be cf b0 41 df d2 07 64 d0 ee 4a 95 bc fe 9c 12 0f 11 1d f0 5d 8d 0a 64 97 f3 8e d5 37 2f 9f 58 91 3c 1f d3 df 55 a1 51 87 28 fd bb ce e9 94 71 58 3c eb 6c cf 13 8a 64 4c 56 72 1e bc 7c f2 c5 a0 de cd a3 00 13 d8 bc 97 f3 fd 15 2a dc f2 c5 58 3c 4c 0b 5d f0 a1 6d 2b 96 3b 85 85 dc 9c 81 fa fe da 33 5d 04 a9 7a dc 27 40 55 1f 94 94 71 cc 3c eb 57 f0 13 84 92 24 be e8 8c bc 43 f2 c5 6e cf 1d 41 df 75 a4 25 2b 86 e8 b2 9b fd d9 71 58 5d b0 f9 d9 0c d8 44 5d be 34 9b 67 43 5d bc 58 cf eb d3 09 55 0a 64 2c 07 c6 95 14 43 9c 71 45 3c 7a 32 09 70 eb 25 87 5d 40 6a 85 fd 9c 81 58 f7 7a 08 df 0c a4 25 0f 65 5d 95 70 fd d1 71 ab 26 45 f6 f0 88 ce 64 0f 28 ea 95 70 fe c0 81 b3 26 cd 0b 35 e3 5a 27 2b 28 ff 95 67 a9 d1 81 d1 b4 eb a3 f0 1b d8 27 e3 f3 fd 36 96 d0 9c 41 91 f7 ce 44 64 c0 d5 89 80 51 fd d1 0e fd 94 8a 06 3c 1f d3 df 0c 0a 2f 97 9e 3b 6a 64 10 d1 e5 fa cf 1f 06 d9 a1 d2 a7 97 28 3b 79 d7 7c 5d 81 e6 92 7a 79 12 0c d8 64 69 27 6a ba bd fd 6c ad 68 11 70 96 df f0 a4 3b 23 5d df 61 96 87 36 41 91 63 d1 44 64 f0 d8 78 f7 ee c2 9b d7 80 94 c5 58 52 1f 9f df 0c a4 6b 2b f3 3b 95 64 a0 d1 bc be 5d 94 0b 09 0c c9 78 ad f3 2a 95 2a 87 5f c5 be 0c 70 f6 df 70 d8 e4 2b f3 74 98 2a 80 6c c4 91 5d 7a 41 d9 d9 d8 d3 80 be 74 1e 70 94 9c 71 45 52 da 6c cf 1b ce 64 2b 90 6a 95 f9 d0 d1 f6 89 52 cd f6 97 a1 a1 a7 a8 28 fd 6a 9d 87 10 f6 35 b4 3c a3 a1 3e fa 51 97 a1 6a d1 b7 fd 4f 3c aa de cd f6 21 70 d8 83 44 be 3b 91 91 fd 9c 81 e6 b4 5d 0b 00 88 d8 83 69 07 69 ba d7 d0 f2 58 aa 55 eb 08 5d 8c d8 37 f7 90 fd ef 85 d0 9c 31 a0 26 4c 41 df 70 a4 83 97 28 41 6a 85 7e d1 71 d1 3c 7a 6c cf d9 6a 2f 87 28 5d 9b 67 34 e4 3c bc 55 cd 41 f0 1b fa a7 2c 9c fd 1e de d0 d9 71 ab 52 b0 f6 c2 55 a1 60 02 90 3b 81 74 dc d9 e5 a0 5d 94 0b b3 55 b4 3b 97 27 df 9b 67 7c d9 cd 45 5d 45 08 d9 55 d5 a7 3d 92 e8 d1 9b 1d be 67 91 26 45 44 a1 36 51 a7 d4 56 41 08 bc cf 10 66 c8 63 3c 0b 09 05 fb a7 73 d9 04 fc b7 fd 94 f6 0f 5d cd 41 a1 1b d8 89 69 ee 6a b9 d7 a8 e4 e1 5c 55 7a 0b d9 8c 6a a7 44 5d df 1e bc 6a 48 8a aa 3c cd 33 10 70 51 c6 a3 56 6a 08 91 d0 31 71 58 88 cd f9 97 55 c9 a7 2c 60 6c 15 9a 96 5d 3c 89 f7 cd 3f df 04 d5 60 5d 01 c6 7f 2a fd 31 f6 0f 3c d9 41 35 36 d8 40 61 96 fb 85 85 d0 4f 9e 91 f7 cd f0 97 70 eb e4 d0 96 6c b2 9b 41 31 81 f4 3c 1d aa df 42 d5 cc a8 90 40 15 de d0 f2 bc 91 7f 7a ae a1 13 51 83 d4 28 8d 7a 07 e1 9a 71 91 3c 94 0b df a1 d8 a7 97 f3 6a 95 5d fd'
msg = enc_msg.replace(' ','').decode('hex')

found_key = '\x00' * 16
key_index_pairs = [(i, PBOX_TABLE[1][i]) for i in range(16)]
for p in key_index_pairs:
	kept_key = found_key
	for k1 in xrange(256):
		for k2 in xrange(256):
			failed = False
			for pos in xrange(p[0], len(msg), 16):
				if SBOX_TABLE[0].index( SBOX_TABLE[1].index( ord(msg[pos]) ^ k1 ) ^ k2 ) > 0x80:
					failed = True
					break

			if not failed:
				print 'Found key', str((k1, k2)), 'for position: ', str((p[0] , p[1]))
				kept_key = found_key[:p[0]] + chr(k1) + found_key[p[0] + 1:]
				kept_key = kept_key[:p[1]] + chr(k2) + kept_key[p[1] + 1:]

	found_key = kept_key
# We actually get several values for keys (4,7) - the last one is the correct one :)
print repr(found_key)
print ps(msg, found_key, True, True)

