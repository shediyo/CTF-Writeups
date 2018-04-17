from ps_enc import ps, prep_psp
prep_psp()
from ps_enc import PBOX_TABLE, SBOX_TABLE

def find_good_key_tuples_1(dec_val, msg_val, msg_space):
	search_range = range(0x30, 0x3a) + range(0x61, 0x67)

	msg_dict = {}
	for i in xrange(256):
		msg_dict[i] = []

	tups = []
	for i1 in search_range[:]:
		for i2 in search_range[:]:
			for j1 in search_range[:]:
				for j2 in search_range[:]:
					z7 = SBOX_TABLE[7].index( ord(msg_val) ^ i1 )
					z6 = SBOX_TABLE[6].index( z7 ^ i2 )
					z5 = SBOX_TABLE[5].index( z6 ^ j1 )
					z4 = SBOX_TABLE[4].index( z5 ^ j2 )
					msg_dict[z4].append((i1, i2, j1, j2))
	
	for i1 in search_range[:]:
		for i2 in search_range[:]:
			print 'Iteration ' + str((i1, i2))
			for j1 in search_range[:]:
				for j2 in search_range[:]:
					z0 = SBOX_TABLE[0][ord(dec_val)] ^ i1
					z1 = SBOX_TABLE[1][z0] ^ i2
					z2 = SBOX_TABLE[2][z1] ^ j1
					z3 = SBOX_TABLE[3][z2] ^ j2
					for k in msg_dict[z3]:
						failed = False
						for m in msg_space:
							z7 = SBOX_TABLE[7].index( m ^ k[0] )
							z6 = SBOX_TABLE[6].index( z7 ^ k[1] )
							z5 = SBOX_TABLE[5].index( z6 ^ k[2] )
							z4 = SBOX_TABLE[4].index( z5 ^ k[3] )
							z3 = SBOX_TABLE[3].index( z4 ^ j2 )
							z2 = SBOX_TABLE[2].index( z3 ^ j1 )
							z1 = SBOX_TABLE[1].index( z2 ^ i2 )
							z0 = SBOX_TABLE[0].index( z1 ^ i1 )
							if z0 > 0x80:
								failed = True
								break
						if not failed:
							p = (k[0], k[1], k[2], k[3], j2, j1, i2, i1)
							tups.append(p)
	return tups

def find_good_key_tuples_2(dec_val1, msg_val1, dec_val2, msg_val2, ms):
	search_range = range(0x30, 0x3a) + range(0x61, 0x67)

	msg_dict = {}
	for i in xrange(256):
		for j in xrange(256):
			msg_dict[(i, j)] = []

	tups = []
	for i1 in search_range[:]:
		for i2 in search_range[:]:
			for j1 in search_range[:]:
				for j2 in search_range[:]:
					z7 = SBOX_TABLE[7].index( ord(msg_val1) ^ i1 )
					z6 = SBOX_TABLE[6].index( z7 ^ i2 )
					z5 = SBOX_TABLE[5].index( z6 ^ j1 )
					z4 = SBOX_TABLE[4].index( z5 ^ j2 )

					z7 = SBOX_TABLE[7].index( ord(msg_val2) ^ i1 )
					z6 = SBOX_TABLE[6].index( z7 ^ i2 )
					z5 = SBOX_TABLE[5].index( z6 ^ j1 )
					y4 = SBOX_TABLE[4].index( z5 ^ j2 )
					msg_dict[(z4, y4)].append((i1, i2, j1, j2))
	
	for i1 in search_range[:]:
		for i2 in search_range[:]:
			for j1 in search_range[:]:
				for j2 in search_range[:]:
					z0 = SBOX_TABLE[0][ord(dec_val1)] ^ i1
					z1 = SBOX_TABLE[1][z0] ^ i2
					z2 = SBOX_TABLE[2][z1] ^ j1
					z3 = SBOX_TABLE[3][z2] ^ j2
					z0 = SBOX_TABLE[0][ord(dec_val2)] ^ i1
					z1 = SBOX_TABLE[1][z0] ^ i2
					z2 = SBOX_TABLE[2][z1] ^ j1
					y3 = SBOX_TABLE[3][z2] ^ j2
					for k in msg_dict[(z3, y3)]:
						failed = False
						for m in ms:
							z7 = SBOX_TABLE[7].index( m ^ k[0] )
							z6 = SBOX_TABLE[6].index( z7 ^ k[1] )
							z5 = SBOX_TABLE[5].index( z6 ^ k[2] )
							z4 = SBOX_TABLE[4].index( z5 ^ k[3] )
							z3 = SBOX_TABLE[3].index( z4 ^ j2 )
							z2 = SBOX_TABLE[2].index( z3 ^ j1 )
							z1 = SBOX_TABLE[1].index( z2 ^ i2 )
							z0 = SBOX_TABLE[0].index( z1 ^ i1 )
							if z0 > 0x80:
								failed = True
								break
						if not failed:
							p = (k[0], k[1], k[2], k[3], j2, j1, i2, i1)
							tups.append(p)
	return tups	

def change_in_offset(found_key, offss, off_val):
	return found_key[:offss] + chr(off_val) + found_key[offss + 1:]

def break_and_update_key(msg, change_bytes, found_keys, dec_val1, offset1, dec_val2 = None, offset2 = None):
	pos = change_bytes[0]
	ms = [ord(msg[s]) for s in xrange(pos, len(msg), 16)]
	if dec_val2 is None:
		for offset2 in xrange(3, len(msg)):
			print 'Guess offset: ' + str(offset2)
			if offset2 == offset1:
				continue
			for guess in xrange(ord('a'), ord('z')):
				tups = find_good_key_tuples_2(dec_val1, msg[len(msg) - 16 * offset1 + pos], chr(guess), msg[len(msg) - 16 * offset2 + pos], ms)
				if len(tups) != 0:
					print 'Found!: ' + chr(guess)
					break
			if len(tups) != 0:
				break
	else:
		tups = find_good_key_tuples_2(dec_val1, msg[len(msg) - 16 * offset1 + pos], dec_val2, msg[len(msg) - 16 * offset2 + pos], ms)
	
	assert len(tups) == 1
	print tups[0]
	new_found_keys = found_keys[:]
	change_vals = list(tups[0])[::-1]
	change_bytes = change_bytes[::-1]
	for i in xrange(len(change_bytes)):
		new_found_keys[i] = change_in_offset(new_found_keys[i], change_bytes[i] , change_vals[i])
	return new_found_keys