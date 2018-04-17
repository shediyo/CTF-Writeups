from ps_enc import ps, prep_ps4
prep_ps4()
from ps_enc import PBOX_TABLE, SBOX_TABLE

def find_good_key_tuples(dec_val, msg_val, bad_cond):
	msg_dict = {}
	for i in xrange(256):
		msg_dict[i] = []

	tups = []
	for i in xrange(256):
		for j in xrange(256):
			msg_dict[ SBOX_TABLE[2].index( SBOX_TABLE[3].index( ord(msg_val) ^ i ) ^ j )  ].append((i, j))
	
	for i in xrange(256):
		for j in xrange(256):
			for k in msg_dict[ SBOX_TABLE[1][SBOX_TABLE[0][ord(dec_val)] ^ i] ^ j ]:
				p = (k[0], k[1], j, i)
				if not bad_cond(p):
					tups.append (p)

	return tups

def break_key_seq_1(msg, pos, dec_val, bad_cond):
	tups = find_good_key_tuples(dec_val, msg[len(msg) - 16 + pos], bad_cond)
	good_tups = []
	for p in tups:
		failed = False
		for s in xrange(pos, len(msg), 16):
			z = SBOX_TABLE[2].index( SBOX_TABLE[3].index( ord(msg[s]) ^ p[0] ) ^ p[1] )
			if SBOX_TABLE[0].index( SBOX_TABLE[1].index( z ^ p[2] ) ^ p[3] ) > 0x80:
				failed = True
				break

		if not failed:
			good_tups.append(p)

	return good_tups

def break_key_seq_2(msg, pos, xor_val_chooser):
	good_pairs = []
	for i in xrange(256):
		for j in xrange(256):
			failed = False
			for s in xrange(pos, len(msg), 16):
				z = SBOX_TABLE[2].index( SBOX_TABLE[3].index( ord(msg[s]) ^ xor_val_chooser(i, j, 3)) ^ xor_val_chooser(i, j, 2) )
				d = SBOX_TABLE[0].index( SBOX_TABLE[1].index( z ^ xor_val_chooser(i, j, 1)) ^ xor_val_chooser(i, j, 0) )
				if d > 0x80:
					failed = True
					break

			if not failed:
				good_pairs.append((i, j))
	return good_pairs