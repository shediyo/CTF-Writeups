from ps_enc import ps, prep_ps4
prep_ps4()
from ps_enc import PBOX_TABLE, SBOX_TABLE
from ps4_utils import break_key_seq_1, break_key_seq_2

enc_msg = 'c4 83 9e 11 19 81 6f b6 ea c0 f3 a0 a4 6a 33 2b 24 07 8a d1 68 07 3f 58 a2 b8 61 4e 76 ed b8 81 1e 07 9e 5b 77 80 37 ad b3 02 b6 7b 7e 20 ca a6 34 c5 78 46 e4 61 37 2e 18 c3 2c 13 02 ca ed bb 24 c5 9b 8b 7b cb 03 5a 40 5e 2c 65 a0 89 6e 36 24 07 ca d1 19 4b 07 8e a2 c0 79 65 ea 88 8b a1 92 7d 9e 9c 28 11 b5 58 ea 02 ef d4 c7 5a 6e bb c4 7d ca fd e4 19 6a 8e 1c c0 2c 5c 20 20 02 35 1e 07 9e 8b 19 80 37 b6 e1 89 64 4e a0 0e 8b 81 3e 1a 1a d1 ff fb 3f cd 65 b8 60 4e 7e 19 b9 4d 34 c5 9e 36 77 80 fd 5a e1 ae c9 e4 38 89 6e 8e 0f 58 ca e8 ff 11 b5 77 65 97 6d 65 27 6a 33 bb cb 23 6a d6 10 11 de b0 18 92 ef 21 76 7c b9 bb b4 c5 89 8b b8 cb 37 2c e1 b1 0d 6d f0 3d b9 7f cb 23 ad cf ae 2d 6a 77 ea 2a b6 2c a0 ed 42 18 24 83 51 d1 4c d6 d4 b0 79 50 b6 6e 76 82 8d 8e 24 c5 95 c7 4c 11 73 2c c7 b8 61 a0 34 8a 33 8d 0f 88 9e 36 ae fb fd 2e ea ae c9 e4 38 89 ae 8e b4 c5 89 8b ff 11 37 2c e1 c3 ef 6d 02 88 b9 bb 34 7d 9e ba 19 4b 50 7f 79 c0 6d db 4a ca ed 36 cb e0 f7 a9 d1 6f 6f 8e f2 02 a2 2c 9d 89 02 8d 0a f0 27 c9 70 d2 37 b6 18 46 ef 4e 98 89 33 d8 b4 c5 89 8b ae 4c 37 2c e1 5e 2f 6d 02 ed b9 7f 24 4b c7 ae 19 d2 c5 72 6f 02 60 2c a8 ee ae 89 cb e8 78 e8 19 4b cc 8e ad c0 f3 13 45 88 8b 36 16 07 9e b2 e4 a8 9c 8e 69 c0 2c e4 e6 32 b9 34 3e b9 02 8b ae 1f 37 8e 18 46 29 5d 98 6a 6e 81 73 ed 9b cf ae 4c 9c 72 40 50 2f 4e fa 21 b9 7f 34 93 52 ae b8 28 6f 77 e1 86 2c a0 7e 89 ae 35 cb 07 94 d1 19 c7 03 e9 f2 c0 b6 fd 22 fc ae aa 80 88 9e 11 28 a8 6f a9 69 c0 92 a0 ec 0e 8d 7f b0 57 ad 44 b8 84 07 5d 18 b8 92 a0 7e 21 6b 8e 2b 20 ad d3 78 6f 37 77 79 cf a2 49 ea cc 6e 8e 63 1a 9e b2 ae 6f 9c a9 65 c0 b6 e4 02 89 ce 8e 24 e4 02 cf 19 1f 37 b0 b0 5e 79 db 98 ee b8 e9 0f 20 b8 b2 88 5e 37 b6 77 5e 2c 9d 98 20 32 bb 4c 9e 02 d1 4c 11 23 77 b0 5e 79 a0 22 8a 33 7f 0f 1e 9b d1 10 11 3f 77 77 86 79 1d 7e 93 6e 57 63 93 78 21 28 11 48 b6 f2 86 60 65 27 ed b9 5a 2b 88 1a d1 19 82 de 5a ad 55 64 7b 76 ca b9 bb 16 07 05 2a 19 82 bc b6 18 2a 2f 2c 02 93 b9 7f cb 23 79 b2 28 11 20 b0 18 46 f3 c0 27 ed b9 08 0a f0 9e 02 ff b5 20 e9 e1 5e f9 c0 a0 19 ae 8e 9c 1a 9e 7d b8 cb 6f 5b e1 89 a2 13 ec 78 b9 a9 24 c5 02 8b 7b 28 97 e9 2b b8 2c db 34 89 6b 35 24 60 51 d1 ae 6f 3f ad 79 b8 b6 4e 76 89 32 8e 84 c5 1a d1 e4 5e 3f b0 b0 b8 a2 4e 7e 32 93 08 34 60 ca ba 4c a8 cb c9 18 b8 c9 2c e6 32 96 8e 24 e4 02 cf 4c 5e 6f b0 b0 b8 41 2c 34 89 b8 a9 24 88 f2 45 19 a8 fd 77 5e ed 64 5d a0 93 02 57 cb 60 7c d1 47 cb 20 8e 77 4d 45 43 ea 82 f4 8e c4 e8 9e b2 b8 81 9c 6b 5e c0 92 e4 6a 88 b9 bb 63 7d f7 c9 28 4c 6a a9 77 b8 a2 db c7 5a ae a9 0a 93 89 45 f6 01 fd ad e1 55 a6 2c a0 89 af 36 0f 83 7c d1 4c cb fd b6 77 50 2f 6c 5e 89 33 8e 59 2d f2 d1 77 5d 9c a2 19 86 c9 c0 34 32 63 bb 2b 69 ea d1 7b 11 07 77 6f c0 2f 65 a4 20 93 8d f1 89 29 ef 11 fb 22 b0 94 f5 45 09 12 33 f3 ad 34 1a f2 21 28 1f ef 77 18 5e cb 6e 5e 0e 8b 8e cb 23 8a 8b 50 6f 9c b0 18 c0 2c 6c ec 88 b9 34 92 57 9e 11 e4 a8 de 6b 04 d0 2c c0 76 32 b9 d5 24 83 02 8b 0a 81 d4 0d 2b b8 92 6d 7e 93 6b 1e 80 c5 8a b2 19 76 03 b0 e1 ed 60 65 5e 90 ed 5a 2b 69 ea d1 4c 11 de 77 6f 55 d6 7b 76 8a 33 34 2b 88 f2 46 b9 28 9c 5a 77 c0 f3 57 02 89 af 36 73 88 9e 8b e4 a8 37 2c e1 5e 2c 5d 98 32 b9 d5 3e 93 78 46 b8 81 13 ff a2 b8 2c 2c fa 0e 93 bb cb e8 8a ba ec 10 37 77 6f 4d 34 db 6a 8a 33 7a 0f 83 c7 d1 50 61 07 0d 79 c0 2c 65 a0 5a ce a9 0a 60 9e 45 4c 61 48 77 e1 b8 c9 6e 76 19 4e a1 0f 58 51 78 7b 11 20 77 ad 02 6d 5d 7e 20 93 7f 83 1a 9e ba e4 61 9c 2e 04 c0 2c db 45 ca ed b1 cb 23 3e cf 50 11 37 b0 18 46 79 9d 98 5e b9 81 b4 c5 89 8b ae 4c 37 2c e1 02 2f 6d ea ed b9 7f 83 ce 9e d3 ae 1f 3b 58 33 89 79 13 12 89 93 8e 80 c5 9e 36 96 6f fd fe bc ae c9 e4 38 89 33 8e 80 c5 9e e8 b8 28 23 fe bc ae 2c a0 a4 89 33 bb 4e 69 8a cf 57 81 37 ad 1c 02 87 5d 30 89 f6 8e 0a 60 9e c7 ff 11 6a 77 e1 89 92 65 12 19 f4 bb 1e 07 ca 44 ff 1f 37 ad 18 46 45 13 02 5a c2 8e 24 60 c7 d1 88 81 37 67 a2 40 f3 6e a0 88 33 1e cb 57 9e 06 5d 11 03 c9 bd ae 41 6e a0 20 96 a9 24 07 51 d1 e0 3a 03 8e a2 c0 17 6e ec dc a3 a9 34 7d 67 cf 5d 84 de d8 79 03 79 e4 76 4e 33 36 c4 7d f2 d1 ff a8 d4 2c ea 86 32 8d 02 93 ed 8d 80 ed f2 45 62 81 de 72 f2 ae 79 8d a4 88 b9 d8 83 ed 9e 36 19 4c e3 77 e1 2a 2f 65 a0 88 6b 81 45 7d 78 ef 62 81 38 b6 ea 1a 79 db 5e 88 e0 a9 92 7d ca 8b 4c 6f 13 b0 b0 4c a2 1d 76 32 59 7f 4d c5 f7 d1 4d 11 3f 2c 18 02 92 1d 34 20 93 8d 3e 07 ac b2 78 11 de ad e1 55 2f 2c 76 19 ae bb 0f f0 02 cf b9 cb 6a 6a 40 b8 f3 c0 c7 32 ed 08 99 4b 02 cf 4c 84 ef 72 b0 02 2c 2c 7e 88 ae 36 83 88 9e ae 28 d2 c5 77 33 4d 9a 65 9d 20 ed a6 cb 4b b8 b2 b8 cb cb b6 18 cf a2 2c ea 89 96 d5 c4 69 9e b2 68 61 9c 77 f2 c0 a2 e4 ec 19 6e a6 3e 7d 9e e8 5d 84 ef d8 79 02 79 13 30 4e 33 36 cb 4b 94 d1 4c 11 37 77 bc c0 92 2c 76 8a 33 bb'
msg = enc_msg.replace(' ','').decode('hex')
found_key = [-1] * 16

# 12 -> 4 -> 12 -> 14 [-> 15]
found = break_key_seq_1(msg, 12, ' ',lambda p: p[0] != p[2])
print 'First key seqs:', found, 'for pos:', str((12, 4, 12, 14))
assert len(found) == 1
found = found[0]
found_key[12] = found[0]
found_key[4] = found[1]
found_key[14] = found[3]

# 6 -> 14 -> 10 -> 3 [-> 13]
found = break_key_seq_1(msg, 6, ' ',lambda p: p[1] != found_key[14])
print 'Second key seqs:', found, 'for pos:', str((6, 14, 10, 3))
assert len(found) == 1
found = found[0]
found_key[6] = found[0]
found_key[10] = found[2]
found_key[3] = found[3]

# 3 -> 10 -> 11 -> 15 [-> 11]
found = break_key_seq_2(msg, 3, lambda i,j,c: i if c == 0 else (j if c == 1 else (found_key[10] if c == 2 else found_key[3])))
print 'Third key seqs:', found, 'for pos:', str((15, 11))
assert len(found) == 1
found = found[0]
found_key[15] = found[0]
found_key[11] = found[1]

# 1 -> 11 -> 6 -> 5 [-> 7]
found = break_key_seq_2(msg, 1, lambda i,j,c: i if c == 0 else (j if c == 3 else (found_key[11] if c == 2 else found_key[6])))
print 'Fourth key seqs:', found, 'for pos:', str((5, 1))
assert len(found) == 1
found = found[0]
found_key[5] = found[0]
found_key[1] = found[1]


# 11 -> 5 -> 2 -> 13 [-> 12]
found = break_key_seq_2(msg, 11, lambda i,j,c: i if c == 0 else (j if c == 1 else (found_key[5] if c == 2 else found_key[11])))
print 'Fifth key seqs:', found, 'for pos:', str((13, 2))
assert len(found) == 1
found = found[0]
found_key[13] = found[0]
found_key[2] = found[1]

# 8 -> 7 -> 4 -> 8 [-> 9]
found = break_key_seq_2(msg, 8, lambda i,j,c: i if c in [0,3] else (j if c == 2 else found_key[4]))
print 'Sixth key seqs:', found, 'for pos:', str((8, 7))
assert len(found) == 1
found = found[0]
found_key[8] = found[0]
found_key[7] = found[1]

# 9 -> 0 -> 8 -> 11 [-> 14]
found = break_key_seq_2(msg, 9, lambda i,j,c: i if c == 3 else (j if c == 2 else (found_key[8] if c == 1 else found_key[11])))
print 'Last key seqs:', found, 'for pos:', str((9, 0))
assert len(found) == 1
found = found[0]
found_key[9] = found[0]
found_key[0] = found[1]

# print the key and plain :)
print found_key
found_key = ''.join([chr(c) for c in found_key])
print repr(found_key)
print ps(msg, found_key, True, True)