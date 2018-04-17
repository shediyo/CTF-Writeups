from ps_enc import ps, ps_multi, prep_psp
prep_psp()
from ps_enc import PBOX_TABLE, SBOX_TABLE
from psp_utils import break_and_update_key

enc_msg = 'b3 79 59 73 99 8c f9 b3 9d 8d 26 0e 33 2e 08 6d 8c 35 f8 e7 01 16 0f fd d9 62 9c 31 d9 0f 9b 53 b3 79 59 73 99 d7 f9 b3 0c 8d 5b 0e 33 80 08 9a b3 b9 e5 1a 99 1c f9 35 9d 8d 4a 0e b9 14 08 d0 1d 35 f6 e7 57 e0 d7 89 29 93 b8 3c 00 01 b8 b5 dc 3b 59 d5 91 16 66 19 44 2f 26 70 33 2e 08 dd 8a d6 f3 36 6e 84 ee 09 c1 ec 49 8b cd 47 9b 5f 3c 35 f8 f6 6a af b1 46 5b 7e bb 59 e7 df 1d bf 51 23 56 09 4d 71 0b 41 2d 44 80 59 14 b3 87 ea 86 35 56 15 08 0e 0b 41 5c e0 09 7a 14 b3 e9 de 5d 35 1c 87 4d 9e 09 1f 53 63 9c bb 5c 38 7b 96 36 35 f8 c9 6a 84 95 d3 5c 6d 2b 59 4c 96 6d 63 da 78 f3 e7 f6 ac b1 75 e3 44 b4 59 d9 1c 06 19 cd 7c 1c 6f 08 16 fc 23 2d 55 9c ec 4d 38 2a 3e ae 2d d0 f6 08 5d 2d fd 7c c4 ee 8b d9 f7 06 bf f4 7c e5 e7 60 7b fc 41 82 05 de b9 b9 23 26 63 df 35 9d d5 4c d2 a3 77 e3 38 81 59 34 f2 26 dd 8a 7c 3e 7b f6 d2 fc 19 e3 1b ee 5b d9 1e 06 7a df 2d 1c 8a 08 5d 09 0d 7c 55 1a ec d9 02 26 19 74 7c d0 6f d0 16 fc 3e e0 ec 9c 4e b3 38 06 82 4c 95 e5 8a 8d c1 f1 16 7e ec f3 bc b9 a6 77 a7 22 78 d0 94 c3 d2 1e e1 5c 44 83 59 d9 38 77 2a df 35 4c 40 f6 0d b1 46 5c 44 2e c9 d9 df ba a7 4c 9e 87 36 08 0d 1d e9 5c c4 32 c8 e7 1b e9 ec 74 c4 5b 40 c3 c1 fc 7d 0f ec 9c a8 e7 f7 44 6d df 3f d0 e7 6e ac 09 d3 d9 5c de 5b 83 1b 1d 19 8a 35 84 09 49 9e 14 23 5c ec 81 4f e9 86 d4 96 f4 f9 f8 8a 4d 16 fc 7f e0 6d 9c 4f 33 4e 7b 4c 94 35 e3 7b d0 0e ed 09 5c a8 2b b9 bb 96 9b 2a df 35 84 80 6e 0e b1 46 53 44 e9 5b 4d b3 e9 a7 7c 52 84 1a 08 39 ed 8c 0c ec 2e 32 0d 80 87 5d f4 66 a2 87 6a 16 1d 77 82 44 6c e9 fb fc 9b dd ae 23 87 36 08 84 fc 77 53 e0 c4 7a 92 86 26 bf b3 79 97 73 91 d7 f9 b3 e3 8d de 70 3d 1e 1b 6d dc 79 e3 73 08 d7 f9 b3 d9 2f 83 68 46 0b 69 9a 0f b4 e5 fa 60 e7 cd 09 44 98 4a e9 b9 14 b0 6d 0f 0f d0 c9 28 0d ed fd d9 e0 9c c8 7e 2e 6d 6b 0f 35 97 7b 93 0e 58 e1 66 e0 9c 9e 33 27 1b ba 6e e3 1c 36 49 1e 0b fd 1c 7e 49 59 5c b3 d4 2a 51 5d e3 40 8d 71 b8 fd 53 7e 9c 59 bb f7 9b 19 f4 c0 f8 8a 6e c1 1d 27 5c ec 81 ff 83 86 9a ea 35 f9 f8 f6 c1 1b 1d 19 5c ec 6f 8b 34 b3 44 bf d7 2d e5 f6 7b 5d 2d fd 82 63 de 4e b9 23 26 bf df 35 db 80 6a 0e 08 a8 82 ff de e9 d9 23 6d 2a 01 c0 1c e7 c1 77 a3 27 a0 ec 9c 5b 92 33 37 bf 0f 57 87 e7 08 16 b8 77 9b a8 3a a8 92 12 e9 0d 00 ae 87 77 6e ac b1 46 4e 6d 9c d6 e9 4e 61 ba 35 2d e3 e7 08 0d fc a8 e3 97 00 ec bb c9 87 84 da 35 84 87 60 9e 0b ef 7c bd de ec d9 1b 7b 96 f4 35 e3 42 60 1e 95 d3 5c 89 2b 59 6d c9 06 bf ae 23 44 12 08 16 fc 16 82 0d de 61 cc 23 9b 2a 35 95 1c f6 8d e2 a1 e8 7c 05 5c 8b 6d c9 61 3e df c4 d0 e7 c3 1e 09 41 82 5c 81 d6 d9 f7 77 5f 8a 9e cc c9 c3 16 fc c8 7a 1b 9c 8b b3 02 1d 7c 6e f3 f8 f6 6e 16 0b fd e3 44 c4 59 92 12 26 19 df f9 d0 f6 6e 2a a3 7f c0 ac de 5b 83 d0 9b bf ae 23 1c c9 08 0d a1 e8 2d 0d ee 4e d9 1e 9a 19 ae cc d0 09 08 77 b1 41 70 0d 80 15 d9 ad 06 2a 4c f9 f8 a9 13 c1 08 7f 82 e0 97 e9 50 86 6d c0 3f 35 13 42 b2 d2 0b 41 5c 0d 83 59 46 e5 98 bf df c4 3e e7 c3 28 09 41 c1 5c 40 c8 d2 f7 69 84 7c c4 13 8a 91 16 c6 41 2d 98 83 70 6d 02 26 ec 0f ae 56 77 08 e0 2d 34 e0 98 4b 7a 14 b3 e9 b5 96 e3 87 e7 28 d7 95 d3 44 44 3e 59 e9 b3 ba 6d 36 35 3e 98 28 9e 95 d3 d9 7e 5c 59 d2 94 06 7a df e3 f8 40 4d 71 1e 41 7c 89 80 4f 14 b3 7b 19 4c 2d 1c e7 c3 0d fc a8 5c e0 de e9 e9 ad 2a 84 94 3f 55 94 08 1e 1e 7f 7c c4 ee f0 34 b3 c5 bf 4d 4b 3e fa c3 e7 f1 e1 2d ec 97 a8 14 b3 d4 2a 36 35 f8 55 b2 5d b1 45 53 7e de b9 34 02 87 19 df 3f 84 e7 b2 af 09 d3 7c 5c 9c c9 29 1e 98 5f 8a c0 3e b1 f6 16 a3 27 c1 ec 9c 5b d2 96 06 bf ed e3 3e 8a 8d 9c 08 fd 63 6d 80 59 34 d0 9b 5f 36 ae f8 77 c3 0d 95 d3 e0 7e 49 59 1c 4e 77 84 df d6 d0 f6 c3 e2 1d fd c1 44 40 d6 d9 df 77 bf df 95 84 8a c1 c1 1e 16 7e c4 9c c8 e9 1e 4f a7 b1 3b 97 36 91 c1 7a 41 7e 44 c4 70 3d df 1b d2 51 f3 d0 12 c3 0e b8 27 5c 6d 80 59 d9 24 77 3e df c4 f8 c9 4d c4 09 45 c7 54 83 4f 73 b3 7b bf f4 5d f8 40 4d 0d b1 fd e0 89 f2 ec 0d 86 36 84 df 7c 5b 09 07 d2 2d 0d 5c b1 9c b9 83 86 2a bf d7 78 9d c9 8d 77 fc 7f 53 c4 b3 a8 6b f7 7b dd ae 7c 44 6f 08 4f fc 23 ad 5c c4 3a 92 12 9b 63 d7 23 1c e1 49 d2 fc 19 7c 89 3a 59 14 b3 d4 bf 86 7c 87 e7 08 0d fc 46 82 de 9c 9e 0d df 7b 84 01 f9 84 e7 c1 0d 1c a8 7c ec f3 5b 34 b3 69 84 4c c4 a2 8a 28 4f f9 fd 7e ec b3 15 6b 1b 6d ba 4c 95 d0 8a 60 16 ee 7f 1c ec 49 9e 34 b3 9b 6b 94 c4 5b ef 08 37 1d fd e0 c4 9c 11 4c 4e 51 19 df 35 b7 e7 c3 88 ee 34 5c 0d 83 af d9 38 ba ba 4c d6 d0 c9 6e 84 0b 16 e3 ec 00 c9 d9 c9 77 19 7c cc d0 12 7b 16 08 19 0c ec 2b d8 cd 80 6d 2a df 06 55 8a 78 16 13 7f 53 41 4b 4f d9 f7 06 a7 36 35 f3 15 f6 9e 09 41 7a 44 de 59 d9 02 06 63 ae f3 f8 12 08 d2 7a a8 5c ec f3 e9 0d 86 e6 dd df 35 d0 80 c3 0e 09 41 82 63 1a 5b d9 d9 77 fe df 35 3e d5 4c 9c 09 09 0c 91 5c 59 d2 80 69 ee da 5d 84 40 60 31 0b fd 82 bd de ec d9 23 7b ba 94 95 cc 6c b3 16 14 7f 5c ec 32 b9 b3 ad 9b a7 df 35 b7 d5 08 0d 2d 32 e3 54 80 ec d2 b3 ba 19 f4 78 5b e7 6f 0d fc 7f 5b 55 9c ec 73 1b e9 84 ae 78 e3 e7 08 1e ee 83 7c ec 4a e9 34 14 69 5f 01 7c f8 09 8d 16 fc 0d 7a 6d f2 5b 6d b3 e9 ee ae 23 55 12 78 1e f9 fd e3 ec 81 26 d9 47 06 bf d7 35 5b df 6f 5d fc 7f 66 63 bb 32 29 df 9b 5f 4c f9 87 e7 6a 0e ed 77 70 a8 80 59 4d f7 51 a7 df 3b 05 36 6e d2 a3 a8 5c 98 b3 c8 6b 86 06 ea f4 9e 17 e7 60 71 c6 a8 0c ec b3 4f 6b 80 9a 5f 00 35 87 c9 b1 84 b8 77 5c 44 83 ec cc 1b 9b ec 6e f3 f3 e7 08 1b b7 a8 a0 44 40 f2 d2 b3 f9 ec b8 35 1c 40 8d 2a f1 e9 1c 6d 9c af 11 a6 26 2a 35 2d 5a fa b1 e7 fc a8 e3 6d 2b c8 d9 b3 51 a7 8a b2 e8 8a 8d 16 13 a8 53 ec ee 5b 14 86 9b 2a 01 2d 87 e7 c3 0d fc a8 e3 6d 80 c8 4d b3 9b 84 df 3b 55 c9 4c 0e 58 09 7c b4 ee 59 34 b3 c5 5f 35 e3 56 e7 6a af fc 7f e0 54 4b 4f 14 b3 e9 6b f4 b9 84 80 08 0e 13 35 c1 89 2b 7a 5c b3 56 fe 86 57 5a e7 6a 16 95 77 5c b1 49 c9 d9 86 06 cb 4c f3 cc d5 08 c4 1e e9 53 ff c4 a8 d9 f7 ba bf 4c cc d0 09 d0 b4 2d e1 82 ec de 4f d9 23 77 ee 86 2d db f6 08 5d 95 fd 5c 97 2b 6b 0d 6b 26 fe 6e ae 56 77 b1 43 13 34 5c 7e 81 59 14 86 d4 84 d7 7c 87 e7 28 af 1d a8 7c ec c2 b9 e9 e5 9b 6b 86 7c d0 40 60 2a fc 98 a0 c4 9c 9e d2 38 9b 2a 6e f9 e8 8a 60 af 7a 7f 5c ec 83 15 d9 1b 6d 96 94 d6 84 f6 b1 e2 2d fd 1c c4 4b 59 d9 a6 d4 63 4c b9 f8 c9 4d 9e ed 35 5c 97 32 32 6d 43 58 bf 6e f3 3e 8a 08 5d fc 77 c1 6d 80 e9 46 f7 d4 de d7 23 55 09 08 9e 27 19 ed ec 65 ec d2 b3 c5 3e 0f cc 5b c9 08 e2 fc e9 02 a8 9c 15 a2 b3 51 63 f4 7c db 15 60 16 2d fd e0 6d 2b 9e 0d b3 9b 2a 6e b9 1c 98 08 77 0b 35 53 7e bb e9 d9 f7 d4 3e df f3 59 e7 8d 77 58 a8 e0 c4 81 c9 d9 f7 9b a7 d7 5d d0 d5 6a 16 b7 a8 5c 63 81 59 d2 10 06 2a df 4d 1c e7 6a 7b b1 77 53 89 9c e9 73 f7 e9 63 0f 78 36 f6 8d 16 b1 fd 7c 7e 49 db d9 1b 9b dd dc 95 f8 f6 4d 2a 0b 77 2d 2f 97 4f 4d 38 7b 7c ae 35 f8 f9 6e af b6 fd 5c a8 c4 59 11 86 26 2a f4 95 cc c9 08 0e 73 77 7c 89 9c af cd 02 ba ba ae 3b 0f 94 8d 31 fc 32 7c a8 1a a8 d9 1b 77 bf ed c0 f8 f6 28 5d b7 fd 70 89 64 59 34 df 1d 19 5d 23 d0 36 c3 60 1d 41 5c 44 97 bb 4c 1b 77 a7 cd 78 5b 80 60 0e 2d fd 02 0d 9c 32 95 b3 d4 a7 cd 35 db 80 08 d2 09 d3 5c ff 4b ff 83 c9 ba bf 4c 35 f8 45 c3 2f 1d 19 c7 44 80 5b b3 f7 31 74 0f c4 db 40 4d 9c fc 32 5c ff de 59 d2 23 7b 84 6e 3f e3 e7 91 71 fd d3 5c 6d 83 70 bb ad 7b 5f 8a 5d f8 ef 4d 31 08 b3 5c 89 f2 ec b3 23 26 3d 6e ec d0 3a 08 d2 fc 83 7e 6d 3a e9 d9 1e 06 63 df 35 b7 09 6e 0e a3 77 5c ff de 5b 83 4e 9b de ae c4 1c 8a c3 16 fc 41 53 54 9c 59 b3 38 69 a7 41 3f e3 e7 91 e2 fd d3 66 6d de 70 34 02 94 a7 4c cc 87 12 49 d2 b1 fd 7c 6d 80 a8 4d b3 9b 63 d7 c4 87 8a c3 16 fc 41 c7 63 9c ec 29 e5 d4 7c 4c cc d0 09 08 77 2d e1 7c 25 00 a8 d9 c9 06 2a df 35 9d 42 6e 1e 09 1f 7c 63 26 af d9 b3 7b bf ae 81 05 ef 37 e2 b7 fd 7a 0d f2 4e 6d 1b 5c 3e df e3 9d e7 6e 0d 2d 83 82 10 de 7a cd a6 9b 5f cd 2d 9d e7 08 0d fc a8 5c 6d bb b9 d2 1b 77 84 0f c4 5a f6 b2 31 0b fd 7c e0 ef 8b d9 b3 1d 7c 6e cc 56 36 08 60 fc 46 7e 6d 3a e9 d9 1e 4f ea 86 e3 97 e7 60 af fc 7f 5c c4 2a 9e 14 b3 1b 6b 94 f3 9d e7 b3 ac 7a 7f a0 ec 9c b9 d2 38 9b 19 0f 35 87 7b 93 0e 58 e1 66 e0 32 9e b3 86 9b ba 94 7c e3 e7 c1 5d fc 41 1c 6d 97 5b 14 b3 7b 19 df 3b 3e 94 60 16 b1 41 c7 0d c4 4f 34 f7 6d ee ae cc 5b 97 37 31 07 19 e3 ec 9c c9 11 47 5c ba 52 35 2f ef 07 ac 14 77 5c ec 81 8b 14 ad 6d ba d7 35 f8 80 c3 0e b7 77 7c 89 80 c9 14 b3 e9 fe 0f cc f8 ef 6e c1 fc d3 a0 ff f3 59 73 f7 7b 2a dc 79 67 73 91 d7 f9 b3 5c 2f 70 70 2a 5e 94 9a df 79 5b 73 28 d7 a1 e8 44 c3 4a c8 d1 14 51 9a ed 35 e5 87 37 9e 2d e9 44 ff 26 31 b9 2e 5c 96 cd 2d 9d e7 08 0d fc a8 5c 6d bb b9 d2 1b 77 84 df 3f 1c ef ad 5d 09 d3 7c 6e 49 c9 4d b3 4f a7 df 3f 84 e7 6e 5d 09 d3 45 5c e9 5b 4d b3 e9 19 d7 c0 f8 ef 6e 0e 2d fd 82 63 81 59 6d 47 7b 3e cd cc b7 d5 37 e2 fc e9 5c 55 de ec 83 4e 5c fe 01 5d 9d 40 13 0d 1d fd 7c 63 5c 32 bb b3 9b 84 6e 3b 44 d5 08 c4 0b fd 5c 7e 83 7d 46 e5 9b bf 86 f3 f3 f0 6e 16 09 a8 7e a8 9c af cc 1e 9b 2a 8a 3b 5b 36 60 e2 1c 0d 53 7e 9c 59 cc f7 26 ba df 78 5b 80 28 d2 1c fd 82 89 4a c8 e9 14 51 bf dc 78 87 ef 91 9c 8a 41 82 2f 81 70 34 23 94 3d 9d 4b 97 ef 99 5d f1 e1 a0 ff b3 59 6b 36 1b 7c b3 66 84 ef 54 0e 68 fc 5c 77 80 59 cd 24 61 3e 6e 95 d0 87 08 0d fc 09 45 6d 40 e9 bb b3 77 84 df 3f 0e ef 78 c1 0b fd 7c 44 9c 4f d9 6d 6d 2a dc 81 87 09 91 d2 f9 fd 5c 2f f2 70 cc 38 94 19 b3 23 db 98 6a d2 68 51 e0 77 63 59 d2 b3 98 bf d7 4d 84 e7 60 ac 13 77 2d 7e 9c 59 0d 1b 26 96 ae f3 9d e7 08 77 13 a8 82 de f3 15 34 b3 26 3e 0f 35 3e 15 c1 77 95 23 61 97 bb 5b d2 b3 87 a7 b3 23 97 09 91 9e 27 19 82 ec 81 70 3d f7 1b 3e df ea 3e f6 60 0d a1 e8 4e 8d 9c 9e b1 1b 6d bf 6e 3b 44 d5 08 16 0b fd c7 7e 83 7d 11 df 9b 6b f4 95 9d c9 99 0e 73 77 5c 89 32 af d2 68 1d ba df 78 d0 e7 7b 0d a3 7f 7c ff 2b d8 cd b3 6d 84 0f 3b 3e 09 b3 d2 fc 0d 7c a8 2e d6 34 b3 e9 a7 52 b1 84 15 d0 16 a1 e8 5c ce 49 ec d9 86 9b ee 0f 78 87 e7 08 ac b8 19 e3 0d 9c 15 92 47 7b ee d5 78 f8 ef 6e 60 95 fd 5c 97 80 ff 1c 12 56 19 df 23 1c 55 f6 d2 f1 1f 5c 55 de c9 e9 1b 06 bf df f9 f8 d5 4d d2 58 83 e3 98 de 4f e9 a0 7b bf 0f e3 87 8a c3 9c a1 e8 e3 97 9c a8 b3 d0 37 5f 4c f9 f8 d5 d7 0d 08 a8 e0 ec 49 9e 3d 4e 9b bf d7 ec f8 ef 6a e2 2d fd 5b 63 81 59 cd 86 1d a7 3c 35 56 1a 60 84 fc b3 7c 6d 4b ec 14 b3 9b 6b df 23 e8 36 b2 60 1d 41 c1 44 c4 8b d9 df 1d bf dc d6 f8 c9 c1 84 0b 16 5a 2f 80 c9 4d 12 77 19 df 78 87 80 c3 d2 b1 a8 5c 44 81 5b d9 df 37 63 6e 35 d0 87 08 9e 95 77 5c 7e 81 6b d2 92 77 96 4c 23 ab 12 6e 71 28 fd 4e a8 de 2d d9 02 e9 bf d7 35 e8 ef 28 ac 14 77 ed ec 32 67 d9 df 06 ba d7 35 97 f6 8d 5d 7a 37 7c 44 80 e9 14 b3 1b bf ae cc e3 94 08 af b7 09 61 0d 2e 4e 34 f7 69 ea 86 35 9f 1a 7b 84 0b bb 0c 98 b3 e9 6b 80 6d 6b df 27 e8 ef b2 ac b7 a8 c1 6e c4 8b d9 df 1d ba d7 f9 84 f6 60 e2 2d fd ed 63 49 59 cd b3 e9 3e d7 3b ab d5 6f 16 fc 19 61 63 83 32 73 b3 9b cb 8a 35 06 36 8d 9e 58 0d c1 ec 80 5b 4d 86 9b 96 df 78 e5 e7 6e 9e 1e 09 c1 ae de e9 b9 1b d4 3e b3 f3 56 e7 08 5d fc 27 7c a6 9c a4 29 33 7b 6b 4c 7c 9d 12 7b f1 0b 27 5b c4 ee 15 d9 12 51 bf df cc 5b d5 b2 16 f1 37 5c ff 80 4e d9 8a d4 6b ae c4 5a 8a c3 c1 fc 41 5c 54 83 59 46 c9 98 19 35 9e e5 e7 c1 c1 c6 a8 5c ec 83 8b b9 38 c5 5f 4c 35 f8 98 8d 9e 1d a8 5c ec 83 bc 46 e5 77 7a df 35 5f d5 c3 d2 58 83 7c 05 9c 5b d9 6d 77 19 b8 cc 3e e7 28 77 1e 09 5c 44 5c 59 d2 94 06 3e cd f9 05 ef c3 16 f1 83 61 ec 2b 4f d9 b3 e9 b3 ae 35 97 80 8d 0e b1 46 7a 0d f3 a8 11 12 1b fe 0f d6 3a e7 b1 5d 2d d3 45 ff f2 32 cc b3 ba 96 4c 7c a2 94 60 31 fc e9 e0 a8 2b 9e 6d b3 9b bf 6e 35 3e e7 6a de 13 34 82 7e 40 59 d2 df 69 5f 86 7c 5b e7 b2 5d fc 41 7a c4 9c 59 92 02 6d 5f df 57 5a e7 6a 16 09 1f 1c 63 b3 e9 6b a6 6d 4b 6e f3 1c 94 08 1e fc a8 53 6d 49 e9 d9 12 26 bf da 66 f3 6f f6 77 b1 fd 5a 44 4b 59 d9 86 06 63 7c cc 87 d5 8d c1 7a 16 2d 0d 80 59 34 1e 9b e3 df 2d 94 e7 b1 1e fc 27 7a 8d 9c 4f 34 a6 6d 5f d7 c4 5b 8a b2 16 fc 41 7a 89 4a 59 e9 14 98 a7 0f 23 5b 09 08 71 cd 32 7e 98 de 26 d9 4e e9 a7 52 d6 87 e7 d0 c1 13 7f 45 ec 80 ec 4d b3 9b 2a 52 35 cc e7 60 19 1e 34 7e 89 f3 59 d9 a6 1d e3 df 4d 87 e7 7b 84 f1 23 82 e0 81 9e d9 f7 6d ec df 35 1c c9 08 0e 2d 32 82 54 4a ec 4d 14 2a fe 6e f9 e3 f6 08 31 b1 fd 7c 6d 9c e9 d2 1b 69 ba cd 35 1c 80 08 d2 09 d3 5c ff 3a ff d2 86 d4 bf ae f3 9d 55 6a 16 1d 27 a0 89 83 9e e7 38 9b 2a ae 35 84 ac 08 9e b6 fd 53 0d bb 4e d9 f7 7b 82 7c 3f 13 8a b2 16 1d 41 0c 6d 5c 59 34 80 98 b3 df 35 1c d5 60 9c 09 09 2d 63 00 b9 d9 c9 d4 ee da 23 84 12 60 71 0b fd 82 bd de ec d9 23 7b bf 7c 23 5b 94 7b 16 58 e1 82 7e de ec d9 23 61 e3 4c 27 05 ef 49 31 b1 fd 1c 6d f2 a8 6d e5 9b ba 94 7c 59 7b b3 16 cd e1 a0 ec 4a b9 d9 14 9b 82 ae 0f d0 15 08 0d fc fd 53 ce 80 c8 d9 86 06 19 df 78 5b 80 49 0e 1c fd c1 89 de 9e 6d b3 51 a7 df 3f 84 e7 6e 77 09 d3 45 5c e9 5b 4d b3 e9 de 6e 94 56 09 c3 77 0b fd 2d 7e c4 59 d9 12 26 2a df ec 5b ef 07 5d b7 77 53 6e 4a 4f b3 14 9b 19 35 0f f8 94 6e 0d fc fd 61 ce 80 8b 14 b3 e9 19 df 35 87 36 b3 9e 58 83 c1 05 2b 74 cd 1e 98 96 ae e9 9d 15 08 5d b7 fd 1c 0d 9c 4e 46 4e ba 19 df 3b 84 12 c1 b4 1e e9 7c 55 9c 15 cc 38 87 6d 00 cc 9d 36 60 77 fc c8 d9 6d 5c 32 bb 38 9b 96 cd 78 d0 40 08 9e 13 7f a0 7e 9c ec bb f7 26 3e ae 78 db e7 58 1e 2d 16 5c ff f2 a8 0d 1c 9b 5f df 95 28 ef 6a 5d 2d fd 7a b1 26 e9 d9 b3 51 19 d7 cc e3 c9 60 e0 fc 45 c0 89 f3 59 d9 47 06 b5 86 78 cc 80 08 d2 a3 fd 66 ff 32 6b 92 86 7b bf 4c 78 cc e7 6f d2 fc 27 be a8 2b 9e cd 02 9b 3e 6e d6 e5 f6 37 e2 b1 fd 61 6d 46 79 b9 1b 5c 68 86 7c 5b 7b 08 2a fc 46 0f de 9c 9e 92 f7 7b bf df 35 e3 ef c3 b4 bb 20 82 75 9c a8 46 df 69 6b 35 b2 cc 8a ad 16 13 a8 7e ec 1a 8b d9 1e ba 2a b8 4b 87 8a f6 9c b7 fd e3 6d 80 af 4d b3 9b 3d 94 35 97 80 b3 77 95 d3 5c 2b c4 b9 11 86 1b 7a da 35 f8 d5 f6 c3 95 23 7c bd 80 32 14 b3 f5 6b 4c 3b e3 94 60 31 fc 98 a0 e0 9c 9e d2 23 06 6b b3 79 97 fa 99 e7 f9 b3 c1 8d b3 0e 6b 6d 1b b0 b3 79 f8 73 91 d7 f9 b3 e3 8d c4 70 11 47 0f 6d cd 3f cc 94 d0 16 08 27 d9 ec 4a b9 95 14 6d 63 df 35 e3 a9 60 d2 a3 77 7c ff 32 b9 e9 38 9b dd 0f f9 84 e7 28 1e 1d 77 ad 54 2b 59 92 b3 1d 5f 52 cc 9d e7 d0 c1 1d 19 7a ec ee b9 34 b3 7b 19 35 79 f8 fa c1 e7 b7 fd 66 44 c4 8b 11 df 4f e3 4c cc db 09 08 77 2d e1 c1 25 49 a8 4d f7 56 2a ae cc 5b b1 08 e0 b7 09 7c 0d 1a 15 d9 4e 9a b5 7c ae d0 77 7b d7 a1 e8 0c 65 42 d8 cd 80 6d bf 35 79 e3 fa 23 e7 0b fd e5 97 de ec 34 02 9b 35 0f 4d 5b e7 08 ac 95 09 2d 97 de 26 d9 96 98 96 4c cc 87 12 ad 16 2d 2c 82 ec 80 a8 4d b3 56 e3 36 62 3e f6 28 e2 fc fd 2d ce 80 b9 34 1b 9b bf 4c cc d0 98 6a 16 1d 19 5a ec c4 4f 53 df 9b 2a 74 b9 ab 73 c3 16 68 35 e3 77 9c 5b 14 df 7b 35 0f 79 87 fa d9 e7 a3 fd 66 c4 80 d6 4d e5 9b 4b df 35 f8 e1 d0 77 08 a8 53 ff 81 4f 34 f7 6d 63 ed 3b 87 d5 08 16 1d 19 7e ec 80 b9 bb f7 26 6b b1 2d b7 40 08 5d 2d fd 82 63 2b 59 83 38 94 a7 00 cc f8 09 08 16 95 d3 82 44 f2 c9 b3 b3 6d 6b 4c b9 b7 1a 6f 84 2d 35 82 e0 2b 9e 83 38 9b 6b 7c 35 3a ef 56 16 1d a8 c1 ec c4 4f d9 df 06 dd df 35 3e a9 6e d2 a3 77 e3 ff c4 7a 34 02 9b dd 0f e3 a2 e7 6a 84 a3 77 ad c4 2b d6 6d b3 9b ec df 7c f3 e7 4d 0d b1 41 a0 7e 49 4f 83 b3 7b 84 dc cc 5b e7 d0 c1 66 19 7c 2f 2e 20 0d b3 06 19 0f 95 f8 80 6a 16 13 83 66 ec c4 59 11 df 1d ba 0f 2d 3e 09 07 9e 1d fd 2d c4 3a 8b 34 02 9b fe d7 7c f8 15 c3 16 b7 fd 5c 6d 5c 5b 34 38 61 2a df 78 87 80 54 16 25 a8 53 ec 9c 20 11 f7 61 6b cd 23 05 d5 6e d2 f9 c8 c1 55 b3 ff 6b f7 e9 7c df 23 a2 36 8d 60 1d 41 45 44 81 8b d2 b3 1d a7 d7 b4 e5 e7 8d 43 7a 09 02 7e 4a 15 b9 14 b1 84 df c0 5b 6f 28 9c 0b fd 7e 7e 9c c8 e9 1b 51 84 00 3b 9d 12 b1 b4 b1 46 5c 44 de 4f b3 a6 9b bf df b2 f8 40 4d 9e b7 77 82 6e 2b 4f 6d 23 7b 96 0f 35 a2 7b 93 0e 58 e1 a0 e0 2b 9e 6d b3 9b ba 4c 78 87 f6 60 16 09 e1 1c ec 4a 8b b3 14 7b 6b 0f 35 a2 09 7b 9e 95 77 5c b1 81 e9 34 ad 1d 96 4c 35 44 98 08 9e 95 d3 82 2b c4 e0 34 12 9b 7a ae f9 f8 e7 08 77 b1 77 7c e0 80 15 14 b3 6d 3e 00 ae f8 77 08 c1 95 d3 61 44 ee c9 14 b3 6d dd 0f 35 f8 e7 60 80 cd 34 ed 98 5c e9 34 38 6d 5f df e3 5b c9 8d 16 2d 7f 0f 97 9c e9 cd f7 9b 84 8a 35 d0 ef c3 1b 7a 37 2d 6d 2e 59 d9 a6 77 6b 4c ec a2 e7 6e 1b fc 83 ed a8 2b af 6d b3 9b ec 86 ae cc 77 08 9e a3 41 82 25 9c 9d cd 23 ba e3 ae 9e e3 94 f1 31 2d 0d 5c 6e 2b 9e 5c 18 9b ee 51 c4 13 c9 c3 16 1e 45 5c 89 83 59 46 e5 37 2a df f9 1c ef 6a 71 ee 45 53 0d 9c e9 73 f7 e9 19 36 35 1c ef 4d 31 95 d3 45 7e 40 59 4d b3 61 ba ae ae 5b 77 08 77 ed a8 e3 ec 9c e9 4c 1c 51 bf f4 78 a2 c9 13 77 fc 7f c1 6d 16 32 bb 86 08 dd f4 5d f8 40 4d 31 b1 fd ad 89 46 ec d9 d9 36 ba df f9 d0 e7 c1 9b fc a8 5c c3 83 c9 d9 4e 77 bf ed 35 9d 98 07 9e b7 77 82 89 bb 4f 34 12 9b 7a 6e 95 d0 8a 08 2a a1 e8 7e 6d 3a e9 d9 1e 06 2a 4c 95 ab 6c 60 16 ed 77 7c ec 9c 9e 14 02 9b 6b df 35 9d 94 28 77 09 09 e0 63 9c db 46 4e 1d 63 6e 78 9d c9 b3 77 fc 7f c7 6d 81 e9 d9 f7 61 dd 6e 35 29 c9 f6 9e b2 77 ad 44 9c 59 d9 6d 06 bf 94 b9 db c9 99 84 ee 35 61 de 32 11 29 df ba ec df 7c d0 6f 7b 16 fc 23 a0 8d 2b d8 cd b3 6d dd ae 7c d0 09 07 16 cd fd 2d 98 c4 8b 14 1e 9b 63 d7 94 2f 80 08 d2 fc fd e3 ce f3 32 d9 a6 56 3e cd cc 9d a9 13 c4 0b 19 5c 7e 80 32 53 12 9b bf dc d6 5b c9 ad 84 0b 16 ff 2f 2b c9 e9 23 d4 19 df 95 db 6c 07 16 1d 83 5c c4 f2 4f 0d 1c 9b ec da f3 87 a9 b1 16 fc 7f e0 bd 80 4f 4d b3 9b 84 4c 3f db 12 08 d2 b2 83 7c ec 40 26 bb b3 98 63 52 35 f8 ef 6e 0d 1e e9 2d 89 f3 59 34 6b 7b 2a ae 35 44 7b 37 77 fd 41 2d a8 00 5c b3 c9 5c a7 86 ae e3 77 08 e0 2d 34 82 de 9c e9 d2 f7 56 b5 86 95 5b f6 08 2a 95 fd ff 97 2b 6b e9 23 d4 2a 7c 78 f8 c9 4d d2 ee 7f 7e ec 32 32 34 1e 7b 63 86 3f 55 94 8d 1e b1 7f e0 89 9c c9 14 33 61 bf df 35 e8 55 28 5d a3 77 82 ff 81 db 14 23 1d 19 df b9 84 87 b2 9e 1d 35 7c 44 9c c9 29 1e 98 96 6e cc cc c9 28 e2 fc e9 02 6d 9c 59 b1 b3 ba 63 4c ec 5b 8a 60 5d 1e 98 e0 ec 9c 9e cd 1b 9b bf f4 f3 f8 8a 6e 5d b8 77 61 6d 97 59 50 f7 7b 6b 6e cc 9d e7 8d 0d 1d 19 82 ec 1a c9 d9 f7 2a 84 5d 23 84 94 b1 16 09 e1 7e 54 ee bb d9 02 d4 a0 d7 7c 3e 6f 6f 5d fc 23 7e 63 f3 32 d2 a6 9b bf 74 35 d0 f6 c3 2a 43 0d e5 ec 32 e9 6d 86 98 19 6e 3b 87 09 08 c1 fc 0d 5c 6d 2b e9 50 38 26 2a ae b2 d0 8a d0 5d fc 77 5c 54 de 59 cd a6 ba ee cd 3b a2 d5 37 16 1d 19 5c ec 83 32 e9 1c 5c a7 df e3 e3 e7 c3 0d 95 83 7c 6e 80 74 34 1e 61 84 df 78 55 8a 28 5d 2d 41 7c 97 49 c8 34 b3 06 bf df 4b 94 e7 d0 0e 58 e9 e3 5c 9c 4e 34 d0 ba 3e d7 f3 f8 c9 c3 d2 0b 77 5c ec 5c eb 34 38 d4 3e 86 f3 e5 e7 08 af ed 77 66 55 1a 9e b9 f7 6d ba 51 3b 1c d5 b2 9c fc 46 2d 6d 9c 59 5c f2 98 5f b1 4b a2 8a 08 9c 2d fd 0f 63 81 59 34 f7 94 3d 35 e3 db 8a 7b 16 f1 98 5c 97 f2 b9 0d 1c 9b 6b cd 3f cc 94 d0 16 08 27 e0 ec 9c b9 95 4e 6d 3e f4 b2 5b 8a 49 16 a3 7f e3 ec 4a 4f 0d 14 d4 6b df 35 9d 09 60 d2 1d 09 66 7e de b9 b3 c9 9b de 01 cc 84 09 c1 b4 2d e1 7c ec de 5b e9 1e 7b ee df 7c 87 12 b2 16 2d fd 02 b1 9c 8b cb b3 49 2a df 06 5b f0 c3 e0 2d 16 53 55 9c a8 0d f7 44 b5 df 23 87 94 c3 60 fc 32 5a 8d 2b c8 50 f7 d4 bf 00 4b 5b e7 4d 7b f1 e1 7a ec 9c 32 cd ad 9b 63 df f9 a7 c9 60 16 1d 7f 7c c4 49 b9 d9 1b 9b 6b 7c 3f 3e 8a e2 16 13 98 5c 7e 5c 59 14 1b 7b fe dc 94 84 80 c3 d2 a1 e8 7e 2f f2 20 92 1e 2a 3e 01 73 13 80 c3 77 1d fd 5c 89 83 59 46 e5 37 63 cd 35 87 a9 78 0e 95 23 e3 25 9c 32 b3 1e ba a7 df 06 cc e7 b1 0d f1 d3 5b 5c 80 74 83 86 ba 5f d7 7c f8 15 c3 16 b7 fd 5c 6d 5c 5b 34 38 61 2a 0f b9 cc ef 58 0d ed 35 53 a8 9c 59 b3 f7 1d 2a b8 35 f8 6f 6e 7b 7a 37 7c 7e 16 59 cd 96 7b bf 74 c4 3a ef 6a 5d fc e5 53 ec 49 d8 d9 12 6d 5f 35 3f 9d 8a 8d 16 1d 41 e0 7e 5c 59 d2 b3 9b e3 d7 c0 f8 f0 c3 16 a3 27 7e ec 5c 7a cd f2 98 7c 6e 2d d0 ef 08 9c a1 e8 7c 6d 16 e9 bb 1b ba 2a d5 f3 d0 94 4d 1e fc a8 5c c4 5c 4f d2 38 9b bf df 35 f8 80 4d d2 f1 e1 53 de f3 4f 73 86 7b bf 51 b9 f8 fa 6e e7 b6 35 7a 6d de 59 11 1b 7b 9a 67 4b 59 e7 91 78 1e e1 44 89 26 70 33 2e 08 6d dc f5 59 80 99 0e a1 e8 d9 2f 26 0e 33 2e 08 a7 7c 3f d0 8a c3 c1 13 98 5c 7e 49 59 d9 12 77 2a df f9 e3 f6 4c 2a a3 7f 5c ac 83 59 46 02 69 bf 35 66 5b e7 08 77 09 e1 7e 05 9c 7a 6d 1b 44 63 df ec f8 f0 4d 16 a3 27 e3 c4 c4 4f 11 47 7b ba 5d 35 9d 80 e2 d2 b1 46 7c 44 f3 bb 34 f2 26 bf df cc db d5 6a c1 7a 16 53 44 49 e9 d9 86 06 bf da cc 1c f0 08 16 1d 19 82 05 9c c9 4d df 26 fe df cc f8 12 28 d2 2d 45 2d e0 00 c8 1c 1b 6d 63 86 d6 87 b1 8d e0 09 41 2d 97 f2 26 5d 38 9b b5 7c ae d0 77 7b d7 a1 e8 0c 65 42 d8 cd 80 6d bf 35 79 e3 fa 23 e7 0b fd e5 97 de ec 34 02 9b 4b 6e f3 1c 97 08 c1 b7 a8 53 44 49 f2 d9 12 26 bf 0f 3b f8 12 60 16 cd fd e3 98 f3 e9 4c 1e 6d 2a f4 3b 1c f6 7b 2a f1 41 53 a8 49 ec d9 12 d4 ea f4 23 87 d5 08 16 28 fd 5c 6d f0 ec 4d b3 56 96 0f ae 06 77 9f 0d fc 7f a0 ff 2b 59 0d 47 9b ec b8 c4 87 40 7b c1 fc 41 70 ff 1a 4f d9 f7 d2 bf f4 3b f8 d5 4d 16 b1 fd 82 89 bb ec 34 12 36 ba 01 7c 84 6f c1 2a f1 e9 7c ec f2 5b cd a0 7b 7c b8 4b f8 e7 4d 0d f1 e1 5c ec 5c 32 34 38 26 84 00 ae db 77 6a 1b b2 77 7c 89 65 59 d2 b3 98 ec df d6 1c 97 4c 5d a3 77 82 38 9c 59 4d 23 2a 19 da 23 5b d5 78 0d fc 0d 5c 63 f3 ff b3 86 9b 19 da e3 97 d2 d7 16 09 16 c1 ff b3 ec 6b 6d 1b 59 df c0 84 e7 8d 28 b7 a8 e3 54 de 4e d9 a0 44 84 df 35 f8 09 28 d2 2d 41 2d 25 83 c8 6d 02 6d 6b d7 35 5b c9 d0 84 b7 e1 61 0d 9c 4f cd e5 9b 19 86 d6 db f6 08 e2 a3 fd 5c ff 2b 6b 0d 6b 26 63 74 c4 1c 8a b2 16 fc 7d 0c ec 49 c8 4d 80 ba b3 df 35 f8 98 d0 9e 58 32 2d a8 f3 4f b3 a6 6d 7a df 78 94 e7 d0 77 f1 09 7e 54 3a 4e d9 1e ba 3e 52 78 56 e7 78 ac b1 a8 61 ec 4b ec 14 b3 9b 19 dc f3 87 d5 60 0e 7a a8 5c 2f 65 b9 0d 86 9b a7 4c f3 db e7 08 77 1e e9 82 ff c4 a8 cd f7 56 ba ae c4 3e 8a c3 c3 fc 41 1c 54 80 59 4d b3 ba bf 4c f5 f8 80 c1 77 fc fd 2d ce 9c d6 d2 38 7b 2a da cc 73 e7 07 0d 1e 09 4e 44 9c 4f 9b 1b 9b 84 dc 23 5b 94 ad 31 b7 77 7c 2f 9c e9 11 e5 d4 ee df 23 3a 55 7b d2 f1 1f 5c 55 83 9e d9 4e 51 bf df 35 84 1a 6a 84 b1 46 2d 44 4b 74 5c 1e 56 6b 8f 35 cc 94 6a 0e b7 23 c1 6d c4 59 d9 df 6d 2a d7 35 cc 9f 8d 0e b6 fd 82 63 de 8b d9 a6 ba 2a 6e 9a f8 e7 c1 9e 68 8e 5c 77 f2 e9 cc 23 44 63 7c 4b 2f e7 b2 84 f1 e1 5c ec 83 8b d9 1b 6d 19 ae 2d 05 f6 08 5d b1 fd 4e 5c f3 c8 d9 a6 06 bf d7 e4 55 40 f6 c1 fc fd 82 ce de 5b d9 23 06 bf df 35 f8 1a 28 84 1d 09 70 7e 49 c8 50 86 6d 6b f4 35 9d 98 37 77 1d 19 c1 44 c4 79 53 df 5c de ae 7c 3e 6f 08 5d fc 23 7e 5c 9c 5b d2 c9 ba a7 f4 35 55 e7 28 16 95 34 5c 89 83 e9 d9 38 06 bf'
msg = enc_msg.replace(' ','').decode('hex')

found_keys = [0] * 8
for i in range(8):
	found_keys[i] = '\x00' * 16

# 15 -> 6 -> 15 -> 1 -> 9 -> 3 -> 7 -> 14 [-> 15]
found_keys = break_and_update_key(msg, [15, 6, 15, 1, 9, 3, 7, 14], found_keys, ' ', 1)

# 5 -> 8 -> 1 -> 2 -> 6 -> 13 -> 5 -> 4 [-> 14]
found_keys = break_and_update_key(msg, [5, 8, 1, 2, 6, 13, 5, 4], found_keys, ' ', 1)

# 3 -> 5 -> 2 -> 7 -> 0 -> 1 -> 4 -> 0 [-> 13]
found_keys = break_and_update_key(msg, [3, 5, 2, 7, 0, 1, 4, 0], found_keys, ' ', 1)

# 1 -> 3 -> 14 -> 0 -> 4 -> 4 -> 6 -> 3 [-> 12]
found_keys = break_and_update_key(msg, [1, 3, 14, 0, 4, 4, 6, 3], found_keys, ' ', 1)

'''
dec = ps_multi(msg, found_keys, True)
for i in range(len(dec) - 16 * 33, len(dec), 16):
	print repr(dec[i + 11: i + 16])
'''

# from here we have educated guesses based on the decrypted values

# 7 -> 15 -> 3 -> 14 -> 3 -> 2 -> 10 -> 2 [-> 11]
found_keys = break_and_update_key(msg, [7, 15, 3, 14, 3, 2, 10, 2], found_keys, ' ', 5, 'e', 13)

# 6 -> 1 -> 13 -> 10 -> 14 -> 12 -> 1 -> 11 [-> 10]
found_keys = break_and_update_key(msg, [6, 1, 13, 10, 14, 12, 1, 11], found_keys, ' ', 2, 'r', 13)

# 9 -> 4 -> 5 -> 4 -> 8 -> 0 -> 9 -> 7 [-> 9]
found_keys = break_and_update_key(msg, [9, 4, 5, 4, 8, 0, 9, 7], found_keys, ' ', 7, 'a', 11)

# 0 -> 7 -> 12 -> 8 -> 5 -> 11 -> 14 -> 13 [-> 8]
found_keys = break_and_update_key(msg, [0, 7, 12, 8, 5, 11, 14, 13], found_keys, ' ', 4, 'c', 14)

# 11 -> 13 -> 0 -> 11 -> 10 -> 9 -> 13 -> 9 [-> 7]
found_keys = break_and_update_key(msg, [11, 13, 0, 11, 10, 9, 13, 9], found_keys, ' ', 10, 'e', 14)

# 4 -> 10 -> 7 -> 15 -> 1 -> 15 -> 0 -> 10 [-> 6]
found_keys = break_and_update_key(msg, [4, 10, 7, 15, 1, 15, 0, 10], found_keys, ' ', 6, 'b', 14)

# 14 -> 9 -> 11 -> 6 -> 7 -> 6 -> 2 -> 1 [-> 5]
found_keys = break_and_update_key(msg, [14, 9, 11, 6, 7, 6, 2, 1], found_keys, 'o', 1, ' ', 14)

# 2 -> 2 -> 10 -> 13 -> 13 -> 14 -> 11 -> 6 [-> 4]
found_keys = break_and_update_key(msg, [2, 2, 10, 13, 13, 14, 11, 6], found_keys, 'h', 9, ' ', 4)

# 12 -> 14 -> 9 -> 9 -> 15 -> 10 -> 3 -> 8 [-> 3]
found_keys = break_and_update_key(msg, [12, 14, 9, 9, 15, 10, 3, 8], found_keys, 'd', 13, ' ', 1)

# 10 -> 11 -> 4 -> 12 -> 2 -> 8 -> 8 -> 5 [-> 2]
found_keys = break_and_update_key(msg, [10, 11, 4, 12, 2, 8, 8, 5], found_keys, 'y', 11, ' ', 2)

# 13 -> 12 -> 8 -> 5 -> 11 -> 5 -> 15 -> 12 [-> 1]
found_keys = break_and_update_key(msg, [13, 12, 8, 5, 11, 5, 15, 12], found_keys, ' ', 16, 'a', 18)

# 8 -> 0 -> 6 -> 3 -> 12 -> 7 -> 12 -> 15 [-> 0]
found_keys = break_and_update_key(msg, [8, 0, 6, 3, 12, 7, 12, 15], found_keys, 't', 9, ' ', 1)

dec = ps_multi(msg, found_keys, True)
print dec

'''
# 15 -> 6 -> 15 -> 1 -> 9 -> 3 -> 7 -> 14
found_keys = break_and_update_key(msg, [15, 6, 15, 1, 9, 3, 7, 14], found_keys, ' ', 1, 'g', 3)

# 5 -> 8 -> 1 -> 2 -> 6 -> 13 -> 5 -> 4 -> 14
found_keys = break_and_update_key(msg, [5, 8, 1, 2, 6, 13, 5, 4], found_keys, ' ', 1, 'a', 3)

# 3 -> 5 -> 2 -> 7 -> 0 -> 1 -> 4 -> 0 -> 13
found_keys = break_and_update_key(msg, [3, 5, 2, 7, 0, 1, 4, 0], found_keys, ' ', 1, 'm', 3)

# 1 -> 3 -> 14 -> 0 -> 4 -> 4 -> 6 -> 3 -> 12
found_keys = break_and_update_key(msg, [1, 3, 14, 0, 4, 4, 6, 3], found_keys, ' ', 1, 'f', 6)
'''