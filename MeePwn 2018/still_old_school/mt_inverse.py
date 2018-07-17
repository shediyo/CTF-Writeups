'''
IMPORTAT NOTE!: 
This script is taken from LaurentMazare/mt_inverse.py - https://gist.github.com/LaurentMazare/e0a6fa3b08c6b76fdcab
'''


import random

### Wikipedia sample Python implementation of the Mersenne-Twister.
### https://en.wikipedia.org/wiki/Mersenne_Twister

def _int32(x):
  return int(0xFFFFFFFF & x)

def temper(y):
  y = y ^ y >> 11
  y = y ^ y << 7 & 2636928640
  y = y ^ y << 15 & 4022730752
  y = y ^ y >> 18
  return y

class MT19937:

  def __init__(self, seed):
    # Initialize the index to 0
    self.index = 624
    self.mt = [0] * 624
    self.mt[0] = seed  # Initialize the initial state to the seed
    for i in range(1, 624):
      self.mt[i] = _int32(
          1812433253 * (self.mt[i - 1] ^ self.mt[i - 1] >> 30) + i)

  def extract_number(self):
    if self.index >= 624:
      self.twist()

    y = self.mt[self.index]
    self.index = self.index + 1
    return _int32(temper(y))

  def twist(self):
    for i in range(0, 624):
      # Get the most significant bit and add it to the less significant
      # bits of the next number
      y = _int32((self.mt[i] & 0x80000000) +
                 (self.mt[(i + 1) % 624] & 0x7fffffff))
      self.mt[i] = self.mt[(i + 397) % 624] ^ y >> 1

      if y % 2 != 0:
        self.mt[i] = self.mt[i] ^ 0x9908b0df
    self.index = 0

### Inverting the temper function is all what is needed to recover the internal state of a
### Mersenne Twister from its last 624 outputs.
### Note that the temper process is "linear":
###   temper(u xor v) = temper(u) xor temper(v)
### This will make it very easy to invert.

# First compute the bit-matrix A associated with the temper function by applying it to all
# the 2^i for i \in [0, 31].
A = [ temper(1 << i) for i in xrange(32) ]

# Now we want to invert this matrix in Z/2Z, for that purpose we use the Gauss-Jordan
# elimination in Z/2Z.
def GaussJordan_mod2(A):
  A = [ (a, 1 << i) for i, a in enumerate(A) ]
  for idx in xrange(len(A)):
    for j in xrange(idx, len(A)):
      if (1 << idx) & A[j][0]:
        A[idx], A[j] = A[j], A[idx]
        for k in xrange(idx+1, len(A)):
          if (1 << idx) & A[k][0]:
            A[k] = A[k][0] ^ A[idx][0], A[k][1] ^ A[idx][1]
        break
  for idx in xrange(len(A), -1, -1):
    for j in xrange(idx):
      if (1 << idx) & A[j][0]:
        A[j] = A[j][0] ^ A[idx][0], A[j][1] ^ A[idx][1]
  return [ b for (_a, b) in A ]

B = GaussJordan_mod2(A)
# Untempering only consists in multiplying the bit-vector given as input by B.
def untemper(x): return reduce(lambda x, y: x^y, [ B[i] for i in xrange(32) if x & (1 << i) ], 0)