## Reference: 
# https://jeremykun.com/category/ring-theory/
# https://www.geeksforgeeks.org/primitive-root-of-a-prime-number-n-modulo-n/

from math import sqrt
from random import randrange

# Returns True if n is prime
def isPrime( n):

	# Corner cases
	if (n <= 1):
		return False
	if (n <= 3):
		return True

	# This is checked so that we can skip
	# middle five numbers in below loop
	if (n % 2 == 0 or n % 3 == 0):
		return False
	i = 5
	while(i * i <= n):
		if (n % i == 0 or n % (i + 2) == 0) :
			return False
		i = i + 6

	return True

""" Iterative Function to calculate (x^n)%p
	in O(logy) */"""
def power(x, y, p):

	res = 1 # Initialize result

	x = x % p # Update x if it is more
			# than or equal to p

	while (y > 0):

		# If y is odd, multiply x with result
		if (y & 1):
			res = (res * x) % p

		# y must be even now
		y = y >> 1 # y = y/2
		x = (x * x) % p

	return res

# Utility function to store prime
# factors of a number
def findPrimefactors(s, n) :

	# Print the number of 2s that divide n
	while (n % 2 == 0) :
		s.add(2)
		n = n // 2

	# n must be odd at this point. So we can
	# skip one element (Note i = i +2)
	for i in range(3, int(sqrt(n)), 2):
		
		# While i divides n, print i and divide n
		while (n % i == 0) :

			s.add(i)
			n = n // i
		
	# This condition is to handle the case
	# when n is a prime number greater than 2
	if (n > 2) :
		s.add(n)

# Function to find smallest primitive
# root of n
def findPrimitive(n) :
	s = set()

	# Check if n is prime or not
	if (isPrime(n) == False):
		return -1

	# Find value of Euler Totient function
	# of n. Since n is a prime number, the
	# value of Euler Totient function is n-1
	# as there are n-1 relatively prime numbers.
	phi = n - 1

	# Find prime factors of phi and store in a set
	findPrimefactors(s, phi)

	# Check for every number from 2 to phi
	for r in range(2, phi + 1):

		# Iterate through all prime factors of phi.
		# and check if we found a power with value 1
		flag = False
		for it in s:

			# Check if r^((phi)/primefactors)
			# mod n is 1 or not
			if (power(r, phi // it, n) == 1):

				flag = True
				break
			
		# If there was no power with value 1.
		if (flag == False):
			return r

	# If no primitive root found
	return -1

def extendedEuclideanAlgorithm(a, b):
    if abs(b) > abs(a):
        (x,y,d) = extendedEuclideanAlgorithm(b, a)
        return (y,x,d)
    
    if abs(b) == 0:
        return (1, 0, a)
    
    x1, x2, y1, y2 = 0, 1, 1, 0
    while abs(b) > 0:
        q, r = divmod(a,b)
        x = x2 - q*x1
        y = y2 - q*y1
        a, b, x2, x1, y2, y1 = b, r, x1, x, y1, y
    
    return (x2, y2, a)

class DomainElement(object):
    def __radd__(self, other): return self + other
    def __rsub__(self, other): return -self + other
    def __rmul__(self, other): return self * other

class FieldElement(DomainElement):
    def __truediv__(self, other): return self * other.inverse()
    def __rtruediv__(self, other): return self.inverse() * other
    def __div__(self, other): return self.__truediv__(other)
    def __rdiv__(self, other): return self.__rtruediv__(other)

def IntegersModP(p):
    if not isPrime(p):
        raise Exception("Modulus is not a prime.")
    
    class IntegerModP(FieldElement):
        def __init__(self, n):
            self.n = n % p
            self.field = IntegerModP

        def __add__(self, other): return IntegerModP(self.n + other.n)
        def __sub__(self, other): return IntegerModP(self.n - other.n)
        def __mul__(self, other): return IntegerModP(self.n * other.n)
        def __truediv__(self, other): return self * other.inverse()
        def __div__(self, other): return self * other.inverse()
        def __neg__(self): return IntegerModP(-self.n)
        def __eq__(self, other): return isinstance(other, IntegerModP) and self.n == other.n
        def __abs__(self): return abs(self.n)
        def __str__(self): return str(self.n)
        def __repr__(self): return '%d (mod %d)' % (self.n, self.p)
        # double-and-add algorithm for efficient exponent
        def __pow__(self, exp):
            exp %= IntegerModP.phi
            return IntegerModP(power(self.n, exp, self.p))

        def __divmod__(self, divisor):
            q,r = divmod(self.n, divisor.n)
            return (IntegerModP(q), IntegerModP(r))
            
        def inverse(self):
            x,y,d = extendedEuclideanAlgorithm(self.n, self.p)
            return IntegerModP(x)

        @classmethod
        def random(cls): return IntegerModP(randrange(cls.p))
        @classmethod
        def randomInt(cls): return randrange(cls.phi)

    IntegerModP.p = p
    IntegerModP.phi = p-1
    IntegerModP.gen = findPrimitive(p)
    IntegerModP.__name__ = 'Z/%d' % (p)
    return IntegerModP