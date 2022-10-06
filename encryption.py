class RSAencryption:
    def __init__(self, p: int, q: int, e: int) -> None:
        self.p = p
        self.q = q
        self.e = e
        self.n = p*q
        self.phi_n = (p-1)*(q-1)
    
    def get_f(self) -> int:
        def helper(v0: int, v1: int) -> tuple[int]:
            w = v0 // v1
            v = v0 % v1
            if v == 1:
                a, b = -w, v 
                return (a, b)
            else:
                a1, b1 = helper(v1,v)
                a, b = b1 - a1 * w, a1
                return (a, b)
        f = helper(self.phi_n, self.e)[0] % self.phi_n
        if (f * self.e) % self.phi_n == 1:
            return f
        else:
            raise ValueError('False f.')
    
    def exponentiateModN(self, base, exponent) -> int:
        temp, result = base, 1
        for i in bin(exponent)[:1:-1]:
            if int(i):
                result = (result * temp) % self.n
            temp = (temp ** 2) % self.n
        return result
    
    def encrypt(self, message: str) -> int:
        mInt = int(''.join(format(x, 'b') for x in bytearray(message, 'utf-8')), 2)
        if mInt > self.n:
            raise ValueError("Message doesn't fit.")
        return self.exponentiateModN(mInt, self.e)
    
    def decrypt(self, message: int) -> str:
        mInt = self.exponentiateModN(message, self.get_f())
        binary = bin(mInt)[2:]
        chunks = [binary[i:i+7] for i in range(0, len(binary), 7)]
        return "".join([chr(int(i,2)) for i in chunks])

encryptor = RSAencryption(956294630647, 956294630657, 17)
#messageToEncrypt = input("Input your short message!")
print(encryptor.decrypt(371002944611659292714170))

