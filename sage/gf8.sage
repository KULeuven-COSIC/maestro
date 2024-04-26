from sage.all import *

print_elem = lambda x: f'0x{natural_encoding_to_int(x):02x}'

def natural_encoding(F, x):
    """
    Bit i is i-th coefficient
    """
    X = F.gen()
    n = F.modulus().degree()
    assert x < 2**n
    return F(sum([X**i for i in range(n) if ((x >> i) & 0x1) > 0]))

def natural_encoding_to_int(x):
    R = PolynomialRing(x.parent().base_ring(), x.parent().gen())
    return sum((2**i for i,c in enumerate(R(x).coefficients(sparse=False)) if c != 0))

def gen_pow_table(F,k,line_length=16):
    pow_table = [natural_encoding(F, e)**k for e in range(F.order())]
    print(f'POW({k})_TABLE = [')
    for i in range(0,len(pow_table),line_length):
        print(', '.join(print_elem(e) for e in pow_table[i:i+line_length]), end='')
        print(',')
    print(']')

def gen_mult_table(F,line_length=32):
    pk = F.order()
    print('MULT_TABLE = [')
    for i in range(pk):
        fi = natural_encoding(F, i)
        mult_table_row = [fi * natural_encoding(F,j) for j in range(pk)]
        print('[')
        for k in range(0,len(mult_table_row),line_length):
            print(', '.join(print_elem(e) for e in mult_table_row[k:k+line_length]), end='')
            print(',')
        print('],')
    print(']')

def gen_inv_table(F):
    square_table = [~natural_encoding(F, e) for e in range(1,F.order())]
    print('INV_TABLE = [', end='')
    print('0x00, ', end='') # 0 has no inverse, but we add a dummy value for the convenience of look ups.
    print(', '.join(f'0x{natural_encoding_to_int(e):02x}' for e in square_table), end='')
    print(']')    

x = polygen(GF(2), 'x')
F = GF(2**8, name=x, modulus=x^8 + x^4 + x^3 + x + 1)

#gen_pow_table(F,2) #square
#gen_pow_table(F,3) #cube
#gen_mult_table(F)
