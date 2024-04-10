from sage.all import *

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

def gen_square_table(F):
    square_table = [natural_encoding(F, e)**2 for e in range(F.order())]
    print("SQ_TABLE = [", end='')
    print(", ".join(f'0x0{natural_encoding_to_int(e):x}' for e in square_table), end='')
    print("]")

def gen_mult_by_E_table(F):
    e = natural_encoding(F,0xE)
    mul_e_table = [e * natural_encoding(F, a) for a in range(F.order())]
    print("MUL_E_TABLE = [", end='')
    print(", ".join(f'0x0{natural_encoding_to_int(a):x}' for a in mul_e_table), end='')
    print("]") 

def gen_mult_table(F):
    pk = F.order()
    print("MULT_TABLE = [")
    for i in range(pk):
        fi = natural_encoding(F, i)
        mult_table_row = [fi * natural_encoding(F,j) for j in range(pk)]
        print("["+ ", ".join(f'0x0{natural_encoding_to_int(e):x}' for e in mult_table_row)+"],")
    print("]")

def gen_inv_table(F):
    square_table = [~natural_encoding(F, e) for e in range(1,F.order())]
    print("INV_TABLE = [", end='')
    print("0x00, ", end='') # 0 has no inverse, but we add a dummy value for the convenience of look ups.
    print(", ".join(f'0x0{natural_encoding_to_int(e):x}' for e in square_table), end='')
    print("]")    

def gen_mult2_table(F):
    pk = F.order()
    print("MULT_TABLE = [")
    for x1 in range(pk):
        for x2 in range(pk):
            fx1 = natural_encoding(F, x1)
            fx2 = natural_encoding(F, x2)
            print('[', end='')
            v = []
            for y1 in range(pk):
                for y2 in range(pk):
                    fy1 = natural_encoding(F, y1)
                    fy2 = natural_encoding(F, y2)
                    z1 = fx1 * fy1
                    z2 = fx2 * fy2
                    v.append(f'0x{natural_encoding_to_int(z1):x}{natural_encoding_to_int(z2):x}')
            print(", ".join(v), end='')
            print('],')
    print("]")

def gen_square2_table(F):
    pk = F.order()
    print("SQUARE_TABLE = [")
    v = []
    for x1 in range(pk):
        for x2 in range(pk):
            fx1 = natural_encoding(F, x1)
            fx2 = natural_encoding(F, x2)
            v.append(f'0x{natural_encoding_to_int(fx1**2):x}{natural_encoding_to_int(fx2**2):x}')
    print(', '.join(v), end='')
    print(']')

def gen_square2_e_table(F):
    pk = F.order()
    print("SQUARE_MUL_E_TABLE = [")
    v = []
    e = natural_encoding(F,0xE)
    for x1 in range(pk):
        for x2 in range(pk):
            fx1 = natural_encoding(F, x1)
            fx2 = natural_encoding(F, x2)
            v.append(f'0x{natural_encoding_to_int(e*fx1**2):x}{natural_encoding_to_int(e*fx2**2):x}')
    print(', '.join(v), end='')
    print(']')

x = polygen(GF(2), 'x')
F = GF(2**4, name=x, modulus=x^4 + x + 1)

#gen_square_table(F)
#gen_mult_table(F)
#gen_mult_by_E_table(F)
gen_square2_e_table(F)
