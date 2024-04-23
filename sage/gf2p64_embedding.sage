from sage.rings.finite_rings.hom_finite_field import FiniteFieldHomomorphism_generic

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

def e_table(F,f):
    embedded_F = [f(natural_encoding(F, e)) for e in range(F.order())]
    print("E_TABLE = [", end='')
    print(", ".join(f'0x{natural_encoding_to_int(e):016x}' for e in embedded_F), end='')
    print("]")   
    print(len(embedded_F))

# Our fields GF(2^4), GF(2^8), GF(2^64)
K.<x> = GF(2)[]
E = GF(2^64, 'a', modulus=x^64+x^4+x^3+x+1)
F1 = GF(2^4, 'b', modulus=x^4+x+1)
F2 = GF(2^8, 'b', modulus=x^8+x^4+x^3+x+1)

# Get the embedding maps
f1 = FiniteFieldHomomorphism_generic(Hom(F1, E))
f2 = FiniteFieldHomomorphism_generic(Hom(F2, E))

e_table(F1,f1)
e_table(F2,f2)
