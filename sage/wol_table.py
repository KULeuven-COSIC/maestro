def wol_map(a):
    assert a < 2**8
    a_bits = [(a & (1 << i)) >> i for i in range(0,8)]
    a_a = a_bits[1] ^ a_bits[7]
    a_b = a_bits[5] ^ a_bits[7]
    a_c = a_bits[4] ^ a_bits[6]
    # Compute (a_h,a_l)
    a_l  = (a_c ^ a_bits[0] ^ a_bits[5]) 
    a_l += (a_bits[1] ^ a_bits[2]) << 1 
    a_l += a_a << 2 
    a_l += (a_bits[2] ^ a_bits[4]) << 3
    a_h  = (a_c ^ a_bits[5]) 
    a_h += (a_a ^ a_c) << 1 
    a_h += (a_b ^ a_bits[2] ^ a_bits[3]) << 2 
    a_h += (a_b) << 3
    return (a_h, a_l)
    
def wol_map_inv(a_h,a_l):
    assert a_h < 2**4 and a_l < 2**4
    ah_bits = [(a_h & (1 << i)) >> i for i in range(0,4)]
    al_bits = [(a_l & (1 << i)) >> i for i in range(0,4)]
    a_a = al_bits[1] ^ ah_bits[3]
    a_b = ah_bits[0] ^ ah_bits[1]
    # Compute a bit-by-bit starting with a_0
    a = al_bits[0] ^ ah_bits[0]
    a += (a_b ^ ah_bits[3]) << 1
    a += (a_a ^ a_b) << 2
    a += (a_b ^ al_bits[1] ^ ah_bits[2]) << 3
    a += (a_a ^ a_b ^ al_bits[3]) << 4
    a += (a_b ^ al_bits[2]) << 5
    a += (a_a ^ al_bits[2] ^ al_bits[3] ^ ah_bits[0]) << 6
    a += (a_b ^ al_bits[2] ^ ah_bits[3]) << 7
    return a

def compute_map_gf8_to_gf42():
    print("GF8_TO_GF42 = [", end='')
    wol_table = [wol_map(a) for a in range(2**8)]
    print(", ".join(f'(0x0{ah:x},0x0{al:x})' for (ah,al) in wol_table), end ='')
    print("]")

def compute_map_gf42_to_gf8():
    print("GF42_TO_GF8 = [")
    for ah in range(2**4):
        wol_inv_table = [wol_map_inv(ah,al) for al in range(2**4)]
        print("["+", ".join(f'0x{a:0{2}x}' for a in wol_inv_table)+"],")
    print("]")



compute_map_gf8_to_gf42()
compute_map_gf42_to_gf8()