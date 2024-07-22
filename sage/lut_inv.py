GF4_INV = [0x00, 0x01, 0x09, 0x0e, 0x0d, 0x0b, 0x07, 0x06, 0x0f, 0x02, 0x0c, 0x05, 0x0a, 0x04, 0x03, 0x08]

def compute_bit_to_index_table(table):
    print("LUT_TABLE = [")
    for i in range(0,4):
        indices = []
        for j in range(len(table)):
            if table[j] & 1 << i > 0:
                indices.append(j)
        print("[" + ",".join([str(j) for j in indices])+ "],")
    print("]")

compute_bit_to_index_table(GF4_INV)