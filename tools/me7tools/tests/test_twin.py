from me7tools.twin import find, mask_immediates, parse_pat


def test_mask_keeps_the_opcode_and_drops_the_word():
    window = bytes.fromhex("E6FC1122E6FD0602F2FE3344")
    pat, mask = mask_immediates(window)
    assert mask.hex() == "ffff0000ffff0000ffff0000"
    assert find(bytes.fromhex("0000E6FC99AAE6FD0602F2FE5566"), pat, mask, 4) == [2]


def test_a_second_copy_is_a_second_hit():
    pat, mask = mask_immediates(bytes.fromhex("C2F40102"))
    img = bytes.fromhex("C2F4AABB" "C2F4CCDD")
    assert find(img, pat, mask, 4) == [0, 4]


def test_pat_xx_is_one_byte():
    pat, mask = parse_pat("E6FCXX22")
    assert find(bytes.fromhex("E6FCAB22"), pat, mask, 2) == [0]
    assert find(bytes.fromhex("E6FCAB23"), pat, mask, 2) == []
