"""Check signed mixed-radix membership algebra, not a proof or security claim.

Normative profile: p=65437, degree=64, secret width=18, ell=18,
radices=(8, 8, 8, 8, 16). For runtime, use two root/tag rows and ell=2.
Secrets retain all 1,152 binary coefficients. Test randomness is public PRNG
data. There is no proof generation, Fiat-Shamir transcript, or cryptographic RNG.
Digits are most significant first. Identifier checks use an incomplete public
manifest fixture. These checks do not validate CRS blob parsing or constraints
in a composite-Q proof backend.
"""

import hashlib
import json
import random

P, DEGREE, WIDTH, ELL = 65437, 64, 18, 2
RADICES = (8, 8, 8, 8, 16)


def check_compilation_shifts():
    # Integer negacyclic identities, independent of field reduction and backend.
    def mul(a, b):
        out = [0] * DEGREE
        for i, left in enumerate(a):
            for j, right in enumerate(b):
                k = i + j
                out[k % DEGREE] += left * right * (1 if k < DEGREE else -1)
        return out

    def inverse_power(r):
        out = [0] * DEGREE
        out[0 if r == 0 else DEGREE-r] = 1 if r == 0 else -1
        return out

    h = [j * j - 97 for j in range(DEGREE)]
    for r in range(DEGREE):
        assert mul(inverse_power(r), h)[0] == h[r]
    for row in range(18):
        shift = (8 * row) % DEGREE
        for digit in range(8):
            z = [0] * DEGREE
            z[digit] = 1
            auto_z = [z[0]] + [-z[DEGREE-i] for i in range(1, DEGREE)]
            assert mul(auto_z, mul(inverse_power(shift), h))[0] == h[shift+digit]
    assert 4*18 + 128 + 144 + 63 + 272 + 5 + 192 == 876
    assert 876 + 1 + 256 == 1133
    print("PASS: 64 coefficient shifts, 144 folded dot products, 1133 evaluation inventory")


def check_identifiers():
    # This fixture is not a complete profile accepted by Sign or Verify.
    fixture = {"commitment_key_digest": bytes(range(64)).hex(),
               "commitment_encoding": "blrs-explicit-crs-v1"}
    label = b"BLRS/proof/v1"

    def identifier(fields):
        payload = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("ascii")
        framed = (len(label).to_bytes(4, "little") + label
                  + len(payload).to_bytes(8, "little") + payload)
        return hashlib.shake_256(framed).digest(64)

    expected_payload = (b'{"commitment_encoding":"blrs-explicit-crs-v1","commitment_key_digest":"'
                        b'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
                        b'202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"}')
    expected_frame = b"\x0d\x00\x00\x00BLRS/proof/v1" + len(expected_payload).to_bytes(8, "little")
    expected = hashlib.shake_256(expected_frame + expected_payload).digest(64)
    assert identifier(fixture) == expected
    assert identifier(dict(reversed(tuple(fixture.items())))) == expected
    for field, replacement in (("commitment_key_digest", (bytes(range(63)) + b"\xff").hex()),
                               ("commitment_encoding", "different-encoding")):
        altered = dict(fixture)
        altered[field] = replacement
        assert identifier(altered) != expected
    print("PASS: canonical proof-id fixture and commitment key digest/encoding binding")


def mv(matrix, vector):
    return tuple(sum(a * b for a, b in zip(row, vector)) % P for row in matrix)


def signed(vector, b):
    return tuple(b * value % P for value in vector)


def canonical(vector):
    return all(isinstance(value, int) and 0 <= value < P for value in vector)


def selector(index, radix, b):
    assert 0 <= index < radix <= DEGREE
    return tuple(b % P if j == index else 0 for j in range(DEGREE))


def selector_ok(z, radix, b):
    # These are coefficient-wise field equations, not polynomial products.
    return (len(z) == DEGREE and canonical(z) and not any(z[radix:])
            and all(value * (value - b) % P == 0 for value in z[:radix])
            and sum(z[:radix]) % P == b)


def fold(columns, phi, radix):
    assert len(columns) % radix == 0
    next_count = len(columns) // radix
    # Flatten projected block entry (a,j) at coefficient a*radix+j.
    return [tuple(value for row in phi
                  for value in (sum(c * t for c, t in zip(row, column)) % P
                                for column in (columns[digit * next_count + index]
                                               for digit in range(radix))))
            for index in range(next_count)]


def prepare(columns, radices, rng):
    matrices, projections = [columns], []
    for radix in radices[:-1]:
        phi = [tuple(rng.randrange(P) for _ in matrices[-1][0]) for _ in range(ELL)]
        projections.append(phi)
        matrices.append(fold(matrices[-1], phi, radix))
    assert len(matrices[-1]) == radices[-1]
    return matrices, projections


def witness(index, secret, radices, matrices, b):
    selectors, blocks = [], []
    for stage, radix in enumerate(radices[:-1]):
        digit, index = divmod(index, len(matrices[stage + 1]))
        selectors.append(selector(digit, radix, b))
        blocks.append(signed(matrices[stage + 1][index], b))
    selectors.append(selector(index, radices[-1], b))
    return ((b % P,) + (0,) * (DEGREE - 1), signed(secret, b), selectors, blocks)


def check(a, tag_matrix, tag, radices, matrices, projections, candidate):
    sign, x, selectors, blocks = candidate
    if (len(sign) != DEGREE or not canonical(sign) or any(sign[1:])
            or sign[0] not in (1, P - 1)):
        return False
    b = sign[0]
    if (len(x) != WIDTH * DEGREE or not canonical(x)
            or any(value * (value - b) % P for value in x)):
        return False
    if (len(selectors) != len(radices) or len(blocks) != len(projections)
            or any(not selector_ok(z, radix, b) for z, radix in zip(selectors, radices))
            or any(len(h) != ELL * radix or not canonical(h)
                   for h, radix in zip(blocks, radices[:-1]))):
        return False
    if len(tag) != len(tag_matrix) or not canonical(tag) or mv(tag_matrix, x) != signed(tag, b):
        return False
    previous = mv(a, x)
    for radix, z, h, phi in zip(radices, selectors, blocks, projections):
        lhs = tuple(sum(h[row * radix + j] * z[j] for j in range(radix)) % P
                    for row in range(ELL))
        if lhs != signed(mv(phi, previous), b):
            return False
        previous = h
    terminal = tuple(sum(column[row] * z for column, z in
                         zip(matrices[-1], selectors[-1][:radices[-1]])) % P
                     for row in range(len(previous)))
    return terminal == previous


def pack_block(values):
    assert len(values) == 18 * 8 and canonical(values)
    padded = tuple(values) + (0,) * 48
    return tuple(padded[start:start + DEGREE] for start in range(0, 192, DEGREE))


def unpack_block(polynomials):
    if len(polynomials) != 3 or any(len(poly) != DEGREE for poly in polynomials):
        raise ValueError("Expected three degree-64 coefficient vectors")
    values = tuple(value for poly in polynomials for value in poly)
    if not canonical(values) or any(values[144:]):
        raise ValueError("Noncanonical coefficients or nonzero packing tail")
    return values[:144]


def exercise(radices, indices, seed):
    rng = random.Random(seed)
    count = 1
    for radix in radices:
        count *= radix
    a, tag_matrix = [[tuple(rng.randrange(P) for _ in range(WIDTH * DEGREE))
                     for _ in range(2)] for _ in range(2)]
    secrets = {index: tuple(rng.randrange(2) for _ in range(WIDTH * DEGREE))
               for index in indices}
    columns = [tuple(rng.randrange(P) for _ in a) for _ in range(count)]
    for index, secret in secrets.items():
        columns[index] = mv(a, secret)
    matrices, projections = prepare(columns, radices, rng)
    valid = 0
    for index, secret in secrets.items():
        tag = mv(tag_matrix, secret)
        for b in (1, -1):
            candidate = witness(index, secret, radices, matrices, b)
            assert check(a, tag_matrix, tag, radices, matrices, projections, candidate)
            sign, x, z, h = candidate
            if radices == RADICES and index in (12345, 65535):
                digits = tuple(values.index(b % P) for values in z)
                expected = (1, 4, 0, 3, 9) if index == 12345 else (7, 7, 7, 7, 15)
                assert digits == expected
                d0, d1, d2, d3, d4 = digits
                assert ((((d0 * 8 + d1) * 8 + d2) * 8 + d3) * 16 + d4) == index
            assert signed(x, sign[0]) == secret  # Recover s=b*x.
            flipped = (signed(sign, -1), signed(x, -1),
                       [signed(value, -1) for value in z], [signed(value, -1) for value in h])
            assert check(a, tag_matrix, tag, radices, matrices, projections, flipped)
            assert flipped != candidate and mv(tag_matrix, signed(flipped[1], flipped[0][0])) == tag
            valid += 1

    index = indices[0]
    tag = mv(tag_matrix, secrets[index])
    sign, x, z, h = witness(index, secrets[index], radices, matrices, 1)
    bad_x = (2,) + x[1:]
    assert not check(a, tag_matrix, tag, radices, matrices, projections, (sign, bad_x, z, h))
    for bad_sign in ((0,) * DEGREE, (1, 1) + (0,) * (DEGREE - 2)):
        assert not check(a, tag_matrix, tag, radices, matrices, projections, (bad_sign, x, z, h))
    for extra in (1, radices[0]):  # Multiple selected entries; nonzero selector packing tail.
        bad_z = list(z)
        values = list(bad_z[0])
        values[extra] = 1
        bad_z[0] = tuple(values)
        assert not check(a, tag_matrix, tag, radices, matrices, projections, (sign, x, bad_z, h))
    bad_tag = ((tag[0] + 1) % P,) + tag[1:]
    assert not check(a, tag_matrix, bad_tag, radices, matrices, projections, (sign, x, z, h))
    for stage in (0, len(h) - 1):
        bad_h = list(h)
        digit = index // len(matrices[1]) if stage == 0 else 0
        values = list(bad_h[stage])
        values[digit] = (values[digit] + 1) % P
        bad_h[stage] = tuple(values)
        assert not check(a, tag_matrix, tag, radices, matrices, projections, (sign, x, z, bad_h))
    reordered = list(columns)
    reordered[index], reordered[(index + 1) % count] = reordered[(index + 1) % count], reordered[index]
    reordered_matrices = [reordered]
    for phi, radix in zip(projections, radices):
        reordered_matrices.append(fold(reordered_matrices[-1], phi, radix))
    assert not check(a, tag_matrix, tag, radices, reordered_matrices, projections, (sign, x, z, h))
    print(f"PASS: N={count}, radices={radices}, {valid} valid signed witnesses plus mutation checks")


if __name__ == "__main__":
    check_compilation_shifts()
    check_identifiers()
    exercise((2, 3, 2), tuple(range(12)), 65437)
    exercise(RADICES, (0, 65535, 12345), 18)
    binary_norms = []
    for b in (1, -1):
        for bit in (0, 1):
            small = (b * bit,) * (WIDTH * DEGREE) + ((b,) + (0,) * 63) * len(RADICES)
            binary = tuple(value - (b - 1) // 2 for value in small)
            binary += ((b + 1) // 2,) + (0,) * 63
            assert len(small) == 23 * DEGREE and sum(value * value for value in small) <= 1157
            assert len(binary) == 24 * DEGREE and all(value in (0, 1) for value in binary)
            binary_norms.append(sum(value * value for value in binary))
    assert max(binary_norms) == 1467
    print("PASS: distinct small-witness and binary-map norm bounds 1157 and 1467")
    values = tuple((index * 37) % P for index in range(144))
    packed = pack_block(values)
    assert unpack_block(packed) == values and len(packed) == 3 and packed[-1][-48:] == (0,) * 48
    bad_packed = packed[:-1] + (packed[-1][:-1] + (1,),)
    try:
        unpack_block(bad_packed)
    except ValueError:
        pass
    else:
        raise AssertionError("Nonzero block packing tail accepted")
    print("PASS: normative 144-coefficient packing round trip and zero-tail rejection")
    print("Reduced algebra and identifier fixtures: ell=2/root rows=2/tag rows=2; no ZK or security validation.")
