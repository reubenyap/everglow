"""Independent Python check of public C++ fixture identifiers and wire bounds.

This checks the codec and identifiers, not the lattice proof equations.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct


def require(condition, message):
    if not condition:
        raise ValueError(message)


def frame(label, data):
    label = label.encode('ascii')
    return struct.pack('<I', len(label)) + label + struct.pack('<Q', len(data)) + data


def identifier(label, data):
    return hashlib.shake_256(frame(label, data)).digest(64)


def unique_object(pairs):
    result = dict(pairs)
    require(len(result) == len(pairs), 'duplicate manifest keys')
    return result


def manifest_profile(manifest):
    def canonical_value(value):
        if isinstance(value, dict):
            for key, child in value.items():
                canonical_value(key)
                canonical_value(child)
        elif isinstance(value, list):
            for child in value:
                canonical_value(child)
        elif isinstance(value, str):
            require(all(32 <= ord(c) <= 126 and c not in '\\"' for c in value), 'manifest string domain')
        else:
            require(type(value) in (int, bool), 'manifest numeric or null domain')
    canonical_value(manifest)
    mode = manifest['sampler']['modes'][0]
    require(mode in ('ordinary', 'bimodal'), 'unknown core profile')
    bimodal = mode == 'bimodal'
    require(type(manifest['D']) is int and manifest['D'] == 0 and manifest['Q'] == 1151179879138398721 and
            manifest['degree'] == 64 and manifest['secret_width'] == 18 and
            manifest['ring_length'] == 65536, 'proof profile dimensions')
    require(manifest['radices'] == [8, 8, 8, 8, 16], 'radices')
    require(manifest['layout'] == {'base_h': 5, 'c': 1, 'hint': 20, 'tA1': 20,
            'tB': 23, 'z1': 23, 'z21': 75, 'z3': 4, 'z4': 0}, 'wire layout profile')
    require(manifest['sampler']['modes'] == [mode, 'one-sided-bimodal', 'ordinary'] and
            manifest['sampler']['multipliers'] == [2 if bimodal else 4, 2, 4], 'sampler modes')
    require(manifest['sampler']['sigma1'] == {'denominator': 5, 'numerator': 126976 if bimodal else 2031616} and
            manifest['sampler']['sigma2'] == {'denominator': 5, 'numerator': 253952} and
            manifest['sampler']['sigma3'] == {'denominator': 5, 'numerator': 2031616}, 'sampler widths')
    require(manifest['z1_abs_max'] == (1377909 if bimodal else 22046544) and
            manifest['z1_norm_squared_max'] == (1898633242869 if bimodal else 486050110174658) and
            manifest['z21_abs_max'] == 5618953 and manifest['z2_norm_squared_max'] == 31572639091752 and
            manifest['hint_abs_max'] == 1124199100721092 and
            manifest['range']['infinity_cap'] == 9751757, 'response profile bounds')
    expected_raw = {'body_bytes': 87168, 'challenge_bytes': 2, 'format': 'raw-v1',
                    'header_bytes': 466, 'q_bytes': 8, 'signed_bytes': 8}
    expected_compressed = {'body_bytes_max': 80650 if bimodal else 81386,
            'body_bytes_min': 38210 if bimodal else 38946, 'challenge_bits': 5,
            'format': 'lossless-rice-v2', 'header_bytes': 466, 'hint_low_bits': 8,
            'omitted_h_lanes': [0, 32], 'q_bits': 60, 'range_low_bits': 19,
            'unary_escape': 31, 'z1_low_bits': 15 if bimodal else 19, 'z21_low_bits': 16}
    wire = manifest['encoding']
    require(json.dumps(wire, sort_keys=True) in
            (json.dumps(expected_raw, sort_keys=True), json.dumps(expected_compressed, sort_keys=True)),
            'unknown encoding profile')
    return wire


def validate_body(values, manifest):
    q = manifest['Q']
    for name in ('tB', 'base_h', 'tA1'):
        require(all(0 <= x < q for x in values[name]), 'proof residue')
    h = values['base_h']
    require(all(h[i*64] == h[i*64+32] == 0 for i in range(5)), 'evaluation lanes')
    challenge = values['c']
    require(all(abs(x) <= 8 for x in challenge) and challenge[32] == 0 and
            all(challenge[i] == -challenge[64-i] for i in range(1, 32)), 'challenge family')
    for name, cap, norm_cap in (
            ('hint', manifest['hint_abs_max'], None),
            ('z1', manifest['z1_abs_max'], manifest['z1_norm_squared_max']),
            ('z21', manifest['z21_abs_max'], manifest['z2_norm_squared_max']),
            ('z3', manifest['range']['infinity_cap'], None)):
        require(all(abs(x) <= cap for x in values[name]), 'signed coefficient bound')
        if norm_cap is not None:
            require(sum(x*x for x in values[name]) <= norm_cap, 'response norm bound')


def decode_raw(body):
    require(len(body) == 87168, 'raw body length')
    values = {}
    offset = 0
    for name, count, code in (('tB', 1472, 'Q'), ('base_h', 320, 'Q'), ('tA1', 1280, 'Q'),
            ('c', 64, 'h'), ('hint', 1280, 'q'), ('z1', 1472, 'q'), ('z21', 4800, 'q'), ('z3', 256, 'q')):
        values[name] = struct.unpack_from('<' + str(count) + code, body, offset)
        offset += count * struct.calcsize(code)
    require(offset == len(body), 'raw layout mismatch')
    return values


class BitReader:
    def __init__(self, body):
        self.body = body
        self.position = 0

    def integer(self, width):
        require(self.position + width <= len(self.body) * 8, 'truncated compressed body')
        result = 0
        for i in range(width):
            position = self.position + i
            result |= ((self.body[position // 8] >> (position % 8)) & 1) << i
        self.position += width
        return result

    def signed_integer(self, width):
        value = self.integer(width)
        return value - (1 << width) if value & (1 << (width-1)) else value

    def coefficient(self, width, cap, escape):
        count = 0
        while count < escape and self.integer(1):
            count += 1
        if count == escape:
            value = self.signed_integer(cap.bit_length()+1)
            require(abs(value) <= cap, 'escaped coefficient bound')
            high = (value + (1 << (width-1))) // (1 << width)
            unary = -2*high if high <= 0 else 2*high-1
            require(unary >= escape, 'noncanonical compressed escape')
        else:
            high = (count+1)//2 if count % 2 else -count//2
            value = high * (1 << width) + self.signed_integer(width)
            require(abs(value) <= cap, 'compressed coefficient bound')
        return value

    def finish(self):
        require(self.integer(1) == 1, 'compressed terminator')
        require((self.position+7)//8 == len(self.body), 'trailing compressed bytes')
        while self.position % 8:
            require(self.integer(1) == 0, 'nonzero compressed padding')


def decode_compressed(body, manifest):
    wire = manifest['encoding']
    require(wire['body_bytes_min'] <= len(body) <= wire['body_bytes_max'], 'compressed body length')
    reader = BitReader(body)
    values = {'tB': [reader.integer(wire['q_bits']) for _ in range(1472)]}
    values['base_h'] = [0 if i % 64 in wire['omitted_h_lanes'] else reader.integer(wire['q_bits'])
                       for i in range(320)]
    values['tA1'] = [reader.integer(wire['q_bits']) for _ in range(1280)]
    challenge = [reader.integer(wire['challenge_bits']) - 8 for _ in range(32)]
    values['c'] = challenge + [0] + [-x for x in reversed(challenge[1:])]
    for name, count, width, cap in (
            ('hint', 1280, wire['hint_low_bits'], manifest['hint_abs_max']),
            ('z1', 1472, wire['z1_low_bits'], manifest['z1_abs_max']),
            ('z21', 4800, wire['z21_low_bits'], manifest['z21_abs_max']),
            ('z3', 256, wire['range_low_bits'], manifest['range']['infinity_cap'])):
        values[name] = [reader.coefficient(width, cap, wire['unary_escape']) for _ in range(count)]
    reader.finish()
    return values


def check(prefix):
    root = Path(__file__).resolve().parents[1]
    def read(suffix):
        return Path(str(prefix) + suffix).read_bytes()
    manifest_bytes = read('.manifest.json').rstrip(b'\r\n')
    manifest = json.loads(manifest_bytes, object_pairs_hook=unique_object)
    require(json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode('ascii') == manifest_bytes,
            'noncanonical manifest')
    wire = manifest_profile(manifest)
    sources = ('src/candidate.cpp', 'src/relation.cpp', 'src/transcript.cpp', 'src/sampler.cpp', 'src/codec.cpp',
               'backend/backend.cpp', 'backend/proof_params.h', 'backend/lazer.patch',
               'include/blrs/candidate.hpp', 'include/blrs/relation.hpp', 'include/blrs/transcript.hpp',
               'include/blrs/codec.hpp',
               'include/blrs/random.hpp', 'include/blrs/sampler.hpp', 'backend/backend.hpp', 'backend/blrs_callbacks.h')
    source_hashes = ''.join(hashlib.sha256((root / name).read_bytes()).hexdigest() for name in sources)
    require(hashlib.sha256(source_hashes.encode()).hexdigest() == manifest['implementation_digest'],
            'fixture belongs to another implementation')
    statement, crs, ring, signature = (read(suffix) for suffix in
        ('.statement.bin', '.crs.bin', '.ring.bin', '.signature.bin'))
    require(struct.unpack_from('<IHH', statement) == (65437, 64, 18), 'statement dimensions')
    require(all(x[0] < 65437 for x in struct.iter_unpack('<H', statement[8:9224])), 'statement residues')
    context_length, = struct.unpack_from('<Q', statement, 9224)
    require(len(statement) == 9232 + context_length, 'statement context length')
    statement_id = identifier('BLRS/statement/v1', statement)
    require(statement_id.hex() == manifest['statement_id'], 'statement identifier')
    require(len(crs) == 1886764 and crs[:8] == b'BLRSCR01', 'CRS size or magic')
    q = 1151179879138398721
    require(struct.unpack_from('<HQH', crs, 8) == (1, q, 64), 'CRS header')
    offset = 20
    for rows, cols in ((20, 23), (20, 75), (23, 75)):
        require(struct.unpack_from('<II', crs, offset) == (rows, cols), 'CRS matrix shape')
        offset += 8
        count = rows * cols * 64 * 8
        require(all(x[0] < q for x in struct.iter_unpack('<Q', crs[offset:offset+count])), 'CRS residue')
        offset += count
    require(identifier('BLRS/commitment-key/v1', crs).hex() == manifest['commitment_key_digest'], 'CRS digest')
    require(len(ring) == 65536 * 256, 'ring size')
    require(all(x[0] < 65437 for x in struct.iter_unpack('<H', ring)), 'ring residue')
    ring_id = identifier('BLRS/ring/v1', statement_id + struct.pack('<I', 65536) + ring)
    proof_id = identifier('BLRS/proof/v1', manifest_bytes)
    compressed = wire['format'] == 'lossless-rice-v2'
    require(len(signature) >= 466 and signature[:10] ==
            (b'BLRSB002\x02\x00' if compressed else b'BLRSB001\x01\x00'), 'signature header')
    require(signature[10:74] == statement_id and signature[74:138] == proof_id and signature[138:202] == ring_id,
            'signature identifiers')
    require(all(x[0] < 65437 for x in struct.iter_unpack('<H', signature[202:458])), 'tag residues')
    require(struct.unpack_from('<Q', signature, 458)[0] == len(signature)-466, 'body length')
    values = decode_compressed(signature[466:], manifest) if compressed else decode_raw(signature[466:])
    validate_body(values, manifest)
    print('Independent identifiers, CRS, challenge, evaluation lanes and wire bounds passed.')
    return {suffix: hashlib.sha256(read(suffix)).hexdigest() for suffix in
        ('.manifest.json', '.statement.bin', '.crs.bin', '.ring.bin', '.message.bin', '.signature.bin')}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('prefix', nargs='?', default='benchmark_results.json', type=Path)
    parser.add_argument('--digest-output', type=Path)
    args = parser.parse_args()
    digests = check(args.prefix)
    if args.digest_output:
        args.digest_output.write_text(json.dumps(digests, indent=2) + '\n', encoding='utf-8')
