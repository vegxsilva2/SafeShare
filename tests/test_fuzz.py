"""Deterministic fuzzing: hostile input must never crash or yield an unverified file."""
import random
import unittest

import helpers
from helpers import fixture, insert_after_soi, segment
from safeshare.jpeg import (
    JPEGFormatError,
    PrivacyMode,
    SanitizeOptions,
    inspect_bytes,
    sanitize_bytes,
)


def seed_corpus() -> list[bytes]:
    base = fixture("rgb_baseline.jpg")
    return [
        base,
        fixture("rgb_progressive.jpg"),
        fixture("rgb_restart.jpg"),
        fixture("cmyk_adobe.jpg"),
        insert_after_soi(
            base,
            segment(0xE1, helpers.rich_exif()),
            segment(0xE1, b"http://ns.adobe.com/xap/1.0/\x00<x:xmpmeta>GPSLatitude</x:xmpmeta>"),
            segment(0xE2, b"ICC_PROFILE\x00\x01\x01" + b"\x00" * 40),
            segment(0xFE, b"comment"),
        ) + b"\xff\xd8\xff\xd9trailer",
    ]


def mutate(rng: random.Random, data: bytes) -> bytes:
    buf = bytearray(data)
    for _ in range(rng.randint(1, 6)):
        choice = rng.random()
        if not buf:
            break
        pos = rng.randrange(len(buf))
        if choice < 0.45:
            buf[pos] = rng.randrange(256)
        elif choice < 0.60:
            buf[pos] ^= 1 << rng.randrange(8)
        elif choice < 0.75:
            del buf[pos:pos + rng.randint(1, 8)]
        elif choice < 0.90:
            buf[pos:pos] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 8)))
        else:
            del buf[pos:]
    return bytes(buf)


class FuzzTests(unittest.TestCase):
    def test_random_mutations_never_crash_and_always_verify(self):
        rng = random.Random(20261018)
        corpus = seed_corpus()
        accepted = rejected = 0
        for i in range(4000):
            data = mutate(rng, rng.choice(corpus))
            try:
                inspect_bytes(data)
            except JPEGFormatError:
                rejected += 1
                with self.assertRaises(JPEGFormatError):
                    sanitize_bytes(data)
                continue
            accepted += 1
            for mode in PrivacyMode:
                out, result = sanitize_bytes(data, SanitizeOptions(mode))
                self.assertTrue(result.verification.passed, (i, mode))
                after = inspect_bytes(out)
                self.assertEqual(after.image_digest, inspect_bytes(data).image_digest)
                self.assertIsNone(after.trailing)
        self.assertGreater(accepted, 200)
        self.assertGreater(rejected, 200)

    def test_random_garbage_is_rejected_cleanly(self):
        rng = random.Random(7)
        for _ in range(500):
            blob = bytes(rng.randrange(256) for _ in range(rng.randint(0, 300)))
            with self.assertRaises(JPEGFormatError):
                inspect_bytes(blob)
        for _ in range(500):
            blob = b"\xff\xd8" + bytes(rng.randrange(256) for _ in range(rng.randint(0, 300)))
            try:
                inspect_bytes(blob)
            except JPEGFormatError:
                pass


if __name__ == "__main__":
    unittest.main()
