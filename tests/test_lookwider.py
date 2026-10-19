import contextlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
import zlib

import lookwider as lw


def chunk(kind, payload):
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)


def png(width=3, height=2, actual_height=5, depth=8, color=2, interlace=0, raw=None):
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color]
    row = (width * channels * depth + 7) // 8
    if raw is None:
        raw = b"".join(b"\0" + bytes([i % 256]) * row for i in range(actual_height))
    packed = zlib.compress(raw)
    split = len(packed) // 2
    return (lw.PNG + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, depth, color, 0, 0, interlace))
            + chunk(b"IDAT", packed[:split]) + chunk(b"IDAT", packed[split:]) + chunk(b"IEND", b""))


def bmp(top_down=False, core=False, tail=b"", profile=False):
    width, declared, actual, bpp = 3, 2, 5, 24
    stride = 12
    dib_size = 12 if core else 124 if profile else 40
    offset = 14 + dib_size
    pixels = b"x" * stride * actual
    dib = bytearray(dib_size)
    struct.pack_into("<I", dib, 0, dib_size)
    if core:
        struct.pack_into("<HHHH", dib, 4, width, declared, 1, bpp)
    else:
        struct.pack_into("<iiHHII", dib, 4, width, -declared if top_down else declared, 1, bpp, 0, stride * declared)
    if profile:
        struct.pack_into("<II", dib, 112, dib_size + len(pixels), len(tail))
    return b"BM" + struct.pack("<IHHI", offset + len(pixels) + len(tail), 0, 0, offset) + dib + pixels + tail


def jpeg(marker=0xC0):
    app = b"\xff\xe1" + struct.pack(">H", 8) + b"abc123"
    sof = b"\xff" + bytes([marker]) + struct.pack(">HBHHB", 11, 8, 20, 30, 1) + b"\1\x11\0"
    return b"\xff\xd8" + app + sof + b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00payload\xff\xd9"


class PNGTests(unittest.TestCase):
    def test_recovers_split_idat_and_crc_without_reencoding(self):
        data = bytearray(png())
        data[29] ^= 1
        data = bytes(data)
        info = lw.parse(data)
        self.assertEqual(len(info["bad_crc"]), 1)
        candidate = lw.infer(data, info)
        self.assertEqual(candidate["height"], 5)
        restored = lw.patch(data, info, height=5)
        self.assertEqual(lw.parse(restored)["bad_crc"], [])
        self.assertEqual(restored[33:], data[33:])
        self.assertEqual(len(restored), len(data))

    def test_packed_and_16bit_rows(self):
        for color, depth in ((0, 1), (0, 2), (3, 4), (2, 16), (4, 16), (6, 8)):
            with self.subTest(color=color, depth=depth):
                data = png(depth=depth, color=color)
                self.assertEqual(lw.infer(data, lw.parse(data))["height"], 5)

    def test_width_override(self):
        original = png()
        data = lw.patch(original, lw.parse(original), width=2)
        self.assertEqual(lw.infer(data, lw.parse(data), width=3)["height"], 5)

    def test_rejects_bad_filters_and_incomplete_rows(self):
        for raw in (b"\5" + b"x" * 9, b"\0" + b"x" * 8):
            data = png(raw=raw)
            with self.assertRaises(lw.ImageError):
                lw.infer(data, lw.parse(data))

    def test_decompression_limit(self):
        data = png(actual_height=1000)
        with self.assertRaisesRegex(lw.ImageError, "max-mib"):
            lw.infer(data, lw.parse(data), limit=100)

    def test_truncated_zlib(self):
        data = png()
        chunks = []
        for kind, pos, size in lw.parse(data)["_chunks"]:
            payload = data[pos + 8:pos + 8 + size]
            if kind == b"IDAT":
                payload = payload[:-2]
            chunks.append(chunk(kind, payload))
        broken = lw.PNG + b"".join(chunks)
        with self.assertRaises(lw.ImageError):
            lw.infer(broken, lw.parse(broken))

    def test_trailer_is_not_counted_as_rows(self):
        data = png() + b"secret trailer"
        info = lw.parse(data)
        self.assertEqual(info["trailing_bytes"], 14)
        self.assertEqual(lw.infer(data, info)["height"], 5)
        self.assertTrue(lw.patch(data, info, height=5).endswith(b"secret trailer"))

    def test_extra_zlib_data_reported(self):
        data = png()
        chunks = []
        positions = [p for k, p, _ in lw.parse(data)["_chunks"] if k == b"IDAT"]
        for kind, pos, size in lw.parse(data)["_chunks"]:
            payload = data[pos + 8:pos + 8 + size]
            if kind == b"IDAT" and pos == positions[-1]:
                payload += b"tail"
            chunks.append(chunk(kind, payload))
        changed = lw.PNG + b"".join(chunks)
        self.assertEqual(lw.infer(changed, lw.parse(changed))["extra_compressed_bytes"], 4)

    def test_interlace_requires_manual_size(self):
        data = png(interlace=1)
        with self.assertRaisesRegex(lw.ImageError, "Adam7"):
            lw.infer(data, lw.parse(data))
        self.assertEqual(lw.parse(lw.patch(data, lw.parse(data), height=5))["height"], 5)

    def test_apng_diagnosed_but_not_patched(self):
        data = png()
        data = data[:33] + chunk(b"acTL", struct.pack(">II", 2, 0)) + data[33:]
        info = lw.parse(data)
        self.assertTrue(info["animated"])
        with self.assertRaises(lw.ImageError):
            lw.patch(data, info, height=5)


class BMPTests(unittest.TestCase):
    def test_restores_both_row_orders_and_core(self):
        for top_down, core in ((False, False), (True, False), (False, True)):
            data = bmp(top_down, core)
            info = lw.parse(data)
            self.assertEqual(lw.infer(data, info)["height"], 5)
            out = lw.patch(data, info, height=5)
            new = lw.parse(out)
            self.assertEqual(new["height"], 5)
            self.assertEqual(new["top_down"], top_down)
            self.assertEqual(out[info["_offset"]:], data[info["_offset"]:])
            if not core:
                self.assertEqual(new["declared_pixel_bytes"], 60)

    def test_profile_excluded(self):
        data = bmp(tail=b"profile" * 12, profile=True)
        self.assertEqual(lw.infer(data, lw.parse(data))["height"], 5)

    def test_ambiguous_tail_refused(self):
        data = bmp(tail=b"?")
        with self.assertRaises(lw.ImageError):
            lw.infer(data, lw.parse(data))

    def test_cannot_invent_pixels(self):
        data = bmp()
        with self.assertRaises(lw.ImageError):
            lw.patch(data, lw.parse(data), height=100)

    def test_compressed_refused(self):
        data = bytearray(bmp())
        struct.pack_into("<I", data, 30, 1)
        with self.assertRaises(lw.ImageError):
            lw.infer(data, lw.parse(data))


class JPEGTests(unittest.TestCase):
    def test_sof_baseline_and_progressive(self):
        for marker in (0xC0, 0xC2):
            data = jpeg(marker)
            info = lw.parse(data)
            self.assertEqual((info["width"], info["height"]), (30, 20))
            out = lw.patch(data, info, width=42, height=1000)
            new = lw.parse(out)
            self.assertEqual((new["width"], new["height"]), (42, 1000))
            changed = {i for i, (a, b) in enumerate(zip(data, out)) if a != b}
            allowed = {info["_width_offset"], info["_width_offset"] + 1,
                       info["_height_offset"], info["_height_offset"] + 1}
            self.assertLessEqual(changed, allowed)
            with self.assertRaises(lw.ImageError):
                lw.infer(data, info)

    def test_size_range(self):
        data = jpeg()
        with self.assertRaises(lw.ImageError):
            lw.patch(data, lw.parse(data), height=65536)


class CLITests(unittest.TestCase):
    def test_workflow_wrong_extension_json_and_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "fake.jpg"
            source.write_bytes(png())
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(lw.main(["inspect", str(source), "--json"]), 0)
                self.assertEqual(json.loads(stdout.getvalue())["format"], "PNG")
                self.assertEqual(lw.main(["recover", str(source)]), 0)
                output = source.with_name("fake.recovered.png")
                self.assertEqual(lw.parse(output.read_bytes())["height"], 5)
                self.assertEqual(lw.main(["recover", str(source)]), 1)
                self.assertEqual(lw.main(["recover", str(source), "--force"]), 0)
                self.assertEqual(lw.main(["set", str(source), "--height", "5", "-o", str(source), "--force"]), 1)
            self.assertEqual(source.read_bytes(), png())

    def test_sweep_preflight(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "test.jpg"
            source.write_bytes(jpeg())
            outdir = Path(directory) / "variants"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(lw.main(["sweep", str(source), "--heights", "100:300:100", "-d", str(outdir)]), 0)
                self.assertEqual(len(list(outdir.glob("*.jpg"))), 3)
                self.assertEqual(lw.main(["sweep", str(source), "--heights", "50:150:50", "-d", str(outdir)]), 1)
            self.assertFalse((outdir / "test_30x50.jpg").exists())

    def test_invalid_inputs_are_controlled_errors(self):
        for data in (b"", lw.PNG, b"BM", b"\xff\xd8", png()[:-1], jpeg()[:9]):
            with self.subTest(data=data[:8]), self.assertRaises(lw.ImageError):
                lw.parse(data)


if __name__ == "__main__":
    unittest.main()
