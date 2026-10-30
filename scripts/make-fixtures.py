"""Make the LZMS chunks for the WIM tests with the Windows Compression API (cabinet.dll).

The tests in tests/wim/ build WIM files around these chunks. A fixed-seed generator makes the
uncompressed data, and tests/wim/data.rs has the same generator. The script uses the oracle
script of the lzms crate, which must be in ../lzms. Run it on Windows with PowerShell 7:

    python scripts/make-fixtures.py
"""

import hashlib
import json
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
ORACLE = ROOT.parent / "lzms" / "scripts" / "lzms-oracle.ps1"
MASK = (1 << 64) - 1
MASK32 = (1 << 32) - 1

WORDS = [
    b"the", b"image", b"stream", b"resource", b"chunk", b"lookup", b"table", b"solid",
    b"header", b"dentry", b"update", b"package", b"payload", b"delta", b"index", b"file",
]


class Rng:
    """SplitMix64. tests/wim/data.rs has the same generator."""

    def __init__(self, seed):
        self.state = seed & MASK

    def next(self):
        self.state = (self.state + 0x9E3779B97F4A7C15) & MASK
        z = self.state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK
        return z ^ (z >> 31)

    def below(self, n):
        return self.next() % n


def text(seed, n):
    rng = Rng(seed)
    out = bytearray()
    while len(out) < n:
        out += WORDS[rng.below(len(WORDS))]
        out += b" " if rng.below(8) else b"\n"
    return bytes(out[:n])


def calls(seed, n):
    """Make bytes like x86 code: calls to a few targets between filler bytes."""
    rng = Rng(seed)
    targets = [rng.below(1 << 20) for _ in range(32)]
    out = bytearray()
    while len(out) < n:
        if rng.below(3) == 0:
            target = targets[rng.below(len(targets))]
            out += b"\xe8" + ((target - len(out) - 5) & MASK32).to_bytes(4, "little")
        else:
            out += b"\x90\x55\x48\x89\xe5"[: 1 + rng.below(5)]
    return bytes(out[:n])


# The chunked file: 300000 bytes in chunks of 128 KiB.
CHUNKED = text(31, 300000)
# The solid data: three files, in chunks of 256 KiB.
SOLID = text(32, 200000) + calls(33, 150000) + text(34, 50000)


def chunks(data, size):
    return [data[i:i + size] for i in range(0, len(data), size)]


# name -> uncompressed chunk. Keep tests/wim/data.rs in sync.
def cases():
    out = {}
    for i, chunk in enumerate(chunks(CHUNKED, 131072)):
        out[f"chunked-{i}"] = chunk
    for i, chunk in enumerate(chunks(SOLID, 262144)):
        out[f"solid-{i}"] = chunk
    return out


def oracle(*args):
    subprocess.run(["pwsh", "-NoProfile", "-File", str(ORACLE), *map(str, args)],
                   check=True, capture_output=True, text=True)


def main():
    FIXTURES.mkdir(parents=True, exist_ok=True)
    manifest = {}
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        for name, data in cases().items():
            src, out, check = tmp / "in", FIXTURES / f"{name}.lzms", tmp / "check"
            src.write_bytes(data)
            args = ["compress", "-In", src, "-Out", out, "-Raw"]
            if len(data) > 65536:
                args += ["-BlockSize", len(data)]
            oracle(*args)
            oracle("decompress", "-In", out, "-Out", check, "-Raw", "-Size", len(data))
            assert check.read_bytes() == data, name
            assert out.stat().st_size < len(data), name
            manifest[name] = {
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "compressed_bytes": out.stat().st_size,
            }
            print(f"{name}: {len(data)} -> {out.stat().st_size} bytes")
    (FIXTURES / "manifest.json").write_bytes((json.dumps(manifest, indent=2) + "\n").encode())


if __name__ == "__main__":
    main()
