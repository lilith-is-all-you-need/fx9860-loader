"""Versioned offline profile codec. ABI declarations are not compatibility proofs."""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path

MAGIC = b"FXEXT002"
HEADER = b"FXLARGE-PAYLOAD1"
LEGACY_HEADER = b"KHICAS-MAPPED/1\0"
BASE = 0x00300000
PAGE_BYTES = 4096
MAX_PAGES = 768  # backend policy, not a measured Flash capacity
STORAGE_BUDGET = 3_000_000  # conservative package budget; includes reserve
DEFAULT_RESERVE = 8192
LEGACY_SHA256 = "176a10ffa918f24f0b98ef89156dc04b02df09190dae0fbe0e3d59780e9455f8"

def inspect_image(image: bytes) -> dict:
    if len(image) < 516:
        raise ValueError("image too small")
    digest = hashlib.sha256(image).hexdigest()
    if image[:16] == HEADER:
        version, entry, raw_bytes, abi, features = struct.unpack_from(">5I", image, 16)
        if (version, entry, raw_bytes, abi, features) != (1, BASE + 512, len(image)-512, 1, 1):
            raise ValueError("unsupported source runtime header")
        if any(image[36:512]):
            raise ValueError("reserved header bytes must be zero")
        evidence = "source-declared-ABI-needs-hardware-test"
    elif digest == LEGACY_SHA256 and image[:16] == LEGACY_HEADER:
        # The checked binary is the only legacy artifact admitted here.
        evidence = "reviewed-Giac-map-v1-adapter"
    else:
        raise ValueError("unsupported runtime: source integration or reviewed binary adapter required")
    return {"imageBytes": len(image), "pageCount": (len(image)+4095)//4096,
            "imageBase": BASE, "entry": BASE+512, "runtimeABI": 1,
            "sha256": digest, "evidence": evidence, "hardwareValidated": False}

def encode_profile(image: bytes, *, capacity: int | None = None,
                   min_free_bytes: int = DEFAULT_RESERVE, guest_ram_bytes: int = 0) -> bytes:
    info = inspect_image(image)
    count = info["pageCount"]
    if capacity is None:
        capacity = (count+15) & ~15
    if not (count <= capacity <= MAX_PAGES):
        raise ValueError("page count/capacity exceeds the configured backend window")
    if not (0 <= min_free_bytes <= STORAGE_BUDGET and 0 <= guest_ram_bytes <= 512*1024):
        raise ValueError("invalid storage or guest RAM budget")
    # 128 profile bytes and 64 metadata bytes are included; the actual device
    # free-space requirement is checked again before executing the payload.
    if len(image)+128+64+min_free_bytes > STORAGE_BUDGET:
        raise ValueError("image plus profile and reserve exceeds the package storage budget")
    out = bytearray(128)
    out[:8] = MAGIC
    struct.pack_into(">10I", out, 8, 2, len(image), BASE, BASE+512, count,
                     capacity, 1, 1, min_free_bytes, guest_ram_bytes)
    out[48:80] = bytes.fromhex(info["sha256"])
    return bytes(out)

def decode_profile(data: bytes) -> dict:
    if len(data) != 128 or data[:8] != MAGIC:
        raise ValueError("EXT.PRF must be 128 bytes with FXEXT002 magic")
    v, size, base, entry, pages, capacity, abi, flags, reserve, ram = struct.unpack_from(">10I", data, 8)
    if (v, base, entry, abi, flags) != (2, BASE, BASE+512, 1, 1):
        raise ValueError("unsupported profile ABI or flags")
    if size < 516 or pages != (size+4095)//4096 or not pages <= capacity <= MAX_PAGES:
        raise ValueError("invalid image/page/capacity bounds")
    if size+192+reserve > STORAGE_BUDGET or ram > 512*1024:
        raise ValueError("storage or RAM budget exceeds policy")
    if any(data[80:]):
        raise ValueError("binary hook records are not executable in ABI v2")
    return dict(version=v, imageBytes=size, imageBase=base, entry=entry,
                pageCount=pages, pageCapacity=capacity, runtimeABI=abi, flags=flags,
                minFreeBytes=reserve, guestRamBytes=ram, sha256=data[48:80].hex(), hookCount=0)

def prepare(input_path: str | Path, output_dir: str | Path, **options) -> dict:
    image = Path(input_path).read_bytes()
    profile = encode_profile(image, **options)
    output = Path(output_dir)
    report = {**inspect_image(image), **decode_profile(profile), "loader": "ExtLoad.g1a"}
    writes = (("IMAGE.BIN", image), ("EXT.PRF", profile),
              ("ext-analysis.json", (json.dumps(report, indent=2)+"\n").encode("utf-8")))
    # Validate the entire write set before creating any member of the package.
    # This also makes a profile-only stale destination fail without adding BIN.
    for name, data in writes:
        path = output / name
        if path.exists() and path.read_bytes() != data:
            raise FileExistsError(path)
    output.mkdir(parents=True, exist_ok=True)
    for name, data in writes:
        path = output / name
        if not path.exists():
            with path.open("xb") as stream:
                stream.write(data)
    return report

def wrap_raw(raw: bytes) -> bytes:
    header = bytearray(512)
    header[:16] = HEADER
    struct.pack_into(">5I", header, 16, 1, BASE+512, len(raw), 1, 1)
    return bytes(header)+raw

if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("input", type=Path); p.add_argument("output", type=Path)
    p.add_argument("--capacity", type=int)
    p.add_argument("--reserve", type=int, default=DEFAULT_RESERVE)
    p.add_argument("--guest-ram", type=int, default=0)
    a = p.parse_args()
    print(json.dumps(prepare(a.input, a.output, capacity=a.capacity,
                            min_free_bytes=a.reserve, guest_ram_bytes=a.guest_ram), indent=2))
