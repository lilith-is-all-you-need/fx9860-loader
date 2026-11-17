"""Bind analyst-selected hook sites to bytes. This does not emit runnable hooks."""
import hashlib
import json
from pathlib import Path

KINDS = {"entry", "vbr-write", "tlb-handler", "syscall-gate", "world-transition", "exit"}
REQUIRED = {"entry", "vbr-write", "tlb-handler", "syscall-gate", "world-transition", "exit"}

def review(image: bytes, evidence: dict) -> dict:
    digest = hashlib.sha256(image).hexdigest()
    if evidence.get("imageSha256") != digest:
        raise ValueError("Ghidra evidence is for different image bytes")
    if evidence.get("architecture") != "SuperH4-BE-32":
        raise ValueError("unsupported processor contract")
    sites = evidence.get("hooks", [])
    seen = set()
    for site in sites:
        kind, offset = site.get("kind"), site.get("fileOffset")
        if kind not in KINDS or type(offset) is not int or offset < 512 or offset & 1:
            raise ValueError("invalid hook kind/offset")
        try:
            expected = bytes.fromhex(site["expectedHex"])
        except (KeyError, TypeError, ValueError) as ex:
            raise ValueError("missing exact instruction bytes") from ex
        if len(expected) < 2 or len(expected) & 1 or offset+len(expected)>len(image):
            raise ValueError("hook byte range is invalid")
        if image[offset:offset+len(expected)] != expected:
            raise ValueError("hook instruction bytes have changed")
        if site.get("virtualAddress") != 0x300000+offset:
            raise ValueError("file/virtual offset mismatch")
        if site.get("delaySlotIncluded") is not True:
            raise ValueError("hook requires an explicit delay-slot review")
        if not site.get("callingConvention") or not site.get("registerPreservation"):
            raise ValueError("hook requires a calling/register convention")
        seen.add(kind)
    contract = evidence.get("exceptionContract", {})
    needed = ("vbrOwner", "residentHandlerRange", "previousHandlerChain", "restoreOrder", "unwindFailure")
    if any(not contract.get(key) for key in needed):
        raise ValueError("incomplete exception ownership/restoration contract")
    return {"imageSha256": digest, "reviewedSites": len(sites),
            "missingKinds": sorted(REQUIRED-seen), "evidenceBound": True,
            "runnable": False, "reason": "ABI v2 does not execute arbitrary binary hook patches; source adapter required"}

if __name__ == "__main__":
    import argparse
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("image",type=Path);p.add_argument("evidence",type=Path)
    a=p.parse_args();print(json.dumps(review(a.image.read_bytes(),json.loads(a.evidence.read_text(encoding="utf-8"))),indent=2))
