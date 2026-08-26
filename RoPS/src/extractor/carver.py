#!/usr/bin/env python3
"""extractor.carver — Pickle blob extraction from model files.

Supports ZIP (including streaming ZIP without Central Directory), GZIP, BZIP2,
LZMA, XZ, LZ4, zlib deflate (compressed joblib), raw pickle, and joblib-interleaved formats.

Public API
----------
extract_pickles(path, out_dir, max_decompressed) -> ExtractionReport
"""
from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import json
import lzma
import math
import pickletools
import re
import struct
import tarfile
import zipfile
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import BinaryIO, List, Optional, Set, Tuple, Dict, Any

try:
    import lz4.frame as lz4frame  # type: ignore
except Exception:  # pragma: no cover
    lz4frame = None

try:
    import numpy as np  # type: ignore
except Exception:  # pragma: no cover
    np = None


PK_LOCAL_FILE_HEADER_SIG = 0x04034B50
PICKLE_PROTO_MIN = 0x02
PICKLE_PROTO_MAX = 0x05
READ_CHUNK = 1024 * 1024
MAX_DEPTH  = 6          
ERR_POS_RE = re.compile(r"at position (\d+)")






MAX_JOIN_BYTES = 8 * 1024 * 1024



#



#     p50 1.00 / p90 1.00 / p99 1.07 / p99.9 2.52 / max 363.17


#




#


MAX_INFLATE_BYTES = 2 * 1024 * 1024 * 1024
MAX_INFLATE_RATIO = 1100


@dataclass
class PickleBlob:
    logical_name: str
    source_kind: str
    size: int
    sha256: str
    container_path: str
    note: str = ""
    offset_start: Optional[int] = None
    offset_end: Optional[int] = None
    compression: Optional[str] = None
    pickle_validated: bool = False
    first_opcodes: Optional[List[str]] = None
    output_path: Optional[str] = None
    complete: bool = True       
    resync_count: int = 0       


@dataclass
class ExtractionReport:
    input_path: str
    file_size: int
    file_type: str
    blobs: List[PickleBlob]
    errors: List[str]
    logs: List[str] = field(default_factory=list)
    
    
    
    container_findings: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class LayoutSegment:
    kind: str
    start: int
    end: int
    detail: str = ""


@dataclass
class AnalysisLayout:
    file_type: str
    extraction_mode: str
    description: str
    wrapper: Optional[str] = None
    segments: List[LayoutSegment] = field(default_factory=list)
    logs: List[str] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_probable_pickle_prefix(data: bytes) -> bool:
    # Protocol 2-5: \x80 + proto byte
    if len(data) >= 2 and data[0] == 0x80 and PICKLE_PROTO_MIN <= data[1] <= PICKLE_PROTO_MAX:
        return True
    # Protocol 0/1 start bytes (opcodes that commonly appear at position 0)
    # Includes EDP-style malformed pickles that put STRING/GLOBAL/INST at offset 0
    return data[:1] in {b"(", b"c", b"}", b"]", b")", b"S", b"V", b"I", b"N", b"i", b"l", b"t", b"d"}


def first_opcodes(data: bytes, limit: int = 12) -> List[str]:
    ops: List[str] = []
    try:
        for i, (op, arg, pos) in enumerate(pickletools.genops(data)):
            ops.append(op.name)
            if i + 1 >= limit:
                break
    except Exception:
        pass
    return ops


def validate_pickle_complete(data: bytes) -> bool:
    """Internal implementation detail."""
    try:
        for op, arg, pos in pickletools.genops(data):
            if op.name == "STOP":
                return pos + 1 == len(data)
        return False
    except Exception:
        return False


def validate_pickle_parsed(data: bytes) -> bool:
    """Internal implementation detail."""
    try:
        saw_any = False
        for op, arg, pos in pickletools.genops(data):
            saw_any = True
            if op.name == "STOP":
                return True
        return saw_any
    except Exception:
        return False



validate_pickle = validate_pickle_complete


def parse_error_position(exc: Exception) -> Optional[int]:
    m = ERR_POS_RE.search(str(exc))
    return int(m.group(1)) if m else None


def round_up(value: int, align: int) -> int:
    if align <= 1:
        return value
    return ((value + align - 1) // align) * align


def safe_name(name: str) -> str:
    return name.replace("/", "__").replace("\\", "__").replace("!", "__")




_UNSAFE_MEMBER_RE = re.compile(r"(?:^|[\\/])\.\.(?:[\\/]|$)|^[\\/]|^[A-Za-z]:[\\/]")


def scan_member_names(path: Path) -> List[Dict[str, str]]:
    """Internal implementation detail."""
    out: List[Dict[str, str]] = []
    names: List[str] = []
    try:
        if zipfile.is_zipfile(str(path)):
            with zipfile.ZipFile(str(path)) as zf:
                names = [zi.filename for zi in zf.infolist()]
        elif tarfile.is_tarfile(str(path)):
            with tarfile.open(str(path), "r:*") as tf:
                names = [m.name for m in tf.getmembers()]
    except Exception:
        return out
    bad = [n for n in names if _UNSAFE_MEMBER_RE.search(n or "")]
    for n in sorted(set(bad))[:8]:
        out.append({
            "kind": "archive_path_traversal",
            "member": n[:160],
            "evidence": "Archive entry escapes the extraction path (tar-slip / zip-slip), "
                        "allowing extraction to write to an arbitrary location",
        })
    return out


def _flag_duplicate_members(names: List[str], logs: List[str], label: str) -> None:
    """Internal implementation detail."""
    from collections import Counter
    dup = [n for n, c in Counter(names).items() if c > 1]
    if dup:
        logs.append("container(%s): **%d duplicate entry names** %s create parser-dependent "
                    "ambiguity; extracting every entry separately."
                    % (label, len(dup), ", ".join(sorted(dup)[:5])))


def write_blob(out_dir: Path, src_path: Path, logical_name: str, data: bytes) -> Path:
    """Internal implementation detail."""
    sub = out_dir / safe_name(src_path.name)
    sub.mkdir(parents=True, exist_ok=True)
    base = safe_name(logical_name)
    out = sub / (base + ".pkl")
    if out.exists():
        try:
            same = out.read_bytes() == data
        except OSError:
            same = False
        if not same:
            
            out = sub / ("%s.%s.pkl" % (base, hashlib.sha256(data).hexdigest()[:8]))
    out.write_bytes(data)
    return out


def read_all_streaming(reader: BinaryIO, max_bytes: Optional[int] = None) -> bytes:
    parts: List[bytes] = []
    total = 0
    while True:
        chunk = reader.read(READ_CHUNK)
        if not chunk:
            break
        parts.append(chunk)
        total += len(chunk)
        if max_bytes is not None and total > max_bytes:
            raise ValueError(f"Decompressed payload exceeds limit {max_bytes}")
    return b"".join(parts)


def detect_file_kind_from_head(head: bytes) -> str:
    if head.startswith(b"PK\x03\x04"):
        return "zip"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"BZh"):
        return "bzip2"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "lzma"
    if len(head) >= 6 and head[0] in range(0x5D, 0xE1) and head[1:5] in {
        b"\x00\x00\x80\x00", b"\x00\x00\x10\x00", b"\x00\x00@\x00", b"\x00\x00\x01\x00"
    }:
        return "lzma"
    if head.startswith(b"\x04\x22\x4d\x18"):
        return "lz4"
    # zlib deflate streams: first byte 0x78, (byte0*256+byte1) % 31 == 0
    # Joblib compress=('zlib', N) produces this format.
    if len(head) >= 2 and head[0] == 0x78 and (head[0] * 256 + head[1]) % 31 == 0:
        return "zlib_deflate"
    if is_probable_pickle_prefix(head):
        return "raw_pickle"
    return "unknown"


def detect_file_kind(path: Path) -> str:
    with path.open("rb") as fp:
        return detect_file_kind_from_head(fp.read(16))


def score_zip_member(name: str) -> int:
    """Internal implementation detail."""
    low = name.lower()
    score = 0
    if low.endswith("/data.pkl"):
        score += 100
    if low.endswith((".pkl", ".pickle", ".joblib", ".p")):
        score += 40
    if low.endswith((".pt", ".pth", ".bin", ".ckpt")):
        score += 20
    
    if low.endswith((".gz", ".bz2", ".xz", ".lzma", ".lz4", ".tar", ".mar",
                     ".zip", ".npy", ".npz")):
        score += 5
    if "/data/" in low:
        score -= 50
    if low.endswith(("byteorder", "version", "serialization_id")):
        score -= 30
    return score




_MEMBER_MAGIC: Tuple[Tuple[bytes, str], ...] = (
    (b"PK\x03\x04", "zip"), (b"PK\x05\x06", "zip"), (b"PK\x07\x08", "zip"),
    (b"\x93NUMPY", "npy"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"\x04\x22\x4d\x18", "lz4"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
)


def sniff_member_kind(head: bytes) -> str:
    """Internal implementation detail."""
    for magic, kind in _MEMBER_MAGIC:
        if head.startswith(magic):
            return kind
    
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    if is_probable_pickle_prefix(head):
        return "pickle"
    return ""


def member_admits(name: str, head: bytes) -> bool:
    """Internal implementation detail."""
    kind = sniff_member_kind(head)
    if kind and kind != "pickle":
        return True                       
    if kind == "pickle":
        if head[:1] == b"\x80" and len(head) > 1 and head[1] in _PGS_VALID_PROTOS:
            return True                   
        
        return _pgs_count_valid_opcodes(head, 0, _PGS_MIN_OPCODES) >= _PGS_MIN_OPCODES
    return score_zip_member(name) > 0


def compression_name(zip_method: int) -> str:
    return {
        zipfile.ZIP_STORED: "stored",
        zipfile.ZIP_DEFLATED: "deflated",
        getattr(zipfile, "ZIP_BZIP2", 12): "bzip2",
        getattr(zipfile, "ZIP_LZMA", 14): "lzma",
    }.get(zip_method, f"zip_method_{zip_method}")




_PK_LOCAL   = b"PK\x03\x04"   # Local File Header signature
_PK_DD_SIG  = b"PK\x07\x08"   # Data Descriptor signature (optional)
_PK_ANY     = b"PK"            


# <IHHHHHIIIHH : sig(4) ver(2) flags(2) comp(2) mtime(2) mdate(2)
#                crc(4)  csz(4) usz(4)  nlen(2) elen(2)
_LFH_FMT  = "<IHHHHHIIIHH"
_LFH_SIZE = struct.calcsize(_LFH_FMT)   # == 30


@dataclass
class LocalEntry:
    """Internal implementation detail."""
    offset: int        
    name: str          
    compression: int   # 0=stored, 8=deflated
    flags: int         # general purpose bit flag
    csz: int           
    usz: int           
    data_offset: int   
    data_end: int      


def _find_entry_end_stored(data: bytes, data_start: int) -> int:
    """Internal implementation detail."""
    pos = data_start
    while pos < len(data) - 1:
        
        pk = data.find(b"PK", pos)
        if pk < 0:
            return len(data)  # EOF

        # Data Descriptor sig: PK\x07\x08 + crc(4) + csz(4) + usz(4)  = 16B
        
        if data[pk:pk + 4] == _PK_DD_SIG:
            return pk  

        if data[pk:pk + 4] == _PK_LOCAL:
            
            # with-sig:    [DD_SIG(4)] [crc(4)] [csz(4)] [usz(4)] = 16 bytes before PK\x03\x04
            # without-sig: [crc(4)]    [csz(4)] [usz(4)]          = 12 bytes before PK\x03\x04
            for dd_bytes in (16, 12):
                candidate = pk - dd_bytes
                if candidate >= data_start:
                    return candidate
            return pk  

        
        if pk + 4 <= len(data) and data[pk:pk + 2] == b"PK":
            next_sig = data[pk:pk + 4]
            if next_sig in (b"PK\x01\x02", b"PK\x05\x06", b"PK\x06\x06"):
                return pk
        pos = pk + 1

    return len(data)


def _find_entry_end_deflated(data: bytes, data_start: int) -> int:
    """Internal implementation detail."""
    import zlib
    d = zlib.decompressobj(wbits=-15)  # raw deflate
    pos = data_start
    chunk = 4096
    while pos < len(data):
        block = data[pos: pos + chunk]
        try:
            d.decompress(block)
        except zlib.error:
            
            break
        pos += chunk
        if d.eof:
            pos = data_start + (len(data) - pos + chunk - len(d.unused_data)
                                ) if d.unused_data else pos
            
            pos -= len(d.unused_data)
            break
    return min(pos, len(data))


def _parse_local_headers(data: bytes) -> List[LocalEntry]:
    """Internal implementation detail."""
    entries: List[LocalEntry] = []
    pos = 0
    n = len(data)

    while pos < n - _LFH_SIZE:
        idx = data.find(_PK_LOCAL, pos)
        if idx < 0:
            break
        if idx + _LFH_SIZE > n:
            break

        try:
            sig, ver, flags, comp, mtime, mdate, crc, csz, usz, nlen, elen =\
                struct.unpack_from(_LFH_FMT, data, idx)
        except struct.error:
            pos = idx + 4
            continue

        if sig != PK_LOCAL_FILE_HEADER_SIG:
            pos = idx + 4
            continue

        name_start = idx + _LFH_SIZE
        name_end   = name_start + nlen
        data_start = name_end + elen

        if name_end > n or data_start > n:
            pos = idx + 4
            continue

        name = data[name_start:name_end].decode("utf-8", errors="replace")

        
        has_dd = bool(flags & 0x0008)  
        if csz > 0 and not has_dd:
            
            data_end = data_start + csz
        else:
            
            if comp == 8:  # deflated
                data_end = _find_entry_end_deflated(data, data_start)
            else:          # stored (comp == 0 or unknown)
                data_end = _find_entry_end_stored(data, data_start)

        data_end = min(data_end, n)

        entries.append(LocalEntry(
            offset=idx,
            name=name,
            compression=comp,
            flags=flags,
            csz=csz,
            usz=usz,
            data_offset=data_start,
            data_end=data_end,
        ))

        
        pos = max(idx + 4, data_end)

    return entries


def local_data_offset(fp: BinaryIO, header_offset: int) -> int:
    fp.seek(header_offset)
    raw = fp.read(30)
    if len(raw) != 30:
        raise ValueError("Short local file header")
    sig, ver, flag, comp, mtime, mdate, crc, csize, usize, nlen, elen = struct.unpack("<IHHHHHIIIHH", raw)
    if sig != PK_LOCAL_FILE_HEADER_SIG:
        raise ValueError(f"Bad local file header signature at {header_offset}")
    return header_offset + 30 + nlen + elen


# ---------- analyzer helpers for joblib/raw pickle ----------
def is_int_opcode(name: str) -> bool:
    return name in {"BININT", "BININT1", "BININT2", "LONG", "LONG1", "LONG4", "INT"}


def infer_shape_from_ops(ops: List[Tuple[str, object, int]], key_index: int) -> Optional[Tuple[int, ...]]:
    ints: List[int] = []
    for name, arg, pos in ops[key_index + 1:]:
        if is_int_opcode(name) and isinstance(arg, int):
            ints.append(int(arg))
            continue
        if name in {"TUPLE1", "TUPLE2", "TUPLE3", "TUPLE"}:
            return tuple(ints)
        if name in {"MEMOIZE", "MARK"}:
            continue
        if ints:
            return tuple(ints)
    return tuple(ints) if ints else None


def infer_small_int_after_key(ops: List[Tuple[str, object, int]], key_index: int) -> Optional[int]:
    for name, arg, pos in ops[key_index + 1:]:
        if is_int_opcode(name) and isinstance(arg, int):
            return int(arg)
        if name not in {"MEMOIZE"}:
            break
    return None


def infer_dtype_token_from_ops(ops: List[Tuple[str, object, int]], key_index: int) -> Optional[str]:
    candidates: List[str] = []
    for name, arg, pos in ops[key_index + 1:key_index + 48]:
        if name in {"SHORT_BINUNICODE", "BINUNICODE", "UNICODE"} and isinstance(arg, str):
            s = arg.strip()
            if s in {"dtype", "shape", "order", "subclass", "allow_mmap", "numpy_array_alignment_bytes"}:
                continue
            candidates.append(s)
    for s in candidates:
        if re.fullmatch(r"[<>=|]?[?bBhHiIlLqQnNpPfdgFDGUVSaMmO]\d+", s):
            return s
    return candidates[0] if candidates else None


def dtype_itemsize(dtype_token: str) -> int:
    if np is not None:
        try:
            return int(np.dtype(dtype_token).itemsize)
        except Exception:
            pass
    m = re.search(r"(\d+)$", dtype_token)
    if m:
        return int(m.group(1))
    if dtype_token.startswith('(') and np is not None:
        try:
            return int(np.dtype(eval(dtype_token)).itemsize)  # noqa: S307
        except Exception:
            pass
    raise ValueError(f"Could not infer itemsize from dtype token {dtype_token!r}")


def infer_last_joblib_numpy_region(parsed_ops: List[Tuple[str, object, int]], segment_abs_start: int, data: bytes) -> Optional[Dict[str, Any]]:
    wrapper_idx = None
    for i in range(len(parsed_ops) - 1, -1, -1):
        name, arg, pos = parsed_ops[i]
        if name in {"SHORT_BINUNICODE", "BINUNICODE", "UNICODE"} and arg == "NumpyArrayWrapper":
            back = parsed_ops[max(0, i - 10):i]
            if any(a == "joblib.numpy_pickle" for _, a, _ in back):
                wrapper_idx = i
                break
    sub = parsed_ops[wrapper_idx:] if wrapper_idx is not None else parsed_ops[max(0, len(parsed_ops)-512):]

    shape = None
    dtype_tok = None
    align = 1
    last_build_pos = None

    for i, (name, arg, pos) in enumerate(sub):
        if name == "BUILD":
            last_build_pos = pos
        if name in {"SHORT_BINUNICODE", "BINUNICODE", "UNICODE"} and arg == "shape":
            shape = infer_shape_from_ops(sub, i)
        elif name in {"SHORT_BINUNICODE", "BINUNICODE", "UNICODE"} and arg == "numpy_array_alignment_bytes":
            maybe_align = infer_small_int_after_key(sub, i)
            if maybe_align is not None:
                align = maybe_align
        elif name in {"SHORT_BINUNICODE", "BINUNICODE", "UNICODE"} and arg == "dtype":
            dtype_tok = infer_dtype_token_from_ops(sub, i)

    if not shape:
        tuple_candidates: List[Tuple[int, ...]] = []
        for j, (name, arg, pos) in enumerate(sub):
            if name in {"TUPLE1", "TUPLE2", "TUPLE3", "TUPLE"}:
                maybe_shape = infer_shape_from_ops(sub, max(-1, j - 8))
                if maybe_shape:
                    tuple_candidates.append(maybe_shape)
        if tuple_candidates:
            shape = max(tuple_candidates, key=lambda t: math.prod(t) if t else 0)

    if not dtype_tok:
        dtype_candidates: List[str] = []
        for name, arg, pos in sub:
            if name in {"SHORT_BINUNICODE", "BINUNICODE", "UNICODE"} and isinstance(arg, str):
                s = arg.strip()
                if re.fullmatch(r"[<>=|]?[?bBhHiIlLqQnNpPfdgFDGUVSaMmO]\d+", s):
                    dtype_candidates.append(s)
        if dtype_candidates:
            dtype_tok = dtype_candidates[0]

    if not shape or not dtype_tok or last_build_pos is None:
        return None

    itemsize = dtype_itemsize(dtype_tok)
    nitems = 1
    for dim in shape:
        nitems *= int(dim)
    nbytes = nitems * itemsize

    post_build = segment_abs_start + last_build_pos + 1
    if post_build >= len(data):
        return None
    # joblib stores: [padding_length:1][0xFF * padding_length][raw ndarray bytes]
    pad_len = data[post_build]
    raw_start = post_build + 1 + pad_len
    raw_end = raw_start + nbytes
    if raw_end > len(data):
        return None

    return {
        "shape": shape,
        "dtype": dtype_tok,
        "align": align,
        "pad_len": int(pad_len),
        "post_build": post_build,
        "raw_start": raw_start,
        "raw_end": raw_end,
        "nbytes": nbytes,
        "note": f"joblib numpy segment: shape={shape}, dtype={dtype_tok}, align={align}, pad_len={pad_len}, nbytes={nbytes}",
    }


def find_pickle_resync(data: bytes, start: int, max_scan: int = 128) -> int:
    upper = min(len(data), start + max_scan + 1)
    for cand in range(start, upper):
        try:
            count = 0
            for _op, _arg, _pos in pickletools.genops(data[cand:]):
                count += 1
                if count >= 8:
                    return cand
            if count > 0:
                return cand
        except Exception:
            continue
    return start


def analyze_raw_or_joblib_bytes(data: bytes, file_label: str = "<memory>") -> AnalysisLayout:
    logs: List[str] = []
    segments: List[LayoutSegment] = []
    if not is_probable_pickle_prefix(data[:16]):
        return AnalysisLayout(
            file_type="unknown", extraction_mode="unsupported",
            description="Not a probable raw pickle prefix", logs=logs, segments=segments
        )

    if b"joblib.numpy_pickle" not in data[:min(len(data), 2*1024*1024)]:
        logs.append("Analyzer: raw pickle signature detected and no early joblib.numpy_pickle marker found")
        return AnalysisLayout(
            file_type="raw_pickle",
            extraction_mode="raw_pickle_file",
            description="Plain raw pickle stream",
            logs=logs,
            segments=[LayoutSegment("pickle_stream", 0, len(data), "file treated as a pickle-bearing artifact")],
        )

    logs.append("Analyzer: raw pickle signature detected with joblib.numpy_pickle markers; entering joblib layout analysis")

    pos = 0
    while pos < len(data):
        parsed_ops: List[Tuple[str, object, int]] = []
        stop_found = False
        try:
            for op, arg, relpos in pickletools.genops(data[pos:]):
                parsed_ops.append((op.name, arg, relpos))
                if op.name == "STOP":
                    stop_abs = pos + relpos + 1
                    segments.append(LayoutSegment("pickle_segment", pos, stop_abs, "pickle opcode stream"))
                    stop_found = True
                    break
            if stop_found:
                if pos == 0 and len(segments) == 1:
                    logs.append("Analyzer: joblib marker present but stream parsed as plain pickle to STOP")
                    return AnalysisLayout(
                        file_type="raw_pickle",
                        extraction_mode="raw_pickle_file",
                        description="Raw pickle stream parsed successfully",
                        logs=logs,
                        segments=segments,
                    )
                logs.append(f"Analyzer: completed joblib-aware parse with {len([s for s in segments if s.kind=='numpy_raw'])} numpy raw segments")
                return AnalysisLayout(
                    file_type="joblib_numpy_pickle",
                    extraction_mode="joblib_interleaved",
                    description="Joblib numpy_pickle layout with interleaved raw ndarray buffers",
                    logs=logs,
                    segments=segments,
                )
            raise ValueError("pickle stream ended without STOP")
        except Exception as exc:
            err_rel = parse_error_position(exc)
            if err_rel is None:
                raise
            err_abs = pos + err_rel
            if err_abs > pos:
                segments.append(LayoutSegment("pickle_segment", pos, err_abs, "pickle opcode region before raw ndarray"))
            inferred = infer_last_joblib_numpy_region(parsed_ops, pos, data)
            if inferred is None:
                logs.append(f"Analyzer: joblib layout analysis became ambiguous near offset {err_abs}: {exc}")
                logs.append("Analyzer: falling back to artifact-preserving mode for this joblib file")
                return AnalysisLayout(
                    file_type="joblib_numpy_pickle",
                    extraction_mode="artifact_only",
                    description="Joblib-like pickle artifact with unresolved interleaved raw buffer layout",
                    logs=logs,
                    segments=segments,
                )
            segments.append(LayoutSegment("padding", inferred["post_build"], inferred["raw_start"], f'joblib pad_len={inferred["pad_len"]}'))
            segments.append(LayoutSegment("numpy_raw", inferred["raw_start"], inferred["raw_end"], inferred["note"]))
            logs.append(f"Analyzer: {inferred['note']} at [{inferred['raw_start']}, {inferred['raw_end']})")
            pos = find_pickle_resync(data, inferred["raw_end"])
            if pos < inferred["raw_end"]:
                pos = inferred["raw_end"]
            logs.append(f"Analyzer: resynced pickle parser at offset {pos}")

    return AnalysisLayout(
        file_type="joblib_numpy_pickle",
        extraction_mode="joblib_interleaved",
        description="Joblib numpy_pickle layout ended without terminal STOP",
        logs=logs,
        segments=segments,
    )


_PGS_VALID_PROTOS = {2, 3, 4, 5}   


_PGS_MAX_RESYNC_WINDOW = 4096      
_PGS_MAX_RESYNC_TRIES  = 3         
_PGS_MIN_POST_RESYNC   = 3         
_PGS_MIN_OPCODES       = 3         



_NAMED_REF_OPCODES = frozenset({"GLOBAL", "INST", "OBJ"})



_STR_OPCODES = frozenset({
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
    "STRING", "BINSTRING", "SHORT_BINSTRING",
})









@dataclass
class GrammarFragment:
    """Internal implementation detail."""
    start:        int
    end:          int     # exclusive
    opcode_count: int
    complete:     bool    
    parse_error:  Optional[str] = None
    has_ref:      bool = False   


@dataclass
class GrammarWalkResult:
    start:        int
    end:          int      
    complete:     bool     
    opcode_count: int      
    resync_count: int
    parse_error:  Optional[str]
    fragments:    List[GrammarFragment] = field(default_factory=list)


def _walk_fragment(data: bytes, start: int) -> GrammarFragment:
    """Internal implementation detail."""
    count = 0
    has_ref = False
    n_str = 0
    try:
        for op, arg, pos in pickletools.genops(data[start:]):
            count += 1
            
            if op.name in _NAMED_REF_OPCODES and arg is not None:
                has_ref = True
            elif op.name in _STR_OPCODES:
                n_str += 1
            elif op.name == "STACK_GLOBAL" and n_str >= 2:
                
                
                
                has_ref = True
            if op.name == "STOP":
                
                return GrammarFragment(start, start + pos + 1, count, True, None, has_ref)
        
        return GrammarFragment(start, len(data), count, False, "no STOP", has_ref)
    except Exception as e:
        err_pos = parse_error_position(e)
        if err_pos is not None:
            
            end = start + err_pos
        else:
            
            end = len(data)
        return GrammarFragment(start, max(end, start), count, False, str(e), has_ref)


def _pgs_chain_fragments(data: bytes, start: int = 0) -> List["GrammarFragment"]:
    """Internal implementation detail."""
    frags: List[GrammarFragment] = []
    n = len(data)
    if start >= n:
        return frags
    bio = io.BytesIO(data)
    bio.seek(start)
    while bio.tell() < n:
        s = bio.tell()
        count = 0
        end = None
        has_ref = False
        n_str = 0
        try:
            
            for op, arg, pos in pickletools.genops(bio):
                count += 1
                if op.name in _NAMED_REF_OPCODES and arg is not None:
                    has_ref = True
                elif op.name in _STR_OPCODES:
                    n_str += 1
                elif op.name == "STACK_GLOBAL" and n_str >= 2:
                    has_ref = True
                if op.name == "STOP":
                    end = pos + 1
                    break
        except Exception:
            end = None
        if end is None or end <= s:
            break
        frags.append(GrammarFragment(s, end, count, True, None, has_ref))
        bio.seek(end)
    return frags


def _pgs_find_next_proto(data: bytes, from_pos: int, window: int) -> int:
    """Internal implementation detail."""
    limit = min(from_pos + window, len(data) - 1)
    for i in range(from_pos, limit):
        if data[i] == 0x80 and data[i + 1] in _PGS_VALID_PROTOS:
            return i
    return -1


def _pgs_count_valid_opcodes(data: bytes, start: int, limit: int) -> int:
    """Internal implementation detail."""
    count = 0
    try:
        for op, arg, pos in pickletools.genops(data[start:]):
            count += 1
            if count >= limit:
                break
    except Exception:
        pass
    return count


def grammar_walk_robust(data: bytes, start: int) -> GrammarWalkResult:
    """Internal implementation detail."""
    _NULL = GrammarWalkResult(start, start, False, 0, 0, "no magic", [])
    if len(data) <= start + 1:
        return _NULL
    if data[start] != 0x80 or data[start + 1] not in _PGS_VALID_PROTOS:
        return _NULL

    fragments: List[GrammarFragment] = []
    resync_count = 0
    scan_start   = start
    parse_error  = None

    while True:
        frag = _walk_fragment(data, scan_start)
        if frag.end > frag.start:
            fragments.append(frag)
        parse_error = frag.parse_error

        if frag.complete:
            break
        if resync_count >= _PGS_MAX_RESYNC_TRIES:
            break
        
        nxt = _pgs_find_next_proto(data, frag.end, _PGS_MAX_RESYNC_WINDOW)
        if nxt < 0:
            break
        if _pgs_count_valid_opcodes(data, nxt, _PGS_MIN_POST_RESYNC) < _PGS_MIN_POST_RESYNC:
            break
        scan_start = nxt
        resync_count += 1

    if not fragments:
        return _NULL

    last = fragments[-1]
    return GrammarWalkResult(
        start=start,
        end=last.end,
        complete=last.complete,
        opcode_count=sum(f.opcode_count for f in fragments),
        resync_count=resync_count,
        parse_error=parse_error,
        fragments=fragments,
    )








def _inv_gzip(data: bytes) -> Optional[bytes]:
    if data[:2] != b"\x1f\x8b":
        return None
    try:
        return gzip.decompress(data)
    except Exception:
        return None


def _inv_bzip2(data: bytes) -> Optional[bytes]:
    if data[:3] != b"BZh":
        return None
    try:
        return bz2.decompress(data)
    except Exception:
        return None


def _inv_xz(data: bytes) -> Optional[bytes]:
    if data[:6] != b"\xfd7zXZ\x00":
        return None
    try:
        return lzma.decompress(data)
    except Exception:
        return None


def _inv_lz4(data: bytes) -> Optional[bytes]:
    if data[:4] != b"\x04\x22\x4d\x18" or lz4frame is None:
        return None
    try:
        return lz4frame.decompress(data)
    except Exception:
        return None


def _inv_zlib(data: bytes) -> Optional[bytes]:
    """Internal implementation detail."""
    if len(data) < 2 or data[0] != 0x78 or (data[0] * 256 + data[1]) % 31 != 0:
        return None
    try:
        import zlib as _z
        return _z.decompress(data)
    except Exception:
        return None



def _inv_npy(data: bytes) -> Optional[bytes]:
    """Internal implementation detail."""
    if not data.startswith(b"\x93NUMPY") or len(data) < 10:
        return None
    major = data[6]
    if major == 1:
        hlen = struct.unpack("<H", data[8:10])[0]
        start = 10 + hlen
    else:
        if len(data) < 12:
            return None
        hlen = struct.unpack("<I", data[8:12])[0]
        start = 12 + hlen
    if start >= len(data):
        return None
    return data[start:]


CODECS: List[Tuple[str, Any]] = [
    ("gzip",  _inv_gzip),
    ("bzip2", _inv_bzip2),
    ("xz",    _inv_xz),
    ("lz4",   _inv_lz4),
    ("zlib",  _inv_zlib),
    ("npy",   _inv_npy),
]


def invert_codecs(data: bytes) -> List[Tuple[str, bytes]]:
    """Internal implementation detail."""
    out: List[Tuple[str, bytes]] = []
    for name, inv in CODECS:
        try:
            res = inv(data)
        except Exception:
            res = None
        if not res or res == data:
            continue
        
        if len(res) > MAX_INFLATE_BYTES:
            continue
        if data and len(res) / len(data) > MAX_INFLATE_RATIO:
            continue
        out.append((name, res))
    return out


def _try_decompress_bytes(data: bytes) -> Optional[bytes]:
    """Internal implementation detail."""
    res = invert_codecs(data)
    return res[0][1] if res else None


def _emit_blob(
    data: bytes,
    *,
    orig_path: Path,
    out_dir: Optional[Path],
    logs: List[str],
    seen: Set[str],
    logical_name: str,
    source_kind: str,
    note: str,
    pickle_validated: bool,
    complete: bool = True,
    offset_start: Optional[int] = None,
    offset_end: Optional[int] = None,
    compression: Optional[str] = None,
    resync_count: int = 0,
) -> Optional[PickleBlob]:
    """Internal implementation detail."""
    h = sha256_bytes(data)
    if h in seen:
        logs.append(f"dedup: {logical_name} -- identical blob already collected (sha256={h[:12]})")
        return None
    seen.add(h)

    blob = PickleBlob(
        logical_name=logical_name,
        source_kind=source_kind,
        size=len(data),
        sha256=h,
        container_path=str(orig_path),
        note=note,
        offset_start=offset_start,
        offset_end=offset_end,
        compression=compression,
        pickle_validated=pickle_validated,
        first_opcodes=first_opcodes(data),
        complete=complete,
        resync_count=resync_count,
    )
    if out_dir is not None:
        blob.output_path = str(write_blob(out_dir, orig_path, logical_name, data))
    return blob




def _zip_members(data: bytes, logs: List[str], label: str) -> List[Tuple[str, bytes]]:
    """Internal implementation detail."""
    out: List[Tuple[str, bytes]] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            _flag_duplicate_members([z.filename for z in zf.infolist()], logs, label)
            for zi in sorted(zf.infolist(), key=lambda z: -score_zip_member(z.filename)):
                if zi.is_dir():
                    continue
                try:
                    
                    
                    
                    
                    
                    inner = zf.read(zi)
                except Exception as e:
                    logs.append(f"container({label}): failed to read ZIP member {zi.filename}: {e}")
                    continue
                
                if inner and member_admits(zi.filename, inner[:512]):
                    out.append((zi.filename, inner))
        return out
    except zipfile.BadZipFile as e:
        logs.append(f"container({label}): BadZipFile ({e}) -> scanning streaming ZIP local headers")
    except Exception as e:
        logs.append(f"container({label}): ZIP processing error: {e}")
        return out

    
    import zlib as _z
    for entry in _parse_local_headers(data):
        raw = data[entry.data_offset: entry.data_end]
        if entry.compression == 8:
            try:
                raw = _z.decompress(raw, wbits=-15)
            except Exception:
                continue
        elif entry.compression != 0:
            continue
        if raw and member_admits(entry.name, raw[:512]):
            out.append((entry.name, raw))
    return out


def _tar_members(data: bytes, logs: List[str], label: str) -> List[Tuple[str, bytes]]:
    """Internal implementation detail."""
    out: List[Tuple[str, bytes]] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            members = tf.getmembers()
            cand = [m for m in members
                    if m.isfile()]
            logs.append(f"container({label}): TAR {len(members)} members, {len(cand)} files")
            for m in cand:
                fobj = tf.extractfile(m)
                if fobj is None:
                    continue
                inner = fobj.read()
                
                if inner and (m.name in ("pickle", "data.pkl")
                              or member_admits(m.name, inner[:512])):
                    out.append((m.name, inner))
    except Exception as e:
        logs.append(f"container({label}): TAR processing failed: {e}")
    return out




def _peel_serialization(
    data: bytes, orig_path: Path, label: str, out_dir: Optional[Path],
    logs: List[str], depth: int, seen: Set[str],
) -> List[PickleBlob]:
    """Internal implementation detail."""
    if not is_probable_pickle_prefix(data[:16]):
        return []

    out: List[PickleBlob] = []
    probe = data[:min(len(data), 2 * 1024 * 1024)]
    if b"joblib.numpy_pickle" in probe:
        try:
            layout = analyze_raw_or_joblib_bytes(data, file_label=label)
        except Exception as e:
            layout = None
            logs.append(f"serialization({label}): joblib layout analysis failed: {e}")
        
        
        
        
        if layout is not None and layout.extraction_mode == "joblib_interleaved":
            for seg in layout.segments:
                if seg.kind != "pickle_segment":
                    continue
                seg_data = data[seg.start:seg.end]
                if not seg_data:
                    continue
                blob = _emit_blob(
                    seg_data, orig_path=orig_path, out_dir=out_dir, logs=logs, seen=seen,
                    logical_name=f"{label}!joblibseg@{seg.start}",
                    source_kind="joblib_pickle_segment",
                    note=f"pickle segment in an interleaved joblib numpy_pickle layout "
                         f"[{seg.start}, {seg.end}) — {seg.detail}",
                    pickle_validated=validate_pickle_complete(seg_data),
                    complete=validate_pickle_complete(seg_data),
                    offset_start=seg.start, offset_end=seg.end,
                )
                if blob is not None:
                    out.append(blob)
            if out:
                logs.append(f"serialization({label}): joblib pickle segments: {len(out)} extracted")
                return out

    
    if validate_pickle_complete(data):
        blob = _emit_blob(
            data, orig_path=orig_path, out_dir=out_dir, logs=logs, seen=seen,
            logical_name=label, source_kind="routed_pickle",
            note=f"RFP Serialization branch (depth={depth}): Validate(B)=true",
            pickle_validated=True, complete=True,
        )
        if blob is not None:
            logs.append(f"serialization({label}): complete pickle {len(data)} bytes")
            return [blob]
    return out


def _peel_container(
    data: bytes, orig_path: Path, label: str, out_dir: Optional[Path],
    logs: List[str], depth: int, seen: Set[str],
) -> List[PickleBlob]:
    """Internal implementation detail."""
    if data[:4] == b"PK\x03\x04":
        members = _zip_members(data, logs, label)
    else:
        try:
            if not tarfile.is_tarfile(io.BytesIO(data)):
                return []
        except Exception:
            return []
        members = _tar_members(data, logs, label)

    if not members:
        return []

    out: List[PickleBlob] = []
    for name, inner in members:
        out.extend(_route_arbitrary_bytes(
            inner, orig_path, f"{label}/{name}", out_dir, logs, depth + 1, seen))

    if len(members) > 1 and depth + 1 <= MAX_DEPTH:
        total = sum(len(b) for _, b in members)
        if total <= MAX_JOIN_BYTES:
            joined = b"".join(b for _, b in members)
            out.extend(_route_arbitrary_bytes(
                joined, orig_path, f"{label}!join", out_dir, logs, depth + 1, seen))
        else:
            logs.append(
                f"container({label}): skipping concatenated-member recursion -- total {total} bytes "
                f"> MAX_JOIN_BYTES({MAX_JOIN_BYTES})"
            )
    return out


def _peel_streaming(
    data: bytes, orig_path: Path, label: str, out_dir: Optional[Path],
    logs: List[str], depth: int, seen: Set[str],
) -> List[PickleBlob]:
    """Internal implementation detail."""
    out: List[PickleBlob] = []
    for codec, inflated in invert_codecs(data):
        logs.append(f"streaming({label}): τ⁻¹={codec} → {len(inflated)} bytes")
        out.extend(_route_arbitrary_bytes(
            inflated, orig_path, f"{label}!{codec}", out_dir, logs, depth + 1, seen))
    return out


def _route_arbitrary_bytes(
    data: bytes,
    orig_path: Path,
    label: str,
    out_dir: Optional[Path],
    logs: List[str],
    depth: int = 0,
    seen: Optional[Set[str]] = None,
) -> List["PickleBlob"]:
    """Internal implementation detail."""
    if seen is None:
        seen = set()
    if not data:
        return []
    if depth > MAX_DEPTH:
        logs.append(f"route: MAX_DEPTH({MAX_DEPTH}) exceeded -- {label} processing stopped")
        return []

    P: List[PickleBlob] = []
    
    P.extend(_peel_serialization(data, orig_path, label, out_dir, logs, depth, seen))
    
    P.extend(_peel_container(data, orig_path, label, out_dir, logs, depth, seen))
    
    P.extend(_peel_streaming(data, orig_path, label, out_dir, logs, depth, seen))

    
    if not P:
        return pgs_scan_bytes(data, orig_path, out_dir, logs, label=label, seen=seen)
    return P


def pgs_scan_bytes(
    data: bytes,
    orig_path: Path,
    out_dir: Optional[Path],
    logs: List[str],
    label: str = "",
    seen: Optional[Set[str]] = None,
) -> List["PickleBlob"]:
    """Internal implementation detail."""
    if seen is None:
        seen = set()
    blobs: List[PickleBlob] = []
    n = len(data)

    
    
    
    
    chain = _pgs_chain_fragments(data, 0)
    
    #
    
    
    #
    
    
    
    
    #
    
    
    
    chain_ok = bool(chain) and (
        sum(f.opcode_count for f in chain) >= _PGS_MIN_OPCODES
        and (chain[-1].end == n or any(f.has_ref for f in chain))
    )
    if chain_ok:
        for frag in chain:
            blob_data = data[frag.start:frag.end]
            if not blob_data:
                continue
            lname = (f"{label}!chain@{frag.start}" if label
                     else f"{orig_path.name}!chain@{frag.start}")
            blob = _emit_blob(
                blob_data, orig_path=orig_path, out_dir=out_dir, logs=logs, seen=seen,
                logical_name=lname, source_kind="pgs_chain",
                note=(f"PGW chain: chained anchor e(delta), offset {frag.start}, "
                      f"opcodes={frag.opcode_count}, chain length={len(chain)}"),
                pickle_validated=True, complete=True,
                offset_start=frag.start, offset_end=frag.end,
            )
            if blob is not None:
                blobs.append(blob)
        logs.append(
            f"PGW chain: {len(chain)} stream chain [0, {chain[-1].end}) "
            f"/ {n} bytes, ops={sum(f.opcode_count for f in chain)}"
        )
    
    
    
    covered = [(f.start, f.end) for f in chain] if chain_ok else []

    
    pos = 0
    while pos < n - 1:
        
        if data[pos] == 0x80 and data[pos + 1] in _PGS_VALID_PROTOS:
            wr = grammar_walk_robust(data, pos)   
            if not wr.fragments:
                pos += 1
                continue
            for frag in wr.fragments:
                
                if frag.opcode_count < _PGS_MIN_OPCODES:
                    continue
                
                
                
                #   PROTO EXT2 DICT <err>              (6 bytes)
                #   PROTO STACK_GLOBAL DICT TUPLE3 <err> (5 bytes)
                #   PROTO EXT1 LONG_BINPUT <err>       (9 bytes)
                
                
                if not frag.complete and not frag.has_ref:
                    continue
                
                if any(a <= frag.start and frag.end <= b for a, b in covered):
                    continue
                blob_data = data[frag.start:frag.end]
                if not blob_data:
                    continue
                source_kind = "pgs_complete" if frag.complete else "pgs_partial"
                lname = (f"{label}!pgs@{frag.start}" if label
                         else f"{orig_path.name}!pgs@{frag.start}")
                blob = _emit_blob(
                    blob_data, orig_path=orig_path, out_dir=out_dir, logs=logs, seen=seen,
                    logical_name=lname, source_kind=source_kind,
                    note=(f"PGW: {source_kind} at offset {frag.start}, "
                          f"opcodes={frag.opcode_count}, resync={wr.resync_count}"),
                    pickle_validated=frag.complete, complete=frag.complete,
                    offset_start=frag.start, offset_end=frag.end,
                    resync_count=wr.resync_count,
                )
                if blob is not None:
                    blobs.append(blob)
                    logs.append(
                        f"PGW: {source_kind} [{frag.start}, {frag.end}) "
                        f"size={frag.end - frag.start}, ops={frag.opcode_count}"
                    )
            pos = wr.end if wr.end > pos else pos + 1
        else:
            pos += 1
    if not blobs:
        logs.append(f"PGW: no pickle blobs found in {n} bytes")
    return blobs




def _extract_from_zip_bytes(
    data: bytes, orig_path: Path, member_prefix: str, out_dir: Optional[Path],
    logs: List[str], depth: int = 0, seen: Optional[Set[str]] = None,
) -> List["PickleBlob"]:
    """Internal implementation detail."""
    return _peel_container(data, orig_path, member_prefix, out_dir, logs, depth,
                           seen if seen is not None else set())


def _extract_from_tar_bytes(
    data: bytes, orig_path: Path, member_prefix: str, out_dir: Optional[Path],
    logs: List[str], depth: int = 0, seen: Optional[Set[str]] = None,
) -> List["PickleBlob"]:
    """Internal implementation detail."""
    return _peel_container(data, orig_path, member_prefix, out_dir, logs, depth,
                           seen if seen is not None else set())


def analyze_path(path: Path, max_decompressed: int) -> Tuple[AnalysisLayout, Optional[bytes], Optional[str]]:
    
    
    
    with path.open("rb") as _fp:
        head = _fp.read(262)
    kind = detect_file_kind_from_head(head)

    if kind == "zip":
        logs = ["Analyzer: detected ZIP container (PK\\x03\\x04 signature)"]
        try:
            with zipfile.ZipFile(path, "r") as zf:
                members = zf.infolist()
                cand = [zi for zi in members if score_zip_member(zi.filename) > 0]
                logs.append(f"Analyzer: ZIP has {len(members)} members; {len(cand)} pickle-like candidate members")
                segments = [
                    LayoutSegment(
                        "zip_member", 0, 0,
                        f"{zi.filename} | usize={zi.file_size} | ctype={compression_name(zi.compress_type)} | score={score_zip_member(zi.filename)}"
                    ) for zi in sorted(cand, key=lambda z: (-score_zip_member(z.filename), z.filename))
                ]
            return AnalysisLayout(
                file_type="zip",
                extraction_mode="zip_member_extract",
                description="ZIP / PyTorch-style container with candidate pickle members",
                logs=logs,
                segments=segments,
            ), None, None
        except zipfile.BadZipFile as e:
            
            logs.append(f"Analyzer: BadZipFile ({e}) -> switching to Streaming ZIP analysis")
            data = path.read_bytes()
            entries = _parse_local_headers(data)
            cand_entries = [e for e in entries if score_zip_member(e.name) > 0]
            logs.append(f"Analyzer: Streaming ZIP — {len(entries)} Local Headers, {len(cand_entries)} pickle candidates")
            segments = [
                LayoutSegment(
                    "streaming_zip_entry", e.data_offset, e.data_end,
                    f"{e.name} | sz={e.data_end - e.data_offset} | comp={e.compression} | score={score_zip_member(e.name)}"
                ) for e in sorted(cand_entries, key=lambda x: (-score_zip_member(x.name), x.name))
            ]
            return AnalysisLayout(
                file_type="streaming_zip",
                extraction_mode="streaming_zip_extract",
                description="Streaming ZIP (no Central Directory) — local header scan",
                logs=logs,
                segments=segments,
            ), None, None

    if kind in {"gzip", "bzip2", "lzma", "lz4", "zlib_deflate"}:
        logs = [f"Analyzer: detected {kind} wrapper; streaming one-layer decompression for inner analysis"]
        if kind == "zlib_deflate":
            # zlib raw deflate (Joblib compress=('zlib', N)) — no streaming API,
            # read the whole file and decompress in one call.
            import zlib as _zlib_mod
            try:
                raw_compressed = path.read_bytes()
                if len(raw_compressed) > max_decompressed:
                    raise RuntimeError(f"zlib_deflate: compressed size {len(raw_compressed)} exceeds limit")
                payload = _zlib_mod.decompress(raw_compressed)
            except Exception as e:
                return AnalysisLayout(
                    file_type="unknown",
                    extraction_mode="unsupported",
                    description=f"zlib_deflate decompression failed: {e}",
                    logs=logs + [f"Analyzer: zlib decompress failed: {e}"],
                    segments=[],
                ), None, None
        elif kind == "gzip":
            reader_cm = gzip.open(path, "rb")
        elif kind == "bzip2":
            reader_cm = bz2.open(path, "rb")
        elif kind == "lzma":
            reader_cm = lzma.open(path, "rb")
        else:
            if lz4frame is None:
                raise RuntimeError("lz4.frame is not available. Install lz4 to handle LZ4 files.")
            reader_cm = lz4frame.open(str(path), mode="rb")
        if kind != "zlib_deflate":
            with reader_cm as reader:
                payload = read_all_streaming(reader, max_bytes=max_decompressed)
        inner_kind = detect_file_kind_from_head(payload[:16])
        logs.append(f"Analyzer: wrapper payload size={len(payload)} bytes; inner kind guess={inner_kind}")
        if inner_kind in {"raw_pickle", "unknown"} and is_probable_pickle_prefix(payload[:16]):
            inner = analyze_raw_or_joblib_bytes(payload, file_label=path.name + "!payload")
        else:
            inner = AnalysisLayout(
                file_type=inner_kind,
                extraction_mode="wrapper_payload_extract",
                description=f"{kind} wrapper carrying inner payload kind={inner_kind}",
                logs=[],
                segments=[],
            )
        inner.wrapper = kind
        inner.logs = logs + inner.logs
        return inner, payload, kind

    if kind == "raw_pickle":
        layout = analyze_raw_or_joblib_bytes(path.read_bytes(), file_label=str(path))
        return layout, None, None

    
    
    try:
        import tarfile as _tarfile
        if _tarfile.is_tarfile(str(path)):
            logs_tar = ["Analyzer: detected tar archive (no fixed magic, tarfile.is_tarfile() positive)"]
            with _tarfile.open(path, "r:*") as tf:
                members = tf.getmembers()
                # PyTorch legacy format: storages, tensors, pickle
                cand = [m for m in members
                        if score_zip_member(m.name) > 0 or m.name in ("pickle", "data.pkl")]
                logs_tar.append(f"Analyzer: tar has {len(members)} members; {len(cand)} pickle-like candidates")
                segments = [
                    LayoutSegment(
                        "tar_member", m.offset_data, m.offset_data + m.size,
                        f"{m.name} | size={m.size} | score={score_zip_member(m.name)}"
                    ) for m in cand
                ]
            return AnalysisLayout(
                file_type="tar",
                extraction_mode="tar_member_extract",
                description="tar archive with candidate pickle members (PyTorch legacy format)",
                logs=logs_tar,
                segments=segments,
            ), None, None
    except Exception:
        pass

    return AnalysisLayout(
        file_type="unknown",
        extraction_mode="unsupported",
        description="Unsupported or unrecognized file type",
        logs=["Analyzer: unsupported or unrecognized file signature"],
        segments=[],
    ), None, None


# ---------- extractors ----------






def extract_from_zip(path: Path, out_dir: Optional[Path], logs: List[str],
                     seen: Optional[Set[str]] = None) -> List[PickleBlob]:
    """Internal implementation detail."""
    if seen is None:
        seen = set()
    blobs: List[PickleBlob] = []
    with zipfile.ZipFile(path, "r") as zf, path.open("rb") as rawfp:
        infos = sorted(zf.infolist(), key=lambda zi: (-score_zip_member(zi.filename), zi.filename))
        _flag_duplicate_members([zi.filename for zi in infos], logs, path.name)
        for zi in infos:
            if zi.is_dir():
                continue
            
            try:
                with zf.open(zi, "r") as _h:
                    _head = _h.read(512)
            except Exception:
                _head = b""
            if not member_admits(zi.filename, _head):
                continue

            if zi.compress_type == zipfile.ZIP_STORED:
                data_off = local_data_offset(rawfp, zi.header_offset)
                rawfp.seek(data_off)
                candidate_data = rawfp.read(zi.file_size)
                logs.append(f"Extractor: sliced stored ZIP member {zi.filename} at [{data_off}, {data_off + zi.file_size})")
            else:
                with zf.open(zi, "r") as member:
                    candidate_data = member.read()
                logs.append(f"Extractor: decompressed ZIP member {zi.filename} (method={compression_name(zi.compress_type)})")

            if not candidate_data:
                continue

            blobs.extend(_route_arbitrary_bytes(
                candidate_data, path, zi.filename, out_dir, logs, 1, seen))
    return blobs


def extract_from_streaming_zip(path: Path, out_dir: Optional[Path], logs: List[str],
                               seen: Optional[Set[str]] = None) -> List[PickleBlob]:
    """Internal implementation detail."""
    import zlib as _zlib
    if seen is None:
        seen = set()

    data = path.read_bytes()
    entries = _parse_local_headers(data)
    logs.append(f"StreamingZIP: {len(entries)} Local File Headers found")

    blobs: List[PickleBlob] = []
    for entry in entries:
        raw = data[entry.data_offset: entry.data_end]

        if entry.compression == 8:  
            try:
                raw = _zlib.decompress(raw, wbits=-15)
            except _zlib.error as e:
                logs.append(f"StreamingZIP: deflate failed {entry.name!r}: {e}")
                continue
        elif entry.compression != 0:
            logs.append(f"StreamingZIP: unsupported compression {entry.name!r} ({entry.compression}), skip")
            continue

        if not raw:
            continue
        
        if not member_admits(entry.name, raw[:512]):
            logs.append(f"StreamingZIP: skip {entry.name!r} (content is not a container or pickle)")
            continue

        sub = _route_arbitrary_bytes(raw, path, entry.name, out_dir, logs, 1, seen)
        blobs.extend(sub)
        logs.append(f"StreamingZIP: {entry.name!r} → {len(sub)} blob(s)")

    return blobs


def extract_wrapper_payload(path: Path, payload: bytes, wrapper_kind: str,
                            out_dir: Optional[Path], layout: AnalysisLayout,
                            logs: List[str], seen: Optional[Set[str]] = None) -> List[PickleBlob]:
    """Internal implementation detail."""
    if seen is None:
        seen = set()
    logs.append(f"Extractor: {wrapper_kind} wrapper payload({len(payload)} bytes) → RFP")
    return _route_arbitrary_bytes(
        payload, path, f"{path.name}!{wrapper_kind}:payload", out_dir, logs, 1, seen)


def extract_raw_pickle(path: Path, out_dir: Optional[Path], logs: List[str],
                       seen: Optional[Set[str]] = None) -> List[PickleBlob]:
    """Internal implementation detail."""
    if seen is None:
        seen = set()
    logs.append("Extractor: raw pickle file -> RFP")
    return _route_arbitrary_bytes(path.read_bytes(), path, path.name, out_dir, logs, 0, seen)


def extract_from_tar(path: Path, out_dir: Optional[Path], logs: List[str],
                     seen: Optional[Set[str]] = None) -> List[PickleBlob]:
    """Internal implementation detail."""
    import tarfile as _tarfile
    if seen is None:
        seen = set()
    blobs: List[PickleBlob] = []
    try:
        with _tarfile.open(path, "r:*") as tf:
            members = tf.getmembers()
            def _tar_head(mm):
                try:
                    f = tf.extractfile(mm)
                    return f.read(512) if f is not None else b""
                except Exception:
                    return b""
            
            cand = sorted(
                [m for m in members
                 if m.isfile() and (m.name in ("pickle", "data.pkl")
                                    or member_admits(m.name, _tar_head(m)))],
                key=lambda m: (-(score_zip_member(m.name) + (100 if m.name == "pickle" else 0)), m.name)
            )
            logs.append(f"Extractor: tar — {len(members)} members, {len(cand)} pickle candidates")
            for m in cand:
                fobj = tf.extractfile(m)
                if fobj is None:
                    continue
                data = fobj.read()
                sub = _route_arbitrary_bytes(data, path, f"tar:{m.name}", out_dir, logs, 1, seen)
                blobs.extend(sub)
                logs.append(f"  tar member {m.name!r}: {len(data)} bytes → {len(sub)} blob(s)")
    except Exception as e:
        logs.append(f"Extractor: tar extraction failed: {e}")
    return blobs


def extract_joblib_interleaved(path: Path, out_dir: Optional[Path], logs: List[str],
                               seen: Optional[Set[str]] = None) -> List[PickleBlob]:
    """Internal implementation detail."""
    if seen is None:
        seen = set()
    logs.append("Extractor: joblib numpy_pickle artifact -> RFP (segment decomposition)")
    return _route_arbitrary_bytes(path.read_bytes(), path, path.name, out_dir, logs, 0, seen)




RFP_INMEMORY_LIMIT = 512 * 1024 * 1024


def extract_pickles(path: Path, out_dir: Optional[Path],
                    max_decompressed: int = MAX_INFLATE_BYTES) -> ExtractionReport:
    """Internal implementation detail."""
    errors: List[str] = []
    blobs: List[PickleBlob] = []
    logs: List[str] = []
    seen: Set[str] = set()

    try:
        
        layout, payload, wrapper_kind = analyze_path(path, max_decompressed)
        logs.extend(layout.logs)
        logs.append(f"Analyzer: file_type={layout.file_type}, extraction_mode={layout.extraction_mode}")
        if layout.description:
            logs.append(f"Analyzer: {layout.description}")
        for seg in layout.segments[:50]:
            if seg.start == 0 and seg.end == 0:
                logs.append(f"Analyzer segment: {seg.kind} | {seg.detail}")
            else:
                logs.append(f"Analyzer segment: {seg.kind} [{seg.start}, {seg.end}) | {seg.detail}")

        file_size = path.stat().st_size
        if file_size <= RFP_INMEMORY_LIMIT:
            logs.append(f"Extractor: RFP(B, 0) -- entire file {file_size} bytes")
            blobs = _route_arbitrary_bytes(
                path.read_bytes(), path, path.name, out_dir, logs, 0, seen)
        else:
            logs.append(
                f"Extractor: file {file_size} bytes > RFP_INMEMORY_LIMIT -- using streaming path"
            )
            if layout.extraction_mode == "zip_member_extract":
                blobs = extract_from_zip(path, out_dir, logs, seen)
            elif layout.extraction_mode == "streaming_zip_extract":
                blobs = extract_from_streaming_zip(path, out_dir, logs, seen)
            elif layout.extraction_mode == "tar_member_extract":
                blobs = extract_from_tar(path, out_dir, logs, seen)
            elif wrapper_kind is not None and payload is not None:
                blobs = extract_wrapper_payload(path, payload, wrapper_kind, out_dir, layout, logs, seen)
            else:
                blobs = []
            if not blobs:
                
                logs.append("Extractor: streaming path produced no output (P = empty); handing off to PGW")
                blobs = pgs_scan_bytes(path.read_bytes(), path, out_dir, logs, seen=seen)

        if not blobs:
            errors.append("No pickle blob found (RFP produced ∅ and PGW found no candidate)")
    except Exception as e:
        errors.append(f"{type(e).__name__}: {e}")

    
    findings = scan_member_names(path)
    for f in findings:
        logs.append("container(%s): %s — %s" % (path.name, f["kind"], f["member"]))

    return ExtractionReport(
        input_path=str(path),
        file_size=path.stat().st_size,
        file_type=detect_file_kind(path),
        blobs=blobs,
        errors=errors,
        logs=logs,
        container_findings=findings,
    )
