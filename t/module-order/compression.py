#!/usr/bin/env python3

"""Check compression module placement in the integrated OpenResty build."""

from pathlib import Path
import re
import sys


source = Path(sys.argv[1]).read_text()
array = re.search(r"ngx_module_t\s+\*ngx_modules\[\]\s*=\s*\{(.*?)\};", source, re.S)
if array is None:
    raise SystemExit("ngx_modules array not found")

modules = re.findall(r"&([a-zA-Z0-9_]+)", array.group(1))
positions = {name: i for i, name in enumerate(modules)}
if len(positions) != len(modules):
    raise SystemExit("duplicate module registration")

removed = (
    "gzip_filter", "gzip_static", "gunzip_filter",
    "brotli_filter", "brotli_static", "zstd_filter", "zstd_static",
    "unbrotli_filter", "undeflate_filter", "unzstd_filter",
)
for name in removed:
    if f"ngx_http_{name}_module" in positions:
        raise SystemExit(f"replaced module is still registered: {name}")

sequences = {
    "static content": (
        "static", "compression_static", "autoindex", "index",
    ),
    "normalize": (
        "try_files", "cache_rocksdb", "compression_normalize",
        "delay", "internal_redirect", "phase_control",
    ),
    "response filters": (
        "v3_filter", "compression_vary_filter", "rewrite_status_filter",
        "range_header_filter", "compression_filter", "modsecurity",
        "postpone_filter", "ssi_filter", "charset_filter", "sub_filter",
        "addition_filter", "decompression_filter", "userid_filter",
        "headers_filter", "lua", "headers_more_filter",
        "headers_control", "cors", "limit_traffic_rate_filter",
        "replace_filter", "security_headers_filter", "trim_filter",
        "cache_dechunk_filter", "copy_filter", "range_body_filter",
        "not_modified_filter", "slice_filter", "cache_purge",
    ),
}

for label, names in sequences.items():
    names = [f"ngx_http_{name}_module" for name in names]
    missing = [name for name in names if name not in positions]
    if missing:
        raise SystemExit(f"{label}: missing modules: {', '.join(missing)}")
    ordered = sorted(names, key=positions.get)
    if ordered != names:
        raise SystemExit(f"{label}: unexpected registration order: {ordered}")
    print(f"PASS: {label} registration order")

print("PASS: replaced compression modules are absent")
