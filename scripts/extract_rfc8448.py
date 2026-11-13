"""Extract RFC 8448 §3 (Simple 1-RTT Handshake) into ordered JSON events.

Usage:
    python scripts/extract_rfc8448.py <rfc8448.txt> tests/vectors/rfc8448/simple_1rtt.json

Each event is one ``{client}``/``{server}`` step, e.g.
``{"actor": "server", "step": "extract secret \"early\"",
   "values": {"salt": "", "IKM": "00..", "secret": "33ad.."}}``.
A salt written as "0 (all zero octets)" becomes the empty string, meaning
"Hash.length zero bytes" as in RFC 8446 §7.1. Page headers and footers are
stripped. Values are lower-case hex.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

PAGE_BREAK = re.compile(r"^(Thomson\s+Informational\s+\[Page \d+\]|RFC 8448\s+TLS 1\.3 Traces\s+January 2019|\f)\s*$")
STEP = re.compile(r"^   \{(client|server)\}  (.+?):?$")
VALUE = re.compile(r"^      ([A-Za-z][\w ]*?)(?: \((\d+) octets\))?:  (.*)$")
TITLE_CONTINUATION = re.compile(r"^ {6,}(\S.*?):?\s*$")
CONTINUATION = re.compile(r"^         ([0-9a-f]{2}(?: [0-9a-f]{2})*)\s*$")


def section3(lines: list[str]) -> list[str]:
    start = next(i for i, line in enumerate(lines) if line.startswith("3.  Simple 1-RTT Handshake"))
    end = next(i for i, line in enumerate(lines) if line.startswith("4.  Resumed 0-RTT Handshake"))
    return [line.rstrip("\n") for line in lines[start:end] if not PAGE_BREAK.match(line.rstrip("\n"))]


def parse(lines: list[str]) -> list[dict]:
    events: list[dict] = []
    declared: list[tuple[dict, str, int]] = []
    current_value: tuple[dict, str, int | None] | None = None
    title_open = False
    for line in lines:
        if m := STEP.match(line):
            events.append({"actor": m.group(1), "step": m.group(2), "values": {}})
            # A title that doesn't end in ':' wraps onto the next line.
            title_open = not line.rstrip().endswith(":")
            current_value = None
        elif events and title_open and (m := TITLE_CONTINUATION.match(line)):
            events[-1]["step"] += " " + m.group(1)
            title_open = False
        elif events and (m := VALUE.match(line)):
            label, octets, rest = m.group(1), m.group(2), m.group(3).strip()
            if rest.startswith("0 (all zero octets)") or rest == "(empty)":
                hexstr = ""
            else:
                hexstr = rest.replace(" ", "")
            if label in events[-1]["values"]:
                raise ValueError(f"duplicate {label!r} in step {events[-1]['step']!r}")
            events[-1]["values"][label] = hexstr
            if octets:
                declared.append((events[-1]["values"], label, int(octets)))
            current_value = (events[-1]["values"], label, int(octets) if octets else None)
        elif current_value and (m := CONTINUATION.match(line)):
            values, label, _ = current_value
            values[label] += m.group(1).replace(" ", "")
        elif not line.strip():
            continue
        else:
            current_value = None
    # Every value with a declared length must have exactly that length.
    for values, label, n in declared:
        if len(values[label]) != 2 * n:
            raise ValueError(f"{label}: declared {n} octets, extracted {len(values[label]) // 2}")
    return events


def main(src: Path, dst: Path) -> None:
    raw = src.read_bytes()
    lines = section3(raw.decode().splitlines())
    events = parse(lines)
    doc = {
        "source": "RFC 8448 §3, https://www.rfc-editor.org/rfc/rfc8448.txt",
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "events": events,
    }
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(doc, indent=1) + "\n")
    print(f"{dst}: {len(events)} events")


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))
