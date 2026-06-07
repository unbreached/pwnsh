"""Unit tests for the incremental sentinel scanner (pwnsh._scan)."""
from __future__ import annotations

from pwnsh._scan import StreamScanner


def test_find_and_text_extract_span_between_markers():
    sc = StreamScanner()
    sc.feed(b"noise @@BEGIN@@ the payload @@END@@ trailing")
    i = sc.find(b"@@BEGIN@@")
    assert i == 6
    start = i + len(b"@@BEGIN@@")
    stop = sc.find(b"@@END@@", start)
    assert sc.text(start, stop) == " the payload "


def test_streaming_find_resumes_across_feeds_and_catches_split_marker():
    sc = StreamScanner()
    marker = b"@@E@@"
    sc.feed(b"xx@@E")  # marker begins but isn't complete yet
    assert sc.find(marker, 0, streaming=True) == -1
    sc.feed(b"@@yy")  # completes the marker across the chunk boundary
    assert sc.find(marker, 0, streaming=True) == 2


def test_handles_large_chunked_payload_correctly():
    sc = StreamScanner()
    big = (b"Z" * 200_000)
    sc.feed(b"@@B@@")
    for off in range(0, len(big), 4096):
        sc.feed(big[off : off + 4096])
    sc.feed(b"@@E@@")
    start = sc.find(b"@@B@@") + len(b"@@B@@")
    stop = sc.find(b"@@E@@", start, streaming=True)
    assert sc.text(start, stop) == big.decode()


def test_text_is_lossy_on_invalid_utf8():
    sc = StreamScanner()
    sc.feed(b"@@B@@\xff\xfe@@E@@")
    start = sc.find(b"@@B@@") + len(b"@@B@@")
    stop = sc.find(b"@@E@@", start)
    assert sc.text(start, stop) == "��"


def test_streaming_find_is_independent_per_marker():
    sc = StreamScanner()
    sc.feed(b"first @@A@@ middle ")
    assert sc.find(b"@@A@@", 0, streaming=True) == 6
    # A different marker maintains its own resume offset.
    assert sc.find(b"@@B@@", 0, streaming=True) == -1
    sc.feed(b"@@B@@ end")
    assert sc.find(b"@@B@@", 0, streaming=True) == len(b"first @@A@@ middle ")
