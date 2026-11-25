#!/usr/bin/env python3
"""Draws the Shellyard app icon (a lime prompt on a dark rounded square) as a
1024x1024 PNG using only the standard library. Usage: make-icon.py OUT.png"""
import math, struct, sys, zlib

N = 1024
SS = 3  # supersampling per axis
BG = (0x12, 0x16, 0x1c)
EDGE = (0x2a, 0x31, 0x3b)
LIME = (0xc5, 0xf0, 0x35)

def in_round_rect(x, y, x0, y0, x1, y1, r):
    cx = min(max(x, x0 + r), x1 - r)
    cy = min(max(y, y0 + r), y1 - r)
    return (x - cx) ** 2 + (y - cy) ** 2 <= r * r

def seg_dist(px, py, ax, ay, bx, by):
    dx, dy = bx - ax, by - ay
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
    return math.hypot(px - (ax + t * dx), py - (ay + t * dy))

# Shapes in a 1024 box: the macOS icon grid leaves ~100 px margin.
M, R = 100, 185
STROKE = 62
chevron = [((300, 360), (470, 512)), ((470, 512), (300, 664))]
underscore = ((540, 664), (730, 664))

def sample(x, y):
    if not in_round_rect(x, y, M, M, N - M, N - M, R):
        return None
    if not in_round_rect(x, y, M + 10, M + 10, N - M - 10, N - M - 10, R - 10):
        return EDGE
    d = min(seg_dist(x, y, *a, *b) for a, b in chevron + [underscore])
    if d <= STROKE / 2:
        return LIME
    # Subtle vertical gradient on the background.
    k = 1.0 + 0.10 * (1 - y / N)
    return tuple(min(255, int(c * k)) for c in BG)

rows = []
for j in range(N):
    row = bytearray([0])
    for i in range(N):
        acc = [0, 0, 0, 0]
        for sj in range(SS):
            for si in range(SS):
                c = sample(i + (si + 0.5) / SS, j + (sj + 0.5) / SS)
                if c:
                    acc[0] += c[0]; acc[1] += c[1]; acc[2] += c[2]; acc[3] += 255
        n = SS * SS
        a = acc[3] // n
        if a:
            row += bytes([acc[0] * 255 // acc[3], acc[1] * 255 // acc[3], acc[2] * 255 // acc[3], a])
        else:
            row += b"\0\0\0\0"
    rows.append(bytes(row))

def chunk(tag, data):
    return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", N, N, 8, 6, 0, 0, 0))
png += chunk(b"IDAT", zlib.compress(b"".join(rows), 9)) + chunk(b"IEND", b"")
open(sys.argv[1], "wb").write(png)
