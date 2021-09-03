---
title: "Nostego"
subtitle: "ALLES! CTF 2021"
author: GoProSlowYo
date: "2021-09-03"
subject: "Nostego Write-Up"
keywords: \[ALLES!, CTF, InfoSec\]
lang: "en"
titlepage: true
titlepage-text-color: "FFFFFF"
titlepage-color: "0c0d0e"
titlepage-rule-color: "8ac53e"
titlepage-rule-height: 0
logo: "./logo.png"
logo-width: 3in
toc: true
toc-own-page: true
---
# Nostego

Writeup by: [GoProSlowYo](https://github.com/goproslowyo)

Team: [OnlyFeet](https://ctftime.org/team/144644)

Writeup URL: [GitHub](https://infosecstreams.github.io/allesctf2021/nostego/)

----

```text
It cannot be stego because the source is attached.
```

----

## Initial Research

We are given an image that looks like "noise" or "snow" on a TV screen and a python script that seems to have generated said noisy image. We can probably reverse the python script to output the original image.

![noisy image](./ALLLES.enc.png)

```python
from PIL import Image
import sys

if len(sys.argv) != 3:
    print("Usage: %s [infile] [outfile]" % sys.argv[0])
    sys.exit(1)

image = Image.open(sys.argv[1]).convert("F")
width, height = image.size
result = Image.new("F", (width, height))

ROUNDS = 32

for i in range(width):
    for j in range(height):
        value = 0
        di, dj = 1337, 42
        for k in range(ROUNDS):
            di, dj = (di * di + dj) % width, (dj * dj + di) % height
            value += image.getpixel(((i + di) % width, (j + dj + (i + di)//width) % height))
        result.putpixel((i, j), value / ROUNDS)

result = result.convert("RGB")
result.save(sys.argv[2])
```

----

## Reversing

```python
code.
```

----

## Victory

Submit the flag and claim the points:

**ALLES!{flag-goes-here}**
