#!/usr/bin/env python3

with open("/dev/fprotect") as f:
    for line in f:
        print(f.readline())

