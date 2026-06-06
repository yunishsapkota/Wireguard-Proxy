#!/usr/bin/env python3
"""
generate_secret.py — One-time utility
======================================
Generates a cryptographically secure 32-byte secret key for
authenticating the home server → VPS registration channel.

Run once on any machine, then paste the output into both config.ini files.

Usage:
  python generate_secret.py
"""
import secrets
import sys

key = secrets.token_hex(32)   # 64-char hex = 256 bits
print(f"\nGenerated secret key:\n\n  {key}\n")
print("Copy this value into the [relay] and [client] sections")
print("of config.ini on both your VPS and home server.\n")
