"""
Legacy Bridge Shim: Redirects execution to core/create_hash.py
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.create_hash import run_interactive

if __name__ == "__main__":
    run_interactive()