#!/usr/bin/env python3
"""Remove generated build artifacts from a DEAC working tree."""
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
DIRS = {"build", "Testing", "CMakeFiles", ".vs", "x64", "Debug", "Release", "ARM64"}
FILES = {"CMakeCache.txt", "cmake_install.cmake", "Makefile", "CTestTestfile.cmake", "install_manifest.txt", "compile_commands.json"}
EXTS = {".o", ".obj", ".a", ".lib", ".dll", ".sys", ".exe", ".pdb", ".ilk", ".exp", ".d", ".gch"}

removed = 0
for path in sorted(ROOT.rglob("*"), reverse=True):
    if not path.exists():
        continue
    if path.is_dir() and path.name in DIRS:
        shutil.rmtree(path)
        removed += 1
    elif path.is_file() and (path.name in FILES or path.suffix.lower() in EXTS):
        path.unlink()
        removed += 1
print(f"Removed {removed} generated artifact(s).")
