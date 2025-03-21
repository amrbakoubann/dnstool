"""
Build script for creating a standalone executable with PyInstaller.
Run this script to package the DNS Query Tool as an EXE file.
"""

import PyInstaller.__main__
import os
import shutil

# Clean build directories if they exist.
if os.path.exists("build"):
    shutil.rmtree("build")
if os.path.exists("dist"):
    shutil.rmtree("dist")

# Configure PyInstaller options.
PyInstaller.__main__.run([
    'dns_query_tool/main.py',
    '--name=DNS_Query_Tool',
    '--windowed',  # No console window.
    '--onefile',   # Single EXE file.
    '--add-data=README.md;.',  # Include additional files.
    '--icon=icon.ico',  # Include an icon file if available.
    '--noconsole',
    '--clean',
])

print("Build completed! EXE file created in the 'dist' directory.")
