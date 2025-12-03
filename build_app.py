import PyInstaller.__main__
import customtkinter
import os
import sys

# 1. Get the path to CustomTkinter so we can include its theme files
ctk_path = os.path.dirname(customtkinter.__file__)

# 2. Define the separation character for Windows (;) vs Linux (:)
separator = ';' if os.name == 'nt' else ':'

# 3. Define the build arguments
args = [
    'main.py',                            # Your main script
    '--name=CyberGuard',                  # Name of the exe
    '--onedir',                           # Create a directory (easier to debug)
    '--noconfirm',                        # Overwrite old builds
    '--clean',                            # Clean cache
    # '--windowed',                       # <--- DISABLED FOR DEBUGGING (See error messages)
    
    # --- COLLECT ALL DATA ---
    f'--add-data={ctk_path}{separator}customtkinter',
    f'--add-data=database{separator}database',
    f'--add-data=modules{separator}modules',
    f'--add-data=tools{separator}tools',
    f'--add-data=ui{separator}ui',
    
    # --- COLLECT COMPLEX LIBRARIES ---
    '--collect-all=customtkinter',
    '--collect-all=matplotlib',
    '--collect-all=dns',
    '--collect-all=apscheduler',
    '--collect-all=plyer',
    '--collect-all=sqlalchemy',
    '--collect-all=reportlab',
    '--collect-all=requests',
    
    # --- HIDDEN IMPORTS ---
    '--hidden-import=PIL._tkinter_finder',
    '--hidden-import=babel.numbers',      # Common missing dep for some libs
]

print("🚀 Starting Professional Build Process...")
print(f"📂 Found CustomTkinter at: {ctk_path}")

# 4. Run PyInstaller
PyInstaller.__main__.run(args)

print("\n✅ BUILD COMPLETE.")
print("👉 Go to the 'dist/CyberGuard' folder and run 'CyberGuard.exe'")
print("👉 If it crashes, the console window will now stay open to tell you WHY.")