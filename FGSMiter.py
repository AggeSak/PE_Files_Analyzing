import os
import lief

# Define source and destination directories
path1 = r"C:\Users\User\Desktop\Diploma\a"  # Replace with your actual source path
path2 = r"C:\Users\User\Desktop\Diploma\j"  # Replace with your actual destination path
dll_to_add = "putty.exe"  # The DLL to inject into all files

# Ensure the destination directory exists
os.makedirs(path2, exist_ok=True)

def add_import(target_file, dll_name, output_file):
    """ Inject a specific DLL into an executable or DLL and save the modified file. """
    binary = lief.parse(target_file)

    if binary:
        # Check if the DLL is already imported
        if dll_name not in [imp.name for imp in binary.imports]:
            binary.add_library(dll_name)  # Inject the DLL
        
        binary.write(output_file)  # Save modified file
        print(f"Modified file saved as: {output_file}")

# Process all .exe and .dll files in path1
pe_files = [f for f in os.listdir(path1) if f.endswith((".exe", ".dll"))]

for pe_file in pe_files:
    input_path = os.path.join(path1, pe_file)  # Original file
    output_path = os.path.join(path2, pe_file)  # Modified file

    add_import(input_path, dll_to_add, output_path)  # Inject `tr.dll`
