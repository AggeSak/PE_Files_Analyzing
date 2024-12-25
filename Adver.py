import pefile
import os


def compare_files(file1, file2):
    if not os.path.exists(file1) or not os.path.exists(file2):
        print("One or both files do not exist.")
        return

    with open(file1, 'rb') as f1:
        data1 = f1.read()
    with open(file2, 'rb') as f2:
        data2 = f2.read()

    size1 = len(data1)
    size2 = len(data2)
    min_size = min(size1, size2)
    max_size = max(size1, size2)

    differences = 0
    for i in range(min_size):
        if data1[i] != data2[i]:
            differences += 1

    # Account for extra bytes in the larger file
    differences += abs(size1 - size2)

    # Calculate percentage difference
    if max_size > 0:
        percent_diff = (differences / max_size) * 100
    else:
        percent_diff = 0.0

    print(f"Number of differing bytes: {differences}")
    print(f"Percentage difference: {percent_diff:.2f}%")


    # Get file sizes
    size1 = len(data1)
    size2 = len(data2)
    min_size = min(size1, size2)
    max_size = max(size1, size2)

    differences = 0
    for i in range(min_size):
        if data1[i] != data2[i]:
            differences += 1

    # Account for extra bytes in the larger file
    differences += abs(size1 - size2)

    # Calculate percentage difference
    if max_size > 0:
        percent_diff = (differences / max_size) * 100
    else:
        percent_diff = 0.0

    # Print results
    print(f"File 1: {file1} | Size: {size1} bytes")
    print(f"File 2: {file2} | Size: {size2} bytes")
    print(f"Number of differing bytes: {differences}")
    print(f"Percentage difference: {percent_diff:.2f}%")



def align(value, alignment):
    """Aligns a value to the nearest multiple of alignment."""
    return (value + alignment - 1) & ~(alignment - 1)

def add_section_to_pe(file_path, output_path, section_name=".newsec", extra_bytes=b'\x00' * 4096):
    """
    Adds a new section to a PE file and writes extra bytes into it.
    Forces an increase in file size by explicitly adding more data.

    Parameters:
        file_path (str): Path to the input PE file.
        output_path (str): Path to save the modified PE file.
        section_name (str): Name of the new section (max 8 characters).
        extra_bytes (bytes): Data to write in the new section (default is 4KB of null bytes).
    """
    try:
        # Load the PE file
        pe = pefile.PE(file_path)

        # Calculate section alignment and file alignment
        section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
        file_alignment = pe.OPTIONAL_HEADER.FileAlignment

        # Determine the new section's raw size and aligned size
        new_section_raw_size = len(extra_bytes)
        aligned_raw_size = align(new_section_raw_size, file_alignment)
        aligned_virtual_size = align(new_section_raw_size, section_alignment)

        # Find the end of the last section
        last_section = pe.sections[-1]
        new_section_raw_offset = align(last_section.PointerToRawData + last_section.SizeOfRawData, file_alignment)
        new_section_virtual_offset = align(last_section.VirtualAddress + last_section.Misc_VirtualSize, section_alignment)

        # Create the new section header
        new_section = pefile.Structure(pe.__IMAGE_SECTION_HEADER_format__)
        new_section.Name = section_name.encode().ljust(8, b'\x00')  # Name must be 8 bytes
        new_section.VirtualAddress = new_section_virtual_offset
        new_section.Misc = new_section.Misc_PhysicalAddress = aligned_virtual_size
        new_section.PointerToRawData = new_section_raw_offset
        new_section.SizeOfRawData = aligned_raw_size
        new_section.Characteristics = 0x60000020  # Readable and executable section

        # Add the new section to the file
        pe.__structures__.append(new_section)
        pe.FILE_HEADER.NumberOfSections += 1

        # Explicitly set SizeOfImage to ensure file size increases
        pe.OPTIONAL_HEADER.SizeOfImage = new_section_virtual_offset + aligned_virtual_size

        # Extend the original data to fit the new section
        with open(file_path, 'rb') as f:
            original_data = f.read()

        # Ensure original_data is a bytes object
        if not isinstance(original_data, bytes):
            original_data = bytes(original_data)

        # Extend the file data to include the new section
        new_data = original_data + b'\x00' * (new_section_raw_offset + aligned_raw_size - len(original_data))
        new_data = new_data[:new_section_raw_offset] + extra_bytes + new_data[new_section_raw_offset + len(extra_bytes):]

        # Update the PE headers in the new data
        pe.set_bytes_at_offset(new_section_raw_offset, new_data[new_section_raw_offset:new_section_raw_offset + aligned_raw_size])

        # Save the modified file
        with open(output_path, 'wb') as f:
            f.write(new_data)

        print(f"Added new section '{section_name}' with {len(extra_bytes)} bytes.")
        print(f"Modified file saved as '{output_path}'.")
        print(f"New SizeOfImage: {pe.OPTIONAL_HEADER.SizeOfImage}")

    except Exception as e:
        print(f"An error occurred: {e}")


def append_data_to_pe(file_path, output_path, data_to_append):
    try:
        # Load the PE file
        pe = pefile.PE(file_path)
        data = bytearray(pe.__data__)

        # Determine file alignment
        file_alignment = pe.OPTIONAL_HEADER.FileAlignment

        # Find the end of the last section's raw data
        last_section = pe.sections[-1]
        end_raw_data = last_section.PointerToRawData + last_section.SizeOfRawData

        # Align the end offset to the file alignment
        append_offset = align(end_raw_data, file_alignment)

        # Extend the file data with the new data
        if append_offset > len(data):
            # Pad with zeros if necessary
            data += b'\x00' * (append_offset - len(data))
        data += data_to_append

        # Write the modified data to the output file
        with open(output_path, 'wb') as f:
            f.write(data)

        print(f"Data appended to '{output_path}' at offset 0x{append_offset:X}.")

    except Exception as e:
        print(f"An error occurred in append_data_to_pe: {e}")

# Example usage
data_to_append = b'ADVERSARnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnngggggggggggggIALDATA'  # Replace with your data

# Example usage
add_section_to_pe('aaaaa.exe', 'aa.exe')
append_data_to_pe('aa.exe', 'aaaaa.exe', data_to_append)


compare_files('putty.exe', 'aaaaa.exe')

