import pefile
import sys

def analyze_pe_sections(filename):
    try:
        pe = pefile.PE(filename)
    except FileNotFoundError:
        print(f"File not found: {filename}")
        return
    except pefile.PEFormatError:
        print(f"Invalid PE file: {filename}")
        return

    print(f"Analyzing PE file: {filename}")
    print(f"Number of sections: {len(pe.sections)}\n")

    for section in pe.sections:
        print(f"Section Name: {section.Name.decode().rstrip('x00')}")
        print(f"  Virtual Address: {hex(section.VirtualAddress)}")
        print(f"  Virtual Size: {hex(section.Misc_VirtualSize)}")
        print(f"  Size of Raw Data: {hex(section.SizeOfRawData)}")
        print(f"  Characteristics: {hex(section.Characteristics)}")

        # Interpret characteristics
        characteristics = []
        if section.Characteristics & 0x00000020:
            characteristics.append("CODE")
        if section.Characteristics & 0x00000040:
            characteristics.append("INITIALIZED_DATA")
        if section.Characteristics & 0x00000080:
            characteristics.append("UNINITIALIZED_DATA")
        if section.Characteristics & 0x00000100:
            characteristics.append("READ_ONLY")
        if section.Characteristics & 0x00000200:
            characteristics.append("WRITE")
        if section.Characteristics & 0x00000400:
            characteristics.append("EXECUTE")
        if section.Characteristics & 0x00000800:
            characteristics.append("SHARED")
        if section.Characteristics & 0x00001000:
            characteristics.append("EXECUTE_READ")
        if section.Characteristics & 0x00002000:
            characteristics.append("EXECUTE_READ_WRITE")
        if section.Characteristics & 0x00004000:
            characteristics.append("EXECUTE_READ_WRITE_SHARE")
        if section.Characteristics & 0x00008000:
            characteristics.append("READ_WRITE")
        if section.Characteristics & 0x00010000:
            characteristics.append("READ_WRITE_SHARE")
        if section.Characteristics & 0x00080000:
            characteristics.append("ALIGN_16BYTES")
        if section.Characteristics & 0x00100000:
            characteristics.append("ALIGN_32BYTES")
        if section.Characteristics & 0x00200000:
            characteristics.append("ALIGN_64BYTES")
        if section.Characteristics & 0x00400000:
            characteristics.append("ALIGN_128BYTES")
        if section.Characteristics & 0x00800000:
            characteristics.append("ALIGN_256BYTES")
        if section.Characteristics & 0x01000000:
            characteristics.append("ALIGN_512BYTES")
        if section.Characteristics & 0x02000000:
            characteristics.append("ALIGN_1024BYTES")
        if section.Characteristics & 0x04000000:
            characteristics.append("ALIGN_2048BYTES")
        if section.Characteristics & 0x08000000:
            characteristics.append("ALIGN_4096BYTES")
        if section.Characteristics & 0x10000000:
            characteristics.append("ALIGN_8192BYTES")
        if section.Characteristics & 0x20000000:
            characteristics.append("LINK_INFO")
        if section.Characteristics & 0x80000000:
            characteristics.append("REMOVE")
        if section.Characteristics & 0x40000000:
            characteristics.append("COMPRESSION_MASK")

        print(f"  Characteristics Flags: {', '.join(characteristics)}\n")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        filename = sys.argv[1]
    else:
        filename = "AgentService.exe"  # Replace with your PE file

    analyze_pe_sections(filename)