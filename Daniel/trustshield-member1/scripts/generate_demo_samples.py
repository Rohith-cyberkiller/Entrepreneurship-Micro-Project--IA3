"""
Module 6: Safe Demo Sample Generator
Generates 4 safe, non-malicious test binaries in demo_samples/ for live IA3 demonstration:
  1. sample1_clean_signed_sim.exe       - Normal entropy (~5.6), standard PE headers, benign imports, signed cert
  2. sample2_fake_chrome_clone.exe       - Claims ProductName='Google Chrome' in metadata but is Unsigned
  3. sample3_packed_high_entropy.exe     - UPX0 + UPX1 sections, simulated high entropy (~7.92), W+X permissions
  4. sample4_masquerading_invoice.pdf.exe - Double extension masquerading, MZ header, suspicious IAT APIs
"""

import os
import sys
import struct
import random
import pefile

def make_version_string(key: str, value: str) -> bytes:
    key_bytes = (key + '\0').encode('utf-16le')
    val_bytes = (value + '\0').encode('utf-16le')
    val_len_words = len(value) + 1
    hdr = bytearray(6)
    struct.pack_into('<HHH', hdr, 0, 0, val_len_words, 1)
    data = hdr + key_bytes
    while len(data) % 4 != 0:
        data += b'\0\0'
    data += val_bytes
    while len(data) % 4 != 0:
        data += b'\0\0'
    struct.pack_into('<H', data, 0, len(data))
    return bytes(data)

def make_version_info_resource(entries: dict) -> bytes:
    """Builds a binary VS_VERSIONINFO resource tree in UTF-16LE."""
    table_key = ('040904b0\0').encode('utf-16le')
    table_data = bytearray()
    for k, v in entries.items():
        table_data += make_version_string(k, v)

    st_hdr = bytearray(6)
    struct.pack_into('<HHH', st_hdr, 0, 0, 0, 1)
    st = st_hdr + table_key
    while len(st) % 4 != 0:
        st += b'\0\0'
    st += table_data
    struct.pack_into('<H', st, 0, len(st))

    sfi_key = ('StringFileInfo\0').encode('utf-16le')
    sfi_hdr = bytearray(6)
    struct.pack_into('<HHH', sfi_hdr, 0, 0, 0, 1)
    sfi = sfi_hdr + sfi_key
    while len(sfi) % 4 != 0:
        sfi += b'\0\0'
    sfi += st
    struct.pack_into('<H', sfi, 0, len(sfi))

    vinfo_key = ('VS_VERSION_INFO\0').encode('utf-16le')
    ffi = bytearray(52)
    struct.pack_into('<I', ffi, 0, 0xFEEF04BD) # dwSignature
    struct.pack_into('<I', ffi, 4, 0x00010000) # dwStrucVersion

    vinfo_hdr = bytearray(6)
    struct.pack_into('<HHH', vinfo_hdr, 0, 0, 52, 0)
    vinfo = vinfo_hdr + vinfo_key
    while len(vinfo) % 4 != 0:
        vinfo += b'\0\0'
    vinfo += ffi
    while len(vinfo) % 4 != 0:
        vinfo += b'\0\0'
    vinfo += sfi
    struct.pack_into('<H', vinfo, 0, len(vinfo))
    return bytes(vinfo)

def build_resource_section(rsrc_rva: int, entries: dict) -> bytes:
    """Builds full .rsrc directory tree containing the version info resource."""
    vi_data = make_version_info_resource(entries)

    root_table = struct.pack('<IIHHHH', 0, 0, 0, 0, 0, 1)
    root_entry = struct.pack('<II', 16, 0x80000000 | 24) # RT_VERSION -> Type Table at offset 24

    type_table = struct.pack('<IIHHHH', 0, 0, 0, 0, 0, 1)
    type_entry = struct.pack('<II', 1, 0x80000000 | 48) # ID 1 -> Lang Table at offset 48

    lang_table = struct.pack('<IIHHHH', 0, 0, 0, 0, 0, 1)
    lang_entry = struct.pack('<II', 0x0409, 72) # Lang 0x0409 (US English) -> Data Entry at 72

    data_rva = rsrc_rva + 88 # 72 + 16 bytes for Data Entry
    data_entry = struct.pack('<IIII', data_rva, len(vi_data), 0, 0)

    return root_table + root_entry + type_table + type_entry + lang_table + lang_entry + data_entry + vi_data

def build_import_section(rdata_rva: int, dll_name: str, functions: list) -> bytes:
    """Builds full .rdata Import Directory Table (IDT), ILT, IAT, and Hint/Name table."""
    idt_size = 40 # 1 descriptor (20 bytes) + null descriptor (20 bytes)
    ilt_offset = idt_size
    ilt_size = (len(functions) + 1) * 4

    iat_offset = ilt_offset + ilt_size
    iat_size = (len(functions) + 1) * 4

    dll_name_offset = iat_offset + iat_size
    dll_bytes = dll_name.encode('ascii') + b'\0'

    hint_name_offset = dll_name_offset + len(dll_bytes)
    if hint_name_offset % 2 != 0:
        hint_name_offset += 1

    hint_offsets = []
    curr = hint_name_offset
    hint_data = bytearray()
    for fn in functions:
        hint_offsets.append(curr)
        entry = struct.pack('<H', 0) + fn.encode('ascii') + b'\0'
        if len(entry) % 2 != 0:
            entry += b'\0'
        hint_data += entry
        curr += len(entry)

    rdata = bytearray(curr)
    # Fill IDT
    struct.pack_into('<IIIII', rdata, 0, rdata_rva + ilt_offset, 0, 0, rdata_rva + dll_name_offset, rdata_rva + iat_offset)

    # Fill ILT & IAT
    for i, h_off in enumerate(hint_offsets):
        struct.pack_into('<I', rdata, ilt_offset + i * 4, rdata_rva + h_off)
        struct.pack_into('<I', rdata, iat_offset + i * 4, rdata_rva + h_off)

    rdata[dll_name_offset:dll_name_offset + len(dll_bytes)] = dll_bytes
    rdata[hint_name_offset:hint_name_offset + len(hint_data)] = hint_data

    return bytes(rdata)

def generate_natural_code_bytes(length: int) -> bytes:
    """Generates synthetic x86/x64 instruction sequence with natural entropy ~5.6."""
    common_opcodes = [
        b"\x55\x89\xE5",         # push ebp; mov ebp, esp
        b"\x83\xEC\x10",         # sub esp, 16
        b"\x8B\x45\x08",         # mov eax, [ebp+8]
        b"\x83\xC0\x01",         # add eax, 1
        b"\x89\x45\xFC",         # mov [ebp-4], eax
        b"\x85\xC0",             # test eax, eax
        b"\x74\x05",             # jz +5
        b"\x31\xC0",             # xor eax, eax
        b"\x5D\xC3",             # pop ebp; ret
        b"\x90\x90\x90",         # nop nop nop
        b"\x48\x89\x5C\x24\x08", # mov [rsp+8], rbx
        b"\xFF\x15\x00\x20\x40\x00" # call dword ptr [IAT]
    ]
    res = bytearray()
    while len(res) < length:
        res += random.choice(common_opcodes)
    return bytes(res[:length])

def get_system_cert_block() -> bytes:
    """Extracts a valid Windows Authenticode signature block from python.exe for clean simulation."""
    try:
        pe = pefile.PE(sys.executable)
        sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
        if sec.Size > 0 and sec.VirtualAddress > 0:
            with open(sys.executable, 'rb') as f:
                f.seek(sec.VirtualAddress)
                return f.read(sec.Size)
    except Exception:
        pass

    # Fallback to simulated WIN_CERTIFICATE structure
    dummy_cert = b"\x30\x82\x04\x00" + os.urandom(1024)
    hdr = struct.pack('<IHH', len(dummy_cert) + 8, 0x0200, 0x0002)
    return hdr + dummy_cert

def assemble_pe(
    sections: list,
    import_rva: int = 0,
    import_size: int = 0,
    rsrc_rva: int = 0,
    rsrc_size: int = 0,
    cert_block: bytes = None,
    timedatestamp: int = 0x66000000
) -> bytes:
    """
    Assembles a valid 32-bit PE binary with arbitrary sections, imports, resources,
    and optional security certificate table.
    """
    FILE_ALIGN = 0x200
    SEC_ALIGN = 0x1000

    dos = bytearray(64)
    dos[0:2] = b'MZ'
    struct.pack_into('<I', dos, 0x3C, 64)

    pe_sig = b'PE\0\0'
    num_sections = len(sections)
    file_hdr = struct.pack('<HHIIIHH', 0x14C, num_sections, timedatestamp, 0, 0, 224, 0x102)

    # Compute SizeOfImage
    highest_rva = 0x1000
    for s in sections:
        top = s['vaddr'] + ((s['vsize'] + SEC_ALIGN - 1) // SEC_ALIGN * SEC_ALIGN)
        if top > highest_rva:
            highest_rva = top

    opt_hdr = bytearray(224)
    struct.pack_into('<H', opt_hdr, 0, 0x10B) # PE32
    struct.pack_into('<I', opt_hdr, 16, 0x1000) # EntryPoint
    struct.pack_into('<I', opt_hdr, 28, 0x400000) # ImageBase
    struct.pack_into('<I', opt_hdr, 32, SEC_ALIGN)
    struct.pack_into('<I', opt_hdr, 36, FILE_ALIGN)
    struct.pack_into('<I', opt_hdr, 56, highest_rva) # SizeOfImage
    struct.pack_into('<I', opt_hdr, 60, 0x200) # SizeOfHeaders
    struct.pack_into('<H', opt_hdr, 68, 2) # GUI
    struct.pack_into('<I', opt_hdr, 92, 16) # Num RVA and sizes

    # Data Directories
    if import_rva > 0:
        struct.pack_into('<II', opt_hdr, 96 + 1 * 8, import_rva, import_size)
    if rsrc_rva > 0:
        struct.pack_into('<II', opt_hdr, 96 + 2 * 8, rsrc_rva, rsrc_size)

    # Section Headers
    sec_hdrs = bytearray()
    for s in sections:
        sec_hdrs += struct.pack(
            '<8sIIIIIIHHI',
            s['name'].encode('ascii')[:8].ljust(8, b'\0'),
            s['vsize'],
            s['vaddr'],
            s['rawsize'],
            s['rawaddr'],
            0, 0, 0, 0,
            s['chars']
        )

    headers = (dos + pe_sig + file_hdr + opt_hdr + sec_hdrs).ljust(FILE_ALIGN, b'\0')

    body = bytearray(headers)
    for s in sections:
        if s['rawsize'] > 0:
            body += s['data'].ljust(s['rawsize'], b'\0')

    # Security Directory (Appended at end of raw file)
    if cert_block:
        cert_offset = len(body)
        struct.pack_into('<II', body, 64 + 4 + 20 + 96 + 4 * 8, cert_offset, len(cert_block))
        body += cert_block

    return bytes(body)

def generate_samples(output_dir: str = "demo_samples"):
    """Creates the 4 safe demonstration binaries."""
    os.makedirs(output_dir, exist_ok=True)
    print(f"Generating safe IA3 demo samples in '{output_dir}'...")

    # ----------------------------------------------------
    # Sample 1: Clean, Signed Simulation (Normal Entropy ~5.4)
    # ----------------------------------------------------
    s1_path = os.path.join(output_dir, "sample1_clean_signed_sim.exe")
    code1 = generate_natural_code_bytes(32768)
    data1 = (b"TrustShield Clean Utility Module - Standard PE Binary Code\x00" * 400)[:16384]
    imports1 = build_import_section(0x2000, "KERNEL32.DLL", ["ExitProcess", "GetModuleHandleA", "CreateFileA", "CloseHandle"])
    cert_block1 = get_system_cert_block()

    sections1 = [
        {"name": ".text", "vsize": len(code1), "vaddr": 0x1000, "rawsize": len(code1), "rawaddr": 0x200, "chars": 0x60000020, "data": code1},
        {"name": ".rdata", "vsize": len(imports1), "vaddr": 0x10000, "rawsize": 0x400, "rawaddr": 0x200 + len(code1), "chars": 0x40000040, "data": imports1},
        {"name": ".data", "vsize": len(data1), "vaddr": 0x11000, "rawsize": len(data1), "rawaddr": 0x600 + len(code1), "chars": 0xC0000040, "data": data1}
    ]
    raw_s1 = assemble_pe(sections1, import_rva=0x10000, import_size=len(imports1), cert_block=cert_block1)
    with open(s1_path, "wb") as f:
        f.write(raw_s1)
    s1_prompt_path = os.path.join(output_dir, "1_clean_utility_sim.exe")
    with open(s1_prompt_path, "wb") as f:
        f.write(raw_s1)
    print(f"  [+] Created: {s1_path} and 1_clean_utility_sim.exe (Clean, signed, normal entropy ~5.6)")

    # ----------------------------------------------------
    # Sample 2: Counterfeit Google Chrome Clone (Unsigned)
    # ----------------------------------------------------
    s2_path = os.path.join(output_dir, "sample2_fake_chrome_clone.exe")
    code2 = generate_natural_code_bytes(1024)
    imports2 = build_import_section(0x2000, "KERNEL32.DLL", ["ExitProcess", "MessageBoxA"])
    rsrc2 = build_resource_section(0x3000, {
        "CompanyName": "Google LLC",
        "ProductName": "Google Chrome",
        "FileDescription": "Google Chrome Installer",
        "OriginalFilename": "chrome.exe"
    })
    sections2 = [
        {"name": ".text", "vsize": len(code2), "vaddr": 0x1000, "rawsize": 0x400, "rawaddr": 0x200, "chars": 0x60000020, "data": code2},
        {"name": ".rdata", "vsize": len(imports2), "vaddr": 0x2000, "rawsize": 0x400, "rawaddr": 0x600, "chars": 0x40000040, "data": imports2},
        {"name": ".rsrc", "vsize": len(rsrc2), "vaddr": 0x3000, "rawsize": 0x400, "rawaddr": 0xA00, "chars": 0x40000040, "data": rsrc2}
    ]
    raw_s2 = assemble_pe(sections2, import_rva=0x2000, import_size=len(imports2), rsrc_rva=0x3000, rsrc_size=len(rsrc2), cert_block=None)
    with open(s2_path, "wb") as f:
        f.write(raw_s2)
    s2_prompt_path = os.path.join(output_dir, "2_fake_chrome_installer.exe")
    with open(s2_prompt_path, "wb") as f:
        f.write(raw_s2)
    print(f"  [+] Created: {s2_path} and 2_fake_chrome_installer.exe (Counterfeit Chrome Clone - Claims Google LLC, Unsigned)")

    # ----------------------------------------------------
    # Sample 3: Packed High Entropy (UPX0 + UPX1 + W+X + Suspicious APIs)
    # ----------------------------------------------------
    s3_path = os.path.join(output_dir, "sample3_packed_high_entropy.exe")
    dangerous_s3 = ["VirtualAllocEx", "WriteProcessMemory"]
    imports3 = build_import_section(0x2000, "KERNEL32.DLL", dangerous_s3)
    high_entropy_bytes = os.urandom(65536)
    sections3 = [
        {"name": "UPX0", "vsize": 409600, "vaddr": 0x1000, "rawsize": 0, "rawaddr": 0, "chars": 0xE0000020, "data": b""},
        {"name": ".rdata", "vsize": len(imports3), "vaddr": 0x2000, "rawsize": 0x400, "rawaddr": 0x200, "chars": 0x40000040, "data": imports3},
        {"name": "UPX1", "vsize": 1433600, "vaddr": 0x65000, "rawsize": len(high_entropy_bytes), "rawaddr": 0x600, "chars": 0xE0000020, "data": high_entropy_bytes}
    ]
    raw_s3 = assemble_pe(sections3, import_rva=0x2000, import_size=len(imports3), cert_block=None)
    with open(s3_path, "wb") as f:
        f.write(raw_s3)
    s3_prompt_path = os.path.join(output_dir, "3_packed_malware_sim.exe")
    with open(s3_prompt_path, "wb") as f:
        f.write(raw_s3)
    print(f"  [+] Created: {s3_path} and 3_packed_malware_sim.exe (High Entropy ~7.92, UPX0, W+X, VirtualAllocEx/WriteProcessMemory)")

    # ----------------------------------------------------
    # Sample 4: Masquerading Double Extension & Document Extension + Dangerous APIs
    # ----------------------------------------------------
    s4_path = os.path.join(output_dir, "sample4_masquerading_invoice.pdf.exe")
    code4 = generate_natural_code_bytes(1024)
    # High-Risk Process Injection Triad + Downloader + Keylogger
    dangerous_apis = [
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "URLDownloadToFileW",
        "SetWindowsHookExW"
    ]
    imports4 = build_import_section(0x2000, "KERNEL32.DLL", dangerous_apis)
    sections4 = [
        {"name": ".text", "vsize": len(code4), "vaddr": 0x1000, "rawsize": 0x400, "rawaddr": 0x200, "chars": 0x60000020, "data": code4},
        {"name": ".rdata", "vsize": len(imports4), "vaddr": 0x2000, "rawsize": 0x400, "rawaddr": 0x600, "chars": 0x40000040, "data": imports4}
    ]
    raw_s4 = assemble_pe(sections4, import_rva=0x2000, import_size=len(imports4), cert_block=None)
    with open(s4_path, "wb") as f:
        f.write(raw_s4)
    s4_prompt_path = os.path.join(output_dir, "4_masquerading_document.pdf")
    with open(s4_prompt_path, "wb") as f:
        f.write(raw_s4)
    print(f"  [+] Created: {s4_path} and 4_masquerading_document.pdf (Masquerading MZ Header, Process Injection Triad + Downloader)")

    print("\nAll safe demo test files generated successfully!")

if __name__ == "__main__":
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "demo_samples"
    generate_samples(out_dir)
