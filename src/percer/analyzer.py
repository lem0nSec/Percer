import hashlib
import pefile
import math
import os
import sys
from functools import cached_property
from typing import Dict, List, Optional, Union, Any, TextIO
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from asn1crypto import cms

from .constants import SUBSYSTEMS, ARCHITECTURES, CHARACTERISTICS

class PEAnalyzer:
    """
    Wrapper for pefile to provide easy access to static analysis data.
    """
    def __init__(self, pe_obj: pefile.PE, file_path: Optional[str] = None):
        self._pe = pe_obj
        self.file_path = file_path

    @classmethod
    def from_file(cls, file_path: str):
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        # Let pefile exceptions bubble up naturally
        pe = pefile.PE(file_path)
        return cls(pe, file_path=file_path)

    @classmethod
    def from_bytes(cls, data: bytes):
        pe = pefile.PE(data=data)
        return cls(pe, file_path=None)

    @property
    def handle(self) -> pefile.PE:
        """Direct access to the underlying pefile object."""
        return self._pe

    @cached_property
    def content(self) -> bytes:
        """
        Returns the raw bytes of the file.
        Uses cached __data__ if available to avoid expensive rebuilds.
        Fallback to write() for compatibility.
        """
        if hasattr(self._pe, '__data__') and self._pe.__data__:
            return self._pe.__data__
        return self._pe.write()

    @cached_property
    def size(self) -> int:
        """Returns the size of the PE file"""
        if hasattr(self._pe, '__data__') and self._pe.__data__:
            return len(self._pe.__data__)
        return len(self._pe.write())

    @cached_property
    def file_information(self) -> Dict[str, str]:
        """Extracts file information (original filename, product name, etc)"""
        info = {}
        if not hasattr(self._pe, 'FileInfo'):
            return info

        for fileinfo in self._pe.FileInfo:
            for entry in fileinfo:
                if entry.Key != b'StringFileInfo':
                    continue
                for st in entry.StringTable:
                    for key, value in st.entries.items():
                        try:
                            k = key.decode('utf-8')
                            v = value.decode('utf-8')
                            info[k] = v
                        except UnicodeDecodeError:
                            continue
        return info

    # These are properties that return single file information
    @property
    def original_filename(self) -> str:
        return self.file_information.get('OriginalFilename', '')

    @property
    def file_description(self) -> str:
        return self.file_information.get('FileDescription', '')

    @property
    def internal_name(self) -> str:
        return self.file_information.get('InternalName', '')

    @property
    def product_name(self) -> str:
        return self.file_information.get('ProductName', '')

    # It seems that ProductVersion is actually the FileVersion and viceversa
    @property
    def product_version(self) -> str:
        return self.file_information.get('ProductVersion', self.file_information.get('FileVersion', ''))

    @property
    def file_version(self) -> str:
        return self.file_information.get('FileVersion', self.file_information.get('ProductVersion', ''))

    @property
    def architecture(self) -> str:
        machine = self._pe.FILE_HEADER.Machine
        return ARCHITECTURES.get(machine, f"Unknown (0x{machine:04x})")

    @property
    def subsystem(self) -> str:
        sub = self._pe.OPTIONAL_HEADER.Subsystem
        return SUBSYSTEMS.get(sub, SUBSYSTEMS.get(0, "Unknown"))

    @property
    def pe_type(self) -> str:
        if self._pe.is_exe():
            return "Executable image - .exe"
        if self._pe.is_dll():
            return "Dynamic link library - .dll"
        if self._pe.is_driver():
             return "Driver (Native subsystem) - .sys"
        return "Unknown or Special PE Type"

    @property
    def is_signed(self) -> bool:
        """Checks if the Security Directory exists and points to data."""
        try:
            dir_index = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
            dir_entry = self._pe.OPTIONAL_HEADER.DATA_DIRECTORY[dir_index]
            
            if dir_entry.VirtualAddress == 0 or dir_entry.Size == 0:
                return False
                
            if dir_entry.VirtualAddress >= len(self.content):
                return False
                
            return True
        except (IndexError, AttributeError):
            return False

    @cached_property
    def certificates(self) -> List[Dict[str, Any]]:
        if not self.is_signed:
            return []

        results = []
        try:
            dir_index = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
            security_dir = self._pe.OPTIONAL_HEADER.DATA_DIRECTORY[dir_index]
            
            # Extract raw signature data
            start = security_dir.VirtualAddress + 8 # Skip wrapper header
            end = security_dir.VirtualAddress + security_dir.Size
            cert_data = self.content[start:end]

            content_info = cms.ContentInfo.load(cert_data)
            signed_data = content_info['content']

            if signed_data['certificates']:
                for cert in signed_data['certificates']:
                    # Dump to DER then load into cryptography
                    x509_cert = x509.load_der_x509_certificate(cert.dump())

                    # Calculating Signature Hash in addition to the thumbprint
                    signature_hash = hashes.Hash(x509_cert.signature_hash_algorithm)
                    signature_hash.update(x509_cert.tbs_certificate_bytes)
                    signature_hash = signature_hash.finalize().hex()
                    
                    results.append({
                        'thumbprint': x509_cert.fingerprint(hashes.SHA1()).hex(),
                        'signature_hash': signature_hash,
                        'subject': x509_cert.subject.rfc4514_string(),
                        'not_before': x509_cert.not_valid_before_utc,
                        'not_after': x509_cert.not_valid_after_utc,
                        'serial': x509_cert.serial_number
                    })
        except Exception as e:
            raise ValueError(f"Failed to parse certificates: {e}")
            
        return results

    @property
    def pdb_path(self) -> str:
        if hasattr(self._pe, 'DIRECTORY_ENTRY_DEBUG'):
            for entry in self._pe.DIRECTORY_ENTRY_DEBUG:
                if hasattr(entry, 'entry') and hasattr(entry.entry, 'PdbFileName'):
                    raw_path = entry.entry.PdbFileName
                    return raw_path.strip(b'\x00').decode(errors='ignore')#.strip(b'\x00').decode()
        return ''

    def _calculate_entropy(data: bytes) -> float:
        """Calculates the Shannon entropy of a byte sequence."""
        if not data:
            return 0.0
        
        entropy = 0
        length = len(data)
        occurences = [0] * 256
        for byte in data:
            occurences[byte] += 1
            
        for count in occurences:
            if count == 0:
                continue
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
            
        return entropy

    @cached_property
    def sections(self) -> List[Dict[str, Any]]:
        results = []
        
        for section in self._pe.sections:
            try:
                name = section.Name.decode('utf-8').strip('\x00')
            except UnicodeDecodeError:
                name = str(section.Name)

            section_characteristics = []
            for char_val, char_name in CHARACTERISTICS.items():
                if section.Characteristics & char_val:
                    section_characteristics.append(char_name)

            entropy = self._calculate_entropy(section.get_data())

            section_info = {
                "name": name,
                "characteristics": section_characteristics,
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": hex(section.Misc_VirtualSize),
                "raw_size": hex(section.SizeOfRawData),
                "raw_offset": hex(section.PointerToRawData),
                "entropy": round(entropy, 3)
            }
            
            results.append(section_info)
            
        return results

    @cached_property
    def imports(self) -> Dict[str, List[str]]:
        if not hasattr(self._pe, 'DIRECTORY_ENTRY_IMPORT'):
            return {}

        results = {}
        for entry in self._pe.DIRECTORY_ENTRY_IMPORT:
            try:
                dll_name = entry.dll.decode('utf-8')
                results[dll_name] = []
                for imp in entry.imports:
                    if imp.name:
                        results[dll_name].append(imp.name.decode('utf-8'))
                    else:
                        results[dll_name].append(f"ordinal_{imp.ordinal}")
            except Exception:
                continue # Skip malformed entries
        return results

    @cached_property
    def exports(self) -> List[str]:
        if not hasattr(self._pe, 'DIRECTORY_ENTRY_EXPORT'):
            return []
        
        results = []
        for func in self._pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if func.name:
                try:
                    results.append(func.name.decode('utf-8'))
                except UnicodeDecodeError:
                    continue
        return results

    # Security Flags
    @property
    def has_nx(self) -> bool:
        return bool(self._pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)

    @property
    def has_guardcf(self) -> bool:
        return bool(self._pe.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_GUARD_CF)

    # Hashing
    def _calculate_pesha(self, algorithm_name: str) -> str:
        """
        Calculates authentihash (PE hash excluding signature and checksum).
        """
        try:
            checksum_offset = self._pe.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum')
            security_dir_entry = self._pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
            security_dir_offset = security_dir_entry.get_field_absolute_offset('VirtualAddress')
            sig_address = security_dir_entry.VirtualAddress
        except Exception:
            raise ValueError("Could not determine PE offsets for hashing")

        data = self.content 
        hasher = hashlib.new(algorithm_name)

        hasher.update(data[:checksum_offset])
        hasher.update(data[checksum_offset + 4 : security_dir_offset])
        
        start_of_rest = security_dir_offset + 8
        
        if 0 < sig_address < len(data):
            hasher.update(data[start_of_rest : sig_address])
        else:
            hasher.update(data[start_of_rest:])

        return hasher.hexdigest()

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()

    @property
    def sha1(self) -> str:
        return hashlib.sha1(self.content).hexdigest()

    @property
    def md5(self) -> str:
        return hashlib.md5(self.content).hexdigest()

    @property
    def pesha256(self) -> str:
        return self._calculate_pesha('sha256')

    @property
    def imp_hash(self) -> str:
        """wraps around pefile.get_imphash() for import hashing"""
        return self._pe.get_imphash()


class PEPrinter:
    """
    handles the formatting and output of PE analysis data.
    """
    def __init__(self, handle):
        self.pe = handle
        self.WIDTH = 17
        self.INDENT = " " * 4

    def dump_all(self, stream: TextIO = sys.stdout):
        """Print the whole report"""
        self.print_header(stream)
        self.print_hashes(stream)
        self.print_information(stream)
        self.print_sections(stream)
        self.print_imports(stream)
        self.print_exports(stream)
        self.print_certificates(stream)

    def _print_kv(self, key: str, value: str, stream: TextIO, indent_level: int = 0):
        """Helper to print aligned Key-Value pairs."""
        indent = self.INDENT * indent_level
        print(f"{indent}{key:<{self.WIDTH}}: {value}", file=stream)

    def print_header(self, stream: TextIO = sys.stdout):
        name = os.path.basename(self.pe.file_path) if self.pe.file_path else "Memory Buffer"
        print("=" * 60, file=stream)
        print(f"PE REPORT: {name}", file=stream)
        print("=" * 60 + "\n", file=stream)

    def print_hashes(self, stream: TextIO = sys.stdout):
        print("[+] HASHES", file=stream)
        self._print_kv("MD5", self.pe.md5, stream, 1)
        self._print_kv("SHA1", self.pe.sha1, stream, 1)
        self._print_kv("SHA256", self.pe.sha256, stream, 1)
        self._print_kv("ImpHash", self.pe.imp_hash, stream, 1)
        self._print_kv("PESHA256", self.pe._calculate_pesha('sha256'), stream, 1)
        print("", file=stream)

    def print_information(self, stream: TextIO = sys.stdout):
        print("[+] FILE GENERIC INFO", file=stream)
        
        # General PE Info
        self._print_kv("Type", self.pe.pe_type, stream, 1)
        self._print_kv("Arch", self.pe.architecture, stream, 1)
        self._print_kv("Subsystem", self.pe.subsystem, stream, 1)
        self._print_kv("Signed", str(self.pe.is_signed), stream, 1)
        self._print_kv("PDB Path", self.pe.pdb_path or "None", stream, 1)
        
        # Security Flags
        flags = []
        if self.pe.has_nx: flags.append("NX")
        if self.pe.has_guardcf: flags.append("GuardCF")
        self._print_kv("Sec. Flags", ", ".join(flags) if flags else "None", stream, 1)

        # File size
        self._print_kv('Size', f"{self.pe.size / 1000} kb", stream, 1)

        # File information
        print(f"\n{self.INDENT}[ File Information ]", file=stream)
        for key, val in self.pe.file_information.items():
            self._print_kv(key, val, stream, 2)

        # Hashes
        print(f"\n{self.INDENT * 2}[ Hashes ]", file=stream)
        self._print_kv("MD5", self.pe.md5, stream, 3)
        self._print_kv("SHA1", self.pe.sha1, stream, 3)
        self._print_kv("SHA256", self.pe.sha256, stream, 3)
        self._print_kv("PESHA256", self.pe._calculate_pesha('sha256'), stream, 3)
        self._print_kv("ImpHash", self.pe.imp_hash, stream, 3)
        print('', file=stream)

    def print_sections(self, stream: TextIO = sys.stdout):
        print("[+] SECTIONS", file=stream)
        sections = self.pe.sections
        
        if not sections:
            print(f"{self.INDENT}No sections found.", file=stream)
            return

        print(f"\n{'NAME':<10} {'VIRT_ADDR':<10} {'VIRT_SIZE':<10} {'RAW_SIZE':<10} {'ENTROPY':<10} {'PROPS'}", file=stream)
        print("-" * 60)

        for s in sections:
            props = ", ".join(s['characteristics'])
            print(f"{s['name']:<10} {s['virtual_address']:<10} {s['virtual_size']:<10} {s['raw_size']:<10} {s['entropy']:<10} {props}", file=stream)
        print("", file=stream)
    
    def print_imports(self, stream: TextIO = sys.stdout):
        print("[+] IMPORTS", file=stream)
        imports = self.pe.imports
        
        if not imports:
            print(f"{self.INDENT}No imports found.", file=stream)
            return

        for dll, functions in imports.items():
            print(f"{self.INDENT}* {dll}", file=stream)
            for func in functions:
                 print(f"{self.INDENT*2}- {func}", file=stream)
        print("", file=stream)

    def print_exports(self, stream: TextIO = sys.stdout):
        print("[+] EXPORTS", file=stream)
        exports = self.pe.exports

        if not exports:
            print(f"{self.INDENT}No exports found.", file=stream)
            return

        for func in exports:
            print(f"{self.INDENT}* {func}", file=stream)
        print("", file=stream)

    def print_certificates(self, stream: TextIO = sys.stdout):
        print("[+] SIGNING CERTIFICATES", file=stream)
        
        if not self.pe.is_signed:
            print(f"{self.INDENT}File is not signed.", file=stream)
            print("", file=stream)
            return

        for i, cert in enumerate(self.pe.certificates, 1):
            print(f"{self.INDENT}Certificate #{i}", file=stream)
            self._print_kv("Subject", cert['subject'], stream, 2)
            self._print_kv("Issuer", cert.get('issuer', 'N/A'), stream, 2) # Added safety get
            self._print_kv("Thumbprint", cert['thumbprint'], stream, 2)
            self._print_kv("Signature Hash", cert['signature_hash'], stream, 2)
            self._print_kv("Valid From", str(cert['not_before']), stream, 2)
            self._print_kv("Valid To", str(cert['not_after']), stream, 2)
            print("", file=stream)
