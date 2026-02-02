import hashlib
import pefile
import os
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from asn1crypto import cms

from .constants import SUBSYSTEMS, ARCHITECTURES, CHARACTERISTICS

class PortExec:
    def __init__(self, pe_obj, file_path=None):
        self.handle = pe_obj
        self.file_path = file_path

        self._parse_info()
        self._parse_headers()

    @classmethod
    def from_file(cls, file_path):
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        try:
            pe = pefile.PE(file_path)
        except Exception as E:
            raise ValueError(f"Exception has occurred: {E}")

        return cls(pe, file_path=file_path)

    @classmethod
    def from_bytes(cls, data):
        try:
            pe = pefile.PE(data=data)
        except Exception as E:
            raise ValueError(f"Exception has occurred: {E}")

        return cls(pe, file_path=None)

    @classmethod
    def from_pefile_object(cls, pe_obj):
        if not isinstance(pe_obj, pefile.PE):
            raise TypeError("Invalid input provided: not a pefile.PE object")

        return cls(pe_obj, file_path=None)

    def _parse_info(self):
        """Internal method to extract file info string table."""
        self.information = {}
        info = {}
        try:
            for fileinfo in self.handle.FileInfo:
                for entry in fileinfo:
                    if entry.Key == b'StringFileInfo':
                        for st in entry.StringTable:
                            for key, value in st.entries.items():
                                decoded_key = key.decode('utf-8')
                                decoded_value = value.decode('utf-8')
                                if decoded_key in [
                                        'OriginalFilename', 
                                        'FileDescription', 
                                        'ProductName', 
                                        'InternalName', 
                                        'FileVersion', 
                                        'ProductVersion']:
                                    info[decoded_key] = decoded_value
        except AttributeError:
            pass

        self.information['OriginalFilename'] = info['OriginalFilename'] if 'OriginalFilename' in info else ""
        self.information['FileDescription'] = info['FileDescription'] if 'FileDescription' in info else ""
        self.information['InternalName'] = info['InternalName'] if 'InternalName' in info else ""
        self.information['ProductName'] = info['ProductName'] if 'ProductName' in info else ""
        self.information['ProductVersion'] = info['FileVersion'] if 'FileVersion' in info else ""
        self.information['FileVersion'] = info['ProductVersion'] if 'ProductVersion' in info else ""
        
    def _parse_headers(self):
        """Internal method to parse header flags."""
        # Architecture and Subsystem logic using imported constants
        self.architecture = ARCHITECTURES.get(
            self.handle.FILE_HEADER.Machine, 
            f"Unknown (0x{self.handle.FILE_HEADER.Machine:04x})"
        )
        self.subsystem = SUBSYSTEMS.get(self.handle.OPTIONAL_HEADER.Subsystem, SUBSYSTEMS[0])
        
        # PE Type logic
        self.pe_type = self.pe_type()

    def _calculate_pesha(self, algorithm):
        """Internal method to calculate authentihash"""
        if algorithm != 'sha256' and algorithm != 'sha1':
            raise ValueError("Wrong pesha algorithm")

        checksum_offset = self.handle.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum')
        security_dir_entry = self.handle.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        security_dir_offset = security_dir_entry.get_field_absolute_offset('VirtualAddress')
        sig_address = security_dir_entry.VirtualAddress
        sig_size = security_dir_entry.Size
        sig_file_offset = sig_address 

        hasher = hashlib.new(algorithm)
        hasher.update(self.get_content()[:checksum_offset])
        hasher.update(self.get_content()[checksum_offset + 4 : security_dir_offset])
        start_of_rest = security_dir_offset + 8
        if sig_address > 0 and sig_address < len(self.get_content()):
            hasher.update(self.get_content()[start_of_rest : sig_file_offset])
        else:
            hasher.update(self.get_content()[start_of_rest:])

        return hasher.hexdigest()

    def pdb(self):
        if not hasattr(self.handle, 'DIRECTORY_ENTRY_DEBUG'):
            return ''

        for debug_entry in self.handle.DIRECTORY_ENTRY_DEBUG:
            dbg_type = debug_entry.struct.Type
            dbg_offset = debug_entry.struct.PointerToRawData

            if dbg_type == 2:
                pe_data = self.handle.__data__
                pe_data.seek(dbg_offset)
                data = pe_data.read(24)  # RSDS header + guid + age

                if data[0:4] == b'RSDS':
                    pdb_bytes = b''
                    while True:
                        byte = pe_data.read(1)
                        if byte == b'\x00' or byte == b'':
                            break
                        pdb_bytes += byte

                return pdb_bytes.decode(errors='ignore')

    def signed_status(self):
        if (self.handle.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]).VirtualAddress != 0:
            return True
        else:
            return False

    def certificates(self):
        if self.signed_status == False:
            raise ValueError(f"File is not signed.")
        
        certificates = []
        try:
            security_dir = self.handle.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
            cert_data = bytes(self.handle.write()[security_dir.VirtualAddress + 8:security_dir.VirtualAddress + security_dir.Size])
            content_info = cms.ContentInfo.load(cert_data)
            signed_data = content_info['content']

            for cert in signed_data['certificates']:
                x509_cert = x509.load_der_x509_certificate(cert.dump())
                thumbprint = x509_cert.fingerprint(hashes.SHA1()).hex()
                subject = x509_cert.subject.rfc4514_string()
                signature_hash = hashes.Hash(x509_cert.signature_hash_algorithm)
                signature_hash.update(x509_cert.tbs_certificate_bytes)
                signature_hash = signature_hash.finalize().hex()

                # Extract certificate validity period
                not_before = x509_cert.not_valid_before_utc
                not_after = x509_cert.not_valid_after_utc

                certificates.append({
                    'thumbprint': thumbprint,
                    'subject': subject,
                    'signature_hash': signature_hash,
                    'not_before': not_before,
                    'not_after': not_after
                })

            return certificates

        except Exception as E:
            print(f"Exception has occurred: {E}")

    def sections(self):
        sections = {}
        for section in self.handle.sections:
            section_name = section.Name.decode('utf-8')
            sections[section_name] = []

            for char in CHARACTERISTICS:
                if (section.Characteristics & char) != 0:
                    sections[section_name].append(CHARACTERISTICS[char])

        return sections

    def imports(self):
        imports = {}
        try:
            if not hasattr(self.handle, 'DIRECTORY_ENTRY_IMPORT'):
                return {}

            for entry in self.handle.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8')
                imports[dll_name] = []

                for imp in entry.imports:
                    if imp.name:
                        imports[dll_name].append(imp.name.decode('utf-8'))
                    else:
                        imports[dll_name].append(f"ordinal_{imp.ordinal}")

            return imports

        except Exception as E:
            print(f"Exception occurred: {E}")

    def exports(self):
        exports = []
        try:
            if not hasattr(self.handle, 'DIRECTORY_ENTRY_EXPORT'):
                return []

            for func in (self.handle).DIRECTORY_ENTRY_EXPORT.symbols:
                try:
                    exports.append(func.name.decode('utf-8'))
                except TypeError:
                    pass

            return exports
        
        except Exception as E:
            print(f"Exception occurred: {E}")

    def origFilename(self):
        return self.information['OriginalFilename']

    def fileDescription(self):
        return self.information['FileDescription']

    def internalName(self):
        return self.information['InternalName']

    def productName(self):
        return self.information['ProductName']

    def productVersion(self):
        return self.information['ProductVersion']

    def fileVersion(self):
        return self.information['FileVersion']

    def pe_type(self):
        if self.handle.is_exe(): return "Executable image - .exe"
        if self.handle.FILE_HEADER.Characteristics & 0x2000: return "Dynamic link library - .dll"
        if self.subsystem == SUBSYSTEMS[1]: return "Driver (Native subsystem) - .sys"
        return "Unknown or Special PE Type"

    def NX(self):
        return True if self.handle.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NX_COMPAT == True else False

    def guardcf(self):
        return True if self.handle.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_GUARD_CF == True else False

    def termserveraware(self):
        return True if self.handle.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE == True else False

    def safeseh(self):
        return True if self.handle.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_SEH == True else False

    def pesha256(self):
        return self._calculate_pesha('sha256')

    def pesha1(self):
        return self._calculate_pesha('sha1')

    def md5(self):
        return hashlib.md5(self.get_content()).hexdigest()

    def sha256(self):
        return hashlib.sha256(self.get_content()).hexdigest()

    def sha1(self):
        return hashlib.sha1(self.get_content()).hexdigest()

    def get_content(self):
        return self.handle.write()

    def get_handle(self):
        return self.handle

    def set_handle(self, handle):
        self.handle = handle


class PEPrinter:
    def __init__(self, handle):
        self.object = handle

    def print_header(self):
        print(f"Input PE\t: {os.path.basename(self.object.file_path)}\n" + "="*60)

    def print_information(self):
        # We'll use a standard width for labels to keep things clean
        w = 10 
        sub_w = 17 # Width for nested items (like hashes)

        print(f"{'PE':<{w}}: {self.object.pe_type}")
        
        print(f"{'Hashes':<{w}}v")
        print(f"\t* {'sha256':<{sub_w}}: {self.object.sha256()}")
        print(f"\t* {'md5':<{sub_w}}: {self.object.md5()}")
        print(f"\t* {'sha1':<{sub_w}}: {self.object.sha1()}")
        print(f"\t* {'peSha256':<{sub_w}}: {self.object.pesha256()}")
        print(f"\t* {'peSha1':<{sub_w}}: {self.object.pesha1()}")

        print(f"{'File Info':<{w}}v")
        for metadata, value in self.object.information.items():
            print(f"\t* {metadata:<{sub_w}}: {value}")

        print(f"\t* {'PDB':<{sub_w}}: {self.object.pdb()}")
        print(f"{'Signed':<{w}}: {self.object.signed_status()}")
        print(f"{'Machine':<{w}}: {self.object.architecture}")
        print(f"{'Subsystem':<{w}}: {self.object.subsystem}")

    def print_sections(self):
        print("Dumping sections:\n")
        for section in self.object.sections():
            print(f"* {section}\n\t{self.object.sections()[section]}")

    def print_imports(self):
        print("Dumping imports:\n")
        imports = self.object.imports()
        for lib in imports:
            print(lib)
            for import_name in imports[lib]:
                print(f"\t* {import_name}")

    def print_exports(self):
        print("Dumping exports:\n")
        exports = self.object.exports()
        for export_name in exports:
            print(f"* {export_name}")

    def print_certificates(self):
        if self.object.signed_status() == False:
            raise ValueError("File is not signed.")
            
        print("Dumping certificates:\n")
        certificates = self.object.certificates()
        for i, cert in enumerate(certificates, 1):
            print(f"[+] Certificate {i}")
            print(f"\t\t* Subject: {cert['subject']}")
            print(f"\t\t* Thumbprint: {cert['thumbprint']}")
            print(f"\t\t* Signature Hash: {cert['signature_hash']}")
            print(f"\t\t* Valid From: {cert['not_before']}")
            print(f"\t\t* Valid Until: {cert['not_after']}")
