#!/usr/bin/env python3

import argparse
import hashlib
import pefile
import os
import sys

from pyfiglet import Figlet
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from asn1crypto import cms


class PortExec:
    SUBSYSTEMS = { 
        0:"IMAGE_SUBSYSTEM_UNKNOWN",
        1:"IMAGE_SUBSYSTEM_NATIVE",
        2:"IMAGE_SUBSYSTEM_WINDOWS_GUI",
        3:"IMAGE_SUBSYSTEM_WINDOWS_CUI",
        5:"IMAGE_SUBSYSTEM_OS2_CUI",
        7:"IMAGE_SUBSYSTEM_POSIX_CUI",
        9:"IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
        10:"IMAGE_SUBSYSTEM_EFI_APPLICATION",
        11:"IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
        12:"IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER",
        13:"IMAGE_SUBSYSTEM_EFI_ROM",
        14:"IMAGE_SUBSYSTEM_XBOX",
        16:"IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION" }

    CHARACTERISTICS = {
        0x20000000: "EXECUTE",
        0x40000000: "READ",
        0x80000000: "WRITE"
    }

    ARCHITECTURES = {
        0x014c: "x86 (32-bit)",
        0x8664: "x64 (64-bit)",
        0x01c0: "ARM",
        0x01c4: "ARMv7",
        0xAA64: "ARM64",
        0x0200: "Intel Itanium (IA-64)",
        0x01f0: "PowerPC",
    }
    
    def __init__(self, name, subsystems=SUBSYSTEMS, architectures=ARCHITECTURES):
        self.name = name

        try:
            self.handle = pefile.PE(self.name)
            with open(self.name, 'rb') as this:
                thisfile = this.read()
                self.sha256 = (hashlib.sha256(thisfile)).hexdigest()
                self.sha1 = (hashlib.sha1(thisfile)).hexdigest()
                self.md5 = (hashlib.md5(thisfile)).hexdigest()
            print(f"Input PE\t: {os.path.basename(self.name)}\n" + "="*60)
        except:
            print("[ERROR] File opening error")
            sys.exit(1)

        try:
            info = {}
            for fileinfo in self.handle.FileInfo:
                for entry in fileinfo:
                    if entry.Key == b'StringFileInfo':
                        for st in entry.StringTable:
                            for key, value in st.entries.items():
                                decoded_key = key.decode('utf-8')
                                decoded_value = value.decode('utf-8')
                                if decoded_key in ['OriginalFilename', 'FileDescription', 'ProductName', 'InternalName', 'FileVersion']:
                                    info[decoded_key] = decoded_value
        except AttributeError:
            pass

        self.aslr = self.handle.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        self.nx = self.handle.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        self.guard_cf = self.handle.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_GUARD_CF
        self.termserveraware = self.handle.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE
        self.safeseh = self.handle.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_SEH
        if (self.handle.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]).VirtualAddress != 0:
            self.isSigned = True
        else:
            self.isSigned = False
        
        if 'OriginalFilename' in info:
            self.originalfilename = info['OriginalFilename']
        else:
            self.originalfilename = ""
        if 'FileDescription' in info:
            self.filedescription = info['FileDescription']
        else:
            self.filedescription = ""
        if 'ProductName' in info:
            self.productname = info['ProductName']
        else:
            self.productname = ""
        if 'InternalName' in info:
            self.internalname = info['InternalName']
        else:
            self.internalname = ""
        if 'FileVersion' in info:
            self.fileversion = info['FileVersion'] # File version could be wrong - need to fix this
        else:
            self.fileversion = ""
        
        # fix PE type identification.
        # Use 'Characteristics' in the FILE_HEADER instead
        if self.handle.is_exe() == True:
            self.pe_type = "Executable image"
        else:
            self.pe_type = "Dynamic library"

        self.architecture = architectures.get(
            self.handle.FILE_HEADER.Machine, 
            f"Unknown (0x{self.handle.FILE_HEADER.Machine:04x})"
            )

        if self.handle.OPTIONAL_HEADER.Subsystem in subsystems:
            self.subsystem = subsystems[self.handle.OPTIONAL_HEADER.Subsystem]
        else:
            self.subsystem = subsystems[0]

        for section in self.handle.sections:
            if (section.Name == b".reloc\x00\x00"):
                self.rebase = True
            else:
                self.rebase = False

    def __str__(self):
        return f"{self.name}\t:{self.pe_type}"

    def get_information(self):
        print(f"PE\t\t: {self.pe_type}")
        print(f"Hashes\t\tv\n\t\t* sha256\t\t: {self.sha256}\n\t\t* md5\t\t\t: {self.md5}\n\t\t* sha1\t\t\t: {self.sha1}")

        # Metadata
        print("File metadata\tv")
        print(f"\t\t* Original Filename\t: {self.originalfilename}")
        print(f"\t\t* File Description\t: {self.filedescription}")
        print(f"\t\t* Product Name\t\t: {self.productname}")
        print(f"\t\t* Internal Name\t\t: {self.internalname}")
        print(f"\t\t* File Version\t\t: {self.fileversion}")

        print(f"Is signed file\t: {self.isSigned}")
        print(f"Architecture\t: {self.architecture}")
        print(f"Subsystem\t: {self.subsystem}")
        print("ASLR\t\t: " + str(self.aslr))
        print("NX\t\t: " + str(self.nx))
        print("SafeSEH\t\t: " + str(self.safeseh))
        print("Rebase\t\t: " + str(self.rebase))
        print("Guard_CF\t: " + str(self.guard_cf))
        print("TermServerAware\t: " + str(self.termserveraware))

    def get_sections(self, characteristics=CHARACTERISTICS):
        protection = []
        for i in self.handle.sections:
            for j in characteristics:
                if (i.Characteristics & j) != 0:
                    protection.append(characteristics[j])
            print(f"* {str(i.Name, encoding='utf-8')}\n\t{hex(i.Characteristics)} - {protection}")
            protection = []

    def get_imports(self):
        try:
            for i in (self.handle).DIRECTORY_ENTRY_IMPORT:
                print("[+] " + str(i.dll, encoding='utf-8'))
                for j in i.imports:
                    try:
                        print("\t* " + str(j.name, encoding='utf-8'))
                    except TypeError:
                        pass
        except AttributeError:
            print("No imports found in the PE file")
            sys.exit(1)

    def get_exports(self):
        try:
            for i in (self.handle).DIRECTORY_ENTRY_EXPORT.symbols:
                try:
                    print("* " + str(i.name, encoding='utf-8'))
                except TypeError:
                    pass
        except AttributeError:
            print("No exports found in the PE file")
            sys.exit(1)

    def get_certificates(self):
        if self.isSigned == False:
            print("No certificate found in the PE file.")
            sys.exit(1)

        security_dir = self.handle.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
        cert_data = bytes(self.handle.write()[security_dir.VirtualAddress + 8:security_dir.VirtualAddress + security_dir.Size])
        certificates = []
        content_info = cms.ContentInfo.load(cert_data)
        signed_data = content_info['content']
        for cert in signed_data['certificates']:
            x509_cert = x509.load_der_x509_certificate(cert.dump())
            thumbprint = x509_cert.fingerprint(hashes.SHA1()).hex()
            subject = x509_cert.subject.rfc4514_string()
            signature_hash = hashes.Hash(x509_cert.signature_hash_algorithm)
            signature_hash.update(x509_cert.tbs_certificate_bytes)
            signature_hash = signature_hash.finalize().hex()

            certificates.append({
                'thumbprint': thumbprint,
                'subject': subject,
                'signature_hash': signature_hash
            })
        for i, cert in enumerate(certificates, 1):
            print(f"[+] Certificate {i}")
            print(f"\t\t* Subject: {cert['subject']}")
            print(f"\t\t* Thumbprint: {cert['thumbprint']}")
            print(f"\t\t* Signature Hash: {cert['signature_hash']}")

    def get_handle(self):
        return self.handle

    def set_handle(self, handle):
        self.handle = handle

def main():
    parser = argparse.ArgumentParser(
                    prog=f'{sys.argv[0]}',
                    epilog=f'[Example] python {sys.argv[0]} C:\\Windows\\System32\\kernel32.dll'
                    )

    parser.add_argument('PE')
    parser.add_argument('-a', '--all', required=False, action='store_true', help='Show all info')
    parser.add_argument('-e', '--exports', required=False, action='store_true', help='List exports')
    parser.add_argument('-i', '--imports', required=False, action='store_true', help='List imports')
    parser.add_argument('-s', '--sections', required=False, action='store_true', help='List sections')
    parser.add_argument('-c', '--certificates', required=False, action='store_true', help='Get certificates information')
    args = parser.parse_args()
    
    f = Figlet(font='slant')
    print(f.renderText("percer.py"))

    portexec = None
    if os.path.isfile(args.PE) == True:
        portexec = PortExec(args.PE)
        if args.all:
            print(portexec.get_handle())
        elif args.exports:
            print("Dumping exports\n")
            portexec.get_exports()
        elif args.imports:
            print("Dumping imports\n")
            portexec.get_imports()
        elif args.sections:
            print("Dumping sections\n")
            portexec.get_sections()
        elif args.certificates:
            portexec.get_certificates()
        else:
            portexec.get_information()
    else:
        print(f"[ERROR] {args.PE} not found")

    return 0;

if __name__ == "__main__":
    main()
