#!/usr/bin/env python3

from pyfiglet import Figlet
import argparse
import pefile
import os
import sys


# le strutture hanno solo informazioni
# le classi hanno anche utilità (metodi), oltre alle informazioni (attributi)

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
        1644167200:"RX",
        1744830496:"RX",
        1610612768:"RX",
        1207959616:"R",
        1073741888:"R",
        1207959616:"R",
        1207959616:"R",
        3355443264:"RW",
        3355443264:"RW",
        3221225536:"RW",
        1107296320:"R"
     }
    
    def __init__(self, name, subsystems=SUBSYSTEMS):
        self.name = name

        try:
            self.handle = pefile.PE(self.name)
            print(f"Input PE : {os.path.basename(self.name)}\n" + "="*60)
        except:
            print("[ERROR] File opening error")
            sys.exit(1)

        self.aslr = self.handle.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        self.nx = self.handle.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        self.guard_cf = self.handle.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_GUARD_CF
        self.termserveraware = self.handle.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE
        self.safeseh = self.handle.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_SEH
        
        if self.handle.is_exe() == True:
            self.pe_type = "Executable image"
        else:
            self.pe_type = "Dynamic library"

        if self.handle.FILE_HEADER.IMAGE_FILE_32BIT_MACHINE == True:
            self.architecture = "32 bit"
        else:
            self.architecture = "64 bit"

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
        print(f"Architecture\t: {self.architecture}")
        print(f"Subsystem\t: {self.subsystem}")
        print("ASLR\t\t: " + str(self.aslr))
        print("NX\t\t: " + str(self.nx))
        print("SafeSEH\t\t: " + str(self.safeseh))
        print("Rebase\t\t: " + str(self.rebase))
        print("Guard_CF\t: " + str(self.guard_cf))
        print("TermServerAware\t: " + str(self.termserveraware))

    def get_sections(self, characteristics=CHARACTERISTICS):
        protection = ""
        for i in self.handle.sections:
            if i.Characteristics in characteristics:
                protection = characteristics[i.Characteristics]
            else:
                protection = "undefined"
            print(f"[+] {str(i.Name, encoding='utf-8')}\n\t{hex(i.Characteristics)} - {protection}")

    def get_imports(self):
        for i in (self.handle).DIRECTORY_ENTRY_IMPORT:
            print("[+] " + str(i.dll, encoding='utf-8'))
            for j in i.imports:
                try:
                    print("\t" + str(j.name, encoding='utf-8'))
                except TypeError:
                    pass

    def get_exports(self):
        for i in (self.handle).DIRECTORY_ENTRY_EXPORT.symbols:
            try:
                print("[+] " + str(i.name, encoding='utf-8'))
            except TypeError:
                pass

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
    args = parser.parse_args()
    
    f = Figlet(font='slant')
    print(f.renderText(f'{sys.argv[0]}'))

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
        else:
            portexec.get_information()
    else:
        print(f"[ERROR] {args.PE} not found")

    return 0;

if __name__ == "__main__":
    main()
