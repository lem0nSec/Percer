import argparse
import sys
import os
from percer.analyzer import PortExec as pex
# from percer.virustotal import VirusTotal as vttl
from percer.printer import PEPrinter as pep
from pyfiglet import Figlet


def main():
    parser = argparse.ArgumentParser(
        prog=f'{os.path.basename(sys.argv[0])} <PE file>',
        epilog=f'Example (no options):\n {os.path.basename(sys.argv[0])} C:\\Windows\\System32\\kernel32.dll')

    parser.add_argument('PE')
    parser.add_argument('-a', '--all', required=False, action='store_true', help='Show all info')
    parser.add_argument('-e', '--exports', required=False, action='store_true', help='List exports')
    parser.add_argument('-i', '--imports', required=False, action='store_true', help='List imports')
    parser.add_argument('-s', '--sections', required=False, action='store_true', help='List sections')
    parser.add_argument('-c', '--certificates', required=False, action='store_true', help='Get certificates information')
    parser.add_argument('-q', '--quiet', required=False, action='store_true', help='Do not print the banner')
    
    args = parser.parse_args()
    
    f = Figlet(font='slant')
    banner = f.renderText("percer")

    try:
        portexec = pex.from_file(args.PE)
        printer = pep(portexec)

        if not args.quiet:
            print(banner)

        if args.all:
            print(portexec.get_handle())

        elif args.exports:
            printer.print_header()
            printer.print_exports()

        elif args.imports:
            printer.print_header()
            printer.print_imports()

        elif args.sections:
            printer.print_header()
            printer.print_sections()

        elif args.certificates:
            printer.print_header()
            printer.print_certificates()

        else:
            printer.print_header()
            printer.print_information()

    except FileNotFoundError:
        print(f"[ERROR] File not found: {args.PE}")
        sys.exit(1)
    except ValueError as e:
        print(f"[ERROR] Invalid PE File: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[CRITICAL] Unexpected error: {e}")
        sys.exit(1)

    return 0
