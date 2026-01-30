import percer.analyzer as alz
import percer.printer
import argparse
import sys
import os
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
    banner = f.renderText("percer.py")

    try:
        portexec = alz.PortExec(args.PE)
        prt = percer.printer.PEPrinter(portexec)

        if not args.quiet:
            print(banner)

        if args.all:
            print(portexec.get_handle())

        elif args.exports:
            prt.print_header()
            prt.print_exports()

        elif args.imports:
            prt.print_header()
            prt.print_imports()

        elif args.sections:
            prt.print_header()
            prt.print_sections()

        elif args.certificates:
            prt.print_header()
            prt.print_certificates()

        else:
            prt.print_header()
            prt.print_information()

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
