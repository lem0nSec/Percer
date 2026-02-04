import argparse
import sys
import os
from percer.analyzer import PortExec as pex
from percer.analyzer import PexPrinter as pep
from percer.virustotal import VirusTotal as vtl
from pyfiglet import Figlet


def main():
    parser = argparse.ArgumentParser(
        prog=f'{os.path.basename(sys.argv[0])} <PE file>',
        epilog=f'Example (no options):\n {os.path.basename(sys.argv[0])} C:\\Windows\\System32\\kernel32.dll')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-F', '--file', metavar="FILE", help='Target file')
    group.add_argument('-H', '--hash', metavar="HASH", help='Target hash (VirusTotal Search requires VT_API_KEY)')
    group.add_argument('-A', '--authentihash', metavar="AUTHENTIHASH", help='Target hash (VirusTotal Search requires VT_API_KEY)')
    parser.add_argument('-a', '--all', required=False, action='store_true', help='Show all info')
    parser.add_argument('-e', '--exports', required=False, action='store_true', help='List exports')
    parser.add_argument('-i', '--imports', required=False, action='store_true', help='List imports')
    parser.add_argument('-s', '--sections', required=False, action='store_true', help='List sections')
    parser.add_argument('-c', '--certificates', required=False, action='store_true', help='Get certificates information')
    parser.add_argument('-q', '--quiet', required=False, action='store_true', help='Do not print the banner')
    
    args = parser.parse_args()
    
    f = Figlet(font='slant')
    banner = f.renderText("percer")

    if not args.quiet:
        print(banner)

    try:
        if args.file:
            pex_obj = pex.from_file(args.file)
            
        elif args.hash:
            with vtl() as scanner:
                v_obj_content = scanner.get_content(args.hash)
                pex_obj = pex.from_bytes(v_obj_content)

        elif args.authentihash:
            with vtl() as scanner:
                v_obj = scanner.query_by_pesha256(args.authentihash)
                if v_obj:
                    v_obj_content = scanner.get_content(v_obj[0].id)
                    pex_obj = pex.from_bytes(v_obj_content)

        printer = pep(pex_obj)

        if args.all:
            print(pex_obj.get_handle())

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
        print(f"[ERROR] File not found: {args.file}")
        sys.exit(1)
    except ValueError as e:
        print(f"[ERROR] Invalid PE File: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[CRITICAL] Unexpected error: {e}")
        sys.exit(1)

    return 0
