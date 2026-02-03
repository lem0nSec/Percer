import sys
from percer.analyzer import PortExec, PEPrinter


if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} PEfile")
    sys.exit(1)

obj = PortExec.from_file(sys.argv[1])
prt = PEPrinter(obj)
prt.print_sections()
