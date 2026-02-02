import sys
from percer.analyzer import PortExec
from percer.printer import PEPrinter


if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} PEfile")
    sys.exit(1)

obj = PortExec(sys.argv[1])
prt = PEPrinter(obj)
prt.print_sections()
