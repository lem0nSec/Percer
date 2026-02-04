import sys
from percer.analyzer import PortExec, PexPrinter


if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} PEfile")
    sys.exit(1)

obj = PortExec.from_file(sys.argv[1])
PexPrinter(obj).print_sections()
