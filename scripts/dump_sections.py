import sys
from percer.analyzer import PEAnalyzer, PEPrinter


if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} PEfile")
    sys.exit(1)

obj = PEAnalyzer.from_file(sys.argv[1])
PEPrinter(obj).print_sections()
