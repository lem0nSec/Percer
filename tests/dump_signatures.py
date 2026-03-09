"""
This script searches for samples sharing the same
authentihash (target_authentihash). Then converts the 
respective vt.object.Object to percer.analyzer.PortExec
objects and extracts their signature information.
"""

import argparse
import sys
import os
from percer.analyzer import PEAnalyzer as pex
from percer.analyzer import PEPrinter as pep
from percer.virustotal import VirusTotal as vtl
from percer.logger import Logger


def main():
	parser = argparse.ArgumentParser(description=f"{os.path.basename(sys.argv[0])} dumps the signature information of a given authentihash - PeSha256")
	parser.add_argument('-H', '--hash', required=True, metavar='HASH', help='Input PeSha256 hash')
	args = parser.parse_args()

	log = Logger('percer')

	with vtl() as scanner:
		log.info(f"Targeting sample {args.hash}")
		try:
			pex_object = pex.from_bytes(scanner.get_content(scanner.resolve_hash(args.hash)))
			if pex_object.is_signed == True:
				log.info(f"Printing signatures of {pex_object.sha256}")
				pep(pex_object).print_certificates()
			else:
				log.err("The sample is unsigned")
		except Exception as E:
			raise ValueError(f"Exception has occurred: {E}")

if __name__ == '__main__':
	main()
