"""
This script searches for samples sharing the same
authentihash (target_authentihash). Then converts the 
respective vt.object.Object to percer.analyzer.PortExec
objects and extracts their signature information.
"""

import argparse
import sys
import os
from percer.analyzer import PortExec as pex
from percer.virustotal import VirusTotal as vtl
from percer.logger import Logger


def main():
	parser = argparse.ArgumentParser(description=f"{os.path.basename(sys.argv[0])} dumps the signature information of a given authentihash - PeSha256")
	parser.add_argument('-A', '--authentihash', required=True, metavar='AUTHENTIHASH', help='Input PeSha256 hash')
	args = parser.parse_args()

	log = Logger('percer')

	target_authentihash = args.authentihash

	with vtl() as vt_scanner:
		log.info(f"Targeting sample {target_authentihash}")
		try:
			vt_objects = vt_scanner.query_by_pesha256(target_authentihash)
			if vt_objects:
				log.info(f"Got {len(vt_objects)} samples from VirusTotal")
				content = vt_scanner.get_content(vt_objects[0].id)
				pex_object = pex.from_bytes(content)
				if pex_object.signed_status() == True:
					log.info(f"Printing signatures information of {pex_object.sha256()}")
					for i, cert in enumerate(pex_object.certificates(), 1):
						log.info(f"Thumbprint: {cert['thumbprint']} | Sign. Hash {cert['signature_hash']} | Subject: {cert['subject'][:20]} | B {cert['not_before']} A {cert['not_after']}")
			else:
				log.err("0 samples found")

		except Exception as E:
			print(f"Exception has occurred: {E}")

if __name__ == '__main__':
	main()
