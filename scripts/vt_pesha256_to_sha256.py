import sys
import os
import argparse
from percer.virustotal import VirusTotal as vtl
from percer.logger import Logger 

def main():
	parser = argparse.ArgumentParser(description=f"{os.path.basename(sys.argv[0])} searches a PeSha256 hash and pulls the corresponding Sha256 hash")
	parser.add_argument('-A', '--authentihash', required=True, metavar='AUTHENTIHASH', help='Input PeSha256 hash')
	args = parser.parse_args()

	log = Logger('percer')

	try:
		with vtl() as v:
			v_obj = v.query_by_pesha256(args.authentihash)
			for sample in v_obj:
				log.info(f"sha256: {sample.sha256}")
	except Exception as E:
		sys.exit(1)

if __name__ == '__main__':
	main()
