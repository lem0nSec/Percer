import sys
import os
import argparse
from percer.virustotal import VirusTotal as vtl 
from percer.logger import Logger

def main():
	parser = argparse.ArgumentParser(description=f"{os.path.basename(sys.argv[0])} searches a sha256/sha1/md5 hash and pulls the corresponding PeSha256 hash")
	parser.add_argument('-H', '--hash', required=True, metavar='HASH', help='Input sha256/sha1/md5 hash')
	args = parser.parse_args()

	log = Logger('percer')

	try:
		with vtl() as scanner:
			v_obj = scanner.query_by_hash(args.hash)
			log.info(f'Authentihash: {v_obj.authentihash}')
	except Exception as E:
		raise ValueError(f"Exception has occurred: {E}")

if __name__ == '__main__':
	main()
