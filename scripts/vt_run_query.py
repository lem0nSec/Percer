import os
import sys
import argparse
from percer.virustotal import VirusTotal as vtl 
from percer.analyzer import PortExec as pex 
from percer.analyzer import PexPrinter as pep

def main():
	parser = argparse.ArgumentParser(description=f"{os.path.basename(sys.argv[0])} runs a custom VirusTotal query")

	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument('-Q', '--query', help='VirusTotal query')
	parser.add_argument('-a', '--all', action='store_true', help='Dump all info (messy in case of a large number of samples)')
	parser.add_argument('-b', '--basic', action='store_true', help='Dump basic info (hashes)')
	# group.add_argument('-H', '--hashes', action='store_true', help='File containing sha256/sha1/md5 hashes')
	# parser.add_argument('filename', help='File containing the hashes')
	args = parser.parse_args()

	with vtl() as scanner:
		count = 0
		v_objects = scanner.query_custom(args.query)
		if v_objects:
			if len(v_objects) > 100:
				print(f"[*] Found {len(v_objects)} samples. Only analysing first 100 results.")
			else:
				print(f"[*] Found {len(v_objects)} samples")
			for object_ in v_objects:
				if count == 101:
					sys.exit(1)

				try:
					# pex_object = pex.from_bytes(scanner.get_content(object_.id))
					if args.basic:
						pesha256 = getattr(object_, 'authentihash', 'Not available (file may not be signed)')
						count += 1
						print(f"[*] Sample: {pesha256}")
					else:
						pex_object = pex.from_bytes(scanner.get_content(object_.id))
						count += 1
						print("-"*100)
						pep(pex_object).print_information()
				except Exception as E:
					raise ValueError(f"Exception raised: {E}")

if __name__ == '__main__':
	main()
