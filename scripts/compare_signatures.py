import argparse
import sys
import os
from collections import Counter, defaultdict
from percer.analyzer import PEAnalyzer as pex 
from percer.virustotal import VirusTotal as vtl
from percer.logger import Logger


def main():
	parser = argparse.ArgumentParser(description=f"{os.path.basename(sys.argv[0])} compares the signatures of the specified hashes/authentihashes")

	parser.add_argument('-f', '--filename', metavar='FILENAME', help='File containing the hashes')
	args = parser.parse_args()

	log = Logger('percer')

	if not os.path.exists(args.filename):
		raise FileNotFoundError(f"File {args.filename} not found")


	with open(args.filename, 'r') as f:
		samples = [line.strip() for line in f]

	log.info(f"Starting scan of {len(samples)} samples...")
    print("-" * 50)

	certificates = {}
	publishers = {}
	with vtl() as scanner:
		for sample in samples:
			try:
				# 1. Checking file on VT...
				log.raw(f"Sample {sample}", end='')
				real_hash = scanner.resolve_hash(sample)
				content = scanner.get_content(real_hash)
				
				# 2. Analyzing file...
				log.raw(" | Available on VT", end='')
				pex_object = pex.from_bytes(content)
				if pex_object.is_signed == True:
					log.raw(" | is signed")

					certificates[sample] = []

					for i, cert in enumerate(pex_object.certificates):
						certificates[sample].append(cert['thumbprint'])
						if not cert['thumbprint'] in publishers:
							publishers[cert['thumbprint']] = cert['subject']
				else:
					log.raw(" | Not signed")
			
			except Exception as E:
				if E.code == 'NotFoundError':
					log.raw(" | Not available on VT")
					pass 
				else:
					raise ValueError(f"Exception has occurred: {E}")

	hash_to_lists = defaultdict(list)

	for list_name, hashes in certificates.items():
		for h in hashes:
			hash_to_lists[h].append(list_name)

	sorted_items = sorted(hash_to_lists.items(), key=lambda item: len(item[1]), reverse=True)

	for h, lists in sorted_items:
		log.success(f"Thumbprint: {h} - {publishers[h][:20]}... ({len(lists)} occurrences)")
		for l in lists:
			print(f"   -> {l}")
		print("-" * 50)


if __name__ == '__main__':
	main()
