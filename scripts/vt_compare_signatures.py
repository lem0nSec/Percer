import argparse
import sys
import os
from collections import Counter, defaultdict
from percer.analyzer import PortExec as pex 
from percer.virustotal import VirusTotal as vtl 


def main():
	parser = argparse.ArgumentParser(description=f"{os.path.basename(sys.argv[0])} compares the signatures of the specified hashes/authentihashes")

	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument('-A', '--authentihashes', action='store_true', help='File containing pesha256 hashes')
	group.add_argument('-H', '--hashes', action='store_true', help='File containing sha256/sha1/md5 hashes')
	parser.add_argument('filename', help='File containing the hashes')
	args = parser.parse_args()

	if not os.path.exists(args.filename):
		raise FileNotFoundError(f"File {args.filename} not found")


	with open(args.filename, 'r') as f:
		samples = [line.strip() for line in f]

	certificates = {}
	publishers = {}
	with vtl() as scanner:
		for sample in samples:
			try:
				print(f"Sample {sample}", end='', flush=True)
				if args.hashes:
					content = scanner.get_content(sample)
				else:
					v_obj = scanner.query_by_pesha256(sample)
					if v_obj:
						content = scanner.get_content(v_obj[0].id)
					else:
						content = b''

				if content:
					print(" | Available on VT", end='')
					pex_object = pex.from_bytes(content)
					if pex_object.is_signed() == True:
						print(" | is signed")
						if args.hashes:
							certificates[pex_object.sha256()] = []
						else:
							certificates[pex_object.pesha256()] = []

						for i, cert in enumerate(pex_object.certificates()):
							if args.hashes:
								certificates[pex_object.sha256()].append(cert['thumbprint'])
							else:
								certificates[pex_object.pesha256()].append(cert['thumbprint'])

							if not cert['thumbprint'] in publishers:
								publishers[cert['thumbprint']] = cert['subject']
					else:
						print(" | Not signed")
				else:
					print(" | Not available on VT")

			except Exception as E:
				print(f"Exception has occurred: {E}")

	hash_to_lists = defaultdict(list)

	for list_name, hashes in certificates.items():
		for h in hashes:
			hash_to_lists[h].append(list_name)

	sorted_items = sorted(hash_to_lists.items(), key=lambda item: len(item[1]), reverse=True)

	for h, lists in sorted_items:
		print(f"[+] Thumbprint: {h} - {publishers[h][:20]}... ({len(lists)} occurrences)")
		for l in lists:
			print(f"   -> {l}")
		print("-" * 50)


if __name__ == '__main__':
	main()
