import sys
import os
from collections import Counter, defaultdict
from percer.analyzer import PortExec as pex 
from percer.virustotal import VirusTotal as vtl 


def main():
	if len(sys.argv) < 2:
		print(f"Usage: {os.path.basename(sys.argv[0])} hashes.txt")
		sys.exit(1)

	with open(sys.argv[1], 'r') as f:
		samples = [line.strip() for line in f]

	certificates = {}
	publishers = {}
	with vtl() as scanner:
		for sample in samples:
			try:
				print(f"[*] Sample {sample}", end='')
				content = scanner.to_bytes(sample)
				if content:
					print(" | Available on VT", end='')
					pex_object = pex.from_bytes(content)
					if pex_object.signed_status() == True:
						print(" | is signed")
						certificates[pex_object.sha256()] = []
						for i, cert in enumerate(pex_object.certificates()):
							certificates[pex_object.sha256()].append(cert['thumbprint'])
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
