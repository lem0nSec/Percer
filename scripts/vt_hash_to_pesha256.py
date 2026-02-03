import sys
import os
from percer.virustotal import VirusTotal as vtl 

def main():
	if len(sys.argv) < 2:
		print(f"Usage: {os.path.basename(sys.argv[0])} hash")
		sys.exit(1)

	try:
		with vtl() as v:
			v_obj = v.query_by_hash(sys.argv[1])
			print(f'[*] Authentihash: {v_obj.authentihash}')
	except Exception as E:
		sys.exit(1)

if __name__ == '__main__':
	main()
