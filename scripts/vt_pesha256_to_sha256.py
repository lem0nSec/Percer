import sys
import os
from percer.virustotal import VirusTotal as vtl 

def main():
	if len(sys.argv) < 2:
		print(f"Usage: {os.path.basename(sys.argv[0])} hash")
		sys.exit(1)

	try:
		with vtl() as v:
			v_obj = v.query_by_pesha256(sys.argv[1])
			for sample in v_obj:
				print(f"[*] sha256: {sample.sha256}")
	except Exception as E:
		sys.exit(1)

if __name__ == '__main__':
	main()
