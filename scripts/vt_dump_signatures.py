"""
This script searches for samples sharing the same
authentihash (target_authentihash). Then converts the 
respective vt.object.Object to percer.analyzer.PortExec
objects and extracts their signature information.
"""

from percer.analyzer import PortExec as pex
from percer.analyzer import PexPrinter as pep
from percer.virustotal import VirusTotal as vtl

# HW.sys vulnerable driver
target_authentihash = 'c71433f694aada643c51302f038d4b954decf50e109a71f2df0c94d1a8b9349e'

with vtl() as vt_scanner:
	print(f"[*] Targeting sample {target_authentihash}")
	try:
		vt_objects = vt_scanner.query_by_pesha256(target_authentihash)
		if vt_objects is not None:
			print(f"[*] Got {len(vt_objects)} samples from VirusTotal")
			for sample in vt_objects:
				content = vt_scanner.to_bytes(sample.id)
				pex_object = pex.from_bytes(content)
				if pex_object.signed_status() == True:
					print(f"[*] Printing signatures information of {pex_object.sha256()}")
					pep(pex_object).print_certificates()
		else:
			print("Empty")
	except Exception as E:
		print(f"Exception has occurred: {E}")
