from percer.analyzer import PortExec as pex
from percer.virustotal import VirusTotal as vtl

# HW.sys vulnerable driver
target_sample = 'c71433f694aada643c51302f038d4b954decf50e109a71f2df0c94d1a8b9349e'

with vtl() as vt_scanner:
	print(f"[*] Targeting sample {target_sample}")
	try:
		vt_objects = vt_scanner.query_by_pesha256(target_sample)
		if vt_objects is not None:
			print(f"[*] Got {len(vt_objects)} samples from VirusTotal")
			for sample in vt_objects:
				content = vt_scanner.object_to_bytes(sample)
				pex_object = pex.from_bytes(content)
				if pex_object.signed_status() == True:
					print(f"[*] Printing signatures information of {pex_object.sha256()}")
					print(pex_object.certificates())
		else:
			print("Empty")
	except Exception as E:
		print(f"Exception has occurred: {E}")
