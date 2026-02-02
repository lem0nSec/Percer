from percer.analyzer import PortExec as pex 
from percer.virustotal import VirusTotal as vtl 
from collections import Counter, defaultdict


samples = [
		'0291b5411914e39721404a6e5628cdf9d400a79ba296e8a437107b3de1c7ba08',
		'0fb338e78146cda5eca21415a88be60da38121df48e1b3e9e73401ee9184fbce',
		'11eacbff8d2e98ec08df3e1d2e19c3b65cd4c53e0430eebb512662e196b01a2d',
		'25515377dabe8805170d817bca460add45f38a3269701856f84aaeca295c1847',
		'2d71c41f64629d018269c83bb4a45e092108d3a5cab0867a83e516784d1f8548',
		'410a851a47d99cc068e65f42ebdec028084d79bfc64f190586bb6fe4723a90b1',
		'642c84665a36c2ef7f5adf9007c343b5d0613123aae4c3ba62a57b7c2f1699e1',
		'6906ccc9622e7f3bd9a152c1f164418e19a26003c6c5081421c6fe5e4a957949',
		'7de227afd50c0981da7e6479893e0c820ac7d5e26fb55ebcfce25bbb0e80d687',
		'80eb4c09526b97be23f6daa4ccd2bc97c467d2f3f5b278127693ccbcc17c8369',
		'8c67a02baf4868ff6c4ba3e85598d51f76c2b7a420fa94e2bd5549c5c4220d52',
		'8de87367c7c476ab071c843d824eedbe53d9d8bc6e6ef35a5d5141923727a80a',
		'8df7e25a2b5615240f943782d97e7e17f0dace01ee10937cbe448d5567175f99',
		'b20e165cccbf115a3993c767fd277d3c4ea0dc1c756872777193584c57c19e8e',
		'b4e48f875dec536dd2ac1129a3dc31c5c4698fbc6a662aff8eaf7fc0577b66a1',
		'bfeb044d4786fa7c85a013c17763dbd408652b7297a05ad74ce60444ea62c09e',
		'cc158698e3362924c6dbee602f2da766d3f234cbbbc62fb55878b27962e68249',
		'd86637f0a7a3531e586c782148d4e29a52ad116e3652d9996124cc433478b303',
		'e27e76b272cac6ae91a1d93a419ec1007822c65d7c35debcc6a596dcfb065503',
		'f17b73cb132ac289bd40247685ee07e92786e7667cf50440c1a37d5110869e5f',
		'f75bbe5014bbf27313381115dec3973f628aa4de80d9a73dc7f98ac92d45696b',
		'fc4108a0b1ebe1b93636ef29a887cc6deee9525342baf57b38715fe6d5c427e0'
	]

certificates = {}
publishers = {}
with vtl() as scanner:
	for sample in samples:
		try:
			content = scanner.get_hash_content(sample)
			if content:
				pex_object = pex.from_bytes(content)
				print(f"[*] File {pex_object.sha256()} is signed.")
				if pex_object.signed_status() == True:
					certificates[pex_object.sha256()] = []
					for i, cert in enumerate(pex_object.certificates()):
						certificates[pex_object.sha256()].append(cert['thumbprint'])
						if not cert['thumbprint'] in publishers:
							publishers[cert['thumbprint']] = cert['subject']

		except Exception as E:
			print(f"Exception has occurred: {E}")


all_thumbprints = [item for sublist in certificates.values() for item in sublist]

counts = Counter(all_thumbprints)

print(f"{'Count':<8} | {'Hash'}")
print("-" * 75)
for hash_str, count in counts.most_common():
	# Skipping non-interesting signatures
	if not 'DigiCert' in publishers[hash_str] and not 'Microsoft' in publishers[hash_str] and not 'VeriSign' in publishers[hash_str]:
		print(f"{count:<8} | {hash_str} | {publishers[hash_str]}")

# hash_to_lists = defaultdict(list)

# for list_name, hashes in certificates.items():
# 	for h in hashes:
# 		hash_to_lists[h].append(list_name)

# sorted_items = sorted(hash_to_lists.items(), key=lambda item: len(item[1]), reverse=True)

# for h, lists in sorted_items:
# 	print(f"Thumbprint: {h}... ({len(lists)} occurrences)")
# 	for l in lists:
# 		print(f"   -> {l}")
# 	print("-" * 50)
