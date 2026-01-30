import os

class PEPrinter:
	def __init__(self, handle):
		self.object = handle

	def print_header(self):
		print(f"Input PE\t: {os.path.basename(self.object.file_path)}\n" + "="*60)

	def print_information(self):
	    # We'll use a standard width for labels to keep things clean
	    w = 10 
	    sub_w = 17 # Width for nested items (like hashes)

	    print(f"{'PE':<{w}}: {self.object.pe_type}")
	    
	    print(f"{'Hashes':<{w}}v")
	    print(f"\t* {'sha256':<{sub_w}}: {self.object.sha256()}")
	    print(f"\t* {'md5':<{sub_w}}: {self.object.md5()}")
	    print(f"\t* {'sha1':<{sub_w}}: {self.object.sha1()}")
	    print(f"\t* {'peSha256':<{sub_w}}: {self.object.pesha256()}")
	    print(f"\t* {'peSha1':<{sub_w}}: {self.object.pesha1()}")

	    print(f"{'File Info':<{w}}v")
	    for metadata, value in self.object.information.items():
	        print(f"\t* {metadata:<{sub_w}}: {value}")

	    print(f"\t* {'PDB':<{sub_w}}: {self.object.pdb()}")
	    print(f"{'Signed':<{w}}: {self.object.signed_status()}")
	    print(f"{'Machine':<{w}}: {self.object.architecture}")
	    print(f"{'Subsystem':<{w}}: {self.object.subsystem}")

	def print_sections(self):
		print("Dumping sections:\n")
		for section in self.object.sections():
			print(f"* {section}\n\t{self.object.sections()[section]}")

	def print_imports(self):
		print("Dumping imports:\n")
		imports = self.object.imports()
		for lib in imports:
			print(lib)
			for import_name in imports[lib]:
				print(f"\t* {import_name}")

	def print_exports(self):
		print("Dumping exports:\n")
		exports = self.object.exports()
		for export_name in exports:
			print(f"* {export_name}")

	def print_certificates(self):
		print("Dumping certificates:\n")
		certificates = self.object.certificates()
		for i, cert in enumerate(certificates, 1):
			print(f"[+] Certificate {i}")
			print(f"\t\t* Subject: {cert['subject']}")
			print(f"\t\t* Thumbprint: {cert['thumbprint']}")
			print(f"\t\t* Signature Hash: {cert['signature_hash']}")
			print(f"\t\t* Valid From: {cert['not_before']}")
			print(f"\t\t* Valid Until: {cert['not_after']}")
