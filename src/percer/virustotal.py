import vt
import io
import os
import sys


class VirusTotal:
	def __init__(self):
		API_KEY = os.getenv('VT_API_KEY')
		if not API_KEY:
			print("[-] VT API_KEY not defined")
			sys.exit(1)

		self.API_KEY = API_KEY
		self.client = None

	def __enter__(self):
		if self.API_KEY:
			self.client = vt.Client(self.API_KEY)
			return self

	def __exit__(self, exc_type, exc_val, exc_tb):
		if self.client:
			self.client.close()

	def get_content(self, hash, path=None):
		if path is None:
			file_stream = io.BytesIO()
			self.client.download_file(hash, file_stream)
			return file_stream.getvalue()
		else:
			with open(path, 'wb') as f:
				self.client.download_file(hash, f)

	def query_by_hash(self, hash):
		try:
			return self.client.get_object(f"/files/{hash}")
		except vt.error.APIError as E:
			print(f"VirusTotal exception has occurred: {E}")
		except Exception as E:
			print(f"Exception has occurred: {E}")

	def query_by_pesha256(self, pesha256):
		samples = []
		query = f'authentihash:{pesha256}'

		try:
			iterator = self.client.iterator('/intelligence/search', params={'query':query})

			for object_ in iterator:
				samples.append(object_)

			return samples

		except vt.error.APIError as E:
			print(f"VirusTotal exception has occurred: {E}")
		except Exception as E:
			print(f"Exception has occurred: {E}")

	def query_by_name(self, name):
		samples = []
		query = f'name:{name}'

		try:
			iterator = self.client.iterator('/intelligence/search', params={'query': query})

			for object_ in iterator:
				pesha = object_.get('authentihash')
				if pesha != None:
					if object_ not in samples:
						samples.append(object_)

			return samples

		except vt.error.APIError as E:
			print(f"VirusTotal exception has occurred: {E}")
		except Exception as E:
			print(f"Exception has occurred: {E}")
