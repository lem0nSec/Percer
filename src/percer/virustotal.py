import vt
import io
import os
import sys


class VirusTotal:
	def __init__(self):
		self.API_KEY = os.getenv('VT_API_KEY')
		if not self.API_KEY:
			raise ValueError("[-] VT API_KEY environment variable not defined")

		self.client = None

	def __enter__(self):
		self.client = vt.Client(self.API_KEY)
		return self

	def __exit__(self, exc_type, exc_val, exc_tb):
		if self.client:
			self.client.close()

	def get_content(self, hash, path=None):
		"""
		Downloads file content from VT to either a bytes stream or a file.
		"""
		if path is None:
			file_stream = io.BytesIO()
			self.client.download_file(hash, file_stream)
			return file_stream.getvalue()
		else:
			with open(path, 'wb') as f:
				self.client.download_file(hash, f)

	def query_by_hash(self, hash):
		"""
		Returns a VirusTotal object by standard hash (sha256/sha1/md5)
		"""
		return self.client.get_object(f"/files/{hash}")

	def query_custom(self, query):
		"""
		Generic VirusTotal query method
		"""
		return list(self.client.iterator('/intelligence/search', params={'query': query}))

	def query_by_pesha256(self, pesha256):
		"""
		Returns a VirusTotal object by authentihash
		"""
		query = f"authentihash:{pesha256}"
		return self.query_custom(query)

	def resolve_hash(self, input_hash):
		"""
		Attempts to resolve as a standard hash (sha256/sha1/md5), falls back to authentihash
		"""
		try:
			obj = self.query_by_hash(input_hash)
			return obj.id 
		except vt.error.APIError as E:
			if E.code == 'NotFoundError':
				results = self.query_by_pesha256(input_hash)
				if results:
					return results[0].id 
				return None
			else:
				raise E
