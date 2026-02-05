import sys
import logging


class Logger:
	def __init__(self, name: str, level: int = logging.INFO):
		self.logger = logging.getLogger(name)
		self.logger.setLevel(level)

		if not self.logger.handlers:
			handler = logging.StreamHandler(sys.stdout)
			handler.setLevel(level)

			# formatter = logging.Formatter('%(asctime)s - %(name)s - %(message)s', datefmt='%H:%M:%S')
			# formatter = logging.formatter()
			# handler.setFormatter(formatter)

			self.logger.addHandler(handler)

	def info(self, message: str):
		self.logger.info(f"[*] {message}")

	def warn(self, message: str):
		self.logger.warning(f"[!] {message}")

	def err(self, message: str):
		self.logger.error(f"[-] {message}")
