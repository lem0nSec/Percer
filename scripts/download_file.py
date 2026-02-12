import sys
import os
import argparse
from percer.virustotal import VirusTotal as vtl
from percer.logger import Logger


def main():
    parser = argparse.ArgumentParser(description=f"{os.path.basename(sys.argv[0])} downloads a file from VirusTotal")

    parser.add_argument('-H', '--hash', required=True, help='sha256/sha1/md5 or authentihash')
    parser.add_argument('-s', '--save', required=True, help='destination path')
    args = parser.parse_args()

    log = Logger('percer')

    with vtl() as scanner:
        try:
            file_hash = scanner.resolve_hash(args.hash)
            v_object = scanner.query_by_hash(file_hash)
            v_size = v_object.size
            log.info(f"Downloading {file_hash} of size {v_size} mb...")
            scanner.get_content(file_hash, args.save)
        except Exception as E:
            raise ValueError(f"Exception has occurred: {E}")

if __name__ == '__main__':
    main()
