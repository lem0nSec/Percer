import sys
import os
from percer.virustotal import VirusTotal as vtl

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {os.path.basename(sys.argv[0])} hash path")
        sys.exit(1)

    with vtl() as v:
        try:
            v.get_content(sys.argv[1], sys.argv[2])
        except Exception as E:
            print(f"Exception has occurred: {E}")
            sys.exit(1)

if __name__ == '__main__':
    main()
