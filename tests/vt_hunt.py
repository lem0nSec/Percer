import sys
import os
import hashlib


from pathlib import Path
from typing import Optional, Any
from percer.virustotal import VirusTotal as vtl
from percer.analyzer import PEAnalyzer as pex


class VTFileCache(object):
    def __init__(self, client: vtl, folder : str):        
        self.client = client

        folder = Path(folder)
        if not folder.exists():
            folder.mkdir()
        self.folder = folder

    def get_file(self, sha256 : str) -> Optional[bytes]:        
        file_path = self.folder / sha256
        if not file_path.exists():
            self.client.get_content(sha256, file_path)        
        return open(file_path,"rb").read()

        

class VTHuntConfig(object):
    def __init__(self, args):
        self.mandatory_fields = args.fields
        
        self.authentihash = args.authentihash
        self.originalfilename = args.originalfilename
        self.imphash = args.imphash
        
        self.pdb = args.pdb
        self.pdb_name_only = args.pdb_name
        
        self.thumbprint = args.thumbprint

        self.name = args.name

        self.new_hashes_threshold = args.threshold
        
        self.output = args.output
        self.cache = args.cache



def get_hashes_from_list(it):
    return list(map(lambda e: e.sha256, it))

def filter_known_hashes(known_hashes, hashes):
    return list(filter(lambda e: e not in known_hashes, hashes))


def display_result_with_label(label, hashes):    
    if len(hashes) > 0:
        print(f"\t{label} ({len(hashes)} hashes)")
        for elem in hashes:
            print(f"\t\t{elem}")


class VTHunt(object):    
    def __init__(self, client : vtl, config : VTHuntConfig, known_hashes):
        self.config = config
        self.client = client

        
        self.known_hashes = known_hashes
        self.new_hashes = set()
        
        self.queries_cache = {}
        self.samples_cache = VTFileCache(client, config.cache)


                
    def add_new_hashes(self, found_hashes):
        new_hashes = filter_known_hashes(self.known_hashes, found_hashes)
        if len(new_hashes) > self.config.new_hashes_threshold:
            print(f"\t/!\\ Too many new hashes ({len(new_hashes)}, current threshold is {self.config.new_hashes_threshold}) found by this rule. Not inserting them /!\\")
        else:
            self.new_hashes.update(set(new_hashes))
        return new_hashes
    
    def query(self, query):        
        query = self.config.mandatory_fields + f" {query}"
        query_hash = hashlib.sha256(query.encode("utf-8")).hexdigest()
        if query_hash in self.queries_cache:
            return self.queries_cache[query_hash]


        hashes = get_hashes_from_list(self.client.query_custom(query))
        self.queries_cache[query_hash] = hashes
        return hashes


    def hunt(self):
        self.hunt_name()
        for sha256 in self.known_hashes:
            sample = self.samples_cache.get_file(sha256)
            pe = pex.from_bytes(sample)
            self.hunt_pe(pe)        
        self.dump()
            
    def hunt_name(self):
        print("Hunting for generic fields")        
        if self.config.name:
            query = f"name:{self.config.name}"
            found_hashes = self.query(query)
            display_result_with_label(f"Name ({query})", self.add_new_hashes(found_hashes))

    def hunt_pe(self, pe : pex):
        print(f"Hunting for {pe.sha256}")
        self.hunt_originalfilename(pe)
        self.hunt_authentihash(pe)        
        self.hunt_imphash(pe)
        self.hunt_thumbprint_with_name(pe)
        self.hunt_pdb(pe)
        
    def hunt_authentihash(self, pe : pex):
        if self.config.authentihash and pe.pesha256:
            query = f"authentihash:{pe.pesha256}"
            found_hashes = self.query(query)            
            display_result_with_label(f"Authentihash ({query})", self.add_new_hashes(found_hashes))

    
    def hunt_originalfilename(self, pe: pex):
        if self.config.originalfilename and pe.original_filename:
            query = f"name:{pe.original_filename}"
            found_hashes = self.query(query)            
            display_result_with_label(f"OriginalFileName ({query})", self.add_new_hashes(found_hashes))


    
    def hunt_imphash(self, pe: pex):
        if self.config.imphash and pe.imp_hash:
            query = f"imphash:{pe.imp_hash}"
            found_hashes = self.query(query)
            display_result_with_label(f"ImpHash ({query})", self.add_new_hashes(found_hashes))           
           
    def hunt_thumbprint_with_name(self, pe: pex):
        if self.config.thumbprint and pe.is_signed:
            leaf_certificate = list(filter(lambda e: e["is_leaf"], pe.certificates))            
            if len(leaf_certificate) == 0:
                return
            leaf_certificate=leaf_certificate[0]
            thumbprint = leaf_certificate["thumbprint"]

            if pe.original_filename:
                query = f"signature:{thumbprint} name:{pe.original_filename}"                
                found_hashes = self.query(query)
                display_result_with_label(f"Thumbprint with OriginalFileName ({query})", self.add_new_hashes(found_hashes))
                
            if self.config.name:
                query = f"signature:{thumbprint} name:{self.config.name}"
                found_hashes = self.query(query)                
                display_result_with_label(f"Thumbprint with Name ({query})", self.add_new_hashes(found_hashes))
    
    def hunt_pdb(self, pe: pex):        
        if self.config.pdb and pe.pdb_path:
            pdb = pe.pdb_path
            if self.config.pdb_name_only:
                pdb = "*" + pdb.split("\\")[-1] + "*"
            
            query = f"metadata:'{pdb}'"
            found_hashes = self.query(query)
            display_result_with_label(f"PDB ({query})", self.add_new_hashes(found_hashes))
            
    
        
    def dump(self):
        if self.config.output:
            with open(self.config.output,"w") as f:
                for sha256 in self.new_hashes:
                    f.write(f"{sha256}\n")
    

import argparse
parser = argparse.ArgumentParser(
                    prog='VTHunt',
                    description='Hunting from fields available on VT',
                    formatter_class=argparse.ArgumentDefaultsHelpFormatter
                    )



# Configuration
parser.add_argument('--fields', default='magic:"PE32+ executable (native) x86-64, for MS Windows" type:peexe tag:native tag:64bits tag:signed', help="Default fields for VT query")
parser.add_argument('--imphash', action=argparse.BooleanOptionalAction, default=False, help="Compare ImpHash")
parser.add_argument('--authentihash', action=argparse.BooleanOptionalAction, default=True, help="Compare AuthentiHash")
parser.add_argument('--originalfilename', action=argparse.BooleanOptionalAction, default=True, help="Compare OriginalFilename")
parser.add_argument('--thumbprint', action=argparse.BooleanOptionalAction, default=True, help="Compare thumbprint and name (OriginalFilename and name if set)")
parser.add_argument('--pdb',  action=argparse.BooleanOptionalAction, default=True, help="Compare pdb full path")
parser.add_argument('--pdb-name', action=argparse.BooleanOptionalAction,  default=False, help="Compare pdb name")
parser.add_argument('--threshold', type=int, default=10, help="Avoid adding more than this threshold hashes in results")
parser.add_argument('--cache', default="./samples", help="Folder for caching files")
parser.add_argument('--name', help="Use this name if OriginalFilename is missing")


parser.add_argument('hashes', help="Input file containing file hashes")
parser.add_argument("--output", help="Output file with only uniques hashes not known")

args = parser.parse_args()
if not os.path.exists(args.hashes):
    print(f"{args.hashes} doesn't exists")

client = vtl()
config = VTHuntConfig(args)
    
hashes = []
for line in open(args.hashes,"r").readlines():
    sha256 = line.strip()
    if len(sha256) > 0:
        hashes.append(sha256)


hunt = VTHunt(client, config, hashes)
hunt.hunt()

client.close()
