import argparse
import sys
import os
import re
from collections import defaultdict
from percer.analyzer import PEAnalyzer as pex 
from percer.virustotal import VirusTotal as vtl 
from percer.logger import Logger

def get_common_name(subject_str):
    if not subject_str:
        return "Unknown"

    # Try to find 'O=' (Organization)
    org_match = re.search(r'(?:^|\s|,)O=((?:[^,]|\\,)+)', subject_str)
    if org_match:
        return org_match.group(1).replace(r'\,', ',')

    # Fallback to 'CN=' (Common Name)
    cn_match = re.search(r'(?:^|\s|,)CN=((?:[^,]|\\,)+)', subject_str)
    if cn_match:
        return cn_match.group(1).replace(r'\,', ',')

    return subject_str

def main():
    parser = argparse.ArgumentParser(description=f"{os.path.basename(sys.argv[0])} groups samples by Publisher or Thumbprint")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-A', '--authentihashes', action='store_true', help='File containing pesha256 hashes')
    group.add_argument('-H', '--hashes', action='store_true', help='File containing sha256/sha1/md5 hashes')
    
    # Filter arguments
    parser.add_argument('-c', '--contains', help='Filter by publisher name (case-insensitive substring)', default=None)
    parser.add_argument('-t', '--thumbprint', help='Filter by certificate thumbprint (case-insensitive)', default=None)
    
    parser.add_argument('filename', help='File containing the hashes')
    args = parser.parse_args()

    # Initialize logger
    log = Logger('percer')

    if not os.path.exists(args.filename):
        raise FileNotFoundError(f"File {args.filename} not found")

    with open(args.filename, 'r') as f:
        samples = [line.strip() for line in f if line.strip()]

    # Stats and Grouping
    publisher_groups = defaultdict(list)
    publisher_raw_subjects = defaultdict(set)
    
    # Lists for "Out" samples
    excluded_samples = []
    unsigned_samples = []
    not_found_samples = []

    log.info(f"Starting scan of {len(samples)} samples...")
    print("-" * 50)

    with vtl() as scanner:
        for sample in samples:
            try:
                log.raw(f"Sample {sample}", end='')
                
                # 1. Fetch
                if args.hashes:
                    content = scanner.get_content(sample)
                else:
                    v_obj = scanner.query_by_pesha256(sample)
                    content = scanner.get_content(v_obj[0].id) if v_obj else b''

                if content:
                    log.raw(" | Available on VT", end='')
                    
                    # 2. Parse
                    pex_object = pex.from_bytes(content)
                    
                    if pex_object.is_signed:
                        log.raw(" | Is signed")
                        current_hash = pex_object.sha256 if args.hashes else pex_object.pesha256
                        
                        matched_any_cert = False
                        
                        # Check all certs in the file
                        for cert in pex_object.certificates:
                            raw_subject = cert.get('subject', 'Unknown Subject')
                            thumbprint = cert.get('thumbprint', '')
                            clean_name = get_common_name(raw_subject)
                            
                            # --- Filter Logic ---
                            
                            # 1. Check Publisher Name
                            if args.contains:
                                search_term = args.contains.lower()
                                if search_term not in clean_name.lower() and search_term not in raw_subject.lower():
                                    continue

                            # 2. Check Thumbprint
                            if args.thumbprint:
                                # Clean strings for comparison (remove spaces/colons, lowercase)
                                t_arg = args.thumbprint.lower().replace(' ', '').replace(':', '')
                                t_cert = thumbprint.lower().replace(' ', '').replace(':', '')
                                
                                if t_arg not in t_cert:
                                    continue

                            # --- End Filter Logic ---

                            # if match, add to group
                            matched_any_cert = True
                            if current_hash not in publisher_groups[clean_name]:
                                publisher_groups[clean_name].append(current_hash)
                                publisher_raw_subjects[clean_name].add(raw_subject)
                        
                        # If signed, but NO certs matched the filters
                        if not matched_any_cert:
                            first_subject = pex_object.certificates[0].get('subject', 'Unknown') if pex_object.certificates else "Unknown"
                            first_thumbprint = pex_object.certificates[0].get('thumbprint', 'Unknown') if pex_object.certificates else "Unknown"
                            excluded_samples.append({'hash': current_hash, 'subject': first_subject, 'thumbprint': first_thumbprint})

                    else:
                        log.raw(" | Not signed")
                        unsigned_samples.append(sample)
                else:
                    log.raw(" | Not available on VT")
                    not_found_samples.append(sample)

            except Exception as E:
                print(f" | Exception: {E}")

    # --- Reporting ---
    total_found_signed = sum(len(v) for v in publisher_groups.values()) + len(excluded_samples)
    
    filters_applied = []
    if args.contains: filters_applied.append(f"Publisher contains '{args.contains}'")
    if args.thumbprint: filters_applied.append(f"Thumbprint contains '{args.thumbprint}'")
    filter_desc = " AND ".join(filters_applied) if filters_applied else "None"

    print("\n" + "=" * 60)
    print(f"SUMMARY STATISTICS")
    print(f"Filters Applied       : {filter_desc}")
    print(f"Total Scanned         : {len(samples)}")
    print(f"Not Found on VT       : {len(not_found_samples)}")
    print(f"Unsigned              : {len(unsigned_samples)}")
    print(f"Signed (Total)        : {total_found_signed}")
    print(f"  -> Matched Filter   : {sum(len(v) for v in publisher_groups.values())}")
    print(f"  -> Excluded (Out)   : {len(excluded_samples)}")
    print("=" * 60 + "\n")

    # Print Matched Groups
    sorted_publishers = sorted(publisher_groups.items(), key=lambda item: len(item[1]), reverse=True)
    
    if not sorted_publishers and filter_desc != "None":
        log.err(f"No signed samples found matching: {filter_desc}\n")

    for publisher, hashes in sorted_publishers:
        log.success(f"Publisher: {publisher}")
        print(f"    Count    : {len(hashes)}")
        
        if len(publisher_raw_subjects[publisher]) > 1:
             print(f"    Variations ({len(publisher_raw_subjects[publisher])}):")
             for raw in publisher_raw_subjects[publisher]:
                 display_raw = (raw[:90] + '...') if len(raw) > 90 else raw
                 print(f"      * {display_raw}")

        for h in hashes:
            print(f"      -> {h}")
        print("-" * 50)

    # Print Excluded (Signed but didn't match filter)
    if excluded_samples:
        print(f"\n[!] EXCLUDED SIGNED SAMPLES (Did not match filters)")
        for item in excluded_samples:
            print(f"    Hash   : {item['hash']}")
            print(f"    Subject: {item['subject']}")
            print(f"    Thumbprint: {item['thumbprint']}")
            print("-" * 30)

    # Print Unsigned / Not Found
    if unsigned_samples:
        print(f"\n[!] UNSIGNED SAMPLES ({len(unsigned_samples)})")
        for s in unsigned_samples:
            print(f"    -> {s}")

    if not_found_samples:
        print(f"\n[!] NOT FOUND ON VT ({len(not_found_samples)})")
        for s in not_found_samples:
            print(f"    -> {s}")

if __name__ == '__main__':
    main()
