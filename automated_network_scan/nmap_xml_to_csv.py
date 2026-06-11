#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import csv
import argparse
import sys

def parse_nmap_xml_to_csv(xml_file, output_file, datacenter):
    """Parse Nmap XML and convert to CSV.
    Includes ALL port states: open, closed, filtered, unfiltered, open|filtered, closed|filtered.
    Columns: IP | Hostname | Port | Status | Service | Version
    """
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        results = []

        for host in root.findall('host'):
            # Get IP address
            address = host.find('address[@addrtype="ipv4"]')
            if address is None:
                continue

            ip = address.get('addr')
            hostname = ''

            # Get hostname
            hostnames = host.find('hostnames')
            if hostnames is not None:
                hostname_elem = hostnames.find('hostname')
                if hostname_elem is not None:
                    hostname = hostname_elem.get('name', '')

            # Get ALL ports regardless of state
            ports = host.find('ports')
            if ports is not None:
                for port in ports.findall('port'):
                    state_elem = port.find('state')
                    if state_elem is None:
                        continue

                    # Capture every state: open, closed, filtered, unfiltered,
                    # open|filtered, closed|filtered
                    status = state_elem.get('state', 'unknown')

                    port_num  = port.get('portid')
                    service_name = ''
                    version      = ''

                    service = port.find('service')
                    if service is not None:
                        service_name = service.get('name', '')
                        product   = service.get('product', '')
                        ver       = service.get('version', '')
                        extrainfo = service.get('extrainfo', '')
                        version   = ' '.join(filter(None, [product, ver, extrainfo])).strip()

                    results.append({
                        'Datacenter': datacenter,
                        'IP'        : ip,
                        'Hostname'  : hostname,
                        'Port'      : port_num,
                        'Status'    : status,
                        'Service'   : service_name,
                        'Version'   : version if version else 'N/A'
                    })

            else:
                # Host was up but no port data (e.g. host discovery only)
                results.append({
                    'Datacenter': datacenter,
                    'IP'        : ip,
                    'Hostname'  : hostname,
                    'Port'      : 'N/A',
                    'Status'    : 'no-ports-found',
                    'Service'   : '',
                    'Version'   : 'N/A'
                })

        # Write CSV
        fieldnames = ['Datacenter', 'IP', 'Hostname', 'Port', 'Status', 'Service', 'Version']
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerows(results)

        # Print summary per state for quick visibility in Jenkins logs
        from collections import Counter
        state_counts = Counter(r['Status'] for r in results)
        print(f"Converted {len(results)} port entries to {output_file}")
        print("  State breakdown:")
        for state, count in sorted(state_counts.items()):
            print(f"    {state}: {count}")

    except Exception as e:
        print(f"Error parsing XML file {xml_file}: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Convert Nmap XML to CSV (all port states)')
    parser.add_argument('-o', '--output', required=True, help='Output CSV file')
    parser.add_argument('-dc', '--datacenter', required=True, help='Datacenter Location')
    parser.add_argument('xml_file', help='Input Nmap XML file')

    args = parser.parse_args()
    parse_nmap_xml_to_csv(args.xml_file, args.output, args.datacenter)
