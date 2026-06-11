"""
Description:
Parses a single Nmap TLS XML scan file (from ssl-enum-ciphers script) and produces two CSVs:
  1. Full cipher CSV (-o): every host/TLS version/cipher combination found in the scan.
  2. Weak findings CSV (-wo): only rows where a weak cipher or unsupported TLS version was detected.

Validation rules:
  - Only TLSv1.2 and TLSv1.3 are allowed; any other version is flagged.
  - Ciphers present in WEAK_CIPHERS are flagged.

Usage:
  python3 cipher_xml_to_csv.py -o <full_output.csv> -wo <weak_output.csv> -dc <datacenter_name> <input.xml>

Dependencies: os, csv, sys, argparse, xml.etree.ElementTree
"""
import os
import csv
import sys
import argparse
import xml.etree.ElementTree as ET

ALLOWED_TLS_VERSIONS = {"TLSv1.2", "TLSv1.3"}

WEAK_CIPHERS = {
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_RC4_128_SHA",
    "TLS_RSA_WITH_RC4_128_MD5",
    "SSL_RSA_WITH_RC4_128_SHA",
    "SSL_RSA_WITH_RC4_128_MD5",
    "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
    "SSL_RSA_WITH_DES_CBC_SHA",
    "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
    "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
    "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    "TLS_RSA_WITH_NULL_SHA",
    "TLS_RSA_WITH_NULL_MD5",
    "SSL_RSA_WITH_IDEA_CBC_SHA",
}

ALL_FIELDS  = ["Datacenter", "IP", "Host State", "Port", "Port State", "Service",
               "TLS Version", "Cipher Name", "Key Exchange Info", "Cipher Strength",
               "Certificate Valid From", "Certificate Valid To"]
WEAK_FIELDS = ["Datacenter", "IP", "TLS Version", "Issue Type", "Cipher Name"]


def parse_nmap_xml(xml_file, datacenter):
    """Parse a single Nmap TLS XML file.

    Returns:
        all_rows  (list[dict]): every cipher row found (full detail).
        weak_rows (list[dict]): only rows with a weak cipher or unsupported TLS version.
    """
    all_rows  = []
    weak_rows = []

    tree = ET.parse(xml_file)
    root = tree.getroot()

    for host in root.findall("host"):
        address    = host.find("address")
        state      = host.find("status")
        ip         = address.get("addr") if address is not None else "N/A"
        host_state = state.get("state")  if state   is not None else "N/A"

        # Certificate validity is per-host, not per-root (avoids first-host cert being used for all)
        validity_table = host.find(".//table[@key='validity']")
        cert_from = (validity_table.find("elem[@key='notBefore']").text
                     if validity_table is not None
                     and validity_table.find("elem[@key='notBefore']") is not None else "N/A")
        cert_to   = (validity_table.find("elem[@key='notAfter']").text
                     if validity_table is not None
                     and validity_table.find("elem[@key='notAfter']") is not None else "N/A")

        # Iterate every scanned port — nmap TLS scan covers 25, 443, 587 (not just 443)
        scanned_any = False
        for port in host.findall(".//port"):
            script = port.find("script[@id='ssl-enum-ciphers']")
            if script is None:
                continue

            scanned_any = True
            port_id    = port.get("portid", "N/A")
            port_state = (port.find("state").get("state")
                          if port.find("state") is not None else "N/A")
            service    = port.find("service")
            svc_name   = service.get("name") if service is not None else "N/A"

            for tls_table in script.findall("table[@key]"):
                tls_ver = tls_table.get("key")

                if tls_ver not in ALLOWED_TLS_VERSIONS:
                    weak_rows.append({
                        "Datacenter" : datacenter,
                        "IP"         : ip,
                        "TLS Version": tls_ver,
                        "Issue Type" : "Unsupported TLS Version",
                        "Cipher Name": "N/A",
                    })

                for cipher in tls_table.findall(".//table"):
                    cipher_name = (cipher.find("elem[@key='name']").text
                                   if cipher.find("elem[@key='name']") is not None else "N/A")
                    kex_info    = (cipher.find("elem[@key='kex_info']").text
                                   if cipher.find("elem[@key='kex_info']") is not None else "N/A")
                    strength    = (cipher.find("elem[@key='strength']").text
                                   if cipher.find("elem[@key='strength']") is not None else "N/A")

                    all_rows.append({
                        "Datacenter"            : datacenter,
                        "IP"                    : ip,
                        "Host State"            : host_state,
                        "Port"                  : port_id,
                        "Port State"            : port_state,
                        "Service"               : svc_name,
                        "TLS Version"           : tls_ver,
                        "Cipher Name"           : cipher_name,
                        "Key Exchange Info"     : kex_info,
                        "Cipher Strength"       : strength,
                        "Certificate Valid From": cert_from,
                        "Certificate Valid To"  : cert_to,
                    })

                    if cipher_name in WEAK_CIPHERS:
                        weak_rows.append({
                            "Datacenter" : datacenter,
                            "IP"         : ip,
                            "TLS Version": tls_ver,
                            "Issue Type" : "Weak Cipher",
                            "Cipher Name": cipher_name,
                        })

        if not scanned_any:
            all_rows.append({
                "Datacenter"            : datacenter,
                "IP"                    : ip,
                "Host State"            : host_state,
                "Port"                  : "N/A",
                "Port State"            : "N/A",
                "Service"               : "N/A",
                "TLS Version"           : "N/A",
                "Cipher Name"           : "N/A",
                "Key Exchange Info"     : "N/A",
                "Cipher Strength"       : "N/A",
                "Certificate Valid From": cert_from,
                "Certificate Valid To"  : cert_to,
            })

    return all_rows, weak_rows


def write_csv(path, fieldnames, rows):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(
        description="Convert a single Nmap TLS XML (ssl-enum-ciphers) to cipher CSVs."
    )
    parser.add_argument("xml_file",          help="Input Nmap TLS XML file")
    parser.add_argument("-dc", "--datacenter", required=True, help="Datacenter name label")
    parser.add_argument("-o",  "--output",     required=True, help="Full cipher CSV output path")
    parser.add_argument("-wo", "--weak-output", required=True, dest="weak_output",
                        help="Weak-findings-only CSV output path")
    args = parser.parse_args()

    try:
        all_rows, weak_rows = parse_nmap_xml(args.xml_file, args.datacenter)
    except Exception as e:
        print(f"Error parsing {args.xml_file}: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

    write_csv(args.output,      ALL_FIELDS,  all_rows)
    write_csv(args.weak_output, WEAK_FIELDS, weak_rows)

    print(f"Generated full cipher CSV : {args.output} ({len(all_rows)} row(s))")
    print(f"Generated weak cipher CSV : {args.weak_output} ({len(weak_rows)} finding(s))")


if __name__ == "__main__":
    main()
