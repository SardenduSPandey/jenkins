import csv
import json
import os
import sys
import traceback


REPORT_FIELDS = [
    "Datacenter",
    "IP",
    "Hostname",
    "Port",
    "Status",
    "Service",
    "Version",
    "Finding",
    "Result",
    "Allowed_Ports",
]


def load_csv_rows(filename):
    with open(filename, "r", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(filename, rows, fieldnames):
    with open(filename, "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writerows(rows)


def write_json(filename, payload):
    with open(filename, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def generate_comparison_report(datacenter):
    """Compare scanned ports with the parsed inventory and emit report artifacts."""
    scanned_file = f"{datacenter}.csv"
    inventory_file = "inventory_parsed.json"
    report_file = f"{datacenter}_unexpected_ports.csv"
    summary_file = f"{datacenter}_scan_summary.json"

    if not os.path.exists(scanned_file):
        raise FileNotFoundError(f"Scanned file {scanned_file} not found")

    if not os.path.exists(inventory_file):
        raise FileNotFoundError(f"Inventory file {inventory_file} not found")

    scanned_rows = load_csv_rows(scanned_file)
    with open(inventory_file, "r", encoding="utf-8") as handle:
        inventory_data = json.load(handle)

    inventory_hosts = inventory_data.get("hosts", {})
    unexpected_ports = []
    scanned_ips = set()

    for row in scanned_rows:
        ip = row.get("IP", "").strip()
        port = row.get("Port", "").strip()
        status = row.get("Status", "").strip()

        if ip:
            scanned_ips.add(ip)

        if status and status != "open":
            continue

        try:
            port_int = int(port)
        except (TypeError, ValueError):
            continue

        host_details = inventory_hosts.get(ip)
        if not host_details:
            unexpected_ports.append(
                {
                    "Datacenter": datacenter,
                    "IP": ip,
                    "Hostname": row.get("Hostname", ""),
                    "Port": port,
                    "Status": status,
                    "Service": row.get("Service", ""),
                    "Version": row.get("Version", ""),
                    "Finding": "NOT_IN_INVENTORY",
                    "Result": "FAIL",
                    "Allowed_Ports": "Unknown",
                }
            )
            continue

        allowed_ports = host_details.get("allowed_ports", [])
        if port_int not in allowed_ports:
            unexpected_ports.append(
                {
                    "Datacenter": datacenter,
                    "IP": ip,
                    "Hostname": row.get("Hostname", ""),
                    "Port": port,
                    "Status": status,
                    "Service": row.get("Service", ""),
                    "Version": row.get("Version", ""),
                    "Finding": "UNEXPECTED_OPEN_PORT",
                    "Result": "FAIL",
                    "Allowed_Ports": ",".join(map(str, allowed_ports)) if allowed_ports else "None",
                }
            )

    write_csv(report_file, unexpected_ports, REPORT_FIELDS)

    summary = {
        "datacenter": datacenter,
        "failure_count": len(unexpected_ports),
        "inventory_ip_count": len(
            [host for host in inventory_hosts.values() if host.get("datacenter") == datacenter]
        ),
        "scanned_ip_count": len(scanned_ips),
        "scanned_row_count": len(scanned_rows),
        "report_file": report_file,
        "scan_file": scanned_file,
    }
    write_json(summary_file, summary)

    if unexpected_ports:
        print(f"Found {len(unexpected_ports)} unexpected open port findings for {datacenter}")
    else:
        print(f"No unexpected open ports found for {datacenter}")

    print(f"Report saved to {report_file}")
    print(f"Summary saved to {summary_file}")


if __name__ == "__main__":
    #TODO: add proper parameters
    if len(sys.argv) != 2:
        print("Usage: python3 generate_report.py <datacenter>")
        sys.exit(1)

    try:
        generate_comparison_report(sys.argv[1])
    except Exception as exc:
        print(f"Error generating report: {exc}")
        traceback.print_exc()
        sys.exit(1)
