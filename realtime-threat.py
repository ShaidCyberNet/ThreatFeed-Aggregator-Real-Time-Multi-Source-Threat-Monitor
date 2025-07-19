import requests
import time
import glob
import json
import re
import subprocess
from rich.console import Console
from rich.table import Table
from rich.live import Live
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from collections import defaultdict, Counter
from datetime import datetime

file_path = "./alerts/"
bad_countries = ["russia", "china", "north korea", "iran"]
alerts = defaultdict(list)
seen_ips = set()
country_scores = defaultdict(int)
global_score = Counter()
ip_hits = Counter()
total_types = Counter()
geo_cache = {}
console = Console()

TRIAGE_STATUS_CODES = {
    "NEW": "NEW",
    "INP": "INP",
    "CLO": "CLO",
    "FPO": "FPO",
    "ESC": "ESC",
    "MON": "MON",
    "BAN": "BAN"
}

def geo(ip):
    if ip in geo_cache:
        return geo_cache[ip]
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        resp.raise_for_status()
        data = resp.json()
        result = (
            data.get("country", "Unknown"),
            data.get("city", "-"),
            data.get("isp", "-")
        )
        geo_cache[ip] = result
        return result
    except requests.exceptions.RequestException:
        return "Unknown", "-", "-"

def ban_ip(ip):
    cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
    try:
        subprocess.run(cmd, check=True)
        console.print(f"BANNED {ip}", style="red")
        return True
    except subprocess.CalledProcessError:
        console.print(f"Error banning {ip}", style="red")
        return False

def generate_triage_status(alert_data, ip_country):
    alert_type = alert_data.get("ALERT_TYPE", "UNKNOWN").upper()
    severity = alert_data.get("SEVERITY", 0)
    if ip_country in bad_countries:
        if severity >= 8:
            return TRIAGE_STATUS_CODES["ESC"]
        elif severity >= 5:
            return TRIAGE_STATUS_CODES["NEW"]
    if "MALWARE" in alert_type or "RANSOMWARE" in alert_type:
        return TRIAGE_STATUS_CODES["INP"]
    if severity >= 7:
        return TRIAGE_STATUS_CODES["NEW"]
    elif severity >= 4:
        return TRIAGE_STATUS_CODES["MON"]
    return TRIAGE_STATUS_CODES["NEW"]

def build_table():
    table = Table(title="Real-Time Threat Feed", style="cyan")
    table.add_column("IP", style="green")
    table.add_column("Alert Type", style="red")
    table.add_column("Triage", style="blue")
    table.add_column("Country", style="yellow")
    table.add_column("City", style="magenta")
    table.add_column("ISP", style="cyan")
    table.add_column("Count", style="white")
    table.add_column("Timestamp", style="blue")

    for ip, ip_alerts_list in alerts.items():
        if not ip_alerts_list:
            continue
        ip_hits[ip] += 1
        latest = ip_alerts_list[-1]
        alert_type = latest.get("ALERT_TYPE", "N/A")
        total_types[alert_type] += 1
        timestamp = latest.get("TIMESTAMP", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        country, city, isp = geo(ip)
        if country in bad_countries:
            country_scores[country] += 10
            global_score[ip] += 10
        status = generate_triage_status(latest, country)
        if ip not in seen_ips and country in bad_countries and ip_hits[ip] >= 3:
            if ban_ip(ip):
                seen_ips.add(ip)
        table.add_row(
            ip, alert_type, status, country, city, isp, str(ip_hits[ip]), timestamp
        )
    return table

class AlertFileHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.src_path.endswith(".json"):
            self.process_alert(event.src_path)

    def on_modified(self, event):
        if event.src_path.endswith(".json"):
            self.process_alert(event.src_path)

    def process_alert(self, file_path_param):
        try:
            with open(file_path_param, "r") as f:
                alert_data = json.load(f)
            ip = alert_data.get("ip") or alert_data.get("SRC_IP")
            if ip:
                alerts[ip].append(alert_data)
                console.print(f"Processed alert for IP: {ip}", style="green")
            else:
                console.print(f"No IP found in alert file: {file_path_param}", style="yellow")
        except json.JSONDecodeError as e:
            console.print(f"JSON error in {file_path_param}: {e}", style="red")
        except Exception as e:
            console.print(f"Error reading {file_path_param}: {e}", style="red")

if __name__ == "__main__":
    event_handler = AlertFileHandler()
    observer = Observer()
    observer.schedule(event_handler, path=file_path, recursive=False)
    observer.start()
    try:
        with Live(build_table(), refresh_per_second=1, console=console) as live:
            while True:
                live.update(build_table())
                time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
