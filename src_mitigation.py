import json
import os
from datetime import datetime

os.makedirs("sandbox", exist_ok=True)
FIREWALL_RULES_FILE = "sandbox/firewall_rules.json"

def get_blocked_ips():
    if not os.path.exists(FIREWALL_RULES_FILE):
        return []
    with open(FIREWALL_RULES_FILE, "r") as f:
        return json.load(f)

def execute_simulated_ip_block(ip_address: str, reason: str):
    """Simulates blocking an IP through a firewall adapter in a safe sandbox."""
    blocked_list = get_blocked_ips()
    
    # Check if already blocked
    for entry in blocked_list:
        if entry["ip"] == ip_address:
            return {
                "status": "ALREADY_BLOCKED",
                "message": f"IP {ip_address} is already blocked in firewall rule table.",
                "timestamp": entry["timestamp"]
            }
            
    new_entry = {
        "ip": ip_address,
        "reason": reason,
        "action": "DROP_ALL_TRAFFIC",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    blocked_list.append(new_entry)
    
    with open(FIREWALL_RULES_FILE, "w") as f:
        json.dump(blocked_list, f, indent=4)
        
    return {
        "status": "SUCCESS",
        "message": f"Successfully added firewall drop rule for IP: {ip_address}",
        "action_taken": "DROP_ALL_TRAFFIC",
        "timestamp": new_entry["timestamp"]
    }