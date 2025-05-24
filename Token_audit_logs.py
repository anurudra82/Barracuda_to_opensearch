import requests
import json
from requests.auth import HTTPBasicAuth
from datetime import datetime, timezone
import pytz
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration ---

WAAS_API_BASE = "https://api.waas.barracudanetworks.com/v4/waasapi"
WAAS_API_TOKEN = "eyJhY2NfaWQiOiAxMTIyNzM0NywgInVzZXJfaWQiOiAyMDg1ODIzNTIsICJleHBpcmF0aW9uIjogMTc0ODA5MzU2NX0=.3dbf4c71872c06e0cd86da8e828b944"  # <-- Place your Barracuda WAAS API token here

# Set IST timezone for index naming
ist = pytz.timezone('Asia/Kolkata')
today_ist = datetime.now(ist).strftime('%Y.%m.%d')
OPENSEARCH_URL = f'https://x.x.x.x:9200/barracuda-waas-auditlogs-{today_ist}/_doc'    # Replace IP Address
OPENSEARCH_USER = "admin"      # Replace with User
OPENSEARCH_PASS = "Password"   # Replace with Password

POST_HEADERS = {
    'Content-Type': 'application/json'
}

def get_utc_timestamp_with_millis():
    now = datetime.now(timezone.utc)
    return now.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

def fetch_waas_audit_logs():
    """Fetch audit logs from Barracuda WAAS using only the API token."""
    url = f"{WAAS_API_BASE}/audit_logs/"
    headers = {
        "auth-api": WAAS_API_TOKEN,
        "Accept": "application/json"
    }
    response = requests.get(url, headers=headers, verify=False)
    print(f"[*] HTTP status: {response.status_code}")
    if response.status_code == 401 or response.status_code == 403:
        print(f"[!] Authentication failed: {response.status_code} - {response.text}")
        return []
    elif response.status_code != 200:
        print(f"[!] Failed to fetch audit logs: {response.status_code} - {response.text}")
        return []
    logs = response.json()  # The response is a list, not a dict
    print(f"[+] Fetched {len(logs)} audit logs.")
    return logs

def normalize_audit_log_entry(log_entry):
    """Normalize a WAAS audit log entry to the desired format."""
    return {
        "unique_id": log_entry.get("unique_id"),
        "actor": log_entry.get("actor"),
        "action": log_entry.get("action"),
        "component_modified": log_entry.get("component_modified"),
        "summary": log_entry.get("summary"),
        "changes": log_entry.get("changes", []),
        "is_api_change": log_entry.get("is_api_change"),
        "date": log_entry.get("date"),
        "user_text": log_entry.get("user_text"),
        "user_tooltip": log_entry.get("user_tooltip"),
        "app_name": log_entry.get("app_name"),
        "app_is_deleted": log_entry.get("app_is_deleted"),
        "@timestamp": get_utc_timestamp_with_millis(),
        "log_data_source": "Barracuda WAAS Audit"
    }

def post_audit_log_to_opensearch(audit_log):
    """Post a single normalized audit log to OpenSearch."""
    auth = HTTPBasicAuth(OPENSEARCH_USER, OPENSEARCH_PASS)
    response = requests.post(
        OPENSEARCH_URL,
        headers=POST_HEADERS,
        auth=auth,
        data=json.dumps(audit_log),
        verify=False
    )
    if response.status_code in [200, 201]:
        print(f"[+] Indexed audit log: {audit_log.get('unique_id', 'unknown')}")
        print(response.text)
    else:
        print(f"[!] Failed to post {audit_log.get('unique_id', 'unknown')}: {response.status_code} - {response.text}")

def main():
    print("Fetching audit logs from Barracuda WAAS using API token...")
    logs = fetch_waas_audit_logs()
    if not logs:
        print("[!] No audit logs fetched. This may be due to insufficient token permissions or API limitations.")
        return
    normalized_logs = [normalize_audit_log_entry(log) for log in logs]
    for audit_log in normalized_logs:
        post_audit_log_to_opensearch(audit_log)

if __name__ == "__main__":
    main()
