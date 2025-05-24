import requests
import json
from requests.auth import HTTPBasicAuth
from datetime import datetime, timezone
import pytz
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration ---

WAAS_API_BASE = "https://api.waas.barracudanetworks.com/v4/waasapi"
WAAS_EMAIL = "wocibe2677@betzenn.com"         # Replace Email
WAAS_PASSWORD = "Password"                    # Replace password

# Set IST timezone for index naming
ist = pytz.timezone('Asia/Kolkata')
today_ist = datetime.now(ist).strftime('%Y.%m.%d')
OPENSEARCH_URL = f'https://x.x.x.x:9200/barracuda-waas-auditlogs-{today_ist}/_doc'     # Replace IP Address 
OPENSEARCH_USER = "admin"                    # Replace user
OPENSEARCH_PASS = "Password"                 # Replace Password

POST_HEADERS = {
    'Content-Type': 'application/json'
}

# ---- Timestamp Utility ---- #
def get_utc_timestamp_with_millis():
    now = datetime.now(timezone.utc)
    return now.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

# ---- WAAS API Functions ---- #
def waas_api_login():
    """Authenticate and return the auth-api token."""
    url = f"{WAAS_API_BASE}/api_login"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {
        "email": WAAS_EMAIL,
        "password": WAAS_PASSWORD
    }
    response = requests.post(url, headers=headers, data=data, verify=False)
    response.raise_for_status()
    token = response.json().get("key")
    if not token:
        raise Exception("Failed to obtain auth-api token.")
    return token

def fetch_waas_audit_logs(auth_token):
    """Fetch audit logs from Barracuda WAAS."""
    url = f"{WAAS_API_BASE}/audit_logs/"
    headers = {
        "auth-api": auth_token,
        "Accept": "application/json"
    }
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    logs = response.json()  # The response is a list, not a dict
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
    print("Authenticating to Barracuda WAAS API...")
    try:
        token = waas_api_login()
        print("Fetching audit logs from Barracuda WAAS...")
        logs = fetch_waas_audit_logs(token)
        print(f"Fetched {len(logs)} audit logs.")
        normalized_logs = [normalize_audit_log_entry(log) for log in logs]
        for audit_log in normalized_logs:
            post_audit_log_to_opensearch(audit_log)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
