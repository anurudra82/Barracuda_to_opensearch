import requests
import json
from requests.auth import HTTPBasicAuth
from datetime import datetime, timezone
import pytz
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration ---

WAAS_API_BASE = "https://api.waas.barracudanetworks.com/v4/waasapi"
WAAS_EMAIL = "wocibe2677@betzenn.com"      # Replace Email
WAAS_PASSWORD = "Password"                 # Replace Password

# Set IST timezone for index naming
ist = pytz.timezone('Asia/Kolkata')
today_ist = datetime.now(ist).strftime('%Y.%m.%d')
OPENSEARCH_URL = f'https://x.x.x.x:9200/barracuda-waas-logs-{today_ist}/_doc'      # Replace with Opensearch IP Address 
OPENSEARCH_USER = "admin"                # Rplace User
OPENSEARCH_PASS = "Password"             # Replace Password

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

def fetch_waas_logs(auth_token):
    """Fetch logs from Barracuda WAAS. Adjust endpoint if needed."""
    url = f"{WAAS_API_BASE}/applications/test/logs/"  # Adjust endpoint if needed!
    headers = {
        "auth-api": auth_token,
        "Accept": "application/json"
    }
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    logs_response = response.json()
    logs = logs_response.get('results', [])  # Use the 'results' field
    return logs

def normalize_log_entry(log_entry):
    fix = log_entry.get("fix", {})
    fix_types = fix.get("fix_types", []) if isinstance(fix, dict) else []
    fix_details = fix.get("fix_details", {}) if isinstance(fix, dict) else {}
    extra_details = fix.get("extra_details", {}) if isinstance(fix, dict) else {}

    return {
        "AccountID": log_entry.get("AccountID"),
        "EpochTime": log_entry.get("EpochTime"),
        "UnitName": log_entry.get("UnitName"),
        "logType": log_entry.get("logType"),
        "UniqueID": log_entry.get("UniqueID"),
        "CustomerContainerID": log_entry.get("CustomerContainerID"),
        "DeviceID": log_entry.get("DeviceID"),
        "DeploymentName": log_entry.get("DeploymentName"),
        "encrypted": log_entry.get("encrypted"),
        "tag": log_entry.get("tag"),
        "server_state": log_entry.get("server_state"),
        "subtag": log_entry.get("subtag"),
        "message": log_entry.get("message"),
        "server_id": log_entry.get("server_id"),
        "date": log_entry.get("date"),
        "ClientIP_country_code": log_entry.get("ClientIP_country_code"),
        "countryName": log_entry.get("countryName"),
        "URL": log_entry.get("URL"),
        "processor_id": log_entry.get("processor_id"),
        "ServiceIP": log_entry.get("ServiceIP"),
        "ServicePort": log_entry.get("ServicePort"),
        "ClientIP": log_entry.get("ClientIP"),
        "ClientPort": log_entry.get("ClientPort"),
        "LoginID": log_entry.get("LoginID"),
        "CertificateUser": log_entry.get("CertificateUser"),
        "Method": log_entry.get("Method"),
        "Protocol": log_entry.get("Protocol"),
        "Host": log_entry.get("Host"),
        "Version": log_entry.get("Version"),
        "HTTPStatus": log_entry.get("HTTPStatus"),
        "BytesSent": log_entry.get("BytesSent"),
        "BytesReceived": log_entry.get("BytesReceived"),
        "CacheHit": log_entry.get("CacheHit"),
        "TimeTaken": log_entry.get("TimeTaken"),
        "ServerIP": log_entry.get("ServerIP"),
        "ServerPort": log_entry.get("ServerPort"),
        "ServerTime": log_entry.get("ServerTime"),
        "SessionID": log_entry.get("SessionID"),
        "ResponseType": log_entry.get("ResponseType"),
        "ProfileMatched": log_entry.get("ProfileMatched"),
        "Protected": log_entry.get("Protected"),
        "WFMatched": log_entry.get("WFMatched"),
        "QueryString": log_entry.get("QueryString"),
        "Referer": log_entry.get("Referer"),
        "Cookie": log_entry.get("Cookie"),
        "UserAgent": log_entry.get("UserAgent"),
        "ProxyIP": log_entry.get("ProxyIP"),
        "ProxyPort": log_entry.get("ProxyPort"),
        "AuthenticatedUser": log_entry.get("AuthenticatedUser"),
        "FormParameter": log_entry.get("FormParameter"),
        "ClickJacking": log_entry.get("ClickJacking"),
        "EncryptedURL": log_entry.get("EncryptedURL"),
        "ClientFP": log_entry.get("ClientFP"),
        "RequestRS": log_entry.get("RequestRS"),
        "ClientRS": log_entry.get("ClientRS"),
        "ClientType": log_entry.get("ClientType"),
        "CaptchaState": log_entry.get("CaptchaState"),
        "RiskFlags": log_entry.get("RiskFlags"),
        "CredStuffState": log_entry.get("CredStuffState"),
        "RuleName": log_entry.get("RuleName"),
        "ErrorDetails": log_entry.get("ErrorDetails"),
        "WaaSAccountId": log_entry.get("WaaSAccountId"),
        "WaaSAccountIdHash": log_entry.get("WaaSAccountIdHash"),
        "endpointIp": log_entry.get("endpointIp"),
        "Severity": log_entry.get("Severity"),
        "AttackType": log_entry.get("AttackType"),
        "AttackID": log_entry.get("AttackID"),
        "AttackGroup": log_entry.get("AttackGroup"),
        "RuleID": log_entry.get("RuleID"),
        "RuleType": log_entry.get("RuleType"),
        "Action": log_entry.get("Action"),
        "FollowUpAction": log_entry.get("FollowUpAction"),
        "AttackDetails": log_entry.get("AttackDetails"),
        "owasp": log_entry.get("owasp"),
        "owasp_risk_score": log_entry.get("owasp_risk_score"),
        "Attack": log_entry.get("Attack"),
        "fix": {
            "attack_type": fix.get("attack_type"),
            "fix_types": fix_types,
            "fix_details": fix_details,
            "extra_details": extra_details,
            "any_fix_applied": fix.get("any_fix_applied"),
            "any_fix_updateable": fix.get("any_fix_updateable")
        } if fix else None,
        "@timestamp": get_utc_timestamp_with_millis(),
        "log_data_source": "Barracuda WAAS"
    }

def post_log_to_opensearch(log_data):
    """Post a single normalized log to OpenSearch."""
    auth = HTTPBasicAuth(OPENSEARCH_USER, OPENSEARCH_PASS)
    response = requests.post(
        OPENSEARCH_URL,
        headers=POST_HEADERS,
        auth=auth,
        data=json.dumps(log_data),
        verify=False
    )
    if response.status_code in [200, 201]:
        print(f"[+] Indexed log: {log_data.get('UniqueID', 'unknown')}")
    else:
        print(f"[!] Failed to post log: {response.status_code} - {response.text}")

def main():
    print("Authenticating to Barracuda WAAS API...")
    try:
        token = waas_api_login()
        print("Fetching logs from Barracuda WAAS...")
        logs = fetch_waas_logs(token)
        print(f"Fetched {len(logs)} logs.")
        normalized_logs = [normalize_log_entry(log) for log in logs]
        for log_data in normalized_logs:
            post_log_to_opensearch(log_data)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
