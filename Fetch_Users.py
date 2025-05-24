import requests
import json
from requests.auth import HTTPBasicAuth
from datetime import datetime, timezone
import pytz
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration ---

WAAS_API_BASE = "https://api.waas.barracudanetworks.com/v4/waasapi"
WAAS_EMAIL = "wocibe2677@betzenn.com"  # Replace mail
WAAS_PASSWORD = "Password"             # Replace Password  

# Set IST timezone for index naming
ist = pytz.timezone('Asia/Kolkata')
today_ist = datetime.now(ist).strftime('%Y.%m.%d')
OPENSEARCH_URL = f'https://x.x.x.x:9200/barracuda-waas-users-{today_ist}/_doc'       # Replace IP address 
OPENSEARCH_USER = "admin"              # Replace user
OPENSEARCH_PASS = "Password"           # Replace Password

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

def fetch_waas_users(auth_token):
    """Fetch users from Barracuda WAAS."""
    url = f"{WAAS_API_BASE}/users/"
    headers = {
        "auth-api": auth_token,
        "Accept": "application/json"
    }
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    users = response.json()  # The response is a list, not a dict
    return users

def normalize_user_entry(user_entry):
    """Normalize a WAAS user entry to the desired format."""
    return {
        "name": user_entry.get("name"),
        "email": user_entry.get("email"),
        "role_name": user_entry.get("role_name"),
        "other_accounts": user_entry.get("other_accounts"),
        "single_admin": user_entry.get("single_admin"),
        "@timestamp": get_utc_timestamp_with_millis(),
        "user_data_source": "Barracuda WAAS"
    }

def post_user_to_opensearch(user):
    """Post a single normalized user to OpenSearch."""
    auth = HTTPBasicAuth(OPENSEARCH_USER, OPENSEARCH_PASS)
    response = requests.post(
        OPENSEARCH_URL,
        headers=POST_HEADERS,
        auth=auth,
        data=json.dumps(user),
        verify=False
    )
    if response.status_code in [200, 201]:
        print(f"[+] Indexed user: {user.get('email', 'unknown')}")
    else:
        print(f"[!] Failed to post {user.get('email', 'unknown')}: {response.status_code} - {response.text}")

def main():
    print("Authenticating to Barracuda WAAS API...")
    try:
        token = waas_api_login()
        print("Fetching users from Barracuda WAAS...")
        users = fetch_waas_users(token)
        print(f"Fetched {len(users)} users.")
        normalized_users = [normalize_user_entry(user) for user in users]
        for user in normalized_users:
            post_user_to_opensearch(user)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
