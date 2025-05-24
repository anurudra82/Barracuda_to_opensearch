import requests
import json
from requests.auth import HTTPBasicAuth
from datetime import datetime, timezone
import pytz
import urllib3
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration ---

WAAS_API_BASE = "https://api.waas.barracudanetworks.com/v4/waasapi"
WAAS_API_TOKEN = "eyJhY2NfaWQiOiAxMTIyNzM0NywgInVzZXJfaWQiOiAyMDg1ODIzNTIsICJleHBpcmF0aW9uIjogMTc0ODA5MzU2NX0=.3dbf4c71872c06e0cd86da8e828b9445c"  # <-- Place your Barracuda WAAS API token here

# Set IST timezone for index naming
ist = pytz.timezone('Asia/Kolkata')
today_ist = datetime.now(ist).strftime('%Y.%m.%d')
OPENSEARCH_URL = f'https://x.x.x.x:9200/barracuda-waas-users-{today_ist}/_doc'   # Replace IP address
OPENSEARCH_USER = "admin"          # Replace user
OPENSEARCH_PASS = "Password"       # Replace Password

POST_HEADERS = {
    'Content-Type': 'application/json'
}

def get_utc_timestamp_with_millis():
    now = datetime.now(timezone.utc)
    return now.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

def fetch_waas_users():
    """Fetch users from Barracuda WAAS using only the API token."""
    if not WAAS_API_TOKEN:
        print("[!] No token found. Please set WAAS_API_TOKEN.")
        sys.exit(1)
    url = f"{WAAS_API_BASE}/users/"
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
        print(f"[!] Failed to fetch users: {response.status_code} - {response.text}")
        return []
    users = response.json()  # The response is a list, not a dict
    print(f"[+] Fetched {len(users)} users.")
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
    """Post a single normalized user to OpenSearch and print the full response."""
    auth = HTTPBasicAuth(OPENSEARCH_USER, OPENSEARCH_PASS)
    print("\n[+] Posting user data to OpenSearch:")
    print(json.dumps(user, indent=2))
    response = requests.post(
        OPENSEARCH_URL,
        headers=POST_HEADERS,
        auth=auth,
        data=json.dumps(user),
        verify=False
    )
    print("[+] OpenSearch response:")
    print(response.status_code, response.text)
    if response.status_code not in [200, 201]:
        print(f"[!] Failed to post {user.get('email', 'unknown')}")

def main():
    print("Fetching users from Barracuda WAAS using API token...")
    users = fetch_waas_users()
    if not users:
        print("[!] No users fetched. This may be due to insufficient token permissions or API limitations.")
        return
    normalized_users = [normalize_user_entry(user) for user in users]
    for user in normalized_users:
        post_user_to_opensearch(user)

if __name__ == "__main__":
    main()
