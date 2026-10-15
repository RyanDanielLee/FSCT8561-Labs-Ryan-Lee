import csv
import requests

BASE_URL = "http://localhost:3000"
TIMEOUT = 5

observations = []

requests_to_make = [
    {"method": "GET", "path": "/", "params": None, "data": None},
    {
        "method": "GET",
        "path": "/rest/products/search",
        "params": {"q": "apple"},
        "data": None,
    },
    {
        "method": "GET",
        "path": "/rest/products/search",
        "params": {"q": "banana"},
        "data": None,
    },
    {
        "method": "POST",
        "path": "/rest/products/search",
        "params": None,
        "data": {"q": "apple"},
    },
]

for req in requests_to_make:
  url = BASE_URL + req["path"]
  method = req["method"]
  params = req["params"]
  data = req["data"]

  if params:
    input_val = str(params)
  elif data:
    input_val = str(data)
  else:
    input_val = "None"

  try:
    if method == "GET":
      response = requests.get(url, params=params, timeout=TIMEOUT)
    elif method == "POST":
      response = requests.post(url, data=data, timeout=TIMEOUT)
    else:
      continue

    record = {
        "endpoint": req["path"],
        "method": method,
        "input": input_val,
        "status_code": response.status_code,
        "response_length": len(response.content),
        "content_type": response.headers.get("Content-Type", "Unknown"),
        "server": response.headers.get("Server", "Unknown"),
    }
    observations.append(record)

    print(
        f"[{method}] Endpoint: {req['path']} | Input: {input_val} | Status:"
        f" {response.status_code} | Length: {len(response.content)} bytes"
    )

  except requests.RequestException as error:
    print(f"Could not connect to {url}: {error}")

fieldnames = [
    "endpoint",
    "method",
    "input",
    "status_code",
    "response_length",
    "content_type",
    "server",
]
with open(
    "http_scan_results.csv", "w", newline="", encoding="utf-8"
) as csvfile:
  writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
  writer.writeheader()
  writer.writerows(observations)

print("Saved http_scan_results.csv successfully.")


import csv
import requests

BASE_URL = "http://localhost:3000"
TIMEOUT = 5
search_url = BASE_URL + "/rest/products/search"

findings = []
seen_alerts = set()


def add_finding(category, endpoint, observation, review_status):
  key = (category, endpoint, observation)
  if key not in seen_alerts:
    seen_alerts.add(key)
    findings.append({
        "category": category,
        "endpoint": endpoint,
        "observation": observation,
        "review_status": review_status,
    })

try:
  marker = "fsct8561-marker-123"
  r_marker = requests.get(search_url, params={"q": marker}, timeout=TIMEOUT)
  if marker in r_marker.text:
    add_finding(
        "Reflected Input / XSS Indicator",
        "/rest/products/search",
        f"Marker '{marker}' reflected in response",
        "Investigate context; reflection alone does not establish XSS",
    )

  html_test = "<u>fsct8561-test</u>"
  r_html = requests.get(search_url, params={"q": html_test}, timeout=TIMEOUT)
  if html_test in r_html.text:
    add_finding(
        "Reflected Input / XSS Indicator",
        "/rest/products/search",
        f"HTML input '{html_test}' reflected unchanged",
        "Manual verification required; check if browser escapes content",
    )
except requests.RequestException as e:
  print("Connection error during XSS checks:", e)

try:
  normal_input = "apple"
  probes = ["'", "')"]

  r_normal = requests.get(
      search_url, params={"q": normal_input}, timeout=TIMEOUT
  )

  for probe in probes:
    r_probe = requests.get(search_url, params={"q": probe}, timeout=TIMEOUT)
    obs_desc = (
        f"Probe '{probe}' returned status {r_probe.status_code} (Normal status"
        f" {r_normal.status_code})"
    )

    error_phrases = [
        "sqlite_error",
        "sql syntax",
        "database error",
        "syntax error",
    ]
    db_error_found = any(
        phrase in r_probe.text.lower() for phrase in error_phrases
    )

    if r_probe.status_code == 500 or db_error_found:
      add_finding(
          "SQL Injection Indicator",
          "/rest/products/search",
          obs_desc + f" | DB Error text found: {db_error_found}",
          (
              "Indicator found (HTTP 500 or DB error text); manual review"
              " required, not proof of exploitation"
          ),
      )
except requests.RequestException as e:
  print("Connection error during SQL injection checks:", e)

try:
  r_home = requests.get(BASE_URL, timeout=TIMEOUT)

  headers_to_check = ["Content-Security-Policy", "X-Content-Type-Options"]
  for h_name in headers_to_check:
    header_value = r_home.headers.get(h_name)

    if not header_value:
      add_finding(
          "Configuration Review",
          "/",
          f"Header '{h_name}' is missing or empty",
          "Review configuration; this alone does not prove exploitation",
      )

  server_header = r_home.headers.get("Server")
  if server_header:
    add_finding(
        "Informational",
        "/",
        f"Server header exists: {server_header}",
        "Informational; implementation detail, not automatically high severity",
    )
except requests.RequestException as e:
  print("Connection error during header checks:", e)

print("\n--- VULNERABILITY DETECTOR SUMMARY ---")
if not findings:
  print(
      "No security indicators found. Note: This does not prove the site is"
      " secure."
  )
else:
  for f in findings:
    print(f"Category:      {f['category']}")
    print(f"Endpoint:      {f['endpoint']}")
    print(f"Observation:   {f['observation']}")
    print(f"Review Status: {f['review_status']}")
    print("-" * 40)

fieldnames = ["category", "endpoint", "observation", "review_status"]
with open(
    "vulnerability_findings.csv", "w", newline="", encoding="utf-8"
) as csvfile:
  writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
  writer.writeheader()
  writer.writerows(findings)

print("Saved vulnerability_findings.csv successfully.")