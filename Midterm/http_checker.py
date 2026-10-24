import requests

BASE_URL = "http://127.0.0.1:8765"
TIMEOUT = 5

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
]


COOKIE_FLAGS = ["Secure", "HttpOnly", "SameSite"]


def run_http_checks(base_url=BASE_URL):
    lines = []
    lines.append("HTTP security checks against " + base_url)

    try:
        response = requests.get(base_url + "/", timeout=TIMEOUT)
    except requests.RequestException as error:
        lines.append(
            "Could not connect to " + base_url + ": " + str(error)
        )
        lines.append(
            "Check that the test website is running "
            "(python test_website.py) and try again."
        )
        return lines

    lines.append(
        "GET / returned status " + str(response.status_code)
        + " (" + str(len(response.content)) + " bytes)"
    )

    if base_url.startswith("http://"):
        lines.append(
            "Category:      Configuration Review"
        )
        lines.append(
            "Observation:   The service is offered over plain HTTP, "
            "not HTTPS"
        )
        lines.append(
            "Review Status: Transport is unencrypted; review "
            "configuration. This alone does not prove exploitation"
        )
        lines.append("-" * 40)

    server_header = response.headers.get("Server")
    if server_header:
        lines.append("Category:      Informational")
        lines.append("Endpoint:      /")
        lines.append(
            "Observation:   Server header exists: " + server_header
        )
        lines.append(
            "Review Status: Informational; implementation detail, "
            "not automatically high severity"
        )
        lines.append("-" * 40)

    cookie_header = response.headers.get("Set-Cookie")
    if cookie_header:
        lines.append("Category:      Configuration Review")
        lines.append("Endpoint:      /")
        missing_flags = []
        for flag in COOKIE_FLAGS:
            if flag.lower() not in cookie_header.lower():
                missing_flags.append(flag)
        if missing_flags:
            lines.append(
                "Observation:   Set-Cookie is missing flag(s): "
                + ", ".join(missing_flags)
            )
            lines.append(
                "Review Status: Review configuration; this alone "
                "does not prove exploitation"
            )
        else:
            lines.append(
                "Observation:   Set-Cookie includes Secure, HttpOnly "
                "and SameSite"
            )
            lines.append("Review Status: No issue observed")
        lines.append("-" * 40)

    for header_name in SECURITY_HEADERS:
        header_value = response.headers.get(header_name)
        if not header_value:
            lines.append("Category:      Configuration Review")
            lines.append("Endpoint:      /")
            lines.append(
                "Observation:   Header '" + header_name
                + "' is missing or empty"
            )
            lines.append(
                "Review Status: Review configuration; this alone "
                "does not prove exploitation"
            )
            lines.append("-" * 40)

    if not response.headers.get("Strict-Transport-Security"):
        lines.append("Category:      Informational")
        lines.append("Endpoint:      /")
        lines.append(
            "Observation:   Strict-Transport-Security is not present; "
            "not counted as a finding because this is an HTTP-only "
            "local test service and HSTS applies to HTTPS deployments"
        )
        lines.append(
            "Review Status: Informational; review only if this "
            "service is ever deployed over HTTPS"
        )
        lines.append("-" * 40)

    for path, note in (
        ("/health", "health endpoint"),
        ("/redirect", "redirect behaviour"),
        ("/missing", "missing page handling"),
    ):
        try:
            r = requests.get(
                base_url + path, timeout=TIMEOUT, allow_redirects=False
            )
            line = (
                "GET " + path + " (" + note + ") returned status "
                + str(r.status_code)
            )
            location = r.headers.get("Location")
            if location:
                line = line + " with Location: " + location
            lines.append(line)
        except requests.RequestException as error:
            lines.append(
                "Could not connect to " + base_url + path + ": "
                + str(error)
            )

    lines.append(
        "HTTP checks complete. Findings are configuration "
        "observations, not proof of exploitability."
    )
    return lines
