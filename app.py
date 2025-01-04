from flask import Flask, render_template, request, redirect, url_for
import re
from collections import defaultdict

app = Flask(__name__)

def analyze_ssh_logs(log_content, threshold=5):
    """
    Analyzes SSH logs for brute-force attack patterns.

    Args:
        log_content (str): Content of the SSH log file.
        threshold (int): Number of failed attempts to classify an IP as suspicious.

    Returns:
        dict: Analysis results containing suspicious IPs and detailed log data.
    """
    failed_attempts = defaultdict(int)  # Dictionary to count failed attempts by IP
    suspicious_ips = []  # List to store IPs exceeding the threshold

    # Define a regex pattern to match failed login attempts
    failed_login_pattern = re.compile(
        r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)"
    )

    for line in log_content.splitlines():
        match = failed_login_pattern.search(line)
        if match:
            ip = match.group(1)
            failed_attempts[ip] += 1

            # Add IP to suspicious list if it exceeds the threshold
            if failed_attempts[ip] == threshold:
                suspicious_ips.append(ip)

    return {
        "suspicious_ips": {ip: failed_attempts[ip] for ip in suspicious_ips},
        "detailed_log": dict(failed_attempts),
    }

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        # Retrieve uploaded file and threshold
        uploaded_file = request.files["log_file"]
        threshold = int(request.form.get("threshold", 5))

        if uploaded_file:
            log_content = uploaded_file.read().decode("utf-8")
            analysis_result = analyze_ssh_logs(log_content, threshold)

            # Render the results page with the analysis data
            return render_template(
                "results.html",
                suspicious_ips=analysis_result["suspicious_ips"],
                detailed_log=analysis_result["detailed_log"],
            )

    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
