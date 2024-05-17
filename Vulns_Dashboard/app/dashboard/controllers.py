import requests
from flask import Blueprint, render_template
from datetime import datetime

dashboard_blueprint = Blueprint('dashboard', __name__)

API_BASE_URL = "http://localhost:5000/api"

@dashboard_blueprint.route('/')
def dashboard_home():
    current_year = datetime.now().year
    response = requests.get(f"{API_BASE_URL}/all_data", params={'year': current_year})

    data = response.json()

    top_ten_chart = data.get("top_ten_vulnerable_softwares")
    impact_chart = data.get("impact_vulnerabilities")
    riskiest_chart = data.get("top_ten_riskiest_vulnerabilities")
    severity_across_time_chart = data.get("qty_vulns_severity_across_time")
    machines_most_vuln_chart = data.get("machines_most_vuln")
    cves_version3_chart = data.get("cves_version3")
    
    recent_vulns_qty = data.get("recent_vulnerabilities_qty", 0)
    most_vulnerable_machine = data.get("most_vulnerable_machine", {}).get('hostname', 0)
    qty_critical_vulns = data.get("qty_critical_vulns", 0)
    total_vulnerabilities = data.get("total_vulnerabilities", 0)

    chart_data = [
        machines_most_vuln_chart ,top_ten_chart, impact_chart, riskiest_chart, 
        severity_across_time_chart, cves_version3_chart
    ]

    return render_template('index.html', chart_data=chart_data, recent_vulns_qty=recent_vulns_qty, current_year=current_year, most_vulnerable_machine=most_vulnerable_machine, qty_critical_vulns=qty_critical_vulns,total_vulnerabilities=total_vulnerabilities)
