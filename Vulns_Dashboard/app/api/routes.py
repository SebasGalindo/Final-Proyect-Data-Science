from flask import Blueprint, jsonify, request
from app.extensions import mongo
from .utilities import *
from datetime import datetime

api_blueprint = Blueprint('api', __name__)

@api_blueprint.route('/ping', methods=['GET'])
def get_data():
    data = {"message": "Pong"}
    return jsonify(data), 200

@api_blueprint.route('/all_data', methods=['GET'])
def get_all_data():
    current_year = request.args.get('year', datetime.now().year)
    vulnerable_softwares = get_vulnerable_softwares()
    
    data = {
        "top_ten_vulnerable_softwares": chart_top_ten_vulnerable_softwares(),
        "impact_vulnerabilities": impact_vulnerabilities(vulnerable_softwares),
        "recent_vulnerabilities_qty": recent_vulnerabilities_qty(str(current_year)),
        "most_vulnerable_machine": most_vulnerable_machine(),
        "qty_critical_vulns": qty_critical_vulns(vulnerable_softwares),
        "top_ten_riskiest_vulnerabilities": chart_top_ten_riskiest_vulnerabilities(),
        "qty_vulns_severity_across_time": qty_vulns_severity_across_time(vulnerable_softwares),
        "machines_most_vuln": donut_chart_machines_most_vuln(),
        "cves_version3": radial_chart_cves_version3()
    }
    
    return jsonify(data)
