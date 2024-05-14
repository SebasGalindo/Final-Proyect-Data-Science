from flask import Blueprint, request, jsonify
from .utilities import get_vulnerable_softwares 
from app.extensions import mongo

api_blueprint = Blueprint('api', __name__)

@api_blueprint.route('/ping', methods=['GET'])
def get_data():
    data = {"message": "Pong"}
    return jsonify(data), 200

@api_blueprint.route('/get_vuln_softwares', methods=['GET'])
def get_vuln_softwares():
    try:
        data = get_vulnerable_softwares()
        if not data:  
            return jsonify({'message': 'No vulnerable software found'}), 404
        return jsonify(data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

