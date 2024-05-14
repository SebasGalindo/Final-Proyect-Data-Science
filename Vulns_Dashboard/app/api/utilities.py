from flask import current_app
from app.extensions import mongo

def get_vulnerable_softwares():
    """
    Get all softwares with vulnerabilities in the database
    Args: None
    Returns: A list of softwares with vulnerabilities    
    """
    softwares_collection = current_app.config['CONTAINER_SOFTWARES']
    softwares_clt = mongo.db[softwares_collection]
    vulnerable_softwares = softwares_clt.find({'vulnerabilities': {'$not': {'$size': 0}}}, {'_id': 0})

    return list(vulnerable_softwares) if vulnerable_softwares else []

