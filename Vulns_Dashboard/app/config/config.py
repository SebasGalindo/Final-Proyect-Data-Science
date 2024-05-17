import os

class Config:
    DATABASE_NAME = os.getenv('DATABASE_NAME', 'default_database_name')
    CONTAINER_MACHINES = os.getenv('CONTAINER_MACHINES', 'default_url_machines')
    CONTAINER_SOFTWARES = os.getenv('CONTAINER_SOFTWARES', 'default_url_softwares')
    CONTAINER_CVES = os.getenv('CONTAINER_CVES', 'default_url_cves')
    API_KEY_CVEDETAILS = os.getenv('API_KEY_CVEDETAILS', 'default_api_key')
    API_KEY_NIST = os.getenv('API_KEY_NIST', 'default_api_key')
    API_URL = os.getenv('API_URL', 'default_api_url')
    MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/defaultdb')
    MONGO_VULNS_KEY = os.getenv('MONGO_VULNS_KEY', 'default_mongo_key')
    MONGO_VULNS_URL = os.getenv('MONGO_VULNS_URL', 'default_mongo_url')
