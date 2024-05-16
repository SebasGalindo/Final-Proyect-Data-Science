from flask import Flask
from .dashboard import dashboard_blueprint
from .api import api_blueprint
from .config.config import Config

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Blueprints register
    app.register_blueprint(api_blueprint, url_prefix='/api')
    app.register_blueprint(dashboard_blueprint, url_prefix='/dashboard')

    return app
