from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, redirect, url_for ,send_from_directory
from app.extensions import mongo
from .config.config import Config
from .api.routes import api_blueprint
from .dashboard.controllers import dashboard_blueprint
import os

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    app.config["MONGO_URI"] = app.config['MONGO_URI']
    
    mongo.init_app(app)
    
    app.register_blueprint(api_blueprint, url_prefix='/api')
    app.register_blueprint(dashboard_blueprint, url_prefix='/dashboard')

    # Path to redirect from root to panel
    @app.route('/')
    def index():
        return redirect(url_for('dashboard.dashboard_home'))
    
    @app.route('/favicon.ico')
    def favicon():
        return send_from_directory(os.path.join(app.root_path, 'static', 'images'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

    @app.errorhandler(404)
    def page_not_found(error):
        return render_template('404.html'), 404

    return app
