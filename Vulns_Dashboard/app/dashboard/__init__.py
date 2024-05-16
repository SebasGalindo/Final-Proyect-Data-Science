from flask import Blueprint

# Crear un Blueprint para el dashboard
dashboard_blueprint = Blueprint('dashboard', __name__)

from . import controllers
