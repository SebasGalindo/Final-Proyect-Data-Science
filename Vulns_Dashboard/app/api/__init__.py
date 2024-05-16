from flask import Blueprint

# Crear un Blueprint para la API
api_blueprint = Blueprint('api', __name__)

from . import routes
