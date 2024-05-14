from flask import Blueprint, render_template

dashboard_blueprint = Blueprint('dashboard', __name__)

@dashboard_blueprint.route('/')
def dashboard_home():
    return render_template('index.html')
