# Final Project: Data Science Dashboard

This project is a vulnerability dashboard designed to visualize and manage security vulnerability data. It is built using Flask and various data visualization tools.

## Project Structure


~~~ markdown
FINAL-PROYECT-DATA-SCIENCE/
├── Notebook/
│   └── DataCharge.ipynb
├── Vulns_Dashboard/
│   ├── app/
│   │   ├── api/
│   │   │   ├── __pycache__/
│   │   │   ├── __init__.py
│   │   │   ├── routes.py
│   │   │   └── utilities.py
│   │   ├── config/
│   │   │   ├── __pycache__/
│   │   │   ├── __init__.py
│   │   │   └── config.py
│   │   ├── dashboard/
│   │   │   ├── __pycache__/
│   │   │   ├── __init__.py
│   │   │   ├── controllers.py
│   │   │   └── models.py
│   ├── static/
│   │   ├── css/
│   │   ├── images/
│   │   └── js/
│   ├── templates/
│   │   ├── 404.html
│   │   ├── base.html
│   │   ├── chart_card.html
│   │   ├── footer.html
│   │   ├── header.html
│   │   ├── index.html
│   │   └── stats_section.html
│   ├── __pycache__/
│   ├── extensions.py
│   ├── requirements.txt
│   ├── run.py
│   ├── .env
│   └── README.md
~~~

## Requirements

Ensure you have the following requirements installed before running the project:

- Python 3.7+
- Flask
- flask_pymongo
- python-dotenv
- plotly
- pandas 
- requests 

Other dependencies listed in requirements.txt
To install the dependencies, use the following command:

~~~ bash
pip install -r requirements.txt
~~~

## Configuration

The .env file should contain the necessary configurations to connect to the database and other environment settings. An example configuration is as follows:

~~~ makefile
DATABASE_NAME = FinalProject
CONTAINER_MACHINES=Machines
CONTAINER_SOFTWARES=Softwares
CONTAINER_CVES=Cves
API_KEY_CVEDETAILS= your_secret_key
API_KEY_NIST= your_secret_key
API_URL= https://www.cvedetails.com/api/v1/vulnerability/search
MONGO_URI= you_mongo_uri
MONGO_VULNS_KEY= your_secret_key
~~~

## Code Structure

***app/api***
Contains the routes and utilities for the application's API. This handles HTTP requests and responses related to vulnerability data.

**routes.py**: Defines the API routes.
**utilities.py**: Helper functions for the API.

***app/config/***
Contains the application's configuration.

**config.py**: Application configurations.

***app/dashboard/***
Contains the logic for the dashboard, including controllers and models.

**controllers.py**: Controllers that handle business logic.
**models.py**: Data model definitions.

***static/***
Contains static files such as CSS, images, and JavaScript.

***templates/***
Contains HTML templates used to render web pages.

**base.html**: Base template for the application.
**index.html**: Main page of the dashboard.

## Running the Application

While in the \Final-Proyect-Data-Science\Vulns_Dashboard directory, use the following command to run the application:
~~~ bash
python run.py
~~~
This will start the Flask server, and you can access the application at http://localhost:5000.
