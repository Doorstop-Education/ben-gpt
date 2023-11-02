from flask import Flask, request, flash, redirect, url_for, session, render_template, abort, jsonify
from flask_oauthlib.client import OAuth
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from google.oauth2 import _client, service_account
from google.oauth2.credentials import Credentials
from googleapiclient import discovery
from oauth2client.client import GoogleCredentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.cloud import dns
from flask_wtf.csrf import CSRFProtect
from urllib.parse import urlencode
from functools import wraps
import requests
import random
import re
import os
from flask_cors import CORS
from google.cloud import secretmanager
import json
import logging
import os
from typing import Dict
import psycopg2


# from connect_connector import connect_with_connector_auto_iam_authn, connect_with_connector
# from connect_unix import connect_unix_socket

import sqlalchemy
# from sqlalchemy import create_engine
# from sqlalchemy.orm import scoped_session, sessionmaker
# from sqlalchemy.ext.declarative import declarative_base

from google.cloud.sql.connector import Connector, IPTypes

app = Flask(__name__)

# consider adding main_domains to list of allowed origins
CORS(app, resources={r"*": {"origins": ["https://logical-bloom-385422.uk.r.appspot.com", "https://woobsite.com"]}})

# logger = logging.getLogger()

project_id = "90587024925"
secret_id = "client_secret_security"
secret_version_name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"
client = secretmanager.SecretManagerServiceClient()
response = client.access_secret_version(request={"name": secret_version_name})
payload = response.payload.data.decode("UTF-8")
secrets = json.loads(payload)

app.config['SECRET_KEY'] = secrets["client_secret"]
csrf = CSRFProtect(app)

db_user = os.environ.get('DB_USER')
db_pass = os.environ.get('DB_PASS')
db_name = os.environ.get('DB_NAME')
db_host = os.environ.get('DB_HOST')
socket_path = os.environ.get('INSTANCE_UNIX_SOCKET')

app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql+psycopg2://{db_user}:{db_pass}@{db_host}:25060/{db_name}'
app.config['SERVER_NAME'] = 'woobsite.com'

# MAIN GCLOUD
# app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql+pg8000://{db_user}:{db_pass}@/{db_name}?unix_sock={socket_path}/.s.PGSQL.5432'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Optional: Disables modification tracking


# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'  # SQLite for testing

db = SQLAlchemy(app)

oauth = OAuth(app)


# Set your Google Cloud project ID and the managed zone name
project_id = "logical-bloom-385422" 
zone_name = "example-zone"

class User(db.Model): 
    __tablename__ = 'users'

    id = db.Column(db.String, primary_key=True)
    # username = db.Column(db.String(80), unique=True, nullable=False)
    main_domain = db.Column(db.String(80), unique=True, nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    subdomains = relationship('Subdomain', backref='user', lazy=True)
    custom_domain = db.Column(db.String(80), unique=False, nullable=True, default="-1")
    navbar_items = relationship('NavbarItem', backref='user', lazy=True)

    def __repr__(self):
        return '<User %r>' % self.id #was username

class Subdomain(db.Model):
    __tablename__ = 'subdomains'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True) 
    name = db.Column(db.String(80), unique=True, nullable=False)
    gdrive_file_id = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)  
    
    # each user can have a subdomain with a particular name only once.
    __table_args__ = (db.UniqueConstraint('name', 'user_id', name='unique_subdomain_per_user'),)

    def __repr__(self):
        return '<Subdomain %r>' % self.name

class NavbarItem(db.Model):
    __tablename__ = 'navbar_items'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True) 
    title = db.Column(db.String(120), nullable=False)
    link = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)

    def __repr__(self):
        return '<NavbarItem %r>' % self.title

with app.app_context():
    # temp refresh with db.drop_all() when needed
    db.create_all()


google = oauth.remote_app(
    'google',
    consumer_key='90587024925-86fvpoltpvcbk3cqtonit5ove0cac5bm.apps.googleusercontent.com',
    consumer_secret='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',
    request_token_params={
        'scope': 'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/documents',
        'discoveryDocs': [
            "https://www.googleapis.com/discovery/v1/apis/drive/v3/rest",
            "https://docs.googleapis.com/$discovery/rest?version=v1"
        ],
    },
    
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
)

def google_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'google_token' not in session:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                response = jsonify({"error": "Unauthorized"})
                response.status_code = 401
                return response
            else:
                return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    # add if already logged in flow
    # user = get_current_user()
    # if user:
    #     return redirect(url_for('account'))
    return render_template('home.html')

@app.route('/login')
def login():
    return google.authorize(callback=url_for('authorized', _external=True))

@app.route('/login/authorized')
def authorized():
    resp = google.authorized_response()
    if resp is None:
        return 'Access denied'
    session['google_token'] = (resp['access_token'], '')
    session['access_token'] = resp['access_token']  # Store the access token in the session
    me = google.get('userinfo')

    user_id = me.data.get('id') # localId
    # username = me.data.get('displayName')
    email = me.data.get('email')

    if user_id and email: # and username 
        user = User.query.get(user_id)
        if not user:
            sub = email.split("@")[0]
            sub = re.sub(r'[^a-zA-Z0-9-]', '', sub)
            # need to check for existing main domains
            if User.query.filter_by(main_domain=sub).first():
                randomName = sub + random.randint(1, 10000) # double check this, too
                create_dns_record(randomName)
                sub = randomName
            else:
                create_dns_record(sub)
            
            user = User(id=user_id, email=email, main_domain=sub) 

            # Create default navbar items
            default_items = [
                NavbarItem(title=sub, link='/'),
                NavbarItem(title='blog', link='/blog'),
                NavbarItem(title='woob', link='/woob')
            ]
            user.navbar_items.extend(default_items)

            db.session.add(user)
            db.session.commit()
        session['user_id'] = user.id
        return redirect(url_for('account'))
    else:
        return 'Error: Missing user data'

def get_current_user():
    user_id = session.get('user_id')
    if user_id:
        return User.query.get(user_id)
    return None

@app.route('/account')
@google_login_required
def account():
    # Get all subdomains associated with the current user
    user = get_current_user()
    if user:
        subdomains = Subdomain.query.filter_by(user_id=user.id).all()
        access_token = session['access_token']  # Add this line
        return render_template('account.html', subdomains=subdomains, access_token=access_token)
    else:
        flash('Error: Unable to load current user')
        return redirect(url_for('home'))

@app.route('/', subdomain='<main_domain>')
def main_domain_page(main_domain):
    # Look up the main domain in the database to get the associated user
    user = User.query.filter_by(main_domain=main_domain).first()
    if not user:
        abort(404)  # Main domain not found
    print(user.main_domain)  # Debugging: Print the main domain name to the console
    return render_template('main_domain_page.html', user=user)

@app.route('/<subpage>', subdomain='<main_domain>')
def subdomain_page(main_domain, subpage):
    # Look up the subdomain in the database to get the associated Google Drive file ID
    user = User.query.filter_by(main_domain=main_domain).first()
    if not user:
        abort(404)  
    # Look up the subdomain in the database to get the associated Google Drive file ID
    subpage = Subdomain.query.filter_by(user_id=user.id, name=subpage).first()

    if not subpage:
        abort(404)  # Subdomain not found
    print(subpage.name)  # Debugging: Print the subdomain name to the console
    print(subpage.gdrive_file_id)  # Debugging: Print the Google Drive file ID to the console
    return render_template('subdomain_page.html', subdomain=subpage, user=user)

@app.route('/create_subdomain', methods=['POST'])
@google_login_required
def create_subdomain():

    data = request.get_json()
    subdomain = data.get('subdomain').lower()
    gdrive_file_id = data.get('fileId')

    # Validate subdomain name here, e.g. check if it's not empty and if it's unique
    if not subdomain:
        flash('Subdomain name is required.')
        return redirect(url_for('account'))

    # Create and store the new Subdomain instance
    user = get_current_user()
    if user:
        new_subdomain = Subdomain(name=subdomain, gdrive_file_id=gdrive_file_id, user_id=user.id)
        db.session.add(new_subdomain)
        db.session.commit()
    else:
        flash('Error: Unable to load current user')
        return redirect(url_for('account'))

    return jsonify({'subdomain': subdomain, 'main_domain': user.main_domain})


@app.route('/delete_subpage', methods=['POST'])
@google_login_required
def delete_subpage():

    data = request.get_json()
    subpage = data.get('subdomain')

    user = get_current_user()
    
    if user and subdomain:
        page = Subdomain.query.filter_by(user_id=user.id, name=subpage).first()
        if page:
            db.session.delete(page)
            db.session.commit()
    else:
        flash('Error: Missing paramenter')
        return redirect(url_for('account'))

    return jsonify({'message': "Successfully removed page"}), 200

@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')


@app.route('/change_nav', methods=['POST'])
@google_login_required
def change_nav():

    data = request.get_json()
    new_nav_items = data.get('new_nav_items', [])  # assuming this format: [{'title': 'Title 1', 'link': '/link1'}, ...]
    user = get_current_user()

    if user:
        # Remove the old navbar items for this user
        NavbarItem.query.filter_by(user_id=user.id).delete()

        # Create and add the new navbar items
        for item in new_nav_items:
            new_nav_item = NavbarItem(title=item['title'], link=item['link'], user_id=user.id)
            db.session.add(new_nav_item)

        # Commit changes to the database
        db.session.commit()

        return jsonify({"message": "Successfully updated navbar items for user"}), 200    
    else:
        flash('Error: Unable to load current user')
        return redirect(url_for('account'))

@app.route('/add_nav_item', methods=['POST'])
@google_login_required
def add_nav_item():
    data = request.get_json()
    new_nav_item = data.get('new_nav_item', {})  # assuming this format: {'title': 'Title 1', 'link': '/link1'}
    
    user = get_current_user()

    if user and new_nav_item.get('title') and new_nav_item.get('link'):
        nav_item = NavbarItem(title=new_nav_item['title'], link=new_nav_item['link'], user_id=user.id)
        db.session.add(nav_item)
        db.session.commit()

        return jsonify({"message": "Successfully added a new navbar item for user"}), 200
    else:
        flash('Error: Unable to add new navbar item')
        return redirect(url_for('account'))

@app.route('/remove_nav_item', methods=['POST'])
@google_login_required
def remove_nav_item():
    data = request.get_json()
    nav_item_id = data.get('nav_item_id')  # assuming this format: {'nav_item_id': 1}
    
    user = get_current_user()

    if user and nav_item_id:
        nav_item = NavbarItem.query.filter_by(user_id=user.id, id=nav_item_id).first()
        if nav_item:
            db.session.delete(nav_item)
            db.session.commit()
            return jsonify({"message": "Successfully removed navbar item"}), 200
        else:
            flash('Error: Navbar item not found')
            return redirect(url_for('account'))
    else:
        flash('Error: Unable to remove navbar item')
        return redirect(url_for('account'))


@app.route('/create_main_domain', methods=['POST'])
@google_login_required
def create_main_domain():
    data = request.get_json()
    main_domain = data.get('main')
    # Validate main domain name here, e.g. check if it's not empty and if it's unique
    if not main_domain:
        return jsonify({"error": "Main domain name is required."}), 400
    
    user = User.query.filter_by(main_domain=main_domain).first()
    if user:
        return jsonify({"error": "Domain name already in use"}), 400


    # Check if the user already has a main domain
    user = get_current_user()
    if user:
        if user.main_domain:
            response = delete_dns_record(user.main_domain)
        #     return jsonify({"error": "You have already created a main domain."}), 400
        # DELETE OLD DOMAIN

        # Update the user's main domain
        user.main_domain = main_domain
        db.session.commit()
        response = create_dns_record(main_domain) # next thing to try is commenting these out

    
    else:
        return jsonify({"error": "Error: Unable to load current user"}), 400
    
    return jsonify({"success": True, "main_domain": main_domain, "response": response})

@app.route('/logout')
@google_login_required
def logout():
    access_token = session['google_token'][0]
    if access_token:
        revoke_url = "https://accounts.google.com/o/oauth2/revoke"
        params = urlencode({'token': access_token})
        headers = {'Content-type': 'application/x-www-form-urlencoded'}
        response = requests.post(revoke_url, data=params, headers=headers)
        if response.status_code == 200:
            session.pop('google_token', None)
        else:
            print(f"Error revoking token: {response.status_code}, {response.text}")

    # Clear the user session
    session.pop('user', None) # was logout_user()

    return redirect(url_for('home'))

# to allow picker api to function
# @app.after_request
# def apply_caching(response):
#     response.headers["Cross-Origin-Opener-Policy"] = "same-origin-allow-popups"
#     return response

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == "__main__":
    app.run() # debug=True
    # app.run(host='0.0.0.0', port=8080) prod

def delete_dns_record(subdomain):
    credentials = GoogleCredentials.get_application_default()
    service = discovery.build('dns', 'v1', credentials=credentials)
    managed_zone = "example-zone"
    name = subdomain + '.woobsite.com.'
    change_body = {
        'deletions': [
            {
                'name': name,
                'type': 'CNAME',
                'ttl': 300,
                'rrdatas': [
                    'ghs.googlehosted.com.',  
                ],
            },
        ],
    }  
    # temp commented out
    # request = service.changes().create(project=project_id, managedZone=managed_zone, body=change_body)
    # response = request.execute()

def create_dns_record(subdomain):
    # The code for creating a DNS record using the google-cloud-dns package
    # Replace with your project_id, zone_name, and key_path
    credentials = GoogleCredentials.get_application_default()
    service = discovery.build('dns', 'v1', credentials=credentials)
    managed_zone = "example-zone"
    name = subdomain + '.woobsite.com.'

    # Check if the subdomain already exists
    request = service.resourceRecordSets().list(
        project=project_id, managedZone=managed_zone
    )
    response = request.execute()

    for rrset in response.get('rrsets', []):
        if rrset['name'] == name:
            print('The subdomain already exists.')
            return
    
    change_body = {
        'additions': [
            {
                'name': name,
                'type': 'CNAME',
                'ttl': 300,
                'rrdatas': [
                    'ghs.googlehosted.com.',  
                ],
            },
        ],
    }  
    request = service.changes().create(project=project_id, managedZone=managed_zone, body=change_body)
    # response = request.execute() TEMP commented out to test if necessary

    return response


# URLs
@app.route('/examples')
def examples():
    return render_template('examples.html')

@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

@app.route('/guides')
@google_login_required
def guides():
    return render_template('guides.html')

@app.route('/upgrade')
@google_login_required
def upgrade():
    return render_template('upgrade.html')

# @app.route('/statiic/nav2')
# def nav2():
#     return render_template('nav2.html')

# @app.route('/templates/nav')
# def nav():
#     return render_template('nav.html')