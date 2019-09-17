import os
from flask import Flask, session
app = Flask(__name__)
from app import routes

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
