from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_ckeditor import CKEditor
import logging
import re


app = Flask(__name__)
app.logger.setLevel(logging.INFO)

app.config['CKEDITOR_PKG_TYPE'] = 'full'
ckeditor = CKEditor(app)

app.config['SECRET_KEY'] = 'suasenha'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://meubanco:minhasenha@meuip:minhaporta/oresto'

database = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'alert-info'

from Intranet import routes
