import os
from dotenv import load_dotenv
load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY') or 'fallback-inseguro'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///bytedev.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False