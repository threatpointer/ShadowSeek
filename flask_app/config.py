import os
import secrets
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Base configuration"""
    # Secret key
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    
    # Database - Fixed path for ShadowSeek
    base_dir = os.path.abspath(os.path.dirname(__file__))
    project_root = os.path.dirname(base_dir)
    default_db_path = os.path.join(project_root, 'instance', 'shadowseek.db')
    # Temporarily ignore DATABASE_URI env var and use correct path
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{default_db_path}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Upload settings
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER') or os.path.join(os.getcwd(), 'uploads')
    TEMP_FOLDER = os.environ.get('TEMP_FOLDER') or os.path.join(os.getcwd(), 'temp')
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100 MB
    ALLOWED_EXTENSIONS = set(os.environ.get('ALLOWED_EXTENSIONS', 'exe,dll,so,dylib,bin,elf').split(','))
    
    # Ghidra settings
    GHIDRA_INSTALL_DIR = os.environ.get('GHIDRA_INSTALL_DIR')
    GHIDRA_BRIDGE_PORT = int(os.environ.get('GHIDRA_BRIDGE_PORT', '4768'))
    GHIDRA_PROJECTS_DIR = os.environ.get('GHIDRA_PROJECTS_DIR') or os.path.join(os.getcwd(), 'ghidra_projects')
    ANALYSIS_SCRIPTS_DIR = os.environ.get('ANALYSIS_SCRIPTS_DIR') or os.path.join(os.getcwd(), 'analysis_scripts')
    
    # Logging
    LOG_FOLDER = os.environ.get('LOG_FOLDER') or os.path.join(os.getcwd(), 'logs')
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    
    # Ensure directories exist
    for directory in [UPLOAD_FOLDER, TEMP_FOLDER, LOG_FOLDER, GHIDRA_PROJECTS_DIR, ANALYSIS_SCRIPTS_DIR]:
        os.makedirs(directory, exist_ok=True)
    
    # If Ghidra path not set, try to find it
    if not GHIDRA_INSTALL_DIR:
        # No hardcoded fallback paths - user must configure GHIDRA_INSTALL_DIR
        # This ensures the application works across different systems
        print("Warning: GHIDRA_INSTALL_DIR not set. Please configure it in environment variables or .env file")
        print("The application may not function properly without a valid Ghidra installation path")

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    SQLALCHEMY_ECHO = True

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False 