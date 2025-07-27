#!/usr/bin/env python3
"""
Flask application package for ShadowSeek - Advanced Binary Security Analysis Platform
"""

import os
import logging
from flask import Flask, Blueprint
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize SQLAlchemy
db = SQLAlchemy()

# Initialize bridge manager (will be set in create_app)
ghidra_bridge_manager = None

# Create API blueprint
api_bp = Blueprint('api', __name__)

def create_app(test_config=None):
    """Create and configure the Flask application"""
    app = Flask(__name__, instance_relative_config=True)
    
    # Load configuration
    app.config.from_object('flask_app.config.Config')
    
    # Override with instance config if it exists
    if test_config is None:
        app.config.from_pyfile('config.py', silent=True)
    else:
        app.config.from_mapping(test_config)
    
    # Ensure instance folder exists
    try:
        os.makedirs(app.instance_path, exist_ok=True)
    except OSError:
        pass
    
    # Initialize CORS
    CORS(app)
    
    # Initialize database
    db.init_app(app)
    
    # Initialize bridge manager
    from flask_app.ghidra_bridge_manager import GhidraBridgeManager
    global ghidra_bridge_manager
    ghidra_bridge_manager = GhidraBridgeManager(app)
    app.ghidra_bridge_manager = ghidra_bridge_manager
    
    # Initialize task manager
    from flask_app.task_manager import TaskManager
    task_manager = TaskManager(app, ghidra_bridge_manager)
    app.task_manager = task_manager
    
    # Import routes first
    from . import routes
    
    # Register blueprints
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Register import endpoint
    from flask_app.import_endpoint import import_bp
    app.register_blueprint(import_bp, url_prefix='/api')
    
    # Register AI insights endpoint
    from flask_app.ai_insights_endpoint import ai_insights_bp
    app.register_blueprint(ai_insights_bp)
    
    # Setup Swagger API documentation
    try:
        from flask_app.swagger_docs import create_swagger_blueprint
        swagger_bp = create_swagger_blueprint()
        app.register_blueprint(swagger_bp, url_prefix='/api')
        logger.info("Swagger API documentation initialized at /api/docs/")
    except ImportError as e:
        logger.warning(f"Could not initialize Swagger documentation: {e}")
        logger.warning("Install Flask-RESTX to enable API documentation")
    except Exception as e:
        logger.error(f"Error setting up Swagger documentation: {e}")
    
    # Create database tables if they don't exist
    with app.app_context():
        db.create_all()
    
    # Try to start the bridge
    with app.app_context():
        try:
            ghidra_bridge_manager.start_bridge()
        except Exception as e:
            logger.error(f"Failed to start Ghidra Bridge: {e}")
    
    return app 