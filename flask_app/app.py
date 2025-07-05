#!/usr/bin/env python3
"""
Flask application for ShadowSeek - Advanced Binary Security Analysis Platform
"""

import os
import logging
from flask import Flask, jsonify

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
    
    # Root endpoint
    @app.route('/')
    def index():
        return jsonify({
            'name': 'ShadowSeek API',
            'version': '2.0.0',
            'status': 'running'
        })
    
    # Health check endpoint
    @app.route('/health')
    def health():
        from datetime import datetime
        return jsonify({
            'status': 'ok',
            'timestamp': datetime.utcnow().isoformat(),
            'message': 'API is running'
        })
    
    return app