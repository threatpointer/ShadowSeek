#!/usr/bin/env python3
"""
Run the Flask application
"""

import os
from flask_app import create_app

# Create Flask application
app = create_app()

if __name__ == '__main__':
    # Get host and port from environment or use defaults
    host = os.environ.get('FLASK_HOST', '127.0.0.1')
    port = int(os.environ.get('FLASK_PORT', '5000'))
    
    # Print startup message
    print(f"Starting Flask application on {host}:{port}")
    
    # Run the application
    app.run(host=host, port=port, debug=True) 