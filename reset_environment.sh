#!/bin/bash

echo ""
echo "======================================================"
echo "   ShadowSeek Environment Reset Utility"
echo "   Use this when encountering setup issues"
echo "======================================================"
echo ""

echo "🧹 Cleaning up corrupted environments..."
echo ""

# Remove virtual environment if it exists
if [ -d ".venv" ]; then
    echo "Removing corrupted virtual environment..."
    rm -rf .venv
    echo "✅ Virtual environment removed"
else
    echo "ℹ️ No virtual environment found"
fi

# Remove Python cache
echo "Removing Python cache..."
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -name "*.pyc" -delete 2>/dev/null || true

# Remove UV cache if it exists
if [ -d ".uv" ]; then
    echo "Removing UV cache..."
    rm -rf .uv
fi

echo ""
echo "🔧 Running fresh setup with pip fallback..."
echo ""

# Run setup with clean environment and pip fallback
python setup_environment.py --force-clean --use-pip --auto

echo ""
echo "======================================================"
echo "Reset complete!"
echo "If issues persist, try manual installation:"
echo "  pip install --user flask flask-sqlalchemy flask-cors requests python-dotenv ghidra-bridge werkzeug"
echo "======================================================"
echo "" 