#!/bin/bash
# ============================================================
# ABHIMANYU X Platform - Service Startup Script
# ============================================================

set -e

echo "============================================================"
echo "ABHIMANYU X Platform v2.0"
echo "Autonomous Cyber Reasoning System for Defence Infrastructure"
echo "============================================================"
echo ""

# Start Ollama in background
echo "[*] Starting Ollama server..."
OLLAMA_HOST=0.0.0.0:11434 ollama serve &
OLLAMA_PID=$!

# Wait for Ollama to start
echo "[*] Waiting for Ollama to initialize..."
sleep 5

# Check if Ollama is running
if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "[✓] Ollama is running on port 11434"
else
    echo "[!] Ollama may not be fully started yet"
fi

echo ""
echo "============================================================"
echo "SERVICES STARTED"
echo "============================================================"
echo ""
echo "Available commands:"
echo "  abhimanyux scan <target>    Scan file or directory"
echo "  abhimanyux setup           Pull recommended model"
echo "  abhimanyux models          List available models"
echo ""
echo "API endpoints:"
echo "  Ollama API: http://localhost:11434"
echo "  ABHIMANYU X API: http://localhost:8000"
echo ""

# If command is provided, run it
if [ $# -gt 0 ]; then
    abhimanyux "$@"
else
    # Keep container running
    echo "Container running. Press Ctrl+C to stop."
    wait $OLLAMA_PID
fi
