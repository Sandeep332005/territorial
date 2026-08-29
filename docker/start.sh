#!/bin/bash
# ABHIMANYU X CORE — Docker Startup Script
# Starts Ollama (local LLM) and the API server

set -e

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  ABHIMANYU X CORE — Starting Up                        ║"
echo "║  Autonomous Cyber Reasoning & Software Immunization     ║"
echo "╚══════════════════════════════════════════════════════════╝"

# ── Start Ollama in background ──
echo "[*] Starting Ollama (local LLM server)..."
OLLAMA_HOST=0.0.0.0:11434 ollama serve &
OLLAMA_PID=$!

# Wait for Ollama to be ready
echo "[*] Waiting for Ollama to start..."
for i in $(seq 1 30); do
    if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
        echo "[✓] Ollama is ready"
        break
    fi
    sleep 1
done

# Pull model if not present
echo "[*] Checking for code model..."
if ! ollama list 2>/dev/null | grep -q "qwen2.5-coder"; then
    echo "[*] Pulling qwen2.5-coder:7b (this may take a few minutes)..."
    ollama pull qwen2.5-coder:7b || echo "[!] Failed to pull model, will use fallback"
fi

# ── Start API Server ──
echo "[*] Starting API server on port 8000..."
exec python -m abhimanyux.api.server
