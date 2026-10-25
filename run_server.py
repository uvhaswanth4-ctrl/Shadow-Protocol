"""
Shadow Protocol - Quick Launcher for Visual Studio Code & Terminal
Run this script via:
    python run_server.py
"""
import os
import sys
import webbrowser
import uvicorn

if __name__ == "__main__":
    print("=" * 70)
    print("  SHADOW PROTOCOL - STATIC MALWARE & APK TRIAGE SYSTEM")
    print("  Cyber Hackathon 2026 | C-DAC Patna & CCSU Bihar Police")
    print("  Team: Jeeva Shree, Jaya Priya, Pugazhenthi P, U.V. Haswanth")
    print("=" * 70)
    print("  Starting FastAPI backend server on http://0.0.0.0:8000 ...")
    print("  Local Access:      http://127.0.0.1:8000")
    print("  Network Access:    http://192.168.1.4:8000 (Open on phone/other devices on same Wi-Fi)")
    print("  Press Ctrl+C to stop the server.")
    print("=" * 70)
    
    # Optionally open browser
    try:
        webbrowser.open("http://192.168.1.4:8000/")
    except Exception:
        pass

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
