"""
Shadow Protocol - FastAPI Backend Server
Cyber Hackathon 2026 | C-DAC Patna and CCSU Bihar Police
Static Malware Analysis & APK Triage Engine
"""
import os
import sys
import json
import sqlite3
from fastapi import FastAPI, File, UploadFile, HTTPException, Form
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

# Ensure shadow-protocol directory is on sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from database.db import init_db, get_all_scans, get_scan_by_id
from engine.analyzer import analyze_file
from ml.model import get_metadata
from ml.train import train_model

# Initialize SQLite database
init_db()

app = FastAPI(
    title="Shadow Protocol - Static Malware Analysis Engine",
    description="Cyber Hackathon 2026 - C-DAC Patna & CCSU Bihar Police",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
static_dir = os.path.join(BASE_DIR, "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_path = os.path.join(BASE_DIR, "templates", "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Shadow Protocol - Templates not found</h1>"

@app.post("/api/scan")
async def scan_file_upload(file: UploadFile = File(...)):
    try:
        contents = await file.read()
        if not contents:
            raise HTTPException(status_code=400, detail="Empty file uploaded.")
        
        result = analyze_file(contents, file.filename)
        return JSONResponse(content=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis error: {str(e)}")

@app.post("/api/scan-preset")
async def scan_preset(preset_name: str = Form(...)):
    """
    Loads one of the pre-built demo samples:
    - cerberus_banking_trojan.apk
    - spy_rat_malware.apk
    - clean_calculator.apk
    - sample_invoice.exe
    """
    sample_path = os.path.join(BASE_DIR, "samples", preset_name)
    if not os.path.exists(sample_path):
        raise HTTPException(status_code=404, detail="Preset sample file not found.")
    
    with open(sample_path, "rb") as f:
        file_bytes = f.read()
        
    result = analyze_file(file_bytes, preset_name)
    return JSONResponse(content=result)

@app.get("/api/scans")
async def get_scans_history():
    return JSONResponse(content=get_all_scans())

@app.get("/api/scans/{sample_id}")
async def get_scan_detail(sample_id: str):
    scan = get_scan_by_id(sample_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    return JSONResponse(content=scan)

@app.get("/api/ml-info")
async def get_ml_info():
    meta = get_metadata()
    return JSONResponse(content=meta)

@app.post("/api/train")
async def trigger_training():
    try:
        new_meta = train_model()
        return JSONResponse(content={"status": "success", "metadata": new_meta})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Training error: {str(e)}")

@app.get("/api/health")
async def health():
    return {"status": "online", "system": "Shadow Protocol Static Analyzer", "version": "2.0.0"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
