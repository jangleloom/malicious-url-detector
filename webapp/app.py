from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import sys
from pathlib import Path

# Add malicious-url-detector/src to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "malicious-url-detector" / "src"))
from predict import score_url

app = FastAPI(title="Malicious URL Detector")
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "result": None})

@app.post("/check", response_class=HTMLResponse)
async def check_url(request: Request, url: str = Form(...)):
    url = url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")
    
    result = score_url(url)
    
    return templates.TemplateResponse("index.html", {"request": request, "result": result})

@app.get("/api/predict", response_class=HTMLResponse)
async def api_predict(url: str):
    url = url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")
    result = score_url(url)
    return result