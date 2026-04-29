from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from laocoon import LaocoonScanner

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://chobryce.github.io"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def home():
    return {"status": "lacooon backend online"}

@app.post("/scan")
async def scan(file: UploadFile = File(...)):
    return {
        "type": "summary",
        "filename": file.filename,
        "message": "Backend received file successfully. Scanner logic not added yet."
    }
