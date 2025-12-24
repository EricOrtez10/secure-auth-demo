from fastapi import FastAPI

app = FastAPI(title="Secure Auth Demo App")

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/")
def root():
    return {"message": "Secure Auth Demo App running"}
