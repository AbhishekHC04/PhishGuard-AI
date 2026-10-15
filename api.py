
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from phishguard.url_analyzer import analyze_url


app = FastAPI(
    title="PhishGuard AI API",
    description="Explainable heuristic phishing URL risk analysis.",
    version="1.0.0",
)


class URLRequest(BaseModel):
    url: str = Field(
        ...,
        min_length=1,
        max_length=4096,
        description="URL text to analyze; the API does not visit it.",
    )


@app.get("/")
def root():
    return {
        "name": "PhishGuard AI API",
        "status": "running",
        "docs": "/docs",
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/analyze")
def analyze(request: URLRequest):
    try:
        return analyze_url(request.url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
