import uvicorn
import os
from dotenv import load_dotenv

if __name__ == "__main__":
    load_dotenv()
    # High performance uvicorn worker
    # Standardizing on 127.0.0.1 for local browser accessibility on Windows
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
