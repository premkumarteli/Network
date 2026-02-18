import uvicorn
import os
from dotenv import load_dotenv

if __name__ == "__main__":
    load_dotenv()
    # High performance uvicorn worker
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
