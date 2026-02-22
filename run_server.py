import uvicorn
from dotenv import load_dotenv

if __name__ == "__main__":
    load_dotenv()
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
