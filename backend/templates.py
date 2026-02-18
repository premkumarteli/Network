from fastapi.templating import Jinja2Templates
from fastapi import Request
import os

# Base directory is one level up from this file (backend/)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

def fastapi_url_for_compat(request: Request):
    def _url_for(name: str, **path_params):
        if name == 'static' and 'filename' in path_params:
            path_params['path'] = path_params.pop('filename')
        return request.url_for(name, **path_params)
    return _url_for
