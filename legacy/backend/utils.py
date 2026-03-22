from fastapi import Request

def fastapi_url_for_compat(request: Request):
    def _url_for(name: str, **path_params):
        if name == 'static' and 'filename' in path_params:
            path_params['path'] = path_params.pop('filename')
        return request.url_for(name, **path_params)
    return _url_for
