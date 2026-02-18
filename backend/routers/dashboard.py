from fastapi import APIRouter, Request, Depends
from ..dependencies import login_required
from ..templates import templates, fastapi_url_for_compat

router = APIRouter()

@router.get("/", name="index")
async def index_page(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "url_for": fastapi_url_for_compat(request)})

@router.get("/dashboard", name="dashboard_page")
async def dashboard_page(request: Request, username: str = Depends(login_required)):
    return templates.TemplateResponse("dashboard.html", {
        "request": request, 
        "url_for": fastapi_url_for_compat(request), 
        "user_info": {"username": username, "role": request.session.get("role")}
    })

@router.get("/devices", name="devices_page")
async def devices_page(request: Request, username: str = Depends(login_required)):
    return templates.TemplateResponse("devices.html", {
        "request": request, 
        "url_for": fastapi_url_for_compat(request), 
        "user_info": {"username": username, "role": request.session.get("role")}
    })

@router.get("/activity", name="activity_page")
async def activity_page(request: Request, username: str = Depends(login_required)):
    return templates.TemplateResponse("activity.html", {
        "request": request, 
        "url_for": fastapi_url_for_compat(request), 
        "user_info": {"username": username, "role": request.session.get("role")}
    })

@router.get("/vpn", name="vpn_page")
async def vpn_page(request: Request, username: str = Depends(login_required)):
    return templates.TemplateResponse("vpn.html", {
        "request": request, 
        "url_for": fastapi_url_for_compat(request), 
        "user_info": {"username": username, "role": request.session.get("role")}
    })

@router.get("/settings", name="settings_page")
async def settings_page(request: Request, username: str = Depends(login_required)):
    return templates.TemplateResponse("settings.html", {
        "request": request, 
        "url_for": fastapi_url_for_compat(request), 
        "user_info": {"username": username, "role": request.session.get("role")}
    })

@router.get("/logs", name="logs_page")
async def logs_page(request: Request, username: str = Depends(login_required)):
    return templates.TemplateResponse("logs.html", {
        "request": request, 
        "url_for": fastapi_url_for_compat(request), 
        "user_info": {"username": username, "role": request.session.get("role")}
    })
