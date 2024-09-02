from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from backend import crud, schemas
from .auth import oauth, get_db, create_access_token
import logging

router = APIRouter()

@router.get('/auth/google/login')
async def google_login(request: Request):
    redirect_uri = request.url_for('google_callback')
    return await oauth.google.authorize_redirect(request, redirect_uri)

@router.get('/auth/google/callback')
async def google_callback(request: Request, db: Session = Depends(get_db)):
    token = await oauth.google.authorize_access_token(request)
    user_info = token.get('userinfo')
    if user_info:
        user = crud.get_user_by_email(db, email=user_info['email'])
        if not user:
            user = crud.create_user(
                db, schemas.UserCreate(username=user_info['name'], email=user_info['email'], password=None)
            )
        # Create JWT token
        access_token = create_access_token(data={"sub": user.username})
        
        # Set the token in an HTTP-only cookie
        response = RedirectResponse(url='/todos/')
        response.set_cookie(key="access_token", value=access_token, httponly=True)
        return response
    raise HTTPException(status_code=400, detail="Google login failed")


@router.get('/auth/facebook/login')
async def facebook_login(request: Request):
    logging.info("Initiating Facebook login")
    redirect_uri = request.url_for('facebook_callback')
    logging.info(f"Redirect URI: {redirect_uri}")
    return await oauth.facebook.authorize_redirect(request, redirect_uri)

@router.get('/auth/facebook/callback')
async def facebook_callback(request: Request, db: Session = Depends(get_db)):
    token = await oauth.facebook.authorize_access_token(request)
    user_info = await oauth.facebook.parse_id_token(request, token)
    if user_info:
        user = crud.get_user_by_email(db, email=user_info['email'])
        if not user:
            user = crud.create_user(
                db, schemas.UserCreate(username=user_info['name'], email=user_info['email'], password=None)
            )
        # Create JWT token and return it or set it in the cookie
        # ...
    return RedirectResponse(url='/')
