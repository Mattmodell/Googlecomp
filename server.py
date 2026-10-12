from fastapi import FastAPI, APIRouter, HTTPException, Depends, UploadFile, File
from fastapi.security import OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import uuid
import logging
from pathlib import Path
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
import shutil

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# --- Config -----------------------------------------------------------------
MONGO_URL = os.environ['MONGO_URL']
DB_NAME = os.environ['DB_NAME']
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'change-me')
JWT_SECRET = os.environ.get('JWT_SECRET', 'dev-secret')
JWT_ALGO = 'HS256'
JWT_EXPIRE_HOURS = 12

UPLOAD_DIR = ROOT_DIR / 'uploads'
UPLOAD_DIR.mkdir(exist_ok=True)

# --- DB ---------------------------------------------------------------------
client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]

# --- Models -----------------------------------------------------------------
class LoginIn(BaseModel):
    username: str
    password: str

class TokenOut(BaseModel):
    token: str
    expires_in: int

# --- Auth -------------------------------------------------------------------
oauth2 = OAuth2PasswordBearer(tokenUrl='/api/auth/login', auto_error=False)


def create_token(sub: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRE_HOURS)
    payload = {'sub': sub, 'exp': exp, 'role': 'admin'}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def require_admin(token: Optional[str] = Depends(oauth2)) -> str:
    if not token:
        raise HTTPException(status_code=401, detail='Not authenticated')
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        if payload.get('role') != 'admin':
            raise HTTPException(status_code=403, detail='Forbidden')
        return payload.get('sub')
    except JWTError:
        raise HTTPException(status_code=401, detail='Invalid or expired token')


# --- App --------------------------------------------------------------------
app = FastAPI(title='KSV-Sportkantine API')
api = APIRouter(prefix='/api')

# Static uploads at /api/uploads/<file>
app.mount('/api/uploads', StaticFiles(directory=str(UPLOAD_DIR)), name='uploads')


def _menu_out(doc: dict) -> dict:
    return {
        'id': doc['id'],
        'image_url': f"/api/uploads/{doc['filename']}",
        'uploaded_at': doc['uploaded_at'],
    }


# --- Public routes ----------------------------------------------------------
@api.get('/')
async def root():
    return {'name': 'KSV-Sportkantine API', 'status': 'ok'}


@api.post('/auth/login', response_model=TokenOut)
async def login(data: LoginIn):
    if data.username != ADMIN_USERNAME or data.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail='Falsche Zugangsdaten')
    token = create_token(data.username)
    return TokenOut(token=token, expires_in=JWT_EXPIRE_HOURS * 3600)


@api.get('/weekly-menu')
async def get_weekly_menu():
    doc = await db.weekly_menu.find_one(sort=[('uploaded_at', -1)])
    if not doc:
        return None
    return _menu_out(doc)


# --- Admin routes -----------------------------------------------------------
@api.post('/admin/weekly-menu')
async def upload_menu(file: UploadFile = File(...), _: str = Depends(require_admin)):
    if not file.content_type or not file.content_type.startswith('image/'):
        raise HTTPException(status_code=400, detail='Nur Bilddateien erlaubt')
    ext = os.path.splitext(file.filename or 'menu.jpg')[1].lower() or '.jpg'
    if ext not in ('.jpg', '.jpeg', '.png', '.webp'):
        ext = '.jpg'
    new_id = str(uuid.uuid4())
    filename = f"menu_{new_id}{ext}"
    dest = UPLOAD_DIR / filename
    # Delete previous menu files
    old_docs = await db.weekly_menu.find({}).to_list(100)
    for od in old_docs:
        try:
            p = UPLOAD_DIR / od.get('filename', '')
            if p.exists():
                p.unlink()
        except Exception:
            pass
    await db.weekly_menu.delete_many({})
    # save file
    with open(dest, 'wb') as f:
        shutil.copyfileobj(file.file, f)
    doc = {
        'id': new_id,
        'filename': filename,
        'uploaded_at': datetime.now(timezone.utc),
    }
    await db.weekly_menu.insert_one(doc)
    return _menu_out(doc)


@api.delete('/admin/weekly-menu')
async def delete_menu(_: str = Depends(require_admin)):
    docs = await db.weekly_menu.find({}).to_list(100)
    for d in docs:
        p = UPLOAD_DIR / d.get('filename', '')
        if p.exists():
            try:
                p.unlink()
            except Exception:
                pass
    await db.weekly_menu.delete_many({})
    return {'ok': True}


# --- Wire it up -------------------------------------------------------------
app.include_router(api)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=['*'],
    allow_methods=['*'],
    allow_headers=['*'],
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@app.on_event('startup')
async def startup():
    logger.info('KSV backend started. Admin user: %s', ADMIN_USERNAME)


@app.on_event('shutdown')
async def shutdown_db_client():
    client.close()
