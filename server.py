from fastapi import FastAPI, APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from dotenv import load_dotenv
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import os
import json
import urllib.request
import urllib.parse
from datetime import datetime, timezone, timedelta
import uuid
import jwt
import httpx
import hashlib
import base64
import secrets

# Load environment variables
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection (synchronous)
mongo_url = os.environ.get('MONGO_URL', '')
client = MongoClient(mongo_url)
db = client[os.environ.get('DB_NAME', 'shadingo_database')]

# Configuration
DISCORD_CLIENT_ID = os.environ.get('DISCORD_CLIENT_ID', '')
DISCORD_CLIENT_SECRET = os.environ.get('DISCORD_CLIENT_SECRET', '')
DISCORD_REDIRECT_URI = os.environ.get('DISCORD_REDIRECT_URI', '')
KICK_CLIENT_ID = os.environ.get('KICK_CLIENT_ID', '')
KICK_CLIENT_SECRET = os.environ.get('KICK_CLIENT_SECRET', '')
KICK_REDIRECT_URI = os.environ.get('KICK_REDIRECT_URI', '')
ADMIN_IDS = os.environ.get('ADMIN_DISCORD_IDS', '').split(',')
JWT_SECRET = os.environ.get('JWT_SECRET', 'default_secret')
RAINBET_API_KEY = os.environ.get('RAINBET_API_KEY', '')
FRONTEND_URL = os.environ.get('FRONTEND_URL', 'https://shadingo.vercel.app')
RAINBET_API_URL = "https://services.rainbet.com/v1/external/affiliates"
PRIZES = {1: 125, 2: 55, 3: 35, 4: 20, 5: 15}

# FastAPI app
app = FastAPI(title="Shadingo Rewards API")
api_router = APIRouter(prefix="/api")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============= MODELS =============

class KickUsernameRequest(BaseModel):
    kick_username: str

class StartCompetitionRequest(BaseModel):
    hunt_id: str

class EndCompetitionRequest(BaseModel):
    final_balance: float

class SubmitGuessRequest(BaseModel):
    guess_amount: float

class SlotModel(BaseModel):
    slot_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    provider: str
    bet_size: float
    win: float = 0.0
    multiplier: float = 0.0

class BonusHuntModel(BaseModel):
    hunt_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    status: str = "preparing"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    start_balance: float
    slots: List[SlotModel] = []
    opened_count: int = 0
    collected_count: int = 0
    best_win: float = 0.0
    run_avg_x: float = 0.0

# ============= PKCE HELPERS =============

def generate_code_verifier() -> str:
    return secrets.token_urlsafe(64)[:128]

def generate_code_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')

def decode_jwt_unsafe(token: str) -> Optional[dict]:
    """Decode JWT without verification to extract claims"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        payload = parts[1]
        # Add padding if needed
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += '=' * padding
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except:
        return None

# ============= AUTH HELPERS =============

def create_jwt_token(user_data: dict) -> str:
    payload = {
        "user_id": user_data["user_id"],
        "discord_id": user_data["discord_id"],
        "is_admin": user_data.get("is_admin", False),
        "exp": datetime.now(timezone.utc) + timedelta(days=30)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def verify_jwt_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except:
        return None

def get_current_user(request: Request) -> Optional[dict]:
    token = request.cookies.get("auth_token")
    if not token:
        return None
    payload = verify_jwt_token(token)
    if not payload:
        return None
    user = db.users.find_one({"discord_id": payload["discord_id"]}, {"_id": 0})
    return user

def require_auth(request: Request) -> dict:
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user

def require_admin(request: Request) -> dict:
    user = require_auth(request)
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# ============= LEADERBOARD =============

def mask_username(username):
    if not username or len(username) <= 3:
        return username
    if len(username) <= 5:
        return username[0] + "*" * (len(username) - 2) + username[-1]
    return username[:2] + "*" * (len(username) - 3) + username[-1]

def get_biweekly_period():
    reference_date = datetime(2025, 1, 1, tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    days_since_ref = (now - reference_date).days
    period_number = days_since_ref // 14
    period_start = reference_date + timedelta(days=period_number * 14)
    period_end = period_start + timedelta(days=13)
    return period_start, period_end

def get_time_remaining(period_end):
    now = datetime.now(timezone.utc)
    end_time = period_end + timedelta(days=1)
    remaining = end_time - now
    if remaining.total_seconds() <= 0:
        return {"days": 0, "hours": 0, "minutes": 0, "seconds": 0}
    days = remaining.days
    hours, remainder = divmod(remaining.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return {"days": days, "hours": hours, "minutes": minutes, "seconds": seconds}

@app.get("/")
def root():
    return {"status": "ok", "message": "Shadingo Rewards API"}

@api_router.get("/leaderboard")
def leaderboard():
    period_start, period_end = get_biweekly_period()
    try:
        params = urllib.parse.urlencode({
            "start_at": period_start.strftime("%Y-%m-%d"),
            "end_at": period_end.strftime("%Y-%m-%d"),
            "key": RAINBET_API_KEY
        })
        url = f"{RAINBET_API_URL}?{params}"
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'Mozilla/5.0')
        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode())
            api_players = data.get('affiliates', []) or []
            players = []
            for idx, player_data in enumerate(api_players[:10], start=1):
                username = player_data.get('username') or player_data.get('name') or ''
                wagered = float(player_data.get('wagered') or player_data.get('wager') or 0)
                players.append({
                    "rank": idx,
                    "username": mask_username(username),
                    "wagered": wagered,
                    "prize": PRIZES.get(idx),
                    "avatar": f"https://api.dicebear.com/7.x/avataaars/svg?seed={username}"
                })
            return {
                "players": players,
                "total_players": len(players),
                "has_data": len(players) > 0,
                "period_start": period_start.strftime("%Y-%m-%d"),
                "period_end": period_end.strftime("%Y-%m-%d"),
                "time_remaining": get_time_remaining(period_end)
            }
    except Exception as e:
        return {
            "players": [],
            "total_players": 0,
            "has_data": False,
            "period_start": period_start.strftime("%Y-%m-%d"),
            "period_end": period_end.strftime("%Y-%m-%d"),
            "time_remaining": get_time_remaining(period_end)
        }

# ============= DISCORD OAUTH =============

@api_router.get("/auth/discord/login")
def discord_login():
    discord_auth_url = (
        f"https://discord.com/api/oauth2/authorize?"
        f"client_id={DISCORD_CLIENT_ID}&"
        f"redirect_uri={urllib.parse.quote(DISCORD_REDIRECT_URI)}&"
        f"response_type=code&"
        f"scope=identify"
    )
    return RedirectResponse(discord_auth_url)

@api_router.get("/auth/discord/callback")
def discord_callback(code: str):
    try:
        with httpx.Client() as http_client:
            token_response = http_client.post(
                "https://discord.com/api/oauth2/token",
                data={
                    "client_id": DISCORD_CLIENT_ID,
                    "client_secret": DISCORD_CLIENT_SECRET,
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": DISCORD_REDIRECT_URI,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            token_data = token_response.json()
            access_token = token_data.get("access_token")
            
            if not access_token:
                raise HTTPException(status_code=400, detail="Failed to get access token")
            
            user_response = http_client.get(
                "https://discord.com/api/users/@me",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            discord_user = user_response.json()
            
            discord_id = discord_user["id"]
            username = discord_user["username"]
            discriminator = discord_user.get("discriminator", "0")
            avatar_hash = discord_user.get("avatar")
            avatar_url = f"https://cdn.discordapp.com/avatars/{discord_id}/{avatar_hash}.png" if avatar_hash else "https://cdn.discordapp.com/embed/avatars/0.png"
            
            existing_user = db.users.find_one({"discord_id": discord_id}, {"_id": 0})
            
            if existing_user:
                user_data = existing_user
                db.users.update_one(
                    {"discord_id": discord_id},
                    {"$set": {"avatar": avatar_url, "discord_username": username}}
                )
            else:
                is_admin = discord_id in ADMIN_IDS
                user_data = {
                    "user_id": str(uuid.uuid4()),
                    "discord_id": discord_id,
                    "discord_username": username,
                    "discord_discriminator": discriminator,
                    "avatar": avatar_url,
                    "kick_username": None,
                    "kick_verified": False,
                    "is_admin": is_admin,
                    "created_at": datetime.now(timezone.utc).isoformat()
                }
                db.users.insert_one(user_data)
            
            jwt_token = create_jwt_token(user_data)
            
            redirect_response = RedirectResponse(url=f"{FRONTEND_URL}/?login=success")
            redirect_response.set_cookie(
                key="auth_token",
                value=jwt_token,
                httponly=True,
                secure=True,
                samesite="none",
                max_age=30*24*60*60
            )
            return redirect_response
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Authentication failed: {str(e)}")

@api_router.get("/auth/me")
def get_me(request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user

@api_router.post("/auth/logout")
def logout(response: Response):
    response.delete_cookie("auth_token")
    return {"message": "Logged out successfully"}

# ============= KICK OAUTH WITH PKCE =============

@api_router.post("/auth/kick/manual")
def kick_manual(req: KickUsernameRequest, request: Request):
    user = require_auth(request)
    if not req.kick_username or len(req.kick_username) < 3:
        raise HTTPException(status_code=400, detail="Invalid Kick username")
    db.users.update_one(
        {"user_id": user["user_id"]},
        {"$set": {"kick_username": req.kick_username, "kick_verified": True}}
    )
    return {"message": "Kick username saved successfully"}

@api_router.get("/auth/kick/login")
def kick_login(request: Request):
    user = require_auth(request)
    if not KICK_CLIENT_ID:
        raise HTTPException(status_code=501, detail="Kick OAuth not configured")
    
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    
    state = str(uuid.uuid4())
    db.oauth_states.insert_one({
        "state": state,
        "user_id": user["user_id"],
        "code_verifier": code_verifier,
        "created_at": datetime.now(timezone.utc).isoformat()
    })
    
    # Request openid scope to get id_token with user info
    kick_auth_url = (
        f"https://id.kick.com/oauth/authorize?"
        f"client_id={KICK_CLIENT_ID}&"
        f"redirect_uri={urllib.parse.quote(KICK_REDIRECT_URI)}&"
        f"response_type=code&"
        f"scope=user:read+openid&"
        f"state={state}&"
        f"code_challenge={code_challenge}&"
        f"code_challenge_method=S256"
    )
    return RedirectResponse(kick_auth_url)

@api_router.get("/auth/kick/callback")
def kick_callback(code: str = None, state: str = None, error: str = None):
    if error:
        return RedirectResponse(url=f"{FRONTEND_URL}/account-settings?kick=error&reason={error}")
    if not code or not state:
        return RedirectResponse(url=f"{FRONTEND_URL}/account-settings?kick=error&reason=missing_code")
    
    try:
        oauth_state = db.oauth_states.find_one({"state": state})
        if not oauth_state:
            return RedirectResponse(url=f"{FRONTEND_URL}/account-settings?kick=error&reason=invalid_state")
        
        user_id = oauth_state["user_id"]
        code_verifier = oauth_state["code_verifier"]
        
        db.oauth_states.delete_one({"state": state})
        
        with httpx.Client(timeout=30.0) as http_client:
            token_response = http_client.post(
                "https://id.kick.com/oauth/token",
                data={
                    "client_id": KICK_CLIENT_ID,
                    "client_secret": KICK_CLIENT_SECRET,
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": KICK_REDIRECT_URI,
                    "code_verifier": code_verifier,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            if token_response.status_code != 200:
                return RedirectResponse(url=f"{FRONTEND_URL}/account-settings?kick=error&reason=token_failed")
            
            token_data = token_response.json()
            access_token = token_data.get("access_token")
            id_token = token_data.get("id_token")
            
            if not access_token:
                return RedirectResponse(url=f"{FRONTEND_URL}/account-settings?kick=error&reason=no_token")
            
            kick_username = None
            
            # Method 1: Decode id_token if present (contains user info)
            if id_token:
                id_claims = decode_jwt_unsafe(id_token)
                if id_claims:
                    kick_username = id_claims.get("preferred_username") or id_claims.get("username") or id_claims.get("name") or id_claims.get("sub")
            
            # Method 2: Decode access_token (might be JWT with user info)
            if not kick_username:
                access_claims = decode_jwt_unsafe(access_token)
                if access_claims:
                    kick_username = access_claims.get("preferred_username") or access_claims.get("username") or access_claims.get("name") or access_claims.get("sub")
            
            # Method 3: Check token response for user info
            if not kick_username:
                kick_username = token_data.get("username") or token_data.get("name")
                if isinstance(token_data.get("user"), dict):
                    kick_username = token_data["user"].get("username") or token_data["user"].get("name")
            
            # Method 4: Try userinfo endpoint (OpenID Connect)
            if not kick_username:
                try:
                    userinfo_response = http_client.get(
                        "https://id.kick.com/oauth/userinfo",
                        headers={"Authorization": f"Bearer {access_token}"}
                    )
                    if userinfo_response.status_code == 200:
                        userinfo = userinfo_response.json()
                        kick_username = userinfo.get("preferred_username") or userinfo.get("username") or userinfo.get("name") or userinfo.get("sub")
                except:
                    pass
            
            # Method 5: Try Kick API endpoints
            if not kick_username:
                for endpoint in [
                    "https://kick.com/api/v1/user",
                    "https://kick.com/api/v2/user",
                    "https://api.kick.com/api/v1/user",
                ]:
                    try:
                        user_response = http_client.get(
                            endpoint,
                            headers={"Authorization": f"Bearer {access_token}"}
                        )
                        if user_response.status_code == 200:
                            kick_user = user_response.json()
                            kick_username = kick_user.get("username") or kick_user.get("name") or kick_user.get("slug")
                            if kick_username:
                                break
                    except:
                        pass
            
            if not kick_username:
                # Store debug info for troubleshooting
                db.kick_debug.insert_one({
                    "user_id": user_id,
                    "token_data_keys": list(token_data.keys()),
                    "has_id_token": id_token is not None,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
                return RedirectResponse(url=f"{FRONTEND_URL}/account-settings?kick=error&reason=no_username")
            
            db.users.update_one(
                {"user_id": user_id},
                {"$set": {"kick_username": kick_username, "kick_verified": True}}
            )
            
            return RedirectResponse(url=f"{FRONTEND_URL}/account-settings?kick=success")
            
    except Exception as e:
        return RedirectResponse(url=f"{FRONTEND_URL}/account-settings?kick=error&reason=server_error")

# ============= BONUS HUNTS =============

@api_router.get("/hunts")
def get_hunts():
    hunts = list(db.bonus_hunts.find({}, {"_id": 0}).sort("created_at", -1).limit(100))
    return hunts

@api_router.get("/hunts/{hunt_id}")
def get_hunt(hunt_id: str):
    hunt = db.bonus_hunts.find_one({"hunt_id": hunt_id}, {"_id": 0})
    if not hunt:
        raise HTTPException(status_code=404, detail="Hunt not found")
    return hunt

@api_router.post("/hunts")
def create_hunt(hunt: BonusHuntModel, request: Request):
    require_admin(request)
    hunt_dict = hunt.model_dump()
    db.bonus_hunts.insert_one(hunt_dict)
    return hunt_dict

@api_router.put("/hunts/{hunt_id}")
def update_hunt(hunt_id: str, hunt_update: Dict[str, Any], request: Request):
    require_admin(request)
    result = db.bonus_hunts.update_one({"hunt_id": hunt_id}, {"$set": hunt_update})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Hunt not found")
    return {"message": "Hunt updated successfully"}

@api_router.delete("/hunts/{hunt_id}")
def delete_hunt(hunt_id: str, request: Request):
    require_admin(request)
    result = db.bonus_hunts.delete_one({"hunt_id": hunt_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Hunt not found")
    return {"message": "Hunt deleted successfully"}

# ============= GUESSING =============

@api_router.get("/competitions")
def get_competitions():
    competitions = list(db.guessing_competitions.find({}, {"_id": 0}).sort("started_at", -1).limit(100))
    return competitions

@api_router.get("/competitions/active")
def get_active_competition():
    competition = db.guessing_competitions.find_one({"status": "active"}, {"_id": 0})
    return competition

@api_router.post("/competitions/start")
def start_competition(req: StartCompetitionRequest, request: Request):
    require_admin(request)
    hunt = db.bonus_hunts.find_one({"hunt_id": req.hunt_id})
    if not hunt:
        raise HTTPException(status_code=404, detail="Hunt not found")
    existing = db.guessing_competitions.find_one({"status": "active"})
    if existing:
        raise HTTPException(status_code=400, detail="There's already an active competition")
    competition = {
        "competition_id": str(uuid.uuid4()),
        "hunt_id": req.hunt_id,
        "status": "active",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "ended_at": None,
        "final_balance": None,
        "winner_discord_id": None,
        "winner_guess": None
    }
    db.guessing_competitions.insert_one(competition)
    return competition

@api_router.post("/competitions/{competition_id}/end")
def end_competition(competition_id: str, req: EndCompetitionRequest, request: Request):
    require_admin(request)
    competition = db.guessing_competitions.find_one({"competition_id": competition_id})
    if not competition:
        raise HTTPException(status_code=404, detail="Competition not found")
    if competition["status"] == "ended":
        raise HTTPException(status_code=400, detail="Competition already ended")
    
    hunt_id = competition["hunt_id"]
    guesses = list(db.guesses.find({"hunt_id": hunt_id}, {"_id": 0}))
    
    winner = None
    closest_diff = float('inf')
    for guess in guesses:
        diff = abs(guess["guess_amount"] - req.final_balance)
        if diff < closest_diff:
            closest_diff = diff
            winner = guess
    
    update_data = {
        "status": "ended",
        "ended_at": datetime.now(timezone.utc).isoformat(),
        "final_balance": req.final_balance,
        "winner_discord_id": winner["user_discord_id"] if winner else None,
        "winner_guess": winner["guess_amount"] if winner else None
    }
    db.guessing_competitions.update_one({"competition_id": competition_id}, {"$set": update_data})
    return {"message": "Competition ended", "winner": winner, "final_balance": req.final_balance}

@api_router.post("/guesses")
def submit_guess(req: SubmitGuessRequest, request: Request):
    user = require_auth(request)
    if not user.get("kick_verified"):
        raise HTTPException(status_code=400, detail="You must connect your Kick account to submit a guess")
    competition = db.guessing_competitions.find_one({"status": "active"})
    if not competition:
        raise HTTPException(status_code=400, detail="No active competition")
    existing_guess = db.guesses.find_one({
        "hunt_id": competition["hunt_id"],
        "user_discord_id": user["discord_id"]
    })
    if existing_guess:
        raise HTTPException(status_code=400, detail="You've already submitted a guess for this competition")
    
    guess = {
        "guess_id": str(uuid.uuid4()),
        "hunt_id": competition["hunt_id"],
        "user_discord_id": user["discord_id"],
        "kick_username": user["kick_username"],
        "guess_amount": req.guess_amount,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    db.guesses.insert_one(guess)
    return guess

@api_router.get("/guesses/hunt/{hunt_id}")
def get_hunt_guesses(hunt_id: str):
    guesses = list(db.guesses.find({"hunt_id": hunt_id}, {"_id": 0}).sort("guess_amount", 1))
    return guesses

@api_router.get("/guesses/my")
def get_my_guesses(request: Request):
    user = require_auth(request)
    guesses = list(db.guesses.find({"user_discord_id": user["discord_id"]}, {"_id": 0}).sort("timestamp", -1).limit(100))
    return guesses

# ============= ADMIN =============

@api_router.get("/admin/users")
def search_users(q: str = "", request: Request = None):
    require_admin(request)
    query = {}
    if q:
        query = {
            "$or": [
                {"discord_username": {"$regex": q, "$options": "i"}},
                {"kick_username": {"$regex": q, "$options": "i"}}
            ]
        }
    users = list(db.users.find(query, {"_id": 0}).limit(50))
    return users

@api_router.get("/admin/stats")
def get_stats(request: Request):
    require_admin(request)
    return {
        "total_users": db.users.count_documents({}),
        "verified_users": db.users.count_documents({"kick_verified": True}),
        "total_hunts": db.bonus_hunts.count_documents({}),
        "total_guesses": db.guesses.count_documents({})
    }

# Debug endpoint to check kick oauth issues
@api_router.get("/admin/kick-debug")
def get_kick_debug(request: Request):
    require_admin(request)
    debug_logs = list(db.kick_debug.find({}, {"_id": 0}).sort("timestamp", -1).limit(10))
    return debug_logs

# Include router
app.include_router(api_router)
