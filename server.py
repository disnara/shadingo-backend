from fastapi import FastAPI, APIRouter, HTTPException, Depends, Request, Response
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from dotenv import load_dotenv
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any
import os
import json
import urllib.request
import urllib.parse
from datetime import datetime, timezone, timedelta
import uuid
from jose import jwt
import requests
import logging

# Load environment variables
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection - use .get() for safer access
mongo_url = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
db_name = os.environ.get('DB_NAME', 'shadingo_database')
client = MongoClient(mongo_url)
db = client[db_name]

# Configuration
DISCORD_CLIENT_ID = os.environ.get('DISCORD_CLIENT_ID', '')
DISCORD_CLIENT_SECRET = os.environ.get('DISCORD_CLIENT_SECRET', '')
DISCORD_REDIRECT_URI = os.environ.get('DISCORD_REDIRECT_URI', '')
KICK_CLIENT_ID = os.environ.get('KICK_CLIENT_ID', '')
KICK_CLIENT_SECRET = os.environ.get('KICK_CLIENT_SECRET', '')
KICK_REDIRECT_URI = os.environ.get('KICK_REDIRECT_URI', '')
ADMIN_IDS = os.environ.get('ADMIN_DISCORD_IDS', '').split(',')
JWT_SECRET = os.environ['JWT_SECRET']
RAINBET_API_KEY = os.environ['RAINBET_API_KEY']
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

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============= MODELS =============

class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    user_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    discord_id: str
    discord_username: str
    discord_discriminator: str = "0"
    avatar: str
    kick_username: Optional[str] = None
    kick_verified: bool = False
    is_admin: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class Slot(BaseModel):
    slot_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    provider: str
    bet_size: float
    win: float = 0.0
    multiplier: float = 0.0

class BonusHunt(BaseModel):
    model_config = ConfigDict(extra="ignore")
    hunt_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    status: str = "preparing"  # preparing, active, completed
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    start_balance: float
    slots: List[Slot] = []
    opened_count: int = 0
    collected_count: int = 0
    best_win: float = 0.0
    run_avg_x: float = 0.0

class Guess(BaseModel):
    model_config = ConfigDict(extra="ignore")
    guess_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    hunt_id: str
    user_discord_id: str
    kick_username: str
    guess_amount: float
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class GuessingCompetition(BaseModel):
    model_config = ConfigDict(extra="ignore")
    competition_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    hunt_id: str
    status: str = "active"  # active, ended
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ended_at: Optional[datetime] = None
    final_balance: Optional[float] = None
    winner_discord_id: Optional[str] = None
    winner_guess: Optional[float] = None

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
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except:
        return None

def get_current_user(request: Request) -> Optional[dict]:
    # First try Authorization header (for cross-domain token-based auth)
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
    else:
        # Fallback to cookie (for same-domain)
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

# ============= LEADERBOARD (Original from your backend) =============

def mask_username(username):
    if not username or len(username) <= 3:
        return username
    if len(username) <= 5:
        return username[0] + "*" * (len(username) - 2) + username[-1]
    return username[:2] + "*" * (len(username) - 3) + username[-1]

def get_weekly_period():
    """Get current weekly period (7 days)"""
    # Set reference to a recent date so periods align better
    reference_date = datetime(2026, 2, 5, tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    days_since_ref = (now - reference_date).days
    period_number = days_since_ref // 7
    period_start = reference_date + timedelta(days=period_number * 7)
    period_end = period_start + timedelta(days=6)
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

def get_race_settings():
    """Get race settings from database or return defaults"""
    settings = db.race_settings.find_one({"_id": "main"}, {"_id": 0})
    if not settings:
        settings = {
            "status": "running",
            "blocked_users": [],
            "custom_users": [],
            "wager_overrides": {}
        }
    return settings

@app.get("/")
def root():
    return {"status": "ok", "message": "Shadingo Rewards API"}

@api_router.get("/leaderboard")
def leaderboard():
    period_start, period_end = get_weekly_period()
    
    # Get race settings
    race_settings = get_race_settings()
    race_status = race_settings.get("status", "running")
    blocked_users = [u.lower() for u in race_settings.get("blocked_users", [])]
    custom_users = race_settings.get("custom_users", [])
    wager_overrides = race_settings.get("wager_overrides", {})
    
    # If race is paused or stopped, return status without player data
    if race_status in ["paused", "stopped"]:
        return {
            "players": [],
            "total_players": 0,
            "has_data": False,
            "race_status": race_status,
            "period_start": period_start.strftime("%Y-%m-%d"),
            "period_end": period_end.strftime("%Y-%m-%d"),
            "time_remaining": get_time_remaining(period_end)
        }
    
    try:
        params = urllib.parse.urlencode({
            "start_at": period_start.strftime("%Y-%m-%d"),
            "end_at": period_end.strftime("%Y-%m-%d"),
            "key": RAINBET_API_KEY
        })
        url = f"{RAINBET_API_URL}?{params}"
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'Mozilla/5.0')
        
        all_players = []
        
        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode())
            api_players = data.get('affiliates', []) or []
            
            for player_data in api_players:
                username = player_data.get('username') or player_data.get('name') or ''
                
                # Skip blocked users
                if username.lower() in blocked_users:
                    continue
                
                # Get wager - check for override first
                if username.lower() in wager_overrides:
                    wagered = float(wager_overrides[username.lower()])
                else:
                    wagered = float(player_data.get('wagered_amount') or player_data.get('wagered') or player_data.get('wager') or 0)
                
                all_players.append({
                    "username": username,
                    "wagered": wagered,
                    "source": "api"
                })
        
        # Add custom users
        for custom_user in custom_users:
            # Check if not blocked
            if custom_user.get("username", "").lower() not in blocked_users:
                all_players.append({
                    "username": custom_user.get("username", ""),
                    "wagered": float(custom_user.get("wagered", 0)),
                    "source": "custom"
                })
        
        # Sort by wagered amount descending
        all_players.sort(key=lambda x: x["wagered"], reverse=True)
        
        # Take top 10 and add rankings
        players = []
        for idx, player in enumerate(all_players[:10], start=1):
            players.append({
                "rank": idx,
                "username": mask_username(player["username"]),
                "wagered": player["wagered"],
                "prize": PRIZES.get(idx),
                "avatar": f"https://api.dicebear.com/7.x/avataaars/svg?seed={player['username']}"
            })
        
        return {
            "players": players,
            "total_players": len(players),
            "has_data": len(players) > 0,
            "race_status": "running",
            "period_start": period_start.strftime("%Y-%m-%d"),
            "period_end": period_end.strftime("%Y-%m-%d"),
            "time_remaining": get_time_remaining(period_end)
        }
    except Exception as e:
        logger.error(f"Leaderboard error: {str(e)}")
        return {
            "players": [],
            "total_players": 0,
            "has_data": False,
            "race_status": "running",
            "period_start": period_start.strftime("%Y-%m-%d"),
            "period_end": period_end.strftime("%Y-%m-%d"),
            "time_remaining": get_time_remaining(period_end)
        }

# ============= DISCORD OAUTH =============

@api_router.get("/auth/discord/login")
def discord_login():
    """Redirect to Discord OAuth"""
    discord_auth_url = (
        f"https://discord.com/api/oauth2/authorize?"
        f"client_id={DISCORD_CLIENT_ID}&"
        f"redirect_uri={urllib.parse.quote(DISCORD_REDIRECT_URI)}&"
        f"response_type=code&"
        f"scope=identify"
    )
    return RedirectResponse(discord_auth_url)

@api_router.get("/auth/discord/callback")
def discord_callback(code: str, response: Response):
    """Handle Discord OAuth callback"""
    try:
        # Exchange code for token
        token_response = requests.post(
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
        
        # Get user info
        user_response = requests.get(
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
        
        # Use FRONTEND_URL for redirect (separate from backend URL for cross-domain deployments)
        frontend_url = os.environ.get('FRONTEND_URL', os.environ.get('REACT_APP_BACKEND_URL', 'https://casino-login-2.preview.emergentagent.com').replace('/api', ''))
        # Pass token in URL for cross-domain auth (localStorage approach)
        redirect_response = RedirectResponse(url=f"{frontend_url}/?token={jwt_token}")
        return redirect_response
        
    except Exception as e:
        logger.error(f"Discord OAuth error: {str(e)}")
        raise HTTPException(status_code=500, detail="Authentication failed")

@api_router.get("/auth/me")
def get_me(request: Request):
    """Get current user info"""
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user

@api_router.post("/auth/logout")
def logout(response: Response):
    """Logout user"""
    response.delete_cookie("auth_token")
    return {"message": "Logged out successfully"}

# ============= KICK MANUAL =============

class KickUsernameRequest(BaseModel):
    kick_username: str

@api_router.post("/auth/kick/manual")
def kick_manual(req: KickUsernameRequest, request: Request):
    """Manually set Kick username"""
    user = require_auth(request)
    
    if not req.kick_username or len(req.kick_username) < 3:
        raise HTTPException(status_code=400, detail="Invalid Kick username")
    
    # Update user with Kick username
    db.users.update_one(
        {"user_id": user["user_id"]},
        {"$set": {"kick_username": req.kick_username, "kick_verified": True}}
    )
    
    return {"message": "Kick username saved successfully"}

# ============= KICK OAUTH =============

@api_router.get("/auth/kick/login")
def kick_login(request: Request, auth_token: str = None):
    """Redirect to Kick OAuth"""
    # For cross-domain: accept token from query param
    if auth_token:
        payload = verify_jwt_token(auth_token)
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db.users.find_one({"discord_id": payload["discord_id"]}, {"_id": 0})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
    else:
        user = require_auth(request)
    
    if not KICK_CLIENT_ID:
        raise HTTPException(status_code=501, detail="Kick OAuth not configured. Please contact admin.")
    
    state = f"{user['user_id']}:{uuid.uuid4()}"
    
    # Kick uses standard OAuth2 but may require specific scopes
    kick_auth_url = (
        f"https://kick.com/oauth2/authorize?"
        f"client_id={KICK_CLIENT_ID}&"
        f"redirect_uri={urllib.parse.quote(KICK_REDIRECT_URI)}&"
        f"response_type=code&"
        f"scope=user:read&"
        f"state={state}"
    )
    return RedirectResponse(kick_auth_url)

@api_router.get("/auth/kick/callback")
def kick_callback(code: str = None, state: str = None, error: str = None):
    """Handle Kick OAuth callback"""
    frontend_url = os.environ.get('REACT_APP_BACKEND_URL', 'https://casino-login-2.preview.emergentagent.com').replace('/api', '')
    
    if error:
        logger.error(f"Kick OAuth error from provider: {error}")
        return RedirectResponse(url=f"{frontend_url}/account-settings?kick=error&reason={error}")
    
    if not code or not state:
        return RedirectResponse(url=f"{frontend_url}/account-settings?kick=error&reason=missing_code")
    
    try:
        user_id = state.split(':')[0]
        
        # Exchange code for token
        token_response = requests.post(
            "https://kick.com/oauth2/token",
            data={
                "client_id": KICK_CLIENT_ID,
                "client_secret": KICK_CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": KICK_REDIRECT_URI,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30
        )
        
        logger.info(f"Kick token response status: {token_response.status_code}")
        logger.info(f"Kick token response: {token_response.text}")
        
        if token_response.status_code != 200:
            raise HTTPException(status_code=400, detail=f"Kick token exchange failed: {token_response.text}")
        
        token_data = token_response.json()
        access_token = token_data.get("access_token")
        
        if not access_token:
            raise HTTPException(status_code=400, detail="No access token in response")
        
        # Try different user endpoints
        kick_username = None
        
        # Try endpoint 1
        try:
            user_response = requests.get(
                "https://kick.com/api/v2/user",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=30
            )
            if user_response.status_code == 200:
                kick_user = user_response.json()
                kick_username = kick_user.get("username") or kick_user.get("name") or kick_user.get("slug")
        except:
            pass
        
        # Try endpoint 2 if first failed
        if not kick_username:
            try:
                user_response = requests.get(
                    "https://api.kick.com/public/v1/user",
                    headers={"Authorization": f"Bearer {access_token}"},
                    timeout=30
                )
                if user_response.status_code == 200:
                    kick_user = user_response.json()
                    kick_username = kick_user.get("username") or kick_user.get("name") or kick_user.get("slug")
            except:
                pass
        
        if not kick_username:
            raise HTTPException(status_code=400, detail="Could not fetch Kick username")
        
        db.users.update_one(
            {"user_id": user_id},
            {"$set": {"kick_username": kick_username, "kick_verified": True}}
        )
        
        return RedirectResponse(url=f"{frontend_url}/account-settings?kick=success")
        
    except Exception as e:
        logger.error(f"Kick OAuth error: {str(e)}")
        return RedirectResponse(url=f"{frontend_url}/account-settings?kick=error&reason=server_error")

# ============= BONUS HUNTS =============

@api_router.get("/hunts")
def get_hunts():
    """Get all bonus hunts"""
    hunts = list(db.bonus_hunts.find({}, {"_id": 0}).sort("created_at", -1))
    return hunts

@api_router.get("/hunts/{hunt_id}")
def get_hunt(hunt_id: str):
    """Get specific bonus hunt"""
    hunt = db.bonus_hunts.find_one({"hunt_id": hunt_id}, {"_id": 0})
    if not hunt:
        raise HTTPException(status_code=404, detail="Hunt not found")
    return hunt

@api_router.post("/hunts")
def create_hunt(hunt: BonusHunt, request: Request):
    """Create new bonus hunt (admin only)"""
    require_admin(request)
    
    hunt_dict = hunt.model_dump()
    hunt_dict["created_at"] = hunt_dict["created_at"].isoformat()
    
    db.bonus_hunts.insert_one(hunt_dict)
    return hunt

@api_router.put("/hunts/{hunt_id}")
def update_hunt(hunt_id: str, hunt_update: Dict[str, Any], request: Request):
    """Update bonus hunt (admin only)"""
    require_admin(request)
    
    result = db.bonus_hunts.update_one(
        {"hunt_id": hunt_id},
        {"$set": hunt_update}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Hunt not found")
    
    return {"message": "Hunt updated successfully"}

@api_router.delete("/hunts/{hunt_id}")
def delete_hunt(hunt_id: str, request: Request):
    """Delete bonus hunt (admin only)"""
    require_admin(request)
    
    result = db.bonus_hunts.delete_one({"hunt_id": hunt_id})
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Hunt not found")
    
    return {"message": "Hunt deleted successfully"}

# ============= GUESSING =============

@api_router.get("/competitions")
def get_competitions():
    """Get all guessing competitions"""
    competitions = list(db.guessing_competitions.find({}, {"_id": 0}).sort("started_at", -1))
    return competitions

@api_router.get("/competitions/active")
def get_active_competition():
    """Get active guessing competition"""
    competition = db.guessing_competitions.find_one({"status": "active"}, {"_id": 0})
    return competition

class StartCompetitionRequest(BaseModel):
    hunt_id: str

@api_router.post("/competitions/start")
def start_competition(req: StartCompetitionRequest, request: Request):
    """Start a guessing competition (admin only)"""
    require_admin(request)
    
    hunt = db.bonus_hunts.find_one({"hunt_id": req.hunt_id})
    if not hunt:
        raise HTTPException(status_code=404, detail="Hunt not found")
    
    existing = db.guessing_competitions.find_one({"status": "active"})
    if existing:
        raise HTTPException(status_code=400, detail="There's already an active competition")
    
    competition = GuessingCompetition(hunt_id=req.hunt_id)
    comp_dict = competition.model_dump()
    comp_dict["started_at"] = comp_dict["started_at"].isoformat()
    
    db.guessing_competitions.insert_one(comp_dict)
    return competition

class EndCompetitionRequest(BaseModel):
    final_balance: float

@api_router.post("/competitions/{competition_id}/end")
def end_competition(competition_id: str, req: EndCompetitionRequest, request: Request):
    """End competition and calculate winner (admin only)"""
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
    
    db.guessing_competitions.update_one(
        {"competition_id": competition_id},
        {"$set": update_data}
    )
    
    return {"message": "Competition ended", "winner": winner, "final_balance": req.final_balance}

class SubmitGuessRequest(BaseModel):
    guess_amount: float

@api_router.post("/guesses")
def submit_guess(req: SubmitGuessRequest, request: Request):
    """Submit a guess (requires Discord login only)"""
    user = require_auth(request)
    
    competition = db.guessing_competitions.find_one({"status": "active"})
    if not competition:
        raise HTTPException(status_code=400, detail="No active competition")
    
    existing_guess = db.guesses.find_one({
        "hunt_id": competition["hunt_id"],
        "user_discord_id": user["discord_id"]
    })
    
    if existing_guess:
        raise HTTPException(status_code=400, detail="You've already submitted a guess for this competition")
    
    guess = Guess(
        hunt_id=competition["hunt_id"],
        user_discord_id=user["discord_id"],
        kick_username=user.get("discord_username", "Unknown"),
        guess_amount=req.guess_amount
    )
    
    guess_dict = guess.model_dump()
    guess_dict["timestamp"] = guess_dict["timestamp"].isoformat()
    guess_dict["discord_username"] = user.get("discord_username", "Unknown")
    
    db.guesses.insert_one(guess_dict)
    return guess

@api_router.get("/guesses/hunt/{hunt_id}")
def get_hunt_guesses(hunt_id: str):
    """Get all guesses for a hunt"""
    guesses = list(db.guesses.find({"hunt_id": hunt_id}, {"_id": 0}).sort("guess_amount", 1))
    return guesses

@api_router.get("/guesses/my")
def get_my_guesses(request: Request):
    """Get current user's guesses"""
    user = require_auth(request)
    guesses = list(db.guesses.find({"user_discord_id": user["discord_id"]}, {"_id": 0}).sort("timestamp", -1))
    return guesses

# ============= ADMIN =============

@api_router.get("/admin/users")
def search_users(q: str = "", request: Request = None):
    """Search users (admin only)"""
    require_admin(request)
    
    query = {}
    if q:
        query = {
            "$or": [
                {"discord_username": {"$regex": q, "$options": "i"}}
            ]
        }
    
    users = list(db.users.find(query, {"_id": 0}).limit(50))
    return users

@api_router.get("/admin/users/all")
def get_all_users(request: Request):
    """Get all users sorted by join date (admin only)"""
    require_admin(request)
    
    users = list(db.users.find({}, {"_id": 0}).sort("created_at", -1))
    return users

@api_router.get("/admin/stats")
def get_stats(request: Request):
    """Get platform statistics (admin only)"""
    require_admin(request)
    
    total_users = db.users.count_documents({})
    total_hunts = db.bonus_hunts.count_documents({})
    total_guesses = db.guesses.count_documents({})
    
    return {
        "total_users": total_users,
        "total_hunts": total_hunts,
        "total_guesses": total_guesses
    }

# ============= RACE CONTROL =============

@api_router.get("/admin/race")
def get_race_settings_endpoint(request: Request):
    """Get race settings (admin only)"""
    require_admin(request)
    return get_race_settings()

@api_router.put("/admin/race/status")
def update_race_status(request: Request, status: str):
    """Update race status (admin only)"""
    require_admin(request)
    
    if status not in ["running", "paused", "stopped"]:
        raise HTTPException(status_code=400, detail="Invalid status. Must be: running, paused, or stopped")
    
    db.race_settings.update_one(
        {"_id": "main"},
        {"$set": {"status": status}},
        upsert=True
    )
    return {"message": f"Race status updated to {status}"}

@api_router.post("/admin/race/block")
def block_user(request: Request, username: str):
    """Block a user from leaderboard (admin only)"""
    require_admin(request)
    
    db.race_settings.update_one(
        {"_id": "main"},
        {"$addToSet": {"blocked_users": username.lower()}},
        upsert=True
    )
    return {"message": f"User {username} blocked from leaderboard"}

@api_router.delete("/admin/race/block/{username}")
def unblock_user(username: str, request: Request):
    """Unblock a user from leaderboard (admin only)"""
    require_admin(request)
    
    db.race_settings.update_one(
        {"_id": "main"},
        {"$pull": {"blocked_users": username.lower()}}
    )
    return {"message": f"User {username} unblocked"}

@api_router.post("/admin/race/custom-user")
def add_custom_user(request: Request, username: str, wagered: float):
    """Add a custom user to leaderboard (admin only)"""
    require_admin(request)
    
    custom_user = {
        "id": str(uuid.uuid4()),
        "username": username,
        "wagered": wagered
    }
    
    db.race_settings.update_one(
        {"_id": "main"},
        {"$push": {"custom_users": custom_user}},
        upsert=True
    )
    return {"message": f"Custom user {username} added with C${wagered} wagered"}

@api_router.put("/admin/race/custom-user/{user_id}")
def update_custom_user(user_id: str, request: Request, wagered: float = None, username: str = None):
    """Update a custom user (admin only)"""
    require_admin(request)
    
    update_fields = {}
    if wagered is not None:
        update_fields["custom_users.$.wagered"] = wagered
    if username is not None:
        update_fields["custom_users.$.username"] = username
    
    if update_fields:
        db.race_settings.update_one(
            {"_id": "main", "custom_users.id": user_id},
            {"$set": update_fields}
        )
    return {"message": "Custom user updated"}

@api_router.delete("/admin/race/custom-user/{user_id}")
def delete_custom_user(user_id: str, request: Request):
    """Delete a custom user (admin only)"""
    require_admin(request)
    
    db.race_settings.update_one(
        {"_id": "main"},
        {"$pull": {"custom_users": {"id": user_id}}}
    )
    return {"message": "Custom user deleted"}

@api_router.post("/admin/race/override")
def set_wager_override(request: Request, username: str, wagered: float):
    """Override wager for a user (admin only)"""
    require_admin(request)
    
    db.race_settings.update_one(
        {"_id": "main"},
        {"$set": {f"wager_overrides.{username.lower()}": wagered}},
        upsert=True
    )
    return {"message": f"Wager override set for {username}: C${wagered}"}

@api_router.delete("/admin/race/override/{username}")
def remove_wager_override(username: str, request: Request):
    """Remove wager override for a user (admin only)"""
    require_admin(request)
    
    db.race_settings.update_one(
        {"_id": "main"},
        {"$unset": {f"wager_overrides.{username.lower()}": ""}}
    )
    return {"message": f"Wager override removed for {username}"}

# Include router
app.include_router(api_router)

@app.on_event("shutdown")
def shutdown_db_client():
    client.close()

# For local development only
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)