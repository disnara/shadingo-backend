from fastapi import FastAPI, APIRouter, HTTPException, Depends, Request, Response
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
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
import jwt
import httpx
import logging
import uvicorn

# Load environment variables
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Configuration
DISCORD_CLIENT_ID = os.environ['DISCORD_CLIENT_ID']
DISCORD_CLIENT_SECRET = os.environ['DISCORD_CLIENT_SECRET']
DISCORD_REDIRECT_URI = os.environ['DISCORD_REDIRECT_URI']
KICK_CLIENT_ID = os.environ.get('KICK_CLIENT_ID', '')
KICK_CLIENT_SECRET = os.environ.get('KICK_CLIENT_SECRET', '')
KICK_REDIRECT_URI = os.environ.get('KICK_REDIRECT_URI', '')
ADMIN_IDS = os.environ['ADMIN_DISCORD_IDS'].split(',')
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

async def get_current_user(request: Request) -> Optional[dict]:
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
    user = await db.users.find_one({"discord_id": payload["discord_id"]}, {"_id": 0})
    return user

async def require_auth(request: Request) -> dict:
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user

async def require_admin(request: Request) -> dict:
    user = await require_auth(request)
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
        logger.error(f"Leaderboard error: {str(e)}")
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
async def discord_login():
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
async def discord_callback(code: str, response: Response):
    """Handle Discord OAuth callback"""
    try:
        async with httpx.AsyncClient() as client:
            token_response = await client.post(
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
            
            user_response = await client.get(
                "https://discord.com/api/users/@me",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            discord_user = user_response.json()
            
            discord_id = discord_user["id"]
            username = discord_user["username"]
            discriminator = discord_user.get("discriminator", "0")
            avatar_hash = discord_user.get("avatar")
            avatar_url = f"https://cdn.discordapp.com/avatars/{discord_id}/{avatar_hash}.png" if avatar_hash else "https://cdn.discordapp.com/embed/avatars/0.png"
            
            existing_user = await db.users.find_one({"discord_id": discord_id}, {"_id": 0})
            
            if existing_user:
                user_data = existing_user
                await db.users.update_one(
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
                await db.users.insert_one(user_data)
            
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
async def get_me(request: Request):
    """Get current user info"""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user

@api_router.post("/auth/logout")
async def logout(response: Response):
    """Logout user"""
    response.delete_cookie("auth_token")
    return {"message": "Logged out successfully"}

# ============= KICK MANUAL =============

class KickUsernameRequest(BaseModel):
    kick_username: str

@api_router.post("/auth/kick/manual")
async def kick_manual(req: KickUsernameRequest, request: Request):
    """Manually set Kick username"""
    user = await require_auth(request)
    
    if not req.kick_username or len(req.kick_username) < 3:
        raise HTTPException(status_code=400, detail="Invalid Kick username")
    
    # Update user with Kick username
    await db.users.update_one(
        {"user_id": user["user_id"]},
        {"$set": {"kick_username": req.kick_username, "kick_verified": True}}
    )
    
    return {"message": "Kick username saved successfully"}

# ============= KICK OAUTH =============

@api_router.get("/auth/kick/login")
async def kick_login(request: Request, auth_token: str = None):
    """Redirect to Kick OAuth"""
    # For cross-domain: accept token from query param
    if auth_token:
        payload = verify_jwt_token(auth_token)
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = await db.users.find_one({"discord_id": payload["discord_id"]}, {"_id": 0})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
    else:
        user = await require_auth(request)
    
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
async def kick_callback(code: str = None, state: str = None, error: str = None):
    """Handle Kick OAuth callback"""
    frontend_url = os.environ.get('REACT_APP_BACKEND_URL', 'https://casino-login-2.preview.emergentagent.com').replace('/api', '')
    
    if error:
        logger.error(f"Kick OAuth error from provider: {error}")
        return RedirectResponse(url=f"{frontend_url}/account-settings?kick=error&reason={error}")
    
    if not code or not state:
        return RedirectResponse(url=f"{frontend_url}/account-settings?kick=error&reason=missing_code")
    
    try:
        user_id = state.split(':')[0]
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Exchange code for token
            token_response = await client.post(
                "https://kick.com/oauth2/token",
                data={
                    "client_id": KICK_CLIENT_ID,
                    "client_secret": KICK_CLIENT_SECRET,
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": KICK_REDIRECT_URI,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
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
            user_response = None
            kick_username = None
            
            # Try endpoint 1
            try:
                user_response = await client.get(
                    "https://kick.com/api/v2/user",
                    headers={"Authorization": f"Bearer {access_token}"}
                )
                if user_response.status_code == 200:
                    kick_user = user_response.json()
                    kick_username = kick_user.get("username") or kick_user.get("name") or kick_user.get("slug")
            except:
                pass
            
            # Try endpoint 2 if first failed
            if not kick_username:
                try:
                    user_response = await client.get(
                        "https://api.kick.com/public/v1/user",
                        headers={"Authorization": f"Bearer {access_token}"}
                    )
                    if user_response.status_code == 200:
                        kick_user = user_response.json()
                        kick_username = kick_user.get("username") or kick_user.get("name") or kick_user.get("slug")
                except:
                    pass
            
            if not kick_username:
                raise HTTPException(status_code=400, detail="Could not fetch Kick username")
            
            await db.users.update_one(
                {"user_id": user_id},
                {"$set": {"kick_username": kick_username, "kick_verified": True}}
            )
            
            return RedirectResponse(url=f"{frontend_url}/account-settings?kick=success")
            
    except Exception as e:
        logger.error(f"Kick OAuth error: {str(e)}")
        return RedirectResponse(url=f"{frontend_url}/account-settings?kick=error&reason=server_error")

# ============= BONUS HUNTS =============

@api_router.get("/hunts")
async def get_hunts():
    """Get all bonus hunts"""
    hunts = await db.bonus_hunts.find({}, {"_id": 0}).sort("created_at", -1).to_list(100)
    return hunts

@api_router.get("/hunts/{hunt_id}")
async def get_hunt(hunt_id: str):
    """Get specific bonus hunt"""
    hunt = await db.bonus_hunts.find_one({"hunt_id": hunt_id}, {"_id": 0})
    if not hunt:
        raise HTTPException(status_code=404, detail="Hunt not found")
    return hunt

@api_router.post("/hunts")
async def create_hunt(hunt: BonusHunt, request: Request):
    """Create new bonus hunt (admin only)"""
    await require_admin(request)
    
    hunt_dict = hunt.model_dump()
    hunt_dict["created_at"] = hunt_dict["created_at"].isoformat()
    
    await db.bonus_hunts.insert_one(hunt_dict)
    return hunt

@api_router.put("/hunts/{hunt_id}")
async def update_hunt(hunt_id: str, hunt_update: Dict[str, Any], request: Request):
    """Update bonus hunt (admin only)"""
    await require_admin(request)
    
    result = await db.bonus_hunts.update_one(
        {"hunt_id": hunt_id},
        {"$set": hunt_update}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Hunt not found")
    
    return {"message": "Hunt updated successfully"}

@api_router.delete("/hunts/{hunt_id}")
async def delete_hunt(hunt_id: str, request: Request):
    """Delete bonus hunt (admin only)"""
    await require_admin(request)
    
    result = await db.bonus_hunts.delete_one({"hunt_id": hunt_id})
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Hunt not found")
    
    return {"message": "Hunt deleted successfully"}

# ============= GUESSING =============

@api_router.get("/competitions")
async def get_competitions():
    """Get all guessing competitions"""
    competitions = await db.guessing_competitions.find({}, {"_id": 0}).sort("started_at", -1).to_list(100)
    return competitions

@api_router.get("/competitions/active")
async def get_active_competition():
    """Get active guessing competition"""
    competition = await db.guessing_competitions.find_one({"status": "active"}, {"_id": 0})
    return competition

class StartCompetitionRequest(BaseModel):
    hunt_id: str

@api_router.post("/competitions/start")
async def start_competition(req: StartCompetitionRequest, request: Request):
    """Start a guessing competition (admin only)"""
    await require_admin(request)
    
    hunt = await db.bonus_hunts.find_one({"hunt_id": req.hunt_id})
    if not hunt:
        raise HTTPException(status_code=404, detail="Hunt not found")
    
    existing = await db.guessing_competitions.find_one({"status": "active"})
    if existing:
        raise HTTPException(status_code=400, detail="There's already an active competition")
    
    competition = GuessingCompetition(hunt_id=req.hunt_id)
    comp_dict = competition.model_dump()
    comp_dict["started_at"] = comp_dict["started_at"].isoformat()
    
    await db.guessing_competitions.insert_one(comp_dict)
    return competition

class EndCompetitionRequest(BaseModel):
    final_balance: float

@api_router.post("/competitions/{competition_id}/end")
async def end_competition(competition_id: str, req: EndCompetitionRequest, request: Request):
    """End competition and calculate winner (admin only)"""
    await require_admin(request)
    
    competition = await db.guessing_competitions.find_one({"competition_id": competition_id})
    if not competition:
        raise HTTPException(status_code=404, detail="Competition not found")
    
    if competition["status"] == "ended":
        raise HTTPException(status_code=400, detail="Competition already ended")
    
    hunt_id = competition["hunt_id"]
    guesses = await db.guesses.find({"hunt_id": hunt_id}, {"_id": 0}).to_list(1000)
    
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
    
    await db.guessing_competitions.update_one(
        {"competition_id": competition_id},
        {"$set": update_data}
    )
    
    return {"message": "Competition ended", "winner": winner, "final_balance": req.final_balance}

class SubmitGuessRequest(BaseModel):
    guess_amount: float

@api_router.post("/guesses")
async def submit_guess(req: SubmitGuessRequest, request: Request):
    """Submit a guess (requires Kick account)"""
    user = await require_auth(request)
    
    if not user.get("kick_verified"):
        raise HTTPException(status_code=400, detail="You must connect your Kick account to submit a guess")
    
    competition = await db.guessing_competitions.find_one({"status": "active"})
    if not competition:
        raise HTTPException(status_code=400, detail="No active competition")
    
    existing_guess = await db.guesses.find_one({
        "hunt_id": competition["hunt_id"],
        "user_discord_id": user["discord_id"]
    })
    
    if existing_guess:
        raise HTTPException(status_code=400, detail="You've already submitted a guess for this competition")
    
    guess = Guess(
        hunt_id=competition["hunt_id"],
        user_discord_id=user["discord_id"],
        kick_username=user["kick_username"],
        guess_amount=req.guess_amount
    )
    
    guess_dict = guess.model_dump()
    guess_dict["timestamp"] = guess_dict["timestamp"].isoformat()
    
    await db.guesses.insert_one(guess_dict)
    return guess

@api_router.get("/guesses/hunt/{hunt_id}")
async def get_hunt_guesses(hunt_id: str):
    """Get all guesses for a hunt"""
    guesses = await db.guesses.find({"hunt_id": hunt_id}, {"_id": 0}).sort("guess_amount", 1).to_list(1000)
    return guesses

@api_router.get("/guesses/my")
async def get_my_guesses(request: Request):
    """Get current user's guesses"""
    user = await require_auth(request)
    guesses = await db.guesses.find({"user_discord_id": user["discord_id"]}, {"_id": 0}).sort("timestamp", -1).to_list(100)
    return guesses

# ============= ADMIN =============

@api_router.get("/admin/users")
async def search_users(q: str = "", request: Request = None):
    """Search users (admin only)"""
    await require_admin(request)
    
    query = {}
    if q:
        query = {
            "$or": [
                {"discord_username": {"$regex": q, "$options": "i"}},
                {"kick_username": {"$regex": q, "$options": "i"}}
            ]
        }
    
    users = await db.users.find(query, {"_id": 0}).limit(50).to_list(50)
    return users

@api_router.get("/admin/stats")
async def get_stats(request: Request):
    """Get platform statistics (admin only)"""
    await require_admin(request)
    
    total_users = await db.users.count_documents({})
    verified_users = await db.users.count_documents({"kick_verified": True})
    total_hunts = await db.bonus_hunts.count_documents({})
    total_guesses = await db.guesses.count_documents({})
    
    return {
        "total_users": total_users,
        "verified_users": verified_users,
        "total_hunts": total_hunts,
        "total_guesses": total_guesses
    }

# Include router
app.include_router(api_router)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)