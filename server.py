from fastapi import FastAPI, APIRouter, HTTPException
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import httpx


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Rainbet API Configuration
RAINBET_API_KEY = os.environ.get('RAINBET_API_KEY', 'o0mRfUFyUTpdp4KDEnn1BHNaGb9U30hY')
RAINBET_API_URL = "https://services.rainbet.com/v1/external/affiliates"

# Create the main app without a prefix
app = FastAPI()

# CORS Middleware - MUST be added before routes
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")


# Define Models
class StatusCheck(BaseModel):
    model_config = ConfigDict(extra="ignore")  # Ignore MongoDB's _id field
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    client_name: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class StatusCheckCreate(BaseModel):
    client_name: str

class LeaderboardPlayer(BaseModel):
    rank: int
    username: str  # This will be masked
    wagered: float
    prize: Optional[float] = None
    avatar: str

class LeaderboardResponse(BaseModel):
    players: List[LeaderboardPlayer]
    total_players: int
    has_data: bool
    period_start: str
    period_end: str
    time_remaining: dict


def mask_username(username: str) -> str:
    """Mask username for privacy - show first 2 and last 1 character"""
    if not username or len(username) <= 3:
        return username
    if len(username) <= 5:
        return username[0] + "*" * (len(username) - 2) + username[-1]
    # Show first 2 chars, mask middle, show last char
    return username[:2] + "*" * (len(username) - 3) + username[-1]


def get_biweekly_period():
    """Calculate the current bi-weekly period"""
    # Start from a reference date (e.g., Jan 1, 2025)
    reference_date = datetime(2025, 1, 1, tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    
    # Calculate days since reference
    days_since_ref = (now - reference_date).days
    
    # Calculate which bi-weekly period we're in (14-day periods)
    period_number = days_since_ref // 14
    
    # Calculate start and end of current period
    period_start = reference_date + timedelta(days=period_number * 14)
    period_end = period_start + timedelta(days=13)  # 14 days total (0-13)
    
    return period_start, period_end


def get_time_remaining(period_end: datetime) -> dict:
    """Calculate time remaining until period end"""
    now = datetime.now(timezone.utc)
    # Add 1 day because period_end is the last day (ends at 23:59:59)
    end_time = period_end + timedelta(days=1)
    remaining = end_time - now
    
    if remaining.total_seconds() <= 0:
        return {"days": 0, "hours": 0, "minutes": 0, "seconds": 0}
    
    days = remaining.days
    hours, remainder = divmod(remaining.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    return {"days": days, "hours": hours, "minutes": minutes, "seconds": seconds}


# Prize breakdown
PRIZES = {
    1: 125,
    2: 55,
    3: 35,
    4: 20,
    5: 15
}


@api_router.get("/leaderboard", response_model=LeaderboardResponse)
async def get_leaderboard():
    """Fetch leaderboard data from Rainbet API"""
    try:
        period_start, period_end = get_biweekly_period()
        
        params = {
            "start_at": period_start.strftime("%Y-%m-%d"),
            "end_at": period_end.strftime("%Y-%m-%d"),
            "key": RAINBET_API_KEY
        }
        
        async with httpx.AsyncClient(timeout=30.0) as http_client:
            response = await http_client.get(RAINBET_API_URL, params=params)
            
            if response.status_code != 200:
                logger.error(f"Rainbet API error: {response.status_code} - {response.text}")
                # Return empty data structure
                return LeaderboardResponse(
                    players=[],
                    total_players=0,
                    has_data=False,
                    period_start=period_start.strftime("%Y-%m-%d"),
                    period_end=period_end.strftime("%Y-%m-%d"),
                    time_remaining=get_time_remaining(period_end)
                )
            
            data = response.json()
            
            # Check if data is empty or invalid
            if not data:
                return LeaderboardResponse(
                    players=[],
                    total_players=0,
                    has_data=False,
                    period_start=period_start.strftime("%Y-%m-%d"),
                    period_end=period_end.strftime("%Y-%m-%d"),
                    time_remaining=get_time_remaining(period_end)
                )
            
            # Process the API response - Rainbet returns { "affiliates": [...] }
            players = []
            api_players = data.get('affiliates', []) or data.get('data', []) or data.get('players', []) or []
            
            if isinstance(data, list):
                api_players = data
            
            # Check if affiliates list is empty
            if not api_players or len(api_players) == 0:
                return LeaderboardResponse(
                    players=[],
                    total_players=0,
                    has_data=False,
                    period_start=period_start.strftime("%Y-%m-%d"),
                    period_end=period_end.strftime("%Y-%m-%d"),
                    time_remaining=get_time_remaining(period_end)
                )
            
            for idx, player_data in enumerate(api_players[:10], start=1):  # Top 10
                # Adjust field names based on actual API response
                username = player_data.get('username') or player_data.get('name') or player_data.get('user', '') or ''
                wagered = float(player_data.get('wagered') or player_data.get('wager') or player_data.get('total_wagered') or 0)
                
                players.append(LeaderboardPlayer(
                    rank=idx,
                    username=mask_username(username),
                    wagered=wagered,
                    prize=PRIZES.get(idx),
                    avatar=f"https://api.dicebear.com/7.x/avataaars/svg?seed={username}"
                ))
            
            return LeaderboardResponse(
                players=players,
                total_players=len(players),
                has_data=len(players) > 0,
                period_start=period_start.strftime("%Y-%m-%d"),
                period_end=period_end.strftime("%Y-%m-%d"),
                time_remaining=get_time_remaining(period_end)
            )
            
    except httpx.RequestError as e:
        logger.error(f"Request error fetching leaderboard: {e}")
        period_start, period_end = get_biweekly_period()
        return LeaderboardResponse(
            players=[],
            total_players=0,
            has_data=False,
            period_start=period_start.strftime("%Y-%m-%d"),
            period_end=period_end.strftime("%Y-%m-%d"),
            time_remaining=get_time_remaining(period_end)
        )
    except Exception as e:
        logger.error(f"Error fetching leaderboard: {e}")
        period_start, period_end = get_biweekly_period()
        return LeaderboardResponse(
            players=[],
            total_players=0,
            has_data=False,
            period_start=period_start.strftime("%Y-%m-%d"),
            period_end=period_end.strftime("%Y-%m-%d"),
            time_remaining=get_time_remaining(period_end)
        )

# Add your routes to the router instead of directly to app
@api_router.get("/")
async def root():
    return {"message": "Hello World"}

@api_router.post("/status", response_model=StatusCheck)
async def create_status_check(input: StatusCheckCreate):
    status_dict = input.model_dump()
    status_obj = StatusCheck(**status_dict)
    
    # Convert to dict and serialize datetime to ISO string for MongoDB
    doc = status_obj.model_dump()
    doc['timestamp'] = doc['timestamp'].isoformat()
    
    _ = await db.status_checks.insert_one(doc)
    return status_obj

@api_router.get("/status", response_model=List[StatusCheck])
async def get_status_checks():
    # Exclude MongoDB's _id field from the query results
    status_checks = await db.status_checks.find({}, {"_id": 0}).to_list(1000)
    
    # Convert ISO string timestamps back to datetime objects
    for check in status_checks:
        if isinstance(check['timestamp'], str):
            check['timestamp'] = datetime.fromisoformat(check['timestamp'])
    
    return status_checks

# Include the router in the main app
app.include_router(api_router)

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
