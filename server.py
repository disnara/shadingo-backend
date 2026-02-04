from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import json
import urllib.request
import urllib.parse
from datetime import datetime, timezone, timedelta
import uvicorn

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

RAINBET_API_KEY = "o0mRfUFyUTpdp4KDEnn1BHNaGb9U30hY"
RAINBET_API_URL = "https://services.rainbet.com/v1/external/affiliates"
PRIZES = {1: 125, 2: 55, 3: 35, 4: 20, 5: 15}

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
    return {"status": "ok", "message": "Shadingo Leaderboard API"}

@app.get("/api/leaderboard")
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

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
