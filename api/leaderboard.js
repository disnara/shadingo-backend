export default async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const RAINBET_API_KEY = "o0mRfUFyUTpdp4KDEnn1BHNaGb9U30hY";
  const RAINBET_API_URL = "https://services.rainbet.com/v1/external/affiliates";
  const PRIZES = { 1: 125, 2: 55, 3: 35, 4: 20, 5: 15 };

  function maskUsername(username) {
    if (!username || username.length <= 3) return username;
    if (username.length <= 5) return username[0] + "*".repeat(username.length - 2) + username.slice(-1);
    return username.slice(0, 2) + "*".repeat(username.length - 3) + username.slice(-1);
  }

  function getBiweeklyPeriod() {
    const referenceDate = new Date('2025-01-01T00:00:00Z');
    const now = new Date();
    const daysSinceRef = Math.floor((now - referenceDate) / (1000 * 60 * 60 * 24));
    const periodNumber = Math.floor(daysSinceRef / 14);
    const periodStart = new Date(referenceDate.getTime() + periodNumber * 14 * 24 * 60 * 60 * 1000);
    const periodEnd = new Date(periodStart.getTime() + 13 * 24 * 60 * 60 * 1000);
    return { periodStart, periodEnd };
  }

  function getTimeRemaining(periodEnd) {
    const now = new Date();
    const endTime = new Date(periodEnd.getTime() + 24 * 60 * 60 * 1000);
    const remaining = endTime - now;

    if (remaining <= 0) {
      return { days: 0, hours: 0, minutes: 0, seconds: 0 };
    }

    const days = Math.floor(remaining / (1000 * 60 * 60 * 24));
    const hours = Math.floor((remaining % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    const minutes = Math.floor((remaining % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((remaining % (1000 * 60)) / 1000);

    return { days, hours, minutes, seconds };
  }

  function formatDate(date) {
    return date.toISOString().split('T')[0];
  }

  const { periodStart, periodEnd } = getBiweeklyPeriod();

  try {
    const url = `${RAINBET_API_URL}?start_at=${formatDate(periodStart)}&end_at=${formatDate(periodEnd)}&key=${RAINBET_API_KEY}`;
    
    const response = await fetch(url, {
      headers: { 'User-Agent': 'Mozilla/5.0' }
    });
    
    const data = await response.json();
    const apiPlayers = data.affiliates || [];

    const players = apiPlayers.slice(0, 10).map((player, idx) => ({
      rank: idx + 1,
      username: maskUsername(player.username || player.name || ''),
      wagered: parseFloat(player.wagered || player.wager || 0),
      prize: PRIZES[idx + 1] || null,
      avatar: `https://api.dicebear.com/7.x/avataaars/svg?seed=${player.username || player.name || ''}`
    }));

    return res.status(200).json({
      players,
      total_players: players.length,
      has_data: players.length > 0,
      period_start: formatDate(periodStart),
      period_end: formatDate(periodEnd),
      time_remaining: getTimeRemaining(periodEnd)
    });

  } catch (error) {
    return res.status(200).json({
      players: [],
      total_players: 0,
      has_data: false,
      period_start: formatDate(periodStart),
      period_end: formatDate(periodEnd),
      time_remaining: getTimeRemaining(periodEnd),
      error: error.message
    });
  }
}
