const express = require("express");
const cookieParser = require("cookie-parser");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- Config ----------
const OWNER_PASSWORD = process.env.OWNER_PASSWORD || "changeme";
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || "";
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || "";
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || "";
const DISCORD_LOG_WEBHOOK_URL = process.env.DISCORD_LOG_WEBHOOK_URL || "";

const discordConfigured = !!(DISCORD_CLIENT_ID && DISCORD_CLIENT_SECRET && DISCORD_REDIRECT_URI);

const DATA_FILE = path.join(__dirname, "tournament-data.json");

app.set("trust proxy", 1);
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

// ---------- Sessions (cookie-based, in-memory) ----------
const sessions = new Map();
const SESSION_DURATION_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

app.use((req, res, next) => {
  let sid = req.cookies.sid;
  let session = sid && sessions.get(sid);

  if (!session) {
    sid = crypto.randomBytes(24).toString("hex");
    session = { discordUser: null, isOwner: false };
    sessions.set(sid, session);
    res.cookie("sid", sid, {
      httpOnly: true,
      sameSite: "lax",
      secure: true,
      maxAge: SESSION_DURATION_MS
    });
  }

  req.session = session;
  next();
});

function requireOwner(req, res, next) {
  if (!req.session.isOwner) {
    return res.status(403).json({ error: "Owner access required." });
  }
  next();
}

// ---------- Tournament state (persisted to disk) ----------
function defaultState() {
  return { players: [], bracketGenerated: false, rounds: [] };
}

function loadState() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, "utf-8"));
  } catch {
    return defaultState();
  }
}

function saveState() {
  fs.writeFileSync(DATA_FILE, JSON.stringify(state, null, 2));
}

let state = loadState();

// ---------- Discord OAuth2 ----------
app.get("/auth/discord", (req, res) => {
  if (!discordConfigured) {
    return res.status(500).send("Discord login is not configured on this server yet.");
  }
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: DISCORD_REDIRECT_URI,
    response_type: "code",
    scope: "identify"
  });
  res.redirect(`https://discord.com/api/oauth2/authorize?${params}`);
});

app.get("/auth/discord/callback", async (req, res) => {
  const { code } = req.query;
  if (!code || !discordConfigured) return res.redirect("/");

  try {
    const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: DISCORD_REDIRECT_URI
      })
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) throw new Error("No access token returned by Discord");

    const userRes = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const userData = await userRes.json();

    const avatarUrl = userData.avatar
      ? `https://cdn.discordapp.com/avatars/${userData.id}/${userData.avatar}.png?size=64`
      : `https://cdn.discordapp.com/embed/avatars/${Number(userData.discriminator || 0) % 5}.png`;

    req.session.discordUser = {
      id: userData.id,
      username: userData.global_name || userData.username,
      avatarUrl
    };

    notifyDiscordLogin(req.session.discordUser);

    res.redirect("/");
  } catch (err) {
    console.error("Discord OAuth error", err);
    res.redirect("/?discord_error=1");
  }
});

async function notifyDiscordLogin(user) {
  if (!DISCORD_LOG_WEBHOOK_URL) return;
  try {
    await fetch(DISCORD_LOG_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        content: `🔵 **${user.username}** just logged in on the tournament site.`
      })
    });
  } catch (err) {
    console.error("Webhook notify failed", err);
  }
}

// ---------- Session info ----------
app.get("/api/session", (req, res) => {
  res.json({
    discordUser: req.session.discordUser,
    isOwner: req.session.isOwner,
    discordConfigured
  });
});

// ---------- Tournament state ----------
app.get("/api/state", (req, res) => {
  res.json(state);
});

// ---------- Registration ----------
app.post("/api/register", (req, res) => {
  if (!req.session.discordUser) {
    return res.status(401).json({ error: "Log in with Discord first." });
  }
  if (state.bracketGenerated) {
    return res.status(400).json({ error: "Registrations are closed." });
  }
  if (state.players.some(p => p.discordId === req.session.discordUser.id)) {
    return res.status(400).json({ error: "You are already registered." });
  }

  const name = String(req.body?.name || "").trim().slice(0, 30) || req.session.discordUser.username;

  state.players.push({
    id: crypto.randomUUID(),
    discordId: req.session.discordUser.id,
    name,
    image: req.session.discordUser.avatarUrl
  });

  saveState();
  res.json({ ok: true });
});

// ---------- Owner login (requires an active Discord session first) ----------
app.post("/api/owner/login", (req, res) => {
  if (!req.session.discordUser) {
    return res.status(401).json({ error: "Log in with Discord first." });
  }
  const { password } = req.body || {};
  if (password !== OWNER_PASSWORD) {
    return res.status(401).json({ error: "Incorrect password." });
  }
  req.session.isOwner = true;
  res.json({ ok: true });
});

app.post("/api/owner/logout", (req, res) => {
  req.session.isOwner = false;
  res.json({ ok: true });
});

// ---------- Owner: manage players ----------
app.post("/api/owner/delete-player", requireOwner, (req, res) => {
  if (state.bracketGenerated) {
    return res.status(400).json({ error: "Reset the bracket before removing players." });
  }
  const { playerId } = req.body || {};
  state.players = state.players.filter(p => p.id !== playerId);
  saveState();
  res.json({ ok: true });
});

// ---------- Bracket helpers ----------
function shuffle(arr) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function roundName(roundIndex, totalRounds) {
  const fromEnd = totalRounds - roundIndex;
  if (fromEnd === 1) return "Final";
  if (fromEnd === 2) return "Semifinals";
  if (fromEnd === 3) return "Quarterfinals";
  return `Round ${roundIndex + 1}`;
}

function placeWinner(roundIndex, matchIndex, winner) {
  const nextRound = state.rounds[roundIndex + 1];
  if (!nextRound) return;
  const nextMatch = nextRound.matches[Math.floor(matchIndex / 2)];
  if (matchIndex % 2 === 0) nextMatch.player1 = winner;
  else nextMatch.player2 = winner;
}

function findMatch(matchId) {
  for (let r = 0; r < state.rounds.length; r++) {
    const idx = state.rounds[r].matches.findIndex(m => m.id === matchId);
    if (idx !== -1) return { roundIndex: r, matchIndex: idx, match: state.rounds[r].matches[idx] };
  }
  return null;
}

function confirmAndPropagate(found) {
  const { roundIndex, matchIndex, match } = found;
  match.status = "confirmed";
  match.winner = match.reportedWinner === match.player1.id ? match.player1 : match.player2;
  placeWinner(roundIndex, matchIndex, match.winner);
}

// ---------- Owner: generate / reset bracket ----------
app.post("/api/owner/generate-bracket", requireOwner, (req, res) => {
  if (state.players.length < 2) {
    return res.status(400).json({ error: "Need at least 2 players." });
  }
  if (state.bracketGenerated) {
    return res.status(400).json({ error: "Bracket already generated." });
  }

  const shuffled = shuffle(state.players);
  let bracketSize = 1;
  while (bracketSize < shuffled.length) bracketSize *= 2;
  const totalRounds = Math.log2(bracketSize);

  const rounds = [];

  const round1Matches = [];
  for (let i = 0; i < bracketSize / 2; i++) {
    const p1 = shuffled[i * 2] || null;
    const p2 = shuffled[i * 2 + 1] || null;
    const match = {
      id: crypto.randomUUID(),
      player1: p1, player2: p2,
      status: "pending", reportedWinner: null, confirmations: {}, winner: null
    };
    if (p1 && !p2) { match.winner = p1; match.status = "confirmed"; }
    else if (!p1 && p2) { match.winner = p2; match.status = "confirmed"; }
    round1Matches.push(match);
  }
  rounds.push({ name: roundName(0, totalRounds), matches: round1Matches });

  for (let r = 1; r < totalRounds; r++) {
    const count = bracketSize / Math.pow(2, r + 1);
    const matches = [];
    for (let i = 0; i < count; i++) {
      matches.push({
        id: crypto.randomUUID(),
        player1: null, player2: null,
        status: "pending", reportedWinner: null, confirmations: {}, winner: null
      });
    }
    rounds.push({ name: roundName(r, totalRounds), matches });
  }

  state.rounds = rounds;

  // Propagate round-1 byes into round 2 immediately
  state.rounds[0].matches.forEach((m, i) => {
    if (m.status === "confirmed") placeWinner(0, i, m.winner);
  });

  state.bracketGenerated = true;
  saveState();
  res.json({ ok: true });
});

app.post("/api/owner/reset-bracket", requireOwner, (req, res) => {
  state.rounds = [];
  state.bracketGenerated = false;
  saveState();
  res.json({ ok: true });
});

app.post("/api/owner/reset-all", requireOwner, (req, res) => {
  state = defaultState();
  saveState();
  res.json({ ok: true });
});

// ---------- Match results ----------
app.post("/api/report-result", (req, res) => {
  if (!req.session.discordUser) {
    return res.status(401).json({ error: "Log in with Discord first." });
  }
  const { matchId, winnerId } = req.body || {};
  const found = findMatch(matchId);
  if (!found) return res.status(404).json({ error: "Match not found." });

  const { match } = found;
  if (!match.player1 || !match.player2) {
    return res.status(400).json({ error: "This match is not ready yet." });
  }

  const myId = req.session.discordUser.id;
  const isParticipant = match.player1.discordId === myId || match.player2.discordId === myId;
  if (!isParticipant) {
    return res.status(403).json({ error: "Only the two players in this match can report a result." });
  }
  if (match.status === "confirmed") {
    return res.status(400).json({ error: "This match is already confirmed." });
  }
  if (winnerId !== match.player1.id && winnerId !== match.player2.id) {
    return res.status(400).json({ error: "Invalid winner." });
  }

  match.reportedWinner = winnerId;
  match.status = "awaiting-confirmation";
  match.confirmations = { [myId]: true };
  saveState();
  res.json({ ok: true });
});

app.post("/api/confirm-result", (req, res) => {
  if (!req.session.discordUser) {
    return res.status(401).json({ error: "Log in with Discord first." });
  }
  const { matchId } = req.body || {};
  const found = findMatch(matchId);
  if (!found) return res.status(404).json({ error: "Match not found." });

  const { match } = found;
  const myId = req.session.discordUser.id;
  const isParticipant = match.player1?.discordId === myId || match.player2?.discordId === myId;
  if (!isParticipant) {
    return res.status(403).json({ error: "Only the two players in this match can confirm." });
  }
  if (match.status !== "awaiting-confirmation") {
    return res.status(400).json({ error: "Nothing to confirm yet." });
  }

  match.confirmations[myId] = true;
  const bothConfirmed =
    !!match.confirmations[match.player1.discordId] &&
    !!match.confirmations[match.player2.discordId];

  if (bothConfirmed) confirmAndPropagate(found);

  saveState();
  res.json({ ok: true });
});

app.post("/api/owner/set-result", requireOwner, (req, res) => {
  const { matchId, winnerId } = req.body || {};
  const found = findMatch(matchId);
  if (!found) return res.status(404).json({ error: "Match not found." });

  const { match } = found;
  if (!match.player1 || !match.player2) {
    return res.status(400).json({ error: "This match is not ready yet." });
  }
  if (winnerId !== match.player1.id && winnerId !== match.player2.id) {
    return res.status(400).json({ error: "Invalid winner." });
  }

  match.reportedWinner = winnerId;
  confirmAndPropagate(found);
  saveState();
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`Tournament server running on port ${PORT}`);
  if (!discordConfigured) {
    console.warn("⚠️  Discord OAuth is not configured (missing env vars).");
  }
  if (OWNER_PASSWORD === "changeme") {
    console.warn("⚠️  OWNER_PASSWORD is not set — using the insecure default!");
  }
});
