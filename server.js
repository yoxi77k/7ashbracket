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

// --- Bot config for auto-created 1v1 ticket channels ---
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN || "";
const DISCORD_GUILD_ID = process.env.DISCORD_GUILD_ID || "";
const DISCORD_TICKET_CATEGORY_ID = process.env.DISCORD_TICKET_CATEGORY_ID || ""; // optional
const DISCORD_MODERATOR_ROLE_ID = process.env.DISCORD_MODERATOR_ROLE_ID || ""; // optional but recommended
const DISCORD_RESULTS_CHANNEL_ID = process.env.DISCORD_RESULTS_CHANNEL_ID || ""; // optional: shared "results" log channel

const discordConfigured = !!(DISCORD_CLIENT_ID && DISCORD_CLIENT_SECRET && DISCORD_REDIRECT_URI);
const ticketsConfigured = !!(DISCORD_BOT_TOKEN && DISCORD_GUILD_ID);

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
// NOTE: state is saved to DATA_FILE on every mutation (saveState()) and
// reloaded from disk at server startup (loadState()). This means the
// player list and bracket already survive a page refresh (and a server
// restart) — the client just re-fetches /api/state, which reflects
// whatever is currently on disk. No change needed for that part.
function defaultState() {
  return {
    players: [],
    teams: [],
    bracketGenerated: false,
    rounds: [],
    maxPlayers: null,
    matchFormat: 1,
    registrationOpen: false // registrations stay closed until the owner explicitly starts them
  };
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

// ---------- Team join codes ----------
// Each team gets a short private code (shown only to its own members, and
// to the owner) that other players type in to join instead of a public
// "Join" button. Ambiguous characters (0/O, 1/I) are excluded.
function generateTeamCode() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let code;
  do {
    code = Array.from({ length: 6 }, () => chars[crypto.randomInt(chars.length)]).join("");
  } while (state.teams.some(t => t.code === code));
  return code;
}

let state = loadState();
if (state.maxPlayers === undefined) state.maxPlayers = null; // backward-compat with older save files
if (!state.matchFormat) state.matchFormat = 1; // backward-compat: default to solo 1v1
if (!Array.isArray(state.teams)) state.teams = []; // backward-compat with older save files
if (state.registrationOpen === undefined) state.registrationOpen = false; // backward-compat: must be explicitly started
state.teams.forEach(t => { if (!t.code) t.code = generateTeamCode(); }); // backward-compat: teams from before the code system

function totalRegisteredCount() {
  const format = state.matchFormat || 1;
  return format === 1 ? state.players.length : state.teams.reduce((sum, t) => sum + t.members.length, 0);
}

// Returns a copy of state safe to send to a given request: team join codes
// are stripped out for everyone except the team's own members and the owner.
function publicStateFor(req) {
  const cloned = JSON.parse(JSON.stringify(state));
  const myId = req.session.discordUser ? req.session.discordUser.id : null;
  const isOwner = !!req.session.isOwner;
  if (Array.isArray(cloned.teams)) {
    cloned.teams.forEach(t => {
      const isMine = myId && t.members.some(m => m.discordId === myId);
      if (!isMine && !isOwner) delete t.code;
    });
  }
  return cloned;
}

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

// Disconnects the current Discord session (and owner mode, since owner
// access requires being logged in with Discord). Existing registrations
// tied to this Discord id are untouched — logging back in with the same
// account will still show as registered.
app.post("/api/auth/logout", (req, res) => {
  req.session.discordUser = null;
  req.session.isOwner = false;
  res.json({ ok: true });
});

// ---------- Tournament state ----------
app.get("/api/state", (req, res) => {
  res.json(publicStateFor(req));
});

// ---------- Registration (solo, 1v1 mode only) ----------
app.post("/api/register", (req, res) => {
  if (!req.session.discordUser) {
    return res.status(401).json({ error: "Log in with Discord first." });
  }
  if (!state.registrationOpen) {
    return res.status(400).json({ error: "Registrations haven't started yet." });
  }
  if ((state.matchFormat || 1) !== 1) {
    return res.status(400).json({ error: "Team mode is active — create or join a team instead." });
  }
  if (state.bracketGenerated) {
    return res.status(400).json({ error: "Registrations are closed." });
  }
  if (state.maxPlayers && totalRegisteredCount() >= state.maxPlayers) {
    return res.status(400).json({ error: `Registrations are full (${state.maxPlayers} max).` });
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

// ---------- Remove a player: the player themselves, or the owner (solo mode) ----------
app.post("/api/remove-player", (req, res) => {
  if ((state.matchFormat || 1) !== 1) {
    return res.status(400).json({ error: "Team mode is active — use the team endpoints instead." });
  }
  if (state.bracketGenerated) {
    return res.status(400).json({ error: "Reset the bracket before removing players." });
  }

  const { playerId } = req.body || {};
  const player = state.players.find(p => p.id === playerId);
  if (!player) {
    return res.status(404).json({ error: "Player not found." });
  }

  const isSelf = req.session.discordUser && player.discordId === req.session.discordUser.id;
  const isOwner = !!req.session.isOwner;

  if (!isSelf && !isOwner) {
    return res.status(403).json({ error: "You can only remove yourself." });
  }

  state.players = state.players.filter(p => p.id !== playerId);
  saveState();
  res.json({ ok: true });
});

// ---------- Team registration (2v2 / 3v3 / 4v4) ----------
// A player creates a team and receives a private join code. They share
// that code with teammates, who use it (not a public list) to join.
app.post("/api/teams/create", (req, res) => {
  if (!req.session.discordUser) {
    return res.status(401).json({ error: "Log in with Discord first." });
  }
  if (!state.registrationOpen) {
    return res.status(400).json({ error: "Registrations haven't started yet." });
  }
  const format = state.matchFormat || 1;
  if (format === 1) {
    return res.status(400).json({ error: "Solo mode is active — register directly instead." });
  }
  if (state.bracketGenerated) {
    return res.status(400).json({ error: "Registrations are closed." });
  }
  if (state.maxPlayers && totalRegisteredCount() >= state.maxPlayers) {
    return res.status(400).json({ error: `Registrations are full (${state.maxPlayers} max).` });
  }

  const myId = req.session.discordUser.id;
  if (state.teams.some(t => t.members.some(m => m.discordId === myId))) {
    return res.status(400).json({ error: "You're already in a team." });
  }

  const name = String(req.body?.name || "").trim().slice(0, 30);
  if (!name) {
    return res.status(400).json({ error: "Enter a team name." });
  }

  const code = generateTeamCode();

  state.teams.push({
    id: crypto.randomUUID(),
    name,
    code,
    members: [{
      id: crypto.randomUUID(),
      discordId: myId,
      name: req.session.discordUser.username,
      image: req.session.discordUser.avatarUrl
    }]
  });

  saveState();
  res.json({ ok: true, code });
});

app.post("/api/teams/join", (req, res) => {
  if (!req.session.discordUser) {
    return res.status(401).json({ error: "Log in with Discord first." });
  }
  if (!state.registrationOpen) {
    return res.status(400).json({ error: "Registrations haven't started yet." });
  }
  const format = state.matchFormat || 1;
  if (format === 1) {
    return res.status(400).json({ error: "Solo mode is active — register directly instead." });
  }
  if (state.bracketGenerated) {
    return res.status(400).json({ error: "Registrations are closed." });
  }
  if (state.maxPlayers && totalRegisteredCount() >= state.maxPlayers) {
    return res.status(400).json({ error: `Registrations are full (${state.maxPlayers} max).` });
  }

  const myId = req.session.discordUser.id;
  if (state.teams.some(t => t.members.some(m => m.discordId === myId))) {
    return res.status(400).json({ error: "You're already in a team." });
  }

  const code = String((req.body || {}).code || "").trim().toUpperCase();
  if (!code) {
    return res.status(400).json({ error: "Enter a team code." });
  }

  const team = state.teams.find(t => t.code === code);
  if (!team) {
    return res.status(404).json({ error: "No team found with that code." });
  }
  if (team.members.length >= format) {
    return res.status(400).json({ error: "This team is already full." });
  }

  team.members.push({
    id: crypto.randomUUID(),
    discordId: myId,
    name: req.session.discordUser.username,
    image: req.session.discordUser.avatarUrl
  });

  saveState();
  res.json({ ok: true, teamName: team.name });
});

// Remove a team member: the member themselves (leave), or the owner.
// If the team ends up empty, it's deleted.
app.post("/api/remove-team-member", (req, res) => {
  if (state.bracketGenerated) {
    return res.status(400).json({ error: "Reset the bracket before changing teams." });
  }

  const { teamId, discordId } = req.body || {};
  const team = state.teams.find(t => t.id === teamId);
  if (!team) {
    return res.status(404).json({ error: "Team not found." });
  }

  const isSelf = req.session.discordUser && req.session.discordUser.id === discordId;
  const isOwner = !!req.session.isOwner;
  if (!isSelf && !isOwner) {
    return res.status(403).json({ error: "You can only remove yourself." });
  }

  team.members = team.members.filter(m => m.discordId !== discordId);
  if (team.members.length === 0) {
    state.teams = state.teams.filter(t => t.id !== teamId);
  }

  saveState();
  res.json({ ok: true });
});

// ---------- Owner: set a registration cap (8/16/32/64/128/custom, or none) ----------
// Locked once registrations have started — reset everything to change it.
app.post("/api/owner/set-max-players", requireOwner, (req, res) => {
  if (state.registrationOpen) {
    return res.status(400).json({ error: "Registrations already started — reset everything to change the limit." });
  }

  let { maxPlayers } = req.body || {};

  if (maxPlayers === null || maxPlayers === undefined || maxPlayers === 0 || maxPlayers === "") {
    state.maxPlayers = null;
    saveState();
    return res.json({ ok: true, maxPlayers: null });
  }

  const n = Number(maxPlayers);
  if (!Number.isInteger(n) || n < 2) {
    return res.status(400).json({ error: "The limit must be a whole number of at least 2 (or empty for no limit)." });
  }
  const registered = totalRegisteredCount();
  if (n < registered) {
    return res.status(400).json({ error: `${registered} players are already registered, the limit can't be lower than that.` });
  }

  state.maxPlayers = n;
  saveState();
  res.json({ ok: true, maxPlayers: n });
});

// ---------- Owner: set the match format (1v1 / 2v2 / 3v3 / 4v4) ----------
// Switching format changes what "registered" means (solo players vs teams),
// so any existing registrations are cleared to avoid a mixed, invalid state.
// Locked once registrations have started — reset everything to change it.
app.post("/api/owner/set-match-format", requireOwner, (req, res) => {
  if (state.bracketGenerated) {
    return res.status(400).json({ error: "Reset the bracket before changing the match format." });
  }
  if (state.registrationOpen) {
    return res.status(400).json({ error: "Registrations already started — reset everything to change the format." });
  }
  const format = Number((req.body || {}).format);
  if (![1, 2, 3, 4].includes(format)) {
    return res.status(400).json({ error: "Format must be 1, 2, 3, or 4 (players per team)." });
  }

  let reset = false;
  if (format !== state.matchFormat) {
    if (state.players.length > 0 || state.teams.length > 0) reset = true;
    state.players = [];
    state.teams = [];
  }

  state.matchFormat = format;
  saveState();
  res.json({ ok: true, matchFormat: format, reset });
});

// ---------- Owner: start registrations ----------
// Requires the format (always set, defaults to 1v1) and a numeric player
// limit to be chosen first. Once started, format/limit are locked until
// "Reset everything" is used.
app.post("/api/owner/start-registration", requireOwner, (req, res) => {
  if (state.bracketGenerated) {
    return res.status(400).json({ error: "The bracket has already been generated." });
  }
  if (state.registrationOpen) {
    return res.status(400).json({ error: "Registrations are already open." });
  }
  if (!state.maxPlayers) {
    return res.status(400).json({ error: "Set a player limit before starting registrations." });
  }

  state.registrationOpen = true;
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

// An "entry" in a match is either a solo player ({ id, discordId, name, image })
// or a team ({ id, name, members: [player, player, ...] }) when matchFormat > 1.
// These helpers let the rest of the code (participant checks, confirmations,
// Discord permissions) treat both shapes the same way.
function entryDiscordIds(entry) {
  if (!entry) return [];
  return entry.members ? entry.members.map(m => m.discordId) : [entry.discordId];
}

function entryHasDiscordId(entry, discordId) {
  return !!discordId && entryDiscordIds(entry).includes(discordId);
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

async function confirmAndPropagate(found) {
  const { roundIndex, matchIndex, match } = found;
  match.status = "confirmed";
  match.winner = match.reportedWinner === match.player1.id ? match.player1 : match.player2;
  placeWinner(roundIndex, matchIndex, match.winner);

  // Best-effort Discord side-effects: announce the result in the match's
  // ticket channel, rename it, and open a new ticket for the next round
  // once both of its players are known. Never blocks the API response.
  try {
    await announceMatchResult(match);

    const nextRound = state.rounds[roundIndex + 1];
    if (nextRound) {
      const nextMatch = nextRound.matches[Math.floor(matchIndex / 2)];
      if (nextMatch.player1 && nextMatch.player2 && !nextMatch.channelId) {
        await createMatchTicket(nextMatch);
      }
    }
  } catch (err) {
    console.error("Discord post-match step failed:", err.message);
  }
}

// ---------- Discord ticket channels (one per round-1 1v1 match) ----------
const DISCORD_API = "https://discord.com/api/v10";
const PERM_VIEW_CHANNEL = 1024n;
const PERM_SEND_MESSAGES = 2048n;
const PERM_READ_HISTORY = 65536n;
const PERM_ALLOW_ALL = (PERM_VIEW_CHANNEL | PERM_SEND_MESSAGES | PERM_READ_HISTORY).toString();
const PERM_VIEW_ONLY = (PERM_VIEW_CHANNEL | PERM_READ_HISTORY).toString(); // can see history, can't post — used to "close" a finished ticket
const PERM_DENY_VIEW = PERM_VIEW_CHANNEL.toString();

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function sanitizeChannelName(name) {
  return String(name)
    .toLowerCase()
    .normalize("NFD").replace(/[\u0300-\u036f]/g, "") // strip accents
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 45) || "player";
}

async function discordApi(endpoint, options = {}) {
  const res = await fetch(`${DISCORD_API}${endpoint}`, {
    ...options,
    headers: {
      Authorization: `Bot ${DISCORD_BOT_TOKEN}`,
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(body.message || `Discord API error (${res.status})`);
  }
  return body;
}

async function createTicketForMatch(entry1, entry2) {
  const channelName = `${sanitizeChannelName(entry1.name)}-vs-${sanitizeChannelName(entry2.name)}`;
  const allDiscordIds = [...entryDiscordIds(entry1), ...entryDiscordIds(entry2)];

  const permission_overwrites = [
    { id: DISCORD_GUILD_ID, type: 0, deny: PERM_DENY_VIEW }, // @everyone (role id == guild id)
    ...allDiscordIds.map(discordId => ({ id: discordId, type: 1, allow: PERM_ALLOW_ALL }))
  ];
  if (DISCORD_MODERATOR_ROLE_ID) {
    permission_overwrites.push({ id: DISCORD_MODERATOR_ROLE_ID, type: 0, allow: PERM_ALLOW_ALL });
  }

  const channel = await discordApi(`/guilds/${DISCORD_GUILD_ID}/channels`, {
    method: "POST",
    body: JSON.stringify({
      name: channelName,
      type: 0, // text channel
      parent_id: DISCORD_TICKET_CATEGORY_ID || undefined,
      permission_overwrites
    })
  });

  const mentions = allDiscordIds.map(id => `<@${id}>`).join(" ");
  const modPing = DISCORD_MODERATOR_ROLE_ID ? ` <@&${DISCORD_MODERATOR_ROLE_ID}>` : "";
  await discordApi(`/channels/${channel.id}/messages`, {
    method: "POST",
    body: JSON.stringify({
      content:
        `🥊 **${entry1.name}** vs **${entry2.name}**\n` +
        `${mentions}${modPing}\n` +
        `This channel is private for your match. A moderator will join to referee.`
    })
  });

  return channel;
}

// Creates (and stores) the channel id on a single match, if it doesn't have one yet.
async function createMatchTicket(match) {
  if (!ticketsConfigured) return;
  if (!match.player1 || !match.player2) return;
  if (match.channelId) return; // already has a ticket

  const channel = await createTicketForMatch(match.player1, match.player2);
  match.channelId = channel.id;
}

// Loops over a set of matches and creates a ticket for every one that's
// ready (both players known) and doesn't have a channel yet. Used right
// after generating the bracket (round 1, and round 2 if byes made it
// instantly ready).
async function createTicketsForReadyMatches(matches) {
  if (!ticketsConfigured) {
    console.warn("⚠️  DISCORD_BOT_TOKEN / DISCORD_GUILD_ID missing — skipping ticket channel creation.");
    return 0;
  }

  let created = 0;
  for (const match of matches) {
    if (!match.player1 || !match.player2 || match.channelId) continue;
    try {
      await createMatchTicket(match);
      created++;
    } catch (err) {
      console.error(`Failed to create ticket for match ${match.id}:`, err.message);
    }
    await sleep(400); // stay comfortably under Discord's rate limits
  }
  return created;
}

// Posts the result in the match's ticket channel, then "closes" that
// ticket: renames it to flag it as finished and strips the two players'
// permission down to view-only (they can still read the history, but
// can't post anymore). Moderators keep full access. Also logs the result
// to the shared results channel if one is configured. Best-effort —
// silently no-ops if there's no channel (e.g. Discord tickets aren't
// configured).
async function announceMatchResult(match) {
  if (!ticketsConfigured || !match.channelId) return;

  const loser = match.winner.id === match.player1.id ? match.player2 : match.player1;

  await discordApi(`/channels/${match.channelId}/messages`, {
    method: "POST",
    body: JSON.stringify({
      content: `🏆 **${match.winner.name}** won\n💀 **${loser.name}** lost`
    })
  });

  const base = `${sanitizeChannelName(match.player1.name)}-vs-${sanitizeChannelName(match.player2.name)}`;
  const allDiscordIds = [...entryDiscordIds(match.player1), ...entryDiscordIds(match.player2)];
  const permission_overwrites = [
    { id: DISCORD_GUILD_ID, type: 0, deny: PERM_DENY_VIEW }, // @everyone
    ...allDiscordIds.map(discordId => ({ id: discordId, type: 1, allow: PERM_VIEW_ONLY, deny: PERM_SEND_MESSAGES.toString() }))
  ];
  if (DISCORD_MODERATOR_ROLE_ID) {
    permission_overwrites.push({ id: DISCORD_MODERATOR_ROLE_ID, type: 0, allow: PERM_ALLOW_ALL });
  }

  await discordApi(`/channels/${match.channelId}`, {
    method: "PATCH",
    body: JSON.stringify({
      name: `${base}-finished`.slice(0, 95),
      permission_overwrites
    })
  });

  await postToResultsChannel(match.winner.name, loser.name);
}

// Logs "Winner won, Loser lost" to a single shared channel (set via
// DISCORD_RESULTS_CHANNEL_ID) so anyone can follow the tournament without
// needing access to the private per-match ticket channels. Optional and
// best-effort — no-ops if not configured.
async function postToResultsChannel(winnerName, loserName) {
  if (!ticketsConfigured || !DISCORD_RESULTS_CHANNEL_ID) return;
  try {
    await discordApi(`/channels/${DISCORD_RESULTS_CHANNEL_ID}/messages`, {
      method: "POST",
      body: JSON.stringify({
        content: `🏆 **${winnerName}** won, **${loserName}** lost`
      })
    });
  } catch (err) {
    console.error("Failed to post to results channel:", err.message);
  }
}

// ---------- Owner: generate / reset bracket ----------
app.post("/api/owner/generate-bracket", requireOwner, async (req, res) => {
  if (state.bracketGenerated) {
    return res.status(400).json({ error: "Bracket already generated." });
  }

  const format = state.matchFormat || 1;
  let shuffled;

  if (format === 1) {
    if (state.players.length < 2) {
      return res.status(400).json({ error: "Need at least 2 players." });
    }
    shuffled = shuffle(state.players);
  } else {
    if (state.teams.length < 2) {
      return res.status(400).json({ error: `Need at least 2 teams for a ${format}v${format} bracket.` });
    }
    const incomplete = state.teams.filter(t => t.members.length !== format);
    if (incomplete.length > 0) {
      return res.status(400).json({
        error: `These teams aren't full yet (need ${format} players each): ${incomplete.map(t => t.name).join(", ")}.`
      });
    }
    shuffled = shuffle(state.teams);
  }

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
      status: "pending", reportedWinner: null, confirmations: {}, winner: null, channelId: null
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
        status: "pending", reportedWinner: null, confirmations: {}, winner: null, channelId: null
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

  // Best-effort: create one private Discord channel per round-1 1v1 match.
  // If this fails or isn't configured, the bracket itself is still generated.
  let ticketsCreated = 0;
  try {
    ticketsCreated += await createTicketsForReadyMatches(round1Matches);
    if (state.rounds[1]) {
      ticketsCreated += await createTicketsForReadyMatches(state.rounds[1].matches);
    }
  } catch (err) {
    console.error("Ticket creation step failed:", err);
  }

  res.json({ ok: true, ticketsCreated });
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
  const isParticipant = entryHasDiscordId(match.player1, myId) || entryHasDiscordId(match.player2, myId);
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

app.post("/api/confirm-result", async (req, res) => {
  if (!req.session.discordUser) {
    return res.status(401).json({ error: "Log in with Discord first." });
  }
  const { matchId } = req.body || {};
  const found = findMatch(matchId);
  if (!found) return res.status(404).json({ error: "Match not found." });

  const { match } = found;
  const myId = req.session.discordUser.id;
  const isParticipant = entryHasDiscordId(match.player1, myId) || entryHasDiscordId(match.player2, myId);
  if (!isParticipant) {
    return res.status(403).json({ error: "Only the two players in this match can confirm." });
  }
  if (match.status !== "awaiting-confirmation") {
    return res.status(400).json({ error: "Nothing to confirm yet." });
  }

  match.confirmations[myId] = true;
  const p1Confirmed = entryDiscordIds(match.player1).some(id => match.confirmations[id]);
  const p2Confirmed = entryDiscordIds(match.player2).some(id => match.confirmations[id]);

  if (p1Confirmed && p2Confirmed) await confirmAndPropagate(found);

  saveState();
  res.json({ ok: true });
});

app.post("/api/owner/set-result", requireOwner, async (req, res) => {
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
  await confirmAndPropagate(found);
  saveState();
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`Tournament server running on port ${PORT}`);
  if (!discordConfigured) {
    console.warn("⚠️  Discord OAuth is not configured (missing env vars).");
  }
  if (!ticketsConfigured) {
    console.warn("⚠️  Discord ticket channels are not configured (missing DISCORD_BOT_TOKEN / DISCORD_GUILD_ID).");
  }
  if (OWNER_PASSWORD === "changeme") {
    console.warn("⚠️  OWNER_PASSWORD is not set — using the insecure default!");
  }
});
