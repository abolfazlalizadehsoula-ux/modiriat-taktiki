import 'express-async-errors';
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import crypto from 'node:crypto';

const { Pool } = pg;
const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');
if (!JWT_SECRET || JWT_SECRET.length < 32) throw new Error('JWT_SECRET must be at least 32 characters');
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false } });
app.use(helmet({ crossOriginResourcePolicy: false }));
const allowedOrigins = (process.env.CORS_ORIGIN || '*').split(',').map(x => x.trim()).filter(Boolean);
app.use(cors({ origin: allowedOrigins.includes('*') ? true : allowedOrigins, credentials: false }));
app.use(express.json({ limit: '2mb' }));

async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY, phone TEXT UNIQUE NOT NULL, username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS club_profiles (
      user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      club_name TEXT NOT NULL, manager_name TEXT NOT NULL DEFAULT '',
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE UNIQUE INDEX IF NOT EXISTS club_profiles_name_unique ON club_profiles (LOWER(club_name));
    CREATE TABLE IF NOT EXISTS game_saves (
      user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      game_state JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS leagues (
      id UUID PRIMARY KEY, tier INTEGER NOT NULL DEFAULT 1, season INTEGER NOT NULL DEFAULT 1,
      status TEXT NOT NULL DEFAULT 'active', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS league_members (
      league_id UUID NOT NULL REFERENCES leagues(id) ON DELETE CASCADE,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      club_name TEXT NOT NULL, manager_name TEXT NOT NULL DEFAULT '',
      played INTEGER NOT NULL DEFAULT 0, won INTEGER NOT NULL DEFAULT 0, drawn INTEGER NOT NULL DEFAULT 0,
      lost INTEGER NOT NULL DEFAULT 0, gf INTEGER NOT NULL DEFAULT 0, ga INTEGER NOT NULL DEFAULT 0,
      points INTEGER NOT NULL DEFAULT 0, joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (league_id, user_id), UNIQUE (league_id, club_name)
    );
    CREATE TABLE IF NOT EXISTS league_queue (
      user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      club_name TEXT NOT NULL, manager_name TEXT NOT NULL DEFAULT '', tier INTEGER NOT NULL DEFAULT 1,
      joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS fixtures (
      id UUID PRIMARY KEY, league_id UUID NOT NULL REFERENCES leagues(id) ON DELETE CASCADE,
      round_no INTEGER NOT NULL, home_user UUID NOT NULL REFERENCES users(id), away_user UUID NOT NULL REFERENCES users(id),
      home_goals INTEGER, away_goals INTEGER, played_at TIMESTAMPTZ,
      UNIQUE (league_id, round_no, home_user, away_user)
    );
    CREATE TABLE IF NOT EXISTS chat_messages (
      id BIGSERIAL PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      username TEXT NOT NULL, message TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS private_messages (
      id BIGSERIAL PRIMARY KEY, from_user UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      to_user UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE, message TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS fixtures_league_round_idx ON fixtures(league_id, round_no);
    CREATE INDEX IF NOT EXISTS chat_created_idx ON chat_messages(created_at DESC);
    CREATE INDEX IF NOT EXISTS private_messages_inbox_idx ON private_messages(to_user, created_at DESC);
  `);
}

function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ error: 'AUTH_REQUIRED' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'INVALID_TOKEN' }); }
}
const clean = (v, max = 40) => String(v ?? '').trim().slice(0, max);
const id = () => crypto.randomUUID();
const tokenFor = user => jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });

app.get('/health', async (_req, res) => {
  try { await pool.query('SELECT 1'); res.json({ status: 'ok', service: 'Modiriat Taktiki API', database: 'connected', version: 1 }); }
  catch (error) { console.error('Health check failed:', error.message); res.status(503).json({ status: 'error', database: 'unavailable' }); }
});
app.post('/auth/register', async (req, res) => {
  try {
    const phone = clean(req.body.phone, 24), username = clean(req.body.username, 24), password = String(req.body.password || '');
    if (phone.replace(/\D/g, '').length < 8) return res.status(400).json({ error: 'INVALID_PHONE' });
    if (!/^[a-zA-Z0-9_.-]{3,24}$/.test(username)) return res.status(400).json({ error: 'INVALID_USERNAME' });
    if (password.length < 8 || password.length > 100) return res.status(400).json({ error: 'INVALID_PASSWORD' });
    const passwordHash = await bcrypt.hash(password, 12), userId = id();
    const q = await pool.query('INSERT INTO users(id,phone,username,password_hash) VALUES($1,$2,$3,$4) RETURNING id,phone,username', [userId, phone, username, passwordHash]);
    const user = q.rows[0];
    res.status(201).json({ accessToken: tokenFor(user), user, gameState: null });
  } catch (e) { if (e.code === '23505') return res.status(409).json({ error: 'PHONE_OR_USERNAME_EXISTS' }); console.error(e); res.status(500).json({ error: 'SERVER_ERROR' }); }
});
app.post('/auth/login', async (req, res) => {
  try {
    const phone = clean(req.body.phone, 24), username = clean(req.body.username, 24), password = String(req.body.password || '');
    const q = await pool.query('SELECT id,phone,username,password_hash FROM users WHERE (phone=$1 OR username=$2) ORDER BY (phone=$1) DESC LIMIT 1', [phone || '__no_phone__', username || '__no_username__']);
    const user = q.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'BAD_CREDENTIALS' });
    const saved = await pool.query('SELECT game_state FROM game_saves WHERE user_id=$1', [user.id]);
    res.json({ accessToken: tokenFor(user), user: { id: user.id, phone: user.phone, username: user.username }, gameState: saved.rows[0]?.game_state || null });
  } catch (e) { console.error(e); res.status(500).json({ error: 'SERVER_ERROR' }); }
});
app.get('/me', auth, async (req, res) => {
  const q = await pool.query(`SELECT u.id,u.phone,u.username,u.created_at,c.club_name,c.manager_name
    FROM users u LEFT JOIN club_profiles c ON c.user_id=u.id WHERE u.id=$1`, [req.user.id]);
  res.json({ user: q.rows[0] || null });
});
app.post('/me/club', auth, async (req, res) => {
  const clubName = clean(req.body?.clubName, 36);
  const managerName = clean(req.body?.managerName || req.user.username, 36);
  if (clubName.length < 2) return res.status(400).json({ error: 'CLUB_NAME_REQUIRED' });
  try {
    const q = await pool.query(`INSERT INTO club_profiles(user_id,club_name,manager_name,updated_at)
      VALUES($1,$2,$3,NOW()) ON CONFLICT(user_id) DO UPDATE SET club_name=EXCLUDED.club_name,manager_name=EXCLUDED.manager_name,updated_at=NOW()
      RETURNING club_name,manager_name,updated_at`, [req.user.id,clubName,managerName]);
    res.json({ ok: true, profile: q.rows[0] });
  } catch (error) {
    if (error.code === '23505') return res.status(409).json({ error: 'CLUB_NAME_ALREADY_USED' });
    throw error;
  }
});
app.post('/me/save', auth, async (req, res) => {
  const gameState = req.body?.gameState;
  if (!gameState || typeof gameState !== 'object' || Array.isArray(gameState)) return res.status(400).json({ error: 'INVALID_GAME_STATE' });
  await pool.query(`INSERT INTO game_saves(user_id,game_state,updated_at) VALUES($1,$2,NOW())
    ON CONFLICT(user_id) DO UPDATE SET game_state=EXCLUDED.game_state,updated_at=NOW()`, [req.user.id, JSON.stringify(gameState)]);
  res.json({ ok: true, saved: true });
});
app.get('/me/save', auth, async (req, res) => {
  const q = await pool.query('SELECT game_state,updated_at FROM game_saves WHERE user_id=$1', [req.user.id]);
  res.json(q.rows[0] || { game_state: null });
});

function makeFixtures(leagueId, userIds) {
  const teams = [...userIds]; if (teams.length !== 10) throw new Error('LEAGUE_MUST_HAVE_10_TEAMS');
  const fixed = [...teams]; const rounds = [];
  for (let r = 0; r < 9; r++) {
    const games = [];
    for (let i = 0; i < 5; i++) {
      const a = fixed[i], b = fixed[9 - i];
      games.push({ home: r % 2 ? b : a, away: r % 2 ? a : b });
    }
    rounds.push(games);
    const last = fixed.pop(); fixed.splice(1, 0, last);
  }
  const all = [...rounds, ...rounds.map(g => g.map(x => ({ home: x.away, away: x.home })))];
  return all.flatMap((games, index) => games.map(g => ({ id: id(), league_id: leagueId, round_no: index + 1, home_user: g.home, away_user: g.away })));
}
async function createFullLeagues(client, tier) {
  while (true) {
    const q = await client.query('SELECT user_id,club_name,manager_name FROM league_queue WHERE tier=$1 ORDER BY joined_at LIMIT 10 FOR UPDATE SKIP LOCKED', [tier]);
    if (q.rows.length < 10) break;
    const leagueId = id();
    await client.query('INSERT INTO leagues(id,tier) VALUES($1,$2)', [leagueId, tier]);
    for (const m of q.rows) await client.query('INSERT INTO league_members(league_id,user_id,club_name,manager_name) VALUES($1,$2,$3,$4)', [leagueId,m.user_id,m.club_name,m.manager_name]);
    const fixtures = makeFixtures(leagueId, q.rows.map(x => x.user_id));
    for (const f of fixtures) await client.query('INSERT INTO fixtures(id,league_id,round_no,home_user,away_user) VALUES($1,$2,$3,$4,$5)', [f.id,f.league_id,f.round_no,f.home_user,f.away_user]);
    await client.query('DELETE FROM league_queue WHERE user_id=ANY($1::uuid[])', [q.rows.map(x => x.user_id)]);
  }
}

async function advanceFinishedLeague(client, leagueId) {
  const done = await client.query('SELECT COUNT(*)::int AS total, COUNT(played_at)::int AS completed FROM fixtures WHERE league_id=$1', [leagueId]);
  if (!done.rows[0] || done.rows[0].total !== 90 || done.rows[0].completed !== 90) return false;
  const league = await client.query('SELECT tier,season,status FROM leagues WHERE id=$1 FOR UPDATE', [leagueId]);
  if (!league.rowCount || league.rows[0].status !== 'active') return false;
  const rows = await client.query('SELECT user_id,club_name,manager_name FROM league_members WHERE league_id=$1 ORDER BY points DESC,(gf-ga) DESC,gf DESC,club_name ASC', [leagueId]);
  await client.query("UPDATE leagues SET status='completed' WHERE id=$1", [leagueId]);
  for (let i=0;i<rows.rows.length;i++) {
    const m=rows.rows[i];
    let nextTier=league.rows[0].tier;
    if (i<2 && nextTier>1) nextTier--;
    else if (i>=8) nextTier++;
    await client.query(`INSERT INTO league_queue(user_id,club_name,manager_name,tier) VALUES($1,$2,$3,$4)
      ON CONFLICT(user_id) DO UPDATE SET club_name=EXCLUDED.club_name,manager_name=EXCLUDED.manager_name,tier=EXCLUDED.tier,joined_at=NOW()`,
      [m.user_id,m.club_name,m.manager_name,nextTier]);
  }
  const tiers = [...new Set([Math.max(1,league.rows[0].tier-1),league.rows[0].tier,league.rows[0].tier+1])];
  for (const tier of tiers) await createFullLeagues(client,tier);
  return true;
}
app.post('/league/join', auth, async (req, res) => {
  const clubName = clean(req.body.clubName, 36), managerName = clean(req.body.managerName || req.user.username, 36);
  if (clubName.length < 2) return res.status(400).json({ error: 'CLUB_NAME_REQUIRED' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Serialize queue formation so simultaneous sign-ups cannot split one set of ten teams.
    await client.query('SELECT pg_advisory_xact_lock(4102026, 1)');
    const active = await client.query(`SELECT l.id,l.tier,l.season FROM leagues l JOIN league_members m ON m.league_id=l.id WHERE m.user_id=$1 AND l.status='active'`, [req.user.id]);
    if (active.rowCount) { await client.query('COMMIT'); return res.json({ status: 'joined', league: active.rows[0] }); }
    const profile = await client.query(`INSERT INTO club_profiles(user_id,club_name,manager_name,updated_at)
      VALUES($1,$2,$3,NOW()) ON CONFLICT(user_id) DO UPDATE SET club_name=EXCLUDED.club_name,manager_name=EXCLUDED.manager_name,updated_at=NOW()
      RETURNING club_name,manager_name`, [req.user.id,clubName,managerName]);
    const savedClub = profile.rows[0].club_name;
    const savedManager = profile.rows[0].manager_name;
    const queued = await client.query('SELECT user_id FROM league_queue WHERE user_id=$1', [req.user.id]);
    if (!queued.rowCount) await client.query('INSERT INTO league_queue(user_id,club_name,manager_name,tier) VALUES($1,$2,$3,1)', [req.user.id,savedClub,savedManager]);
    await createFullLeagues(client, 1);
    const joined = await client.query(`SELECT l.id,l.tier,l.season FROM leagues l JOIN league_members m ON m.league_id=l.id WHERE m.user_id=$1 AND l.status='active'`, [req.user.id]);
    if (joined.rowCount) { await client.query('COMMIT'); return res.json({ status: 'joined', league: joined.rows[0] }); }
    const count = await client.query('SELECT COUNT(*)::int AS count FROM league_queue WHERE tier=1');
    await client.query('COMMIT');
    res.json({ status: 'waiting', queueCount: count.rows[0].count, required: 10 });
  } catch (e) { await client.query('ROLLBACK'); if (e.code === '23505') return res.status(409).json({ error: 'CLUB_NAME_ALREADY_USED' }); console.error(e); res.status(500).json({ error: 'LEAGUE_ERROR' }); }
  finally { client.release(); }
});
app.get('/league/me', auth, async (req, res) => {
  const membership = await pool.query(`SELECT l.id,l.tier,l.season,l.status,m.club_name,m.manager_name,m.played,m.won,m.drawn,m.lost,m.gf,m.ga,m.points FROM leagues l JOIN league_members m ON m.league_id=l.id WHERE m.user_id=$1 AND l.status='active' ORDER BY l.created_at DESC LIMIT 1`, [req.user.id]);
  if (!membership.rowCount) {
    const q = await pool.query('SELECT COUNT(*)::int AS count FROM league_queue WHERE tier=1');
    const mine = await pool.query('SELECT 1 FROM league_queue WHERE user_id=$1', [req.user.id]);
    return res.json({ status: mine.rowCount ? 'waiting' : 'not_joined', queueCount: q.rows[0].count, required: 10 });
  }
  const league = membership.rows[0];
  const table = await pool.query('SELECT user_id,club_name,manager_name,played,won,drawn,lost,gf,ga,(gf-ga) AS gd,points FROM league_members WHERE league_id=$1 ORDER BY points DESC,(gf-ga) DESC,gf DESC,club_name ASC', [league.id]);
  const fixtures = await pool.query(`SELECT f.id,f.round_no,f.home_goals,f.away_goals,f.played_at,
    h.club_name AS home_name,a.club_name AS away_name,f.home_user,f.away_user
    FROM fixtures f JOIN league_members h ON h.league_id=f.league_id AND h.user_id=f.home_user
    JOIN league_members a ON a.league_id=f.league_id AND a.user_id=f.away_user
    WHERE f.league_id=$1 ORDER BY f.round_no,f.id`, [league.id]);
  res.json({ status: 'joined', league, table: table.rows, fixtures: fixtures.rows });
});
app.post('/league/result', auth, async (_req, res) => {
  // Never trust a score submitted by a player's browser. Results will be enabled
  // only after the authoritative server-side match simulator is integrated.
  res.status(501).json({ error: 'SERVER_MATCH_ENGINE_NOT_READY', message: 'نتیجه مسابقه تا اتصال موتور شبیه‌سازی سمت سرور ثبت نمی‌شود.' });
});

app.get('/chat/messages', auth, async (_req,res) => { const q=await pool.query('SELECT username,message,created_at FROM chat_messages ORDER BY id DESC LIMIT 50'); res.json({ messages:q.rows.reverse() }); });
app.post('/chat/messages', auth, async (req,res) => { const message=clean(req.body.message,500); if(!message) return res.status(400).json({error:'EMPTY_MESSAGE'}); await pool.query('INSERT INTO chat_messages(user_id,username,message) VALUES($1,$2,$3)',[req.user.id,req.user.username,message]); res.json({ok:true}); });
app.get('/private-messages', auth, async (req,res) => {
  const q = await pool.query(`SELECT pm.id,pm.message,pm.created_at,
    sender.username AS from_username,recipient.username AS to_username,
    (pm.from_user=$1) AS sent_by_me
    FROM private_messages pm JOIN users sender ON sender.id=pm.from_user
    JOIN users recipient ON recipient.id=pm.to_user
    WHERE pm.from_user=$1 OR pm.to_user=$1 ORDER BY pm.created_at DESC LIMIT 50`, [req.user.id]);
  res.json({ messages: q.rows.reverse() });
});
app.post('/private-messages', auth, async (req,res) => { const to=clean(req.body.to,64),message=clean(req.body.message,1000); if(!message||!to)return res.status(400).json({error:'INVALID_MESSAGE'}); const u=await pool.query('SELECT id FROM users WHERE id::text=$1 OR username=$1 LIMIT 1',[to]); if(!u.rowCount)return res.status(404).json({error:'RECIPIENT_NOT_FOUND'}); if(u.rows[0].id===req.user.id)return res.status(400).json({error:'CANNOT_MESSAGE_SELF'}); await pool.query('INSERT INTO private_messages(from_user,to_user,message) VALUES($1,$2,$3)',[req.user.id,u.rows[0].id,message]); res.json({ok:true}); });
app.use((err,_req,res,_next)=>{ console.error(err); res.status(500).json({error:'SERVER_ERROR'}); });
await migrate();
pool.on('error', error => console.error('Unexpected PostgreSQL pool error:', error));
app.listen(PORT, () => console.log(`Modiriat Taktiki API listening on ${PORT}`));
