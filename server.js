const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const Datastore = require('nedb-promises');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: 'dont give knight',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true }
}));

const usersDb = Datastore.create({ filename: path.join(__dirname, 'data/users.db'), autoload: true });
const postsDb = Datastore.create({ filename: path.join(__dirname, 'data/posts.db'), autoload: true });

async function seedDB() {
  const count = await usersDb.count({});
  if (count > 0) return;
  await usersDb.insert([
    { uid: 1, username: 'admin',     password: await bcrypt.hash('s3cr3t_p4ss', 10), role: 'administrator', flag: 'nice try ' },
    { uid: 2, username: 'alice',     password: await bcrypt.hash('alice123', 10),     role: 'moderator',     flag: 'catch me if u can' },
    { uid: 3, username: 'bob',       password: await bcrypt.hash('bob456', 10),       role: 'user',          flag: null },
    { uid: 4, username: 'flag_user', password: await bcrypt.hash('unfindable!', 10),  role: 'user',          flag: 'keep going ya knight' },
  ]);
  await postsDb.insert([
    { pid: 1, author: 'admin', content: 'Welcome to SecBlog. Stay ethical.', createdAt: Date.now() - 3600000 },
    { pid: 2, author: 'alice', content: 'Great platform for security research!', createdAt: Date.now() - 1800000 },
  ]);
  console.log('[db] seeded');
}

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'unauthenticated' });
  next();
}

// VULN #1 — SQLi simulation
// Blocked: admin'--, ' or 1=1, ' OR '1'='1
// Works:   admin'#  | admin'/* | ' or 'x'='x | ' or true-- | ' UNION SELECT
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  const easyBlocked =
    /admin'\s*--\s*$/i.test(username) ||
    /'\s+or\s+['"]?1['"]?\s*=\s*['"]?1/i.test(username) ||
    /'\s+or\s+1\s*=\s*1/i.test(username);

  if (easyBlocked) {
    return res.status(401).json({ error: 'invalid credentials' });
  }

  const sqliBypass =
    /'\s*#/.test(username) ||
    /'\s*\/\*/.test(username) ||
    /'\s*\|\|/.test(username) ||
    /'\s*or\s*'[^=]{1,10}'\s*=\s*'/i.test(username) ||
    /'\s*or\s+true\s*--/i.test(username) ||
    /union\s+(all\s+)?select/i.test(username);

  if (sqliBypass) {
    const first = await usersDb.findOne({ uid: 1 });
    req.session.user = { uid: first.uid, username: first.username, role: first.role };
    return res.json({ ok: true, username: first.username, flag: 'no ai yasta ???????' });
  }

  const user = await usersDb.findOne({ username });
  if (!user) return res.status(401).json({ error: 'invalid credentials' });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: 'invalid credentials' });

  req.session.user = { uid: user.uid, username: user.username, role: user.role };
  res.json({ ok: true, username: user.username });
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ ok: true }); });
app.get('/api/me', requireAuth, (req, res) => { res.json(req.session.user); });

app.get('/api/posts', requireAuth, async (req, res) => {
  const posts = await postsDb.find({}).sort({ createdAt: -1 });
  res.json(posts);
});

// VULN #2 — Stored XSS (harder)
// Blocked: <script>, <img>, <svg>, onerror=, onload=
// Works:   <iframe src=javascript:...>, <details ontoggle=...>, <body onpageshow=...>,
//          <input autofocus onfocus=...>, <a href=javascript:...>
app.post('/api/posts', requireAuth, async (req, res) => {
  const { content } = req.body;
  if (!content?.trim()) return res.status(400).json({ error: 'empty content' });

  const easyBlocked =
    /<script/i.test(content) ||
    /<img\s/i.test(content) ||
    /<svg[\s>]/i.test(content) ||
    /\bonerror\s*=/i.test(content) ||
    /\bonload\s*=/i.test(content);

  if (easyBlocked) {
    return res.status(400).json({ error: 'invalid content' });
  }

  await postsDb.insert({
    pid: Date.now(),
    author: req.session.user.username,
    content,
    createdAt: Date.now()
  });

  const hardXss =
    /javascript\s*:/i.test(content) ||
    /on(focus|blur|click|mouse|key|page|toggle|input|change|submit|pointer|touch)\s*=/i.test(content) ||
    /\beval\s*\(/i.test(content) ||
    /expression\s*\(/i.test(content) ||
    /data\s*:\s*text\/html/i.test(content);

  if (hardXss) {
    await postsDb.insert({
      pid: Date.now() + 1,
      author: 'system',
      content: `nah bro go to sleep`,
      createdAt: Date.now() + 1
    });
  }

  res.json({ ok: true });
});

// VULN #3 — IDOR
app.get('/api/users/:uid', requireAuth, async (req, res) => {
  const uid = parseInt(req.params.uid);
  const user = await usersDb.findOne({ uid });
  if (!user) return res.status(404).json({ error: 'user not found' });
  const { password, ...safe } = user;
  res.json(safe);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
  require('fs').mkdirSync(path.join(__dirname, 'data'), { recursive: true });
  await seedDB();
  console.log(`[ctf] server running → http://localhost:${PORT}`);
});
