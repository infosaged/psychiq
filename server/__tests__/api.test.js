process.env.DB_PATH = ':memory:';
process.env.JWT_SECRET = 'test-secret';

const request = require('supertest');
const { app } = require('../server');

// ── Helpers ───────────────────────────────────────────────────────────────────

let uid = 0;

function nextUser(overrides = {}) {
  uid++;
  return {
    email: `user${uid}@example.com`,
    password: 'password123',
    displayName: `User ${uid}`,
    username: `user${uid}`,
    ...overrides,
  };
}

async function register(overrides = {}) {
  return request(app).post('/api/auth/register').send(nextUser(overrides));
}

async function registerAndToken(overrides = {}) {
  const res = await register(overrides);
  return res.body.token;
}

// ── Health ────────────────────────────────────────────────────────────────────

describe('GET /api/health', () => {
  it('returns ok', async () => {
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });
});

// ── assetlinks.json ───────────────────────────────────────────────────────────

describe('GET /.well-known/assetlinks.json', () => {
  it('returns TWA asset links array', async () => {
    const res = await request(app).get('/.well-known/assetlinks.json');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body[0].target.package_name).toBe('com.psychiciq.app');
  });
});

// ── Register ──────────────────────────────────────────────────────────────────

describe('POST /api/auth/register', () => {
  it('creates a user and returns a token', async () => {
    const res = await register();
    expect(res.status).toBe(201);
    expect(res.body.token).toBeTruthy();
    expect(res.body.user.displayName).toBeTruthy();
  });

  it('rejects duplicate email', async () => {
    const u = nextUser();
    await request(app).post('/api/auth/register').send(u);
    const res = await request(app)
      .post('/api/auth/register')
      .send({ ...u, username: `other${uid}` });
    expect(res.status).toBe(409);
  });

  it('rejects duplicate username', async () => {
    const u = nextUser();
    await request(app).post('/api/auth/register').send(u);
    const res = await request(app)
      .post('/api/auth/register')
      .send({ ...u, email: `other${uid}@example.com` });
    expect(res.status).toBe(409);
  });

  it('rejects missing required fields', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: 'a@b.com' });
    expect(res.status).toBe(400);
  });

  it('rejects short password', async () => {
    const res = await register({ password: '123' });
    expect(res.status).toBe(400);
  });

  it('rejects invalid username format', async () => {
    const res = await register({ username: 'Bad User!' });
    expect(res.status).toBe(400);
  });
});

// ── Login ─────────────────────────────────────────────────────────────────────

describe('POST /api/auth/login', () => {
  let loginEmail;

  beforeEach(async () => {
    const u = nextUser();
    loginEmail = u.email;
    await request(app).post('/api/auth/register').send(u);
  });

  it('returns token and user for valid credentials', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: loginEmail, password: 'password123' });
    expect(res.status).toBe(200);
    expect(res.body.token).toBeTruthy();
  });

  it('rejects wrong password', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: loginEmail, password: 'wrongpass' });
    expect(res.status).toBe(401);
  });

  it('rejects unknown email', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'nobody@example.com', password: 'password123' });
    expect(res.status).toBe(401);
  });

  it('rejects missing fields', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: loginEmail });
    expect(res.status).toBe(400);
  });
});

// ── Auth middleware ───────────────────────────────────────────────────────────

describe('requireAuth middleware', () => {
  it('rejects requests without a token', async () => {
    const res = await request(app).get('/api/users/me');
    expect(res.status).toBe(401);
  });

  it('rejects a malformed token', async () => {
    const res = await request(app)
      .get('/api/users/me')
      .set('Authorization', 'Bearer not.a.real.token');
    expect(res.status).toBe(401);
  });
});

// ── GET /api/users/me ─────────────────────────────────────────────────────────

describe('GET /api/users/me', () => {
  it('returns the authenticated user', async () => {
    const token = await registerAndToken();
    const res = await request(app)
      .get('/api/users/me')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.displayName).toBeTruthy();
    expect(res.body).not.toHaveProperty('password_hash');
  });
});

// ── PUT /api/users/me ─────────────────────────────────────────────────────────

describe('PUT /api/users/me', () => {
  it('updates display name', async () => {
    const token = await registerAndToken();
    const res = await request(app)
      .put('/api/users/me')
      .set('Authorization', `Bearer ${token}`)
      .send({ displayName: 'New Name' });
    expect(res.status).toBe(200);
    expect(res.body.displayName).toBe('New Name');
  });

  it('updates country and state', async () => {
    const token = await registerAndToken();
    const res = await request(app)
      .put('/api/users/me')
      .set('Authorization', `Bearer ${token}`)
      .send({ country: 'US', stateCode: 'CA' });
    expect(res.status).toBe(200);
    expect(res.body.country).toBe('US');
    expect(res.body.stateCode).toBe('CA');
  });

  it('updates card back', async () => {
    const token = await registerAndToken();
    const res = await request(app)
      .put('/api/users/me')
      .set('Authorization', `Bearer ${token}`)
      .send({ cardBack: 'basic_blue' });
    expect(res.status).toBe(200);
    expect(res.body.cardBack).toBe('basic_blue');
  });

  it('rejects invalid username format', async () => {
    const token = await registerAndToken();
    const res = await request(app)
      .put('/api/users/me')
      .set('Authorization', `Bearer ${token}`)
      .send({ username: 'Bad Name!' });
    expect(res.status).toBe(400);
  });

  it('rejects duplicate username', async () => {
    const taken = nextUser();
    await request(app).post('/api/auth/register').send(taken);
    const token = await registerAndToken();
    const res = await request(app)
      .put('/api/users/me')
      .set('Authorization', `Bearer ${token}`)
      .send({ username: taken.username });
    expect(res.status).toBe(409);
  });
});

// ── GET /api/users/:username ──────────────────────────────────────────────────

describe('GET /api/users/:username', () => {
  it('returns public profile for existing user', async () => {
    const u = nextUser();
    await request(app).post('/api/auth/register').send(u);
    const res = await request(app).get(`/api/users/${u.username}`);
    expect(res.status).toBe(200);
    expect(res.body.username).toBe(u.username);
    expect(res.body).not.toHaveProperty('password_hash');
  });

  it('returns 404 for unknown username', async () => {
    const res = await request(app).get('/api/users/nobody_at_all');
    expect(res.status).toBe(404);
  });
});

// ── POST /api/scores ──────────────────────────────────────────────────────────

describe('POST /api/scores', () => {
  it('records a score and returns best scores', async () => {
    const token = await registerAndToken();
    const res = await request(app)
      .post('/api/scores')
      .set('Authorization', `Bearer ${token}`)
      .send({ topicId: 'cards', score: 75 });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.bestScores.cards).toBe(75);
  });

  it('rejects an invalid topic', async () => {
    const token = await registerAndToken();
    const res = await request(app)
      .post('/api/scores')
      .set('Authorization', `Bearer ${token}`)
      .send({ topicId: 'hacking', score: 99 });
    expect(res.status).toBe(400);
  });

  it('rejects an out-of-range score', async () => {
    const token = await registerAndToken();
    const res = await request(app)
      .post('/api/scores')
      .set('Authorization', `Bearer ${token}`)
      .send({ topicId: 'cards', score: 99999 });
    expect(res.status).toBe(400);
  });

  it('requires auth', async () => {
    const res = await request(app)
      .post('/api/scores')
      .send({ topicId: 'cards', score: 50 });
    expect(res.status).toBe(401);
  });
});

// ── GET /api/scores/me ────────────────────────────────────────────────────────

describe('GET /api/scores/me', () => {
  it('returns score history for the current user', async () => {
    const token = await registerAndToken();
    await request(app)
      .post('/api/scores')
      .set('Authorization', `Bearer ${token}`)
      .send({ topicId: 'colors', score: 60 });
    const res = await request(app)
      .get('/api/scores/me')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body[0].topic_id).toBe('colors');
    expect(res.body[0].score).toBe(60);
  });
});

// ── GET /api/leaderboard ──────────────────────────────────────────────────────

async function seedLeaderboard() {
  const u = nextUser({ zodiac: 'Aries' });
  const token = await registerAndToken({ ...u });
  await request(app)
    .put('/api/users/me')
    .set('Authorization', `Bearer ${token}`)
    .send({ country: 'US', stateCode: 'TX' });
  await request(app)
    .post('/api/scores')
    .set('Authorization', `Bearer ${token}`)
    .send({ topicId: 'cards', score: 80 });
  return { token, username: u.username };
}

describe('GET /api/leaderboard', () => {
  beforeEach(() => seedLeaderboard());

  it('returns leaderboard entries', async () => {
    const res = await request(app).get('/api/leaderboard');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.entries)).toBe(true);
    expect(res.body.entries.length).toBeGreaterThan(0);
    expect(res.body.entries[0]).toHaveProperty('rank');
    expect(res.body.entries[0]).toHaveProperty('bestScore');
  });

  it('filters by topic', async () => {
    const res = await request(app).get('/api/leaderboard?topic=cards');
    expect(res.status).toBe(200);
    expect(res.body.entries.length).toBeGreaterThan(0);
  });

  it('filters by zodiac', async () => {
    const res = await request(app).get('/api/leaderboard?zodiac=Aries');
    expect(res.status).toBe(200);
    expect(res.body.entries.length).toBeGreaterThan(0);
  });

  it('returns empty for non-matching zodiac filter', async () => {
    const res = await request(app).get('/api/leaderboard?zodiac=Pisces');
    expect(res.status).toBe(200);
    expect(res.body.entries.length).toBe(0);
  });

  it('filters by country', async () => {
    const res = await request(app).get('/api/leaderboard?country=US');
    expect(res.status).toBe(200);
    expect(res.body.entries.length).toBeGreaterThan(0);
  });

  it('filters by country + state', async () => {
    const res = await request(app).get('/api/leaderboard?country=US&stateCode=TX');
    expect(res.status).toBe(200);
    expect(res.body.entries.length).toBeGreaterThan(0);
  });

  it('respects limit and offset', async () => {
    const res = await request(app).get('/api/leaderboard?limit=1&offset=0');
    expect(res.status).toBe(200);
    expect(res.body.entries.length).toBeLessThanOrEqual(1);
    expect(res.body.limit).toBe(1);
  });

  it('ignores invalid topic and returns results', async () => {
    const res = await request(app).get('/api/leaderboard?topic=invalid');
    expect(res.status).toBe(200);
  });
});

// ── POST /api/purchases ───────────────────────────────────────────────────────

describe('POST /api/purchases', () => {
  it('records a valid purchase', async () => {
    const token = await registerAndToken();
    const res = await request(app)
      .post('/api/purchases')
      .set('Authorization', `Bearer ${token}`)
      .send({ productId: 'special_vibrant_mystics' });
    expect(res.status).toBe(200);
    expect(res.body.purchases).toContain('special_vibrant_mystics');
  });

  it('is idempotent — does not duplicate a purchase', async () => {
    const token = await registerAndToken();
    await request(app)
      .post('/api/purchases')
      .set('Authorization', `Bearer ${token}`)
      .send({ productId: 'special_vibrant_mystics' });
    const res = await request(app)
      .post('/api/purchases')
      .set('Authorization', `Bearer ${token}`)
      .send({ productId: 'special_vibrant_mystics' });
    expect(res.status).toBe(200);
    expect(res.body.purchases.filter(p => p === 'special_vibrant_mystics').length).toBe(1);
  });

  it('rejects an invalid product ID', async () => {
    const token = await registerAndToken();
    const res = await request(app)
      .post('/api/purchases')
      .set('Authorization', `Bearer ${token}`)
      .send({ productId: 'free_everything' });
    expect(res.status).toBe(400);
  });

  it('requires auth', async () => {
    const res = await request(app)
      .post('/api/purchases')
      .send({ productId: 'special_vibrant_mystics' });
    expect(res.status).toBe(401);
  });
});
