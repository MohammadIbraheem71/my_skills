---
name: auth-security
description: Node.js/Express authentication and security skill covering Passport.js strategies (local, JWT, OAuth), session management, password hashing, cookie hardening, CSRF protection, rate limiting, HTTP security headers with Helmet, input validation, and OWASP best practices. Use when the user mentions authentication, login/logout, Passport.js, sessions, JWT tokens, OAuth, bcrypt, cookies, CSRF, rate limiting, Helmet, security headers, protecting routes, user registration, password reset, or asks how to secure an Express app.
---

# Auth & Security Skill

## Overview

This skill covers production-grade authentication and security for **Node.js / Express** applications. It covers:

- Local username/password auth with Passport.js
- JWT (JSON Web Token) stateless auth
- OAuth2 / OpenID Connect (Google, GitHub, etc.)
- Session management (express-session + Redis)
- Password hashing with bcrypt
- Cookie hardening
- CSRF protection
- Rate limiting
- HTTP security headers (Helmet)
- Input validation & sanitization
- OWASP Top 10 mitigations

---

## 1. Dependencies

```bash
npm install passport passport-local passport-jwt passport-google-oauth20 \
  express-session connect-redis ioredis \
  jsonwebtoken bcrypt \
  helmet express-rate-limit csurf \
  express-validator \
  cookie-parser
```

---

## 2. Password Hashing (bcrypt)

Always hash passwords before storing. Never store plaintext.

```js
const bcrypt = require('bcrypt');
const SALT_ROUNDS = 12;

// Hash on registration
const hash = await bcrypt.hash(plainTextPassword, SALT_ROUNDS);

// Verify on login
const match = await bcrypt.compare(plainTextPassword, storedHash);
if (!match) return res.status(401).json({ error: 'Invalid credentials' });
```

**Rules:**
- Use `SALT_ROUNDS >= 12` in production
- Never log passwords or hashes
- Use `bcrypt.compare` (timing-safe); never `===`

---

## 3. Local Auth with Passport.js

```js
const passport = require('passport');
const { Strategy: LocalStrategy } = require('passport-local');

passport.use(new LocalStrategy(
  { usernameField: 'email' },
  async (email, password, done) => {
    try {
      const user = await User.findOne({ email });
      if (!user) return done(null, false, { message: 'User not found' });
      const valid = await bcrypt.compare(password, user.passwordHash);
      if (!valid) return done(null, false, { message: 'Wrong password' });
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});
```

---

## 4. Session Management

```js
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const Redis = require('ioredis');

const redisClient = new Redis(process.env.REDIS_URL);

app.use(session({
  store: new RedisStore({ client: redisClient }),
  secret: process.env.SESSION_SECRET, // 32+ random bytes
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,       // No JS access
    secure: true,         // HTTPS only
    sameSite: 'strict',   // CSRF mitigation
    maxAge: 1000 * 60 * 60 * 24, // 24 hours
  },
}));

app.use(passport.initialize());
app.use(passport.session());
```

**Rules:**
- Always use a Redis (or DB) store — never the default in-memory store in production
- `SESSION_SECRET` must be a long random string (use `crypto.randomBytes(32).toString('hex')`)
- Regenerate session ID after login to prevent session fixation:
  ```js
  req.session.regenerate((err) => {
    req.logIn(user, () => res.redirect('/dashboard'));
  });
  ```

---

## 5. JWT Authentication

Use JWTs for stateless APIs (SPAs, mobile apps, microservices).

```js
const jwt = require('jsonwebtoken');
const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt');

// Issue token on login
const token = jwt.sign(
  { sub: user.id, email: user.email },
  process.env.JWT_SECRET,
  { expiresIn: '15m', algorithm: 'HS256' }
);

// Refresh token (long-lived, stored in httpOnly cookie)
const refreshToken = jwt.sign(
  { sub: user.id },
  process.env.JWT_REFRESH_SECRET,
  { expiresIn: '7d' }
);
res.cookie('refreshToken', refreshToken, {
  httpOnly: true, secure: true, sameSite: 'strict'
});

// Passport JWT strategy
passport.use(new JwtStrategy(
  {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET,
  },
  async (payload, done) => {
    try {
      const user = await User.findById(payload.sub);
      return user ? done(null, user) : done(null, false);
    } catch (err) {
      return done(err);
    }
  }
));
```

**Rules:**
- Keep access tokens short-lived (15m)
- Store refresh tokens in `httpOnly` cookies, not `localStorage`
- Maintain a refresh token revocation list (Redis set) for logout
- Never put sensitive data in JWT payload (it's base64, not encrypted)

---

## 6. OAuth2 (Google Example)

```js
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');

passport.use(new GoogleStrategy(
  {
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback',
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await User.findOne({ googleId: profile.id });
      if (!user) {
        user = await User.create({
          googleId: profile.id,
          email: profile.emails[0].value,
          name: profile.displayName,
        });
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));

// Routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => res.redirect('/dashboard')
);
```

---

## 7. Protecting Routes

```js
// Middleware for session-based auth
function requireAuth(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

// Middleware for JWT auth
const requireJwt = passport.authenticate('jwt', { session: false });

// Usage
app.get('/api/profile', requireJwt, (req, res) => res.json(req.user));
app.get('/dashboard', requireAuth, (req, res) => res.render('dashboard'));
```

---

## 8. HTTP Security Headers (Helmet)

```js
const helmet = require('helmet');

app.use(helmet()); // Enables all default headers

// Or configure individually:
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  referrerPolicy: { policy: 'no-referrer' },
}));
```

---

## 9. CSRF Protection

For session-based apps with HTML forms:

```js
const csrf = require('csurf');

const csrfProtection = csrf({ cookie: { httpOnly: true, secure: true } });
app.use(csrfProtection);

// Pass token to templates
app.get('/form', (req, res) => {
  res.render('form', { csrfToken: req.csrfToken() });
});
```

```html
<!-- In your HTML form -->
<input type="hidden" name="_csrf" value="<%= csrfToken %>">
```

> For JWT-based SPAs: CSRF is less relevant because you're not using cookies for auth. Use `SameSite=Strict` cookies and avoid storing tokens in `localStorage`.

---

## 10. Rate Limiting

```js
const rateLimit = require('express-rate-limit');

// Global limiter
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

// Strict limiter for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: { error: 'Too many attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.post('/auth/login', authLimiter, passport.authenticate('local'), loginHandler);
app.post('/auth/register', authLimiter, registerHandler);
app.post('/auth/forgot-password', authLimiter, forgotPasswordHandler);
```

---

## 11. Input Validation

```js
const { body, validationResult } = require('express-validator');

const registerValidation = [
  body('email').isEmail().normalizeEmail(),
  body('password')
    .isLength({ min: 12 })
    .matches(/[A-Z]/).withMessage('Must contain uppercase')
    .matches(/[0-9]/).withMessage('Must contain number')
    .matches(/[^A-Za-z0-9]/).withMessage('Must contain special character'),
];

app.post('/auth/register', registerValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  // proceed with registration
});
```

---

## 12. Secure Password Reset Flow

```js
const crypto = require('crypto');

// 1. Generate token
const resetToken = crypto.randomBytes(32).toString('hex');
const tokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
const expiry = Date.now() + 10 * 60 * 1000; // 10 minutes

// 2. Store hash (not raw token) in DB
await User.updateOne({ email }, { resetTokenHash: tokenHash, resetTokenExpiry: expiry });

// 3. Email the raw token to user
await sendEmail({ to: email, subject: 'Password Reset', text: `Reset link: /reset?token=${resetToken}` });

// 4. On reset form submit — verify
const hash = crypto.createHash('sha256').update(req.body.token).digest('hex');
const user = await User.findOne({
  resetTokenHash: hash,
  resetTokenExpiry: { $gt: Date.now() },
});
if (!user) return res.status(400).json({ error: 'Invalid or expired token' });

// 5. Update password and clear token
user.passwordHash = await bcrypt.hash(req.body.newPassword, 12);
user.resetTokenHash = undefined;
user.resetTokenExpiry = undefined;
await user.save();
```

---

## 13. Logout

```js
// Session-based
app.post('/auth/logout', (req, res) => {
  req.logout((err) => {
    req.session.destroy(() => {
      res.clearCookie('connect.sid');
      res.redirect('/login');
    });
  });
});

// JWT-based (add refresh token to blocklist)
app.post('/auth/logout', requireJwt, async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (refreshToken) {
    await redisClient.set(`blocklist:${refreshToken}`, '1', 'EX', 7 * 24 * 3600);
  }
  res.clearCookie('refreshToken');
  res.json({ message: 'Logged out' });
});
```

---

## 14. OWASP Quick Reference

| Risk | Mitigation |
|------|-----------|
| Broken Auth | bcrypt, MFA, account lockout, rate limiting |
| Session Fixation | Regenerate session ID after login |
| XSS | Helmet CSP, `httpOnly` cookies, input sanitization |
| CSRF | `SameSite=Strict`, csurf middleware |
| Injection | Parameterized queries, express-validator |
| Sensitive Data | HTTPS only, never log credentials |
| Brute Force | Rate limiting on auth routes |
| Insecure JWT | Short expiry, `httpOnly` refresh token, revocation list |

---

## 15. Environment Variables Checklist

```env
SESSION_SECRET=<32+ random bytes hex>
JWT_SECRET=<32+ random bytes hex>
JWT_REFRESH_SECRET=<32+ random bytes hex>
REDIS_URL=redis://localhost:6379
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
```

Generate secrets with:
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```
