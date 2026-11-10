const ORIGINS = [
  "https://ekpobassey01-glitch.github.io",
  "https://planetsurfx.ekpobassey01.workers.dev"
];

const SQL = [
`CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,username TEXT UNIQUE NOT NULL,email TEXT UNIQUE,password_hash TEXT NOT NULL,full_name TEXT NOT NULL,bio TEXT DEFAULT '',avatar TEXT DEFAULT '',cover TEXT DEFAULT '',location TEXT DEFAULT '',status TEXT DEFAULT 'active',created_at TEXT NOT NULL)`,
`CREATE TABLE IF NOT EXISTS admins(id TEXT PRIMARY KEY,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,status TEXT DEFAULT 'active',created_at TEXT NOT NULL)`,
`CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,user_id TEXT,role TEXT,token_hash TEXT UNIQUE,expires_at TEXT,created_at TEXT)`,
`CREATE TABLE IF NOT EXISTS posts(id TEXT PRIMARY KEY,user_id TEXT,content TEXT,visibility TEXT DEFAULT 'public',created_at TEXT)`,
`CREATE TABLE IF NOT EXISTS comments(id TEXT PRIMARY KEY,post_id TEXT,user_id TEXT,content TEXT,created_at TEXT)`,
`CREATE TABLE IF NOT EXISTS likes(id TEXT PRIMARY KEY,post_id TEXT,user_id TEXT,created_at TEXT,UNIQUE(post_id,user_id))`,
`CREATE TABLE IF NOT EXISTS friendships(id TEXT PRIMARY KEY,requester_id TEXT,receiver_id TEXT,status TEXT DEFAULT 'pending',created_at TEXT,UNIQUE(requester_id,receiver_id))`,
`CREATE TABLE IF NOT EXISTS messages(id TEXT PRIMARY KEY,sender_id TEXT,receiver_id TEXT,content TEXT,read_at TEXT,created_at TEXT)`,
`CREATE TABLE IF NOT EXISTS notifications(id TEXT PRIMARY KEY,user_id TEXT,actor_id TEXT,type TEXT,message TEXT,reference_id TEXT,read_at TEXT,created_at TEXT)`,
`CREATE TABLE IF NOT EXISTS listings(id TEXT PRIMARY KEY,user_id TEXT,title TEXT,description TEXT,price REAL,category TEXT,location TEXT,status TEXT DEFAULT 'active',created_at TEXT)`,
`CREATE TABLE IF NOT EXISTS stories(id TEXT PRIMARY KEY,user_id TEXT,caption TEXT DEFAULT '',media_url TEXT,media_type TEXT DEFAULT 'image',expires_at TEXT,created_at TEXT)`,
`CREATE TABLE IF NOT EXISTS reels(id TEXT PRIMARY KEY,user_id TEXT,caption TEXT DEFAULT '',video_url TEXT,created_at TEXT)`,
`CREATE TABLE IF NOT EXISTS reel_likes(id TEXT PRIMARY KEY,reel_id TEXT,user_id TEXT,created_at TEXT,UNIQUE(reel_id,user_id))`,
`CREATE TABLE IF NOT EXISTS social_groups(id TEXT PRIMARY KEY,owner_id TEXT,name TEXT,description TEXT,privacy TEXT,created_at TEXT)`,
`CREATE TABLE IF NOT EXISTS group_members(id TEXT PRIMARY KEY,group_id TEXT,user_id TEXT,role TEXT DEFAULT 'member',created_at TEXT,UNIQUE(group_id,user_id))`,
`CREATE TABLE IF NOT EXISTS group_posts(id TEXT PRIMARY KEY,group_id TEXT,user_id TEXT,content TEXT,created_at TEXT)`
];

let schemaPromise = null;

const now = () => new Date().toISOString();
const id = () => crypto.randomUUID();
const clean = v => String(v ?? "").trim();

async function readBody(req) {
  try { return await req.json(); }
  catch { return {}; }
}

function makeResponse(data, status, req) {
  const origin = req.headers.get("Origin") || "";
  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Vary": "Origin",
    "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type,Authorization,X-Admin-Setup-Key",
    "Access-Control-Max-Age": "86400"
  };

  if (ORIGINS.includes(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
  }

  return new Response(JSON.stringify(data), {
    status,
    headers
  });
}

async function initializeDatabase(db) {
  if (!schemaPromise) {
    schemaPromise = (async () => {
      for (const statement of SQL) {
        await db.prepare(statement).run();
      }
    })().catch(error => {
      schemaPromise = null;
      throw error;
    });
  }

  await schemaPromise;
}

async function passwordHash(password, salt) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    salt: new TextEncoder().encode(salt),
    iterations: 100000,
    hash: "SHA-256"
  }, key, 256);

  return Array.from(new Uint8Array(bits))
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

async function makePassword(password) {
  const salt = id();
  return `pbkdf2$100000$${salt}$${await passwordHash(password, salt)}`;
}

function constantEqual(a, b) {
  a = String(a);
  b = String(b);

  if (a.length !== b.length) return false;

  let difference = 0;

  for (let i = 0; i < a.length; i++) {
    difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return difference === 0;
}

async function verifyPassword(password, stored) {
  const parts = String(stored || "").split("$");

  if (
    parts.length !== 4 ||
    parts[0] !== "pbkdf2" ||
    parts[1] !== "100000"
  ) return false;

  const calculated = await passwordHash(password, parts[2]);
  return constantEqual(calculated, parts[3]);
}

async function digest(value) {
  const result = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );

  return Array.from(new Uint8Array(result))
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

async function createSession(db, account, role) {
  const token = id() + id().replaceAll("-", "");

  await db.prepare(
    "INSERT INTO sessions VALUES(?,?,?,?,?,?)"
  ).bind(
    id(),
    account.id,
    role,
    await digest(token),
    new Date(Date.now() + 2592000000).toISOString(),
    now()
  ).run();

  return token;
}

function safeUser(user) {
  if (!user) return null;

  return {
    id: user.id,
    username: user.username,
    full_name: user.full_name,
    email: user.email || "",
    bio: user.bio || "",
    avatar: user.avatar || "",
    cover: user.cover || "",
    location: user.location || "",
    created_at: user.created_at || ""
  };
}

async function notify(db, userId, actorId, type, message, reference = null) {
  await db.prepare(
    "INSERT INTO notifications VALUES(?,?,?,?,?,?,NULL,?)"
  ).bind(
    id(), userId, actorId, type, message, reference, now()
  ).run();
}

function httpsUrl(value) {
  try {
    return new URL(value).protocol === "https:";
  } catch {
    return false;
  }
}

async function canSeePost(db, postId, userId) {
  const post = await db.prepare(
    "SELECT user_id,visibility FROM posts WHERE id=?"
  ).bind(postId).first();

  if (!post) return false;
  if (post.visibility === "public" || post.user_id === userId) return true;

  if (post.visibility === "friends") {
    return !!await db.prepare(`
      SELECT id FROM friendships
      WHERE status='accepted'
      AND (
        (requester_id=? AND receiver_id=?)
        OR (requester_id=? AND receiver_id=?)
      )
    `).bind(post.user_id, userId, userId, post.user_id).first();
  }

  return false;
}

export default {
  async fetch(req, env) {
    const J = (data, status = 200) =>
      makeResponse(data, status, req);

    if (req.method === "OPTIONS") {
      const origin = req.headers.get("Origin") || "";

      if (origin && !ORIGINS.includes(origin)) {
        return new Response(null, { status: 403 });
      }

      const headers = {
        "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type,Authorization,X-Admin-Setup-Key",
        "Access-Control-Max-Age": "86400",
        "Vary": "Origin"
      };

      if (ORIGINS.includes(origin)) {
        headers["Access-Control-Allow-Origin"] = origin;
      }

      return new Response(null, { status: 204, headers });
    }

    try {
      const db = env.DB;

      if (!db) {
        return J({ error: "PlanetSurfX database binding DB is missing." }, 500);
      }

      await initializeDatabase(db);

      const url = new URL(req.url);
      const path = url.pathname;
      const method = req.method;

      if (path === "/" || path === "/api") {
        return J({
          success: true,
          platform: "PlanetSurfX",
          version: "1.2",
          status: "operational"
        });
      }

      const token = (req.headers.get("Authorization") || "")
        .replace(/^Bearer\s+/i, "").trim();

      let account = null;
      let role = null;

      if (token) {
        const session = await db.prepare(`
          SELECT user_id,role FROM sessions
          WHERE token_hash=? AND expires_at>?
        `).bind(await digest(token), now()).first();

        if (session && ["user", "admin"].includes(session.role)) {
          role = session.role;

          const table = role === "admin" ? "admins" : "users";

          account = await db.prepare(
            `SELECT * FROM ${table} WHERE id=? AND status='active'`
          ).bind(session.user_id).first();
        }
      }

      // REGISTRATION
      if (path === "/api/register" && method === "POST") {
        const b = await readBody(req);

        const username = clean(b.username).toLowerCase();
        const fullName = clean(b.full_name);
        const password = String(b.password || "");
        const email = clean(b.email).toLowerCase() || null;

        if (
          !/^[a-z0-9_]{3,30}$/.test(username) ||
          !fullName ||
          fullName.length > 100 ||
          password.length < 8
        ) {
          return J({
            error: "Enter a valid username, full name and password of at least 8 characters."
          }, 400);
        }

        if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          return J({ error: "Enter a valid email address." }, 400);
        }

        const exists = await db.prepare(`
          SELECT id FROM users
          WHERE username=? OR (? IS NOT NULL AND email=?)
        `).bind(username, email, email).first();

        if (exists) {
          return J({ error: "Username or email already exists." }, 409);
        }

        const user = {
          id: id(),
          username,
          full_name: fullName,
          email
        };

        await db.prepare(`
          INSERT INTO users
          (id,username,email,password_hash,full_name,status,created_at)
          VALUES(?,?,?,?,?,'active',?)
        `).bind(
          user.id,
          username,
          email,
          await makePassword(password),
          fullName,
          now()
        ).run();

        return J({
          success: true,
          token: await createSession(db, user, "user"),
          user
        });
      }

      // USER LOGIN
      if (path === "/api/login" && method === "POST") {
        const b = await readBody(req);
        const username = clean(b.username).toLowerCase();

        const user = await db.prepare(
          "SELECT * FROM users WHERE username=? OR email=?"
        ).bind(username, username).first();

        if (
          !user ||
          user.status !== "active" ||
          !await verifyPassword(String(b.password || ""), user.password_hash)
        ) {
          return J({ error: "Incorrect username or password." }, 401);
        }

        return J({
          success: true,
          token: await createSession(db, user, "user"),
          user: safeUser(user)
        });
      }

      // FIRST ADMIN SETUP
      if (path === "/api/admin/setup" && method === "POST") {
        if (
          !env.ADMIN_SETUP_KEY ||
          !constantEqual(
            req.headers.get("X-Admin-Setup-Key") || "",
            env.ADMIN_SETUP_KEY
          )
        ) {
          return J({ error: "Invalid administrator setup key." }, 403);
        }

        const count = await db.prepare(
          "SELECT COUNT(*) AS total FROM admins"
        ).first();

        if (count.total > 0) {
          return J({ error: "Administrator already exists." }, 409);
        }

        const b = await readBody(req);
        const username = clean(b.username).toLowerCase();
        const password = String(b.password || "");

        if (
          !/^[a-z0-9_]{3,30}$/.test(username) ||
          password.length < 12
        ) {
          return J({
            error: "Use a valid admin username and a password of at least 12 characters."
          }, 400);
        }

        await db.prepare(`
          INSERT INTO admins(id,username,password_hash,status,created_at)
          VALUES(?,?,?,'active',?)
        `).bind(
          id(), username, await makePassword(password), now()
        ).run();

        return J({
          success: true,
          message: "Administrator created successfully."
        });
      }

      // ADMIN LOGIN
      if (path === "/api/admin/login" && method === "POST") {
        const b = await readBody(req);
        const username = clean(b.username).toLowerCase();

        const admin = await db.prepare(
          "SELECT * FROM admins WHERE username=?"
        ).bind(username).first();

        if (
          !admin ||
          admin.status !== "active" ||
          !await verifyPassword(String(b.password || ""), admin.password_hash)
        ) {
          return J({ error: "Incorrect administrator credentials." }, 401);
        }

        return J({
          success: true,
          token: await createSession(db, admin, "admin"),
          user: {
            id: admin.id,
            username: admin.username
          }
        });
      }

      // CURRENT SESSION
      if (path === "/api/me" && method === "GET") {
        if (!account) return J({ authenticated: false }, 401);

        const profile = role === "user"
          ? safeUser(account)
          : { id: account.id, username: account.username };

        return J({
          authenticated: true,
          role,
          profile,
          user: profile
        });
      }

      // LOGOUT
      if (path === "/api/logout" && method === "POST") {
        if (token) {
          await db.prepare(
            "DELETE FROM sessions WHERE token_hash=?"
          ).bind(await digest(token)).run();
        }

        return J({ success: true });
      }

      if (!account) {
        return J({ error: "Please sign in." }, 401);
      }

      // PROFILE
      if (path === "/api/profile" && method === "GET") {
        if (role !== "user") {
          return J({ error: "User account required." }, 403);
        }

        return J({ profile: safeUser(account) });
      }

      if (path === "/api/profile" && method === "PATCH") {
        if (role !== "user") {
          return J({ error: "User account required." }, 403);
        }

        const b = await readBody(req);

        const avatar = b.avatar === undefined
          ? account.avatar
          : (httpsUrl(b.avatar) ? b.avatar : "");

        const cover = b.cover === undefined
          ? account.cover
          : (httpsUrl(b.cover) ? b.cover : "");

        await db.prepare(`
          UPDATE users
          SET full_name=?,bio=?,avatar=?,cover=?,location=?
          WHERE id=?
        `).bind(
          clean(b.full_name).slice(0, 100) || account.full_name,
          b.bio === undefined ? account.bio : clean(b.bio).slice(0, 500),
          avatar,
          cover,
          b.location === undefined ? account.location : clean(b.location).slice(0, 120),
          account.id
        ).run();

        return J({ success: true });
      }

      // FEED
      if (path === "/api/feed" && method === "GET") {
        const result = await db.prepare(`
          SELECT p.*,u.username,u.full_name,u.avatar,
          (SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id) AS likes,
          (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id) AS comments
          FROM posts p
          JOIN users u ON u.id=p.user_id
          WHERE p.visibility='public'
          OR p.user_id=?
          OR (
            p.visibility='friends'
            AND EXISTS (
              SELECT 1 FROM friendships f
              WHERE f.status='accepted'
              AND (
                (f.requester_id=p.user_id AND f.receiver_id=?)
                OR
                (f.receiver_id=p.user_id AND f.requester_id=?)
              )
            )
          )
          ORDER BY p.created_at DESC LIMIT 60
        `).bind(account.id, account.id, account.id).all();

        return J({ posts: result.results });
      }

      // CREATE POST
      if (path === "/api/posts" && method === "POST") {
        const b = await readBody(req);
        const content = clean(b.content);

        if (!content || content.length > 5000) {
          return J({ error: "Post must contain 1–5000 characters." }, 400);
        }

        const postId = id();

        await db.prepare(
          "INSERT INTO posts VALUES(?,?,?,?,?)"
        ).bind(
          postId,
          account.id,
          content,
          b.visibility === "friends" ? "friends" : "public",
          now()
        ).run();

        return J({ success: true, id: postId });
      }

      // DELETE POST
      let match = path.match(/^\/api\/posts\/([^/]+)$/);

      if (match && method === "DELETE") {
        const post = await db.prepare(
          "SELECT user_id FROM posts WHERE id=?"
        ).bind(match[1]).first();

        if (!post) return J({ error: "Post not found." }, 404);

        if (post.user_id !== account.id && role !== "admin") {
          return J({ error: "You cannot delete this post." }, 403);
        }

        await db.batch([
          db.prepare("DELETE FROM comments WHERE post_id=?").bind(match[1]),
          db.prepare("DELETE FROM likes WHERE post_id=?").bind(match[1]),
          db.prepare("DELETE FROM posts WHERE id=?").bind(match[1])
        ]);

        return J({ success: true });
      }

      // LIKE POST
      match = path.match(/^\/api\/posts\/([^/]+)\/like$/);

      if (match && method === "POST") {
        const post = await db.prepare(
          "SELECT id FROM posts WHERE id=?"
        ).bind(match[1]).first();

        if (!post) return J({ error: "Post not found." }, 404);

        const existing = await db.prepare(
          "SELECT id FROM likes WHERE post_id=? AND user_id=?"
        ).bind(match[1], account.id).first();

        if (existing) {
          await db.prepare(
            "DELETE FROM likes WHERE id=?"
          ).bind(existing.id).run();
        } else {
          await db.prepare(
            "INSERT INTO likes VALUES(?,?,?,?)"
          ).bind(id(), match[1], account.id, now()).run();
        }

        return J({ success: true, liked: !existing });
      }

      // COMMENTS
      match = path.match(/^\/api\/posts\/([^/]+)\/comments$/);

      if (match && (method === "GET" || method === "POST")) {
        if (!await canSeePost(db, match[1], account.id)) {
          return J({ error: "Post not found or access denied." }, 404);
        }

        if (method === "GET") {
          const result = await db.prepare(`
            SELECT c.*,u.username,u.full_name
            FROM comments c
            JOIN users u ON u.id=c.user_id
            WHERE c.post_id=?
            ORDER BY c.created_at
          `).bind(match[1]).all();

          return J({ comments: result.results });
        }

        const b = await readBody(req);
        const content = clean(b.content);

        if (!content || content.length > 1000) {
          return J({ error: "Comment required (maximum 1000 characters)." }, 400);
        }

        await db.prepare(
          "INSERT INTO comments VALUES(?,?,?,?,?)"
        ).bind(id(), match[1], account.id, content, now()).run();

        return J({ success: true });
      }

      // FRIEND REQUEST
      if (path === "/api/friends/request" && method === "POST") {
        const b = await readBody(req);

        const target = await db.prepare(`
          SELECT id,username FROM users
          WHERE username=? AND status='active'
        `).bind(clean(b.username).toLowerCase()).first();

        if (!target || target.id === account.id) {
          return J({ error: "Member not found." }, 404);
        }

        const existing = await db.prepare(`
          SELECT id FROM friendships
          WHERE (requester_id=? AND receiver_id=?)
          OR (requester_id=? AND receiver_id=?)
        `).bind(account.id, target.id, target.id, account.id).first();

        if (existing) {
          return J({ error: "A request or friendship already exists." }, 409);
        }

        await db.prepare(
          "INSERT INTO friendships VALUES(?,?,?,'pending',?)"
        ).bind(id(), account.id, target.id, now()).run();

        await notify(
          db,
          target.id,
          account.id,
          "friend_request",
          `${account.username} sent you a friend request.`
        );

        return J({ success: true });
      }

      // FRIEND REQUESTS
      if (path === "/api/friends/requests" && method === "GET") {
        const result = await db.prepare(`
          SELECT f.id AS request_id,u.username,u.full_name,u.avatar
          FROM friendships f
          JOIN users u ON u.id=f.requester_id
          WHERE f.receiver_id=? AND f.status='pending'
          ORDER BY f.created_at DESC
        `).bind(account.id).all();

        return J({ requests: result.results });
      }

      // ACCEPT FRIEND REQUEST
      if (path === "/api/friends/accept" && method === "POST") {
        const b = await readBody(req);

        const request = await db.prepare(`
          SELECT * FROM friendships
          WHERE id=? AND receiver_id=? AND status='pending'
        `).bind(clean(b.request_id), account.id).first();

        if (!request) {
          return J({ error: "Friend request not found." }, 404);
        }

        await db.prepare(
          "UPDATE friendships SET status='accepted' WHERE id=?"
        ).bind(request.id).run();

        await notify(
          db,
          request.requester_id,
          account.id,
          "friend_accept",
          "Your friend request was accepted."
        );

        return J({ success: true });
      }

      // FRIEND LIST
      if (path === "/api/friends" && method === "GET") {
        const result = await db.prepare(`
          SELECT u.id,u.username,u.full_name,u.avatar
          FROM friendships f
          JOIN users u ON u.id=CASE
            WHEN f.requester_id=? THEN f.receiver_id
            ELSE f.requester_id END
          WHERE (f.requester_id=? OR f.receiver_id=?)
          AND f.status='accepted'
        `).bind(account.id, account.id, account.id).all();

        return J({ friends: result.results });
      }

      // SEND MESSAGE
      if (path === "/api/messages" && method === "POST") {
        const b = await readBody(req);

        const target = await db.prepare(`
          SELECT id FROM users
          WHERE username=? AND status='active'
        `).bind(clean(b.username).toLowerCase()).first();

        const content = clean(b.content);

        if (
          !target ||
          target.id === account.id ||
          !content ||
          content.length > 4000
        ) {
          return J({ error: "A valid recipient and message are required." }, 400);
        }

        await db.prepare(`
          INSERT INTO messages(id,sender_id,receiver_id,content,created_at)
          VALUES(?,?,?,?,?)
        `).bind(
          id(), account.id, target.id, content, now()
        ).run();

        await notify(
          db,
          target.id,
          account.id,
          "message",
          `New message from ${account.username}.`
        );

        return J({ success: true });
      }

      // READ MESSAGES
      if (path === "/api/messages" && method === "GET") {
        const username = clean(
          url.searchParams.get("username")
        ).toLowerCase();

        const target = await db.prepare(
          "SELECT id FROM users WHERE username=?"
        ).bind(username).first();

        if (!target) return J({ error: "Member not found." }, 404);

        const result = await db.prepare(`
          SELECT * FROM messages
          WHERE (sender_id=? AND receiver_id=?)
          OR (sender_id=? AND receiver_id=?)
          ORDER BY created_at
        `).bind(
          account.id, target.id,
          target.id, account.id
        ).all();

        await db.prepare(`
          UPDATE messages SET read_at=?
          WHERE receiver_id=? AND sender_id=? AND read_at IS NULL
        `).bind(now(), account.id, target.id).run();

        return J({ messages: result.results });
      }

      // NOTIFICATIONS
      if (path === "/api/notifications" && method === "GET") {
        const result = await db.prepare(`
          SELECT * FROM notifications
          WHERE user_id=?
          ORDER BY created_at DESC LIMIT 100
        `).bind(account.id).all();

        return J({ notifications: result.results });
      }

      if (path === "/api/notifications/read" && method === "POST") {
        await db.prepare(`
          UPDATE notifications SET read_at=?
          WHERE user_id=? AND read_at IS NULL
        `).bind(now(), account.id).run();

        return J({ success: true });
      }

      // STORIES
      if (path === "/api/stories" && method === "POST") {
        const b = await readBody(req);

        if (!httpsUrl(b.media_url)) {
          return J({ error: "A valid HTTPS media URL is required." }, 400);
        }

        const storyId = id();
        const expires = new Date(Date.now() + 86400000).toISOString();

        await db.prepare(
          "INSERT INTO stories VALUES(?,?,?,?,?,?,?)"
        ).bind(
          storyId,
          account.id,
          clean(b.caption).slice(0, 300),
          b.media_url,
          b.media_type === "video" ? "video" : "image",
          expires,
          now()
        ).run();

        return J({
          success: true,
          id: storyId,
          expires_at: expires
        });
      }

      if (path === "/api/stories" && method === "GET") {
        await db.prepare(
          "DELETE FROM stories WHERE expires_at<=?"
        ).bind(now()).run();

        const result = await db.prepare(`
          SELECT s.*,u.username,u.full_name,u.avatar
          FROM stories s
          JOIN users u ON u.id=s.user_id
          WHERE s.expires_at>?
          ORDER BY s.created_at DESC LIMIT 100
        `).bind(now()).all();

        return J({ stories: result.results });
      }

      // REELS
      if (path === "/api/reels" && method === "POST") {
        const b = await readBody(req);

        if (!httpsUrl(b.video_url)) {
          return J({ error: "A valid HTTPS video URL is required." }, 400);
        }

        const reelId = id();

        await db.prepare(
          "INSERT INTO reels VALUES(?,?,?,?,?)"
        ).bind(
          reelId,
          account.id,
          clean(b.caption).slice(0, 1000),
          b.video_url,
          now()
        ).run();

        return J({ success: true, id: reelId });
      }

      if (path === "/api/reels" && method === "GET") {
        const result = await db.prepare(`
          SELECT r.*,u.username,u.full_name,u.avatar,
          (SELECT COUNT(*) FROM reel_likes l WHERE l.reel_id=r.id) AS likes
          FROM reels r
          JOIN users u ON u.id=r.user_id
          ORDER BY r.created_at DESC LIMIT 100
        `).all();

        return J({ reels: result.results });
      }

      // LIKE REEL
      match = path.match(/^\/api\/reels\/([^/]+)\/like$/);

      if (match && method === "POST") {
        const reel = await db.prepare(
          "SELECT id FROM reels WHERE id=?"
        ).bind(match[1]).first();

        if (!reel) return J({ error: "Reel not found." }, 404);

        const existing = await db.prepare(
          "SELECT id FROM reel_likes WHERE reel_id=? AND user_id=?"
        ).bind(match[1], account.id).first();

        if (existing) {
          await db.prepare(
            "DELETE FROM reel_likes WHERE id=?"
          ).bind(existing.id).run();
        } else {
          await db.prepare(
            "INSERT INTO reel_likes VALUES(?,?,?,?)"
          ).bind(id(), match[1], account.id, now()).run();
        }

        return J({ success: true, liked: !existing });
      }

      // CREATE GROUP
      if (path === "/api/groups" && method === "POST") {
        const b = await readBody(req);
        const name = clean(b.name);

        if (name.length < 3 || name.length > 70) {
          return J({ error: "Group name must contain 3–70 characters." }, 400);
        }

        const groupId = id();

        await db.prepare(
          "INSERT INTO social_groups VALUES(?,?,?,?,?,?)"
        ).bind(
          groupId,
          account.id,
          name,
          clean(b.description).slice(0, 1000),
          b.privacy === "private" ? "private" : "public",
          now()
        ).run();

        await db.prepare(
          "INSERT INTO group_members VALUES(?,?,?,'owner',?)"
        ).bind(id(), groupId, account.id, now()).run();

        return J({ success: true, id: groupId });
      }

      // LIST GROUPS
      if (path === "/api/groups" && method === "GET") {
        const result = await db.prepare(`
          SELECT g.*,u.username AS owner_username,
          (SELECT COUNT(*) FROM group_members x WHERE x.group_id=g.id) AS members,
          (SELECT COUNT(*) FROM group_members x
           WHERE x.group_id=g.id AND x.user_id=?) AS joined
          FROM social_groups g
          JOIN users u ON u.id=g.owner_id
          WHERE g.privacy='public'
          OR EXISTS(
            SELECT 1 FROM group_members x
            WHERE x.group_id=g.id AND x.user_id=?
          )
          ORDER BY g.created_at DESC
        `).bind(account.id, account.id).all();

        return J({ groups: result.results });
      }

      // JOIN GROUP
      match = path.match(/^\/api\/groups\/([^/]+)\/join$/);

      if (match && method === "POST") {
        const group = await db.prepare(
          "SELECT * FROM social_groups WHERE id=?"
        ).bind(match[1]).first();

        if (!group) return J({ error: "Group not found." }, 404);

        if (group.privacy === "private" && group.owner_id !== account.id) {
          return J({ error: "This is a private group." }, 403);
        }

        await db.prepare(
          "INSERT OR IGNORE INTO group_members VALUES(?,?,?,'member',?)"
        ).bind(id(), group.id, account.id, now()).run();

        return J({ success: true });
      }

      // GROUP POSTS
      match = path.match(/^\/api\/groups\/([^/]+)\/posts$/);

      if (match && (method === "GET" || method === "POST")) {
        const member = await db.prepare(
          "SELECT id FROM group_members WHERE group_id=? AND user_id=?"
        ).bind(match[1], account.id).first();

        if (!member) {
          return J({ error: "Join this group first." }, 403);
        }

        if (method === "GET") {
          const result = await db.prepare(`
            SELECT p.*,u.username,u.full_name
            FROM group_posts p
            JOIN users u ON u.id=p.user_id
            WHERE p.group_id=?
            ORDER BY p.created_at DESC
          `).bind(match[1]).all();

          return J({ posts: result.results });
        }

        const b = await readBody(req);
        const content = clean(b.content);

        if (!content || content.length > 3000) {
          return J({ error: "Group post must contain 1–3000 characters." }, 400);
        }

        await db.prepare(
          "INSERT INTO group_posts VALUES(?,?,?,?,?)"
        ).bind(id(), match[1], account.id, content, now()).run();

        return J({ success: true });
      }

      // MARKETPLACE
      if (path === "/api/marketplace" && method === "POST") {
        const b = await readBody(req);
        const title = clean(b.title);
        const price = clean(b.price) === "" ? null : Number(b.price);

        if (
          !title ||
          title.length > 120 ||
          (price !== null && (!Number.isFinite(price) || price < 0))
        ) {
          return J({ error: "Enter a valid listing title and price." }, 400);
        }

        await db.prepare(`
          INSERT INTO listings
          VALUES(?,?,?,?,?,?,?,'active',?)
        `).bind(
          id(),
          account.id,
          title,
          clean(b.description).slice(0, 2000),
          price,
          clean(b.category).slice(0, 80),
          clean(b.location).slice(0, 120),
          now()
        ).run();

        return J({ success: true });
      }

      if (path === "/api/marketplace" && method === "GET") {
        const result = await db.prepare(`
          SELECT l.*,u.username,u.full_name
          FROM listings l
          JOIN users u ON u.id=l.user_id
          WHERE l.status='active'
          ORDER BY l.created_at DESC LIMIT 200
        `).all();

        return J({ listings: result.results });
      }

      // ADMIN DASHBOARD
      if (path === "/api/admin/dashboard" && method === "GET") {
        if (role !== "admin") {
          return J({ error: "Administrator access required." }, 403);
        }

        const counts = {};

        for (const table of ["users", "posts", "listings", "messages"]) {
          const result = await db.prepare(
            `SELECT COUNT(*) AS total FROM ${table}`
          ).first();

          counts[table] = result.total;
        }

        return J(counts);
      }

      // ADMIN USER LIST
      if (path === "/api/admin/users" && method === "GET") {
        if (role !== "admin") {
          return J({ error: "Administrator access required." }, 403);
        }

        const result = await db.prepare(`
          SELECT id,username,full_name,status,created_at
          FROM users
          ORDER BY created_at DESC LIMIT 500
        `).all();

        return J({ users: result.results });
      }

      // ADMIN SUSPEND OR RESTORE USER
      match = path.match(/^\/api\/admin\/users\/([^/]+)$/);

      if (match && method === "PATCH") {
        if (role !== "admin") {
          return J({ error: "Administrator access required." }, 403);
        }

        const b = await readBody(req);
        const status = b.status === "suspended" ? "suspended" : "active";

        const target = await db.prepare(
          "SELECT id FROM users WHERE id=?"
        ).bind(match[1]).first();

        if (!target) return J({ error: "User not found." }, 404);

        await db.prepare(
          "UPDATE users SET status=? WHERE id=?"
        ).bind(status, match[1]).run();

        if (status === "suspended") {
          await db.prepare(
            "DELETE FROM sessions WHERE user_id=? AND role='user'"
          ).bind(match[1]).run();
        }

        return J({ success: true });
      }

      return J({ error: "Endpoint not found." }, 404);

    } catch (error) {
      console.error("PlanetSurfX backend error:", error);

      return J({
        error: "A server error occurred. Please try again."
      }, 500);
    }
  }
};
