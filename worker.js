const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type,Authorization",
  "Content-Type": "application/json"
};

const now = () => new Date().toISOString();
const id = () => crypto.randomUUID();

function reply(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: CORS
  });
}

async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    salt,
    iterations: 100000,
    hash: "SHA-256"
  }, key, 256);

  return btoa(String.fromCharCode(...new Uint8Array(bits)));
}

function randomSalt() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return btoa(String.fromCharCode(...bytes));
}

async function passwordHash(password) {
  const salt = randomSalt();
  return `pbkdf2$100000$${salt}$${await hashPassword(password, Uint8Array.from(atob(salt), c => c.charCodeAt(0)))}`;
}

async function verifyPassword(password, stored) {
  try {
    const [algorithm, iterations, salt, expected] = stored.split("$");
    if (algorithm !== "pbkdf2" || iterations !== "100000") return false;
    const actual = await hashPassword(
      password,
      Uint8Array.from(atob(salt), c => c.charCodeAt(0))
    );
    return actual === expected;
  } catch {
    return false;
  }
}

async function digest(value) {
  const bytes = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );
  return Array.from(new Uint8Array(bytes))
    .map(x => x.toString(16).padStart(2, "0")).join("");
}

async function createSession(db, userId, role = "user") {
  const token = crypto.randomUUID() + crypto.randomUUID();
  await db.prepare(
    "INSERT INTO sessions (id,user_id,role,token_hash,expires_at,created_at) VALUES (?,?,?,?,?,?)"
  ).bind(id(), userId, role, await digest(token),
    new Date(Date.now() + 30 * 86400000).toISOString(), now()).run();
  return token;
}

async function authenticate(request, db) {
  const header = request.headers.get("Authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return null;

  const session = await db.prepare(
    "SELECT * FROM sessions WHERE token_hash=? AND expires_at>?"
  ).bind(await digest(token), now()).first();

  if (!session) return null;

  const table = session.role === "admin" ? "admins" : "users";
  const user = await db.prepare(
    `SELECT * FROM ${table} WHERE id=?`
  ).bind(session.user_id).first();

  if (!user || user.status !== "active") return null;

  return { ...user, role: session.role, token_hash: session.token_hash };
}

const SCHEMA = [
`CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY,
 username TEXT NOT NULL UNIQUE,
 email TEXT UNIQUE,
 password_hash TEXT NOT NULL,
 full_name TEXT NOT NULL,
 bio TEXT DEFAULT '',
 avatar TEXT DEFAULT '',
 cover TEXT DEFAULT '',
 location TEXT DEFAULT '',
 status TEXT DEFAULT 'active',
 created_at TEXT NOT NULL
)`,
`CREATE TABLE IF NOT EXISTS admins (
 id TEXT PRIMARY KEY,
 username TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 status TEXT DEFAULT 'active',
 created_at TEXT NOT NULL
)`,
`CREATE TABLE IF NOT EXISTS sessions (
 id TEXT PRIMARY KEY,
 user_id TEXT NOT NULL,
 role TEXT NOT NULL,
 token_hash TEXT NOT NULL UNIQUE,
 expires_at TEXT NOT NULL,
 created_at TEXT NOT NULL
)`,
`CREATE TABLE IF NOT EXISTS posts (
 id TEXT PRIMARY KEY,
 user_id TEXT NOT NULL,
 content TEXT NOT NULL,
 visibility TEXT DEFAULT 'public',
 created_at TEXT NOT NULL
)`,
`CREATE TABLE IF NOT EXISTS comments (
 id TEXT PRIMARY KEY,
 post_id TEXT NOT NULL,
 user_id TEXT NOT NULL,
 content TEXT NOT NULL,
 created_at TEXT NOT NULL
)`,
`CREATE TABLE IF NOT EXISTS likes (
 id TEXT PRIMARY KEY,
 post_id TEXT NOT NULL,
 user_id TEXT NOT NULL,
 created_at TEXT NOT NULL,
 UNIQUE(post_id,user_id)
)`,
`CREATE TABLE IF NOT EXISTS friendships (
 id TEXT PRIMARY KEY,
 requester_id TEXT NOT NULL,
 receiver_id TEXT NOT NULL,
 status TEXT DEFAULT 'pending',
 created_at TEXT NOT NULL,
 UNIQUE(requester_id,receiver_id)
)`,
`CREATE TABLE IF NOT EXISTS messages (
 id TEXT PRIMARY KEY,
 sender_id TEXT NOT NULL,
 receiver_id TEXT NOT NULL,
 content TEXT NOT NULL,
 read_at TEXT,
 created_at TEXT NOT NULL
)`,
`CREATE TABLE IF NOT EXISTS notifications (
 id TEXT PRIMARY KEY,
 user_id TEXT NOT NULL,
 actor_id TEXT,
 type TEXT NOT NULL,
 message TEXT NOT NULL,
 reference_id TEXT,
 read_at TEXT,
 created_at TEXT NOT NULL
)`,
`CREATE TABLE IF NOT EXISTS listings (
 id TEXT PRIMARY KEY,
 user_id TEXT NOT NULL,
 title TEXT NOT NULL,
 description TEXT DEFAULT '',
 price REAL NOT NULL,
 category TEXT DEFAULT 'General',
 location TEXT DEFAULT '',
 status TEXT DEFAULT 'active',
 created_at TEXT NOT NULL
)`,
`CREATE INDEX IF NOT EXISTS posts_created ON posts(created_at)`,
`CREATE INDEX IF NOT EXISTS comments_post ON comments(post_id)`,
`CREATE INDEX IF NOT EXISTS messages_pair ON messages(sender_id,receiver_id,created_at)`,
`CREATE INDEX IF NOT EXISTS notifications_user ON notifications(user_id,created_at)`,
`CREATE INDEX IF NOT EXISTS listings_created ON listings(created_at)`
];

async function initialize(db) {
  await db.batch(SCHEMA.map(sql => db.prepare(sql)));
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS });
    }

    try {
      if (!env.DB) return reply({ error: "Database binding DB is missing." }, 500);

      const db = env.DB;
      await initialize(db);

      const url = new URL(request.url);
      const path = url.pathname.replace(/\/+$/, "") || "/";
      const method = request.method;

      const body = async () => request.json();
      const user = await authenticate(request, db);

      const requireUser = () => {
        if (!user || user.role !== "user") {
          throw Object.assign(new Error("Please log in first."), { status: 401 });
        }
      };

      const requireAdmin = () => {
        if (!user || user.role !== "admin") {
          throw Object.assign(new Error("Administrator access required."), { status: 403 });
        }
      };

      async function notify(userId, actorId, type, message, referenceId = null) {
        await db.prepare(
          "INSERT INTO notifications (id,user_id,actor_id,type,message,reference_id,created_at) VALUES (?,?,?,?,?,?,?)"
        ).bind(id(), userId, actorId, type, message, referenceId, now()).run();
      }

      // HEALTH CHECK
      if (path === "/" || path === "/api") {
        return reply({
          success: true,
          platform: "PlanetSurfX",
          version: "1.0",
          status: "operational"
        });
      }

      // USER REGISTRATION
      if (path === "/api/register" && method === "POST") {
        const b = await body();
        const username = String(b.username || "").trim().toLowerCase();
        const fullName = String(b.full_name || "").trim();
        const password = String(b.password || "");

        if (!username || !fullName || password.length < 8) {
          return reply({ error: "Provide username, full name and a password of at least 8 characters." }, 400);
        }

        if (!/^[a-z0-9_]{3,30}$/.test(username)) {
          return reply({ error: "Username must contain 3–30 letters, numbers or underscores." }, 400);
        }

        const email = b.email ? String(b.email).trim().toLowerCase() : null;

        const existing = await db.prepare(
          "SELECT id FROM users WHERE username=? OR (? IS NOT NULL AND email=?)"
        ).bind(username, email, email).first();

        if (existing) return reply({ error: "Username or email already exists." }, 409);

        const uid = id();
        await db.prepare(
          "INSERT INTO users (id,username,email,password_hash,full_name,created_at) VALUES (?,?,?,?,?,?)"
        ).bind(uid, username, email, await passwordHash(password), fullName, now()).run();

        const token = await createSession(db, uid);
        return reply({
          success: true,
          message: "Account created.",
          token,
          user: { id: uid, username, full_name: fullName }
        }, 201);
      }

      // USER LOGIN
      if (path === "/api/login" && method === "POST") {
        const b = await body();
        const login = String(b.username || "").trim().toLowerCase();
        const account = await db.prepare(
          "SELECT * FROM users WHERE username=? OR email=?"
        ).bind(login, login).first();

        if (!account || !(await verifyPassword(String(b.password || ""), account.password_hash))) {
          return reply({ error: "Incorrect username or password." }, 401);
        }

        if (account.status !== "active") return reply({ error: "Account unavailable." }, 403);

        const token = await createSession(db, account.id);
        return reply({
          success: true,
          token,
          user: {
            id: account.id,
            username: account.username,
            full_name: account.full_name,
            avatar: account.avatar
          }
        });
      }

      // ADMIN INITIAL SETUP
      if (path === "/api/admin/setup" && method === "POST") {
        if (!env.ADMIN_SETUP_KEY) return reply({ error: "ADMIN_SETUP_KEY is not configured." }, 500);

        if (request.headers.get("X-Admin-Setup-Key") !== env.ADMIN_SETUP_KEY) {
          return reply({ error: "Invalid setup key." }, 403);
        }

        const count = await db.prepare("SELECT COUNT(*) AS total FROM admins").first();
        if (count.total > 0) return reply({ error: "Administrator already exists." }, 409);

        const b = await body();
        const username = String(b.username || "").trim();
        const password = String(b.password || "");

        if (!username || password.length < 12) {
          return reply({ error: "Username required. Admin password must be at least 12 characters." }, 400);
        }

        const aid = id();
        await db.prepare(
          "INSERT INTO admins (id,username,password_hash,created_at) VALUES (?,?,?,?)"
        ).bind(aid, username, await passwordHash(password), now()).run();

        return reply({ success: true, message: "Administrator created. You can now log in." }, 201);
      }

      // ADMIN LOGIN
      if (path === "/api/admin/login" && method === "POST") {
        const b = await body();
        const admin = await db.prepare(
          "SELECT * FROM admins WHERE username=?"
        ).bind(String(b.username || "").trim()).first();

        if (!admin || !(await verifyPassword(String(b.password || ""), admin.password_hash))) {
          return reply({ error: "Invalid administrator credentials." }, 401);
        }

        const token = await createSession(db, admin.id, "admin");
        return reply({ success: true, token, admin: { id: admin.id, username: admin.username } });
      }

      // LOGOUT
      if (path === "/api/logout" && method === "POST") {
        if (user?.token_hash) {
          await db.prepare("DELETE FROM sessions WHERE token_hash=?").bind(user.token_hash).run();
        }
        return reply({ success: true, message: "Logged out." });
      }

      // CURRENT PROFILE
      if (path === "/api/me" && method === "GET") {
        if (!user) return reply({ authenticated: false });
        return reply({
          authenticated: true,
          role: user.role,
          profile: {
            id: user.id,
            username: user.username,
            full_name: user.full_name || user.username,
            bio: user.bio || "",
            avatar: user.avatar || "",
            cover: user.cover || "",
            location: user.location || ""
          }
        });
      }

      // UPDATE PROFILE
      if (path === "/api/profile" && method === "PATCH") {
        requireUser();
        const b = await body();
        const fullName = String(b.full_name ?? user.full_name).trim();
        const bio = String(b.bio ?? user.bio ?? "").slice(0, 500);
        const avatar = String(b.avatar ?? user.avatar ?? "").slice(0, 2000);
        const cover = String(b.cover ?? user.cover ?? "").slice(0, 2000);
        const location = String(b.location ?? user.location ?? "").slice(0, 150);

        await db.prepare(
          "UPDATE users SET full_name=?,bio=?,avatar=?,cover=?,location=? WHERE id=?"
        ).bind(fullName, bio, avatar, cover, location, user.id).run();

        return reply({ success: true });
      }

      // PUBLIC USER PROFILE
      if (path.startsWith("/api/users/") && method === "GET") {
        const username = path.split("/").pop().toLowerCase();
        const profile = await db.prepare(
          "SELECT id,username,full_name,bio,avatar,cover,location,created_at FROM users WHERE username=? AND status='active'"
        ).bind(username).first();

        if (!profile) return reply({ error: "User not found." }, 404);

        const counts = await db.prepare(
          "SELECT (SELECT COUNT(*) FROM posts WHERE user_id=?) AS posts,(SELECT COUNT(*) FROM friendships WHERE receiver_id=? AND status='accepted') AS followers"
        ).bind(profile.id, profile.id).first();

        return reply({ profile, counts });
      }

      // CREATE POST
      if (path === "/api/posts" && method === "POST") {
        requireUser();
        const b = await body();
        const content = String(b.content || "").trim();
        if (!content || content.length > 10000) {
          return reply({ error: "Post must contain 1–10,000 characters." }, 400);
        }

        const postId = id();
        await db.prepare(
          "INSERT INTO posts (id,user_id,content,visibility,created_at) VALUES (?,?,?,?,?)"
        ).bind(postId, user.id, content,
          ["public", "friends"].includes(b.visibility) ? b.visibility : "public", now()).run();

        return reply({ success: true, post_id: postId }, 201);
      }

      // FEED
      if (path === "/api/feed" && method === "GET") {
        const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || 30), 1), 100);
        const posts = await db.prepare(
          `SELECT p.id,p.content,p.visibility,p.created_at,
          u.id AS user_id,u.username,u.full_name,u.avatar,
          (SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id) AS likes,
          (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id) AS comments
          FROM posts p JOIN users u ON u.id=p.user_id
          WHERE p.visibility='public' AND u.status='active'
          ORDER BY p.created_at DESC LIMIT ?`
        ).bind(limit).all();

        return reply({ posts: posts.results });
      }

      // DELETE OWN POST
      if (path.startsWith("/api/posts/") && method === "DELETE") {
        requireUser();
        const postId = path.split("/").pop();
        const result = await db.prepare(
          "DELETE FROM posts WHERE id=? AND user_id=?"
        ).bind(postId, user.id).run();

        return reply({ success: result.meta.changes > 0 });
      }

      // POST COMMENTS
      if (path.startsWith("/api/posts/") && path.endsWith("/comments")) {
        requireUser();
        const postId = path.split("/")[3];

        if (method === "GET") {
          const comments = await db.prepare(
            `SELECT c.id,c.content,c.created_at,u.username,u.full_name,u.avatar
             FROM comments c JOIN users u ON u.id=c.user_id
             WHERE c.post_id=? ORDER BY c.created_at ASC`
          ).bind(postId).all();

          return reply({ comments: comments.results });
        }

        if (method === "POST") {
          const b = await body();
          const content = String(b.content || "").trim();
          if (!content || content.length > 3000) return reply({ error: "Invalid comment." }, 400);

          const post = await db.prepare("SELECT user_id FROM posts WHERE id=?").bind(postId).first();
          if (!post) return reply({ error: "Post not found." }, 404);

          const commentId = id();
          await db.prepare(
            "INSERT INTO comments (id,post_id,user_id,content,created_at) VALUES (?,?,?,?,?)"
          ).bind(commentId, postId, user.id, content, now()).run();

          if (post.user_id !== user.id) await notify(post.user_id, user.id, "comment", "Commented on your post.", postId);

          return reply({ success: true, comment_id: commentId }, 201);
        }
      }

      // LIKE / UNLIKE
      if (path.startsWith("/api/posts/") && path.endsWith("/like") && method === "POST") {
        requireUser();
        const postId = path.split("/")[3];
        const existing = await db.prepare(
          "SELECT id FROM likes WHERE post_id=? AND user_id=?"
        ).bind(postId, user.id).first();

        if (existing) {
          await db.prepare("DELETE FROM likes WHERE id=?").bind(existing.id).run();
          return reply({ success: true, liked: false });
        }

        const post = await db.prepare("SELECT user_id FROM posts WHERE id=?").bind(postId).first();
        if (!post) return reply({ error: "Post not found." }, 404);

        await db.prepare(
          "INSERT INTO likes (id,post_id,user_id,created_at) VALUES (?,?,?,?)"
        ).bind(id(), postId, user.id, now()).run();

        if (post.user_id !== user.id) await notify(post.user_id, user.id, "like", "Liked your post.", postId);

        return reply({ success: true, liked: true });
      }

      // FRIEND REQUEST
      if (path === "/api/friends/request" && method === "POST") {
        requireUser();
        const b = await body();
        const target = await db.prepare(
          "SELECT id FROM users WHERE username=? AND status='active'"
        ).bind(String(b.username || "").toLowerCase()).first();

        if (!target || target.id === user.id) return reply({ error: "Invalid friend." }, 400);

        const existing = await db.prepare(
          "SELECT id FROM friendships WHERE (requester_id=? AND receiver_id=?) OR (requester_id=? AND receiver_id=?)"
        ).bind(user.id, target.id, target.id, user.id).first();

        if (existing) return reply({ error: "Friendship request already exists." }, 409);

        await db.prepare(
          "INSERT INTO friendships (id,requester_id,receiver_id,status,created_at) VALUES (?,?,?,'pending',?)"
        ).bind(id(), user.id, target.id, now()).run();

        await notify(target.id, user.id, "friend_request", "Sent you a friend request.");

        return reply({ success: true }, 201);
      }

      // ACCEPT FRIEND REQUEST
      if (path === "/api/friends/accept" && method === "POST") {
        requireUser();
        const b = await body();
        const result = await db.prepare(
          "UPDATE friendships SET status='accepted' WHERE id=? AND receiver_id=? AND status='pending'"
        ).bind(b.request_id, user.id).run();

        if (!result.meta.changes) return reply({ error: "Request not found." }, 404);

        const request = await db.prepare("SELECT requester_id FROM friendships WHERE id=?").bind(b.request_id).first();
        await notify(request.requester_id, user.id, "friend_accepted", "Accepted your friend request.");

        return reply({ success: true });
      }

      // FRIEND REQUESTS
      if (path === "/api/friends/requests" && method === "GET") {
        requireUser();
        const requests = await db.prepare(
          `SELECT f.id,f.created_at,u.username,u.full_name,u.avatar
           FROM friendships f JOIN users u ON u.id=f.requester_id
           WHERE f.receiver_id=? AND f.status='pending'
           ORDER BY f.created_at DESC`
        ).bind(user.id).all();

        return reply({ requests: requests.results });
      }

      // FRIENDS LIST
      if (path === "/api/friends" && method === "GET") {
        requireUser();
        const friends = await db.prepare(
          `SELECT u.id,u.username,u.full_name,u.avatar
           FROM friendships f JOIN users u
           ON u.id=CASE WHEN f.requester_id=? THEN f.receiver_id ELSE f.requester_id END
           WHERE (f.requester_id=? OR f.receiver_id=?) AND f.status='accepted'`
        ).bind(user.id, user.id, user.id).all();

        return reply({ friends: friends.results });
      }

      // SEND MESSAGE
      if (path === "/api/messages" && method === "POST") {
        requireUser();
        const b = await body();
        const receiver = await db.prepare(
          "SELECT id FROM users WHERE username=? AND status='active'"
        ).bind(String(b.username || "").toLowerCase()).first();

        const content = String(b.content || "").trim();
        if (!receiver || receiver.id === user.id || !content || content.length > 5000) {
          return reply({ error: "Invalid message or recipient." }, 400);
        }

        const messageId = id();
        await db.prepare(
          "INSERT INTO messages (id,sender_id,receiver_id,content,created_at) VALUES (?,?,?,?,?)"
        ).bind(messageId, user.id, receiver.id, content, now()).run();

        await notify(receiver.id, user.id, "message", "Sent you a message.", messageId);

        return reply({ success: true, message_id: messageId }, 201);
      }

      // CONVERSATION
      if (path === "/api/messages" && method === "GET") {
        requireUser();
        const other = url.searchParams.get("username");
        if (!other) return reply({ error: "Specify a username." }, 400);

        const target = await db.prepare("SELECT id FROM users WHERE username=?").bind(other.toLowerCase()).first();
        if (!target) return reply({ error: "User not found." }, 404);

        const messages = await db.prepare(
          `SELECT * FROM messages
           WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?)
           ORDER BY created_at ASC LIMIT 200`
        ).bind(user.id, target.id, target.id, user.id).all();

        await db.prepare(
          "UPDATE messages SET read_at=? WHERE sender_id=? AND receiver_id=? AND read_at IS NULL"
        ).bind(now(), target.id, user.id).run();

        return reply({ messages: messages.results });
      }

      // NOTIFICATIONS
      if (path === "/api/notifications" && method === "GET") {
        requireUser();
        const items = await db.prepare(
          "SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 100"
        ).bind(user.id).all();

        return reply({ notifications: items.results });
      }

      if (path === "/api/notifications/read" && method === "POST") {
        requireUser();
        await db.prepare(
          "UPDATE notifications SET read_at=? WHERE user_id=? AND read_at IS NULL"
        ).bind(now(), user.id).run();

        return reply({ success: true });
      }

      // MARKETPLACE: CREATE LISTING
      if (path === "/api/marketplace" && method === "POST") {
        requireUser();
        const b = await body();
        const title = String(b.title || "").trim();
        const price = Number(b.price);

        if (!title || title.length > 150 || !Number.isFinite(price) || price < 0) {
          return reply({ error: "Provide a valid title and price." }, 400);
        }

        const listingId = id();
        await db.prepare(
          "INSERT INTO listings (id,user_id,title,description,price,category,location,created_at) VALUES (?,?,?,?,?,?,?,?)"
        ).bind(listingId, user.id, title,
          String(b.description || "").slice(0, 3000), price,
          String(b.category || "General").slice(0, 80),
          String(b.location || "").slice(0, 150), now()).run();

        return reply({ success: true, listing_id: listingId }, 201);
      }

      // MARKETPLACE: VIEW LISTINGS
      if (path === "/api/marketplace" && method === "GET") {
        const listings = await db.prepare(
          `SELECT l.*,u.username,u.full_name,u.avatar
           FROM listings l JOIN users u ON u.id=l.user_id
           WHERE l.status='active' AND u.status='active'
           ORDER BY l.created_at DESC LIMIT 100`
        ).all();

        return reply({ listings: listings.results });
      }

      // ADMIN DASHBOARD
      if (path === "/api/admin/dashboard" && method === "GET") {
        requireAdmin();

        const [users, posts, listings, messages] = await Promise.all([
          db.prepare("SELECT COUNT(*) AS total FROM users").first(),
          db.prepare("SELECT COUNT(*) AS total FROM posts").first(),
          db.prepare("SELECT COUNT(*) AS total FROM listings").first(),
          db.prepare("SELECT COUNT(*) AS total FROM messages").first()
        ]);

        return reply({
          users: users.total,
          posts: posts.total,
          listings: listings.total,
          messages: messages.total
        });
      }

      // ADMIN USER LIST
      if (path === "/api/admin/users" && method === "GET") {
        requireAdmin();
        const results = await db.prepare(
          "SELECT id,username,email,full_name,status,created_at FROM users ORDER BY created_at DESC LIMIT 200"
        ).all();

        return reply({ users: results.results });
      }

      // ADMIN SUSPEND / ACTIVATE USER
      if (path.startsWith("/api/admin/users/") && method === "PATCH") {
        requireAdmin();
        const targetId = path.split("/").pop();
        const b = await body();

        if (!["active", "suspended"].includes(b.status)) {
          return reply({ error: "Invalid status." }, 400);
        }

        await db.prepare("UPDATE users SET status=? WHERE id=?")
          .bind(b.status, targetId).run();

        if (b.status === "suspended") {
          await db.prepare("DELETE FROM sessions WHERE user_id=? AND role='user'")
            .bind(targetId).run();
        }

        return reply({ success: true });
      }

      // ADMIN REMOVE POST
      if (path.startsWith("/api/admin/posts/") && method === "DELETE") {
        requireAdmin();
        const postId = path.split("/").pop();
        await db.prepare("DELETE FROM comments WHERE post_id=?").bind(postId).run();
        await db.prepare("DELETE FROM likes WHERE post_id=?").bind(postId).run();
        await db.prepare("DELETE FROM posts WHERE id=?").bind(postId).run();

        return reply({ success: true });
      }

      return reply({ error: "Endpoint not found." }, 404);

    } catch (error) {
      return reply({
        error: error.message || "Internal server error."
      }, error.status || 500);
    }
  }
};
