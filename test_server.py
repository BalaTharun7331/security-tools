"""
Local vulnerable test server for XSS scanner testing
Run: python test_server.py
Open: http://localhost:8888
"""
from flask import Flask, request, render_template_string

app = Flask(__name__)

HOME = """
<!DOCTYPE html>
<html>
<head><title>Vulnerable Test App</title>
<style>
body{font-family:sans-serif;max-width:800px;margin:40px auto;background:#1a1a1a;color:#eee;padding:20px}
h1{color:#ff4444}
.box{background:#222;padding:20px;border-radius:8px;margin:20px 0}
input{padding:8px;width:300px;background:#333;border:1px solid #555;color:#eee;border-radius:4px}
button{padding:8px 16px;background:#ff4444;color:#fff;border:none;border-radius:4px;cursor:pointer}
a{color:#00ff88;display:block;margin:8px 0}
</style>
</head>
<body>
<h1>🎯 XSS Vulnerable Test App</h1>
<p>This app is intentionally vulnerable for testing purposes.</p>

<div class="box">
  <h2>1. Reflected XSS — Search</h2>
  <form method="GET" action="/search">
    <input name="q" placeholder="Search something..."/>
    <button type="submit">Search</button>
  </form>
</div>

<div class="box">
  <h2>2. Reflected XSS — Login Form</h2>
  <form method="POST" action="/login">
    <input name="username" placeholder="Username"/><br><br>
    <input name="password" type="password" placeholder="Password"/><br><br>
    <button type="submit">Login</button>
  </form>
</div>

<div class="box">
  <h2>3. Reflected XSS — Comment</h2>
  <form method="POST" action="/comment">
    <input name="name" placeholder="Your name"/><br><br>
    <input name="comment" placeholder="Your comment"/><br><br>
    <button type="submit">Post Comment</button>
  </form>
</div>

<div class="box">
  <h2>4. URL Parameter XSS</h2>
  <a href="/profile?user=admin">View Profile (click and modify URL)</a>
  <a href="/page?id=1&name=test">Page with params</a>
</div>
</body>
</html>
"""

@app.route("/")
def home():
    return render_template_string(HOME)

@app.route("/search")
def search():
    q = request.args.get("q", "")
    return render_template_string(f"""
    <!DOCTYPE html><html>
    <head><title>Search</title>
    <style>body{{font-family:sans-serif;background:#1a1a1a;color:#eee;padding:40px}}
    .box{{background:#222;padding:20px;border-radius:8px}}
    input{{padding:8px;width:300px;background:#333;border:1px solid #555;color:#eee;border-radius:4px}}
    button{{padding:8px 16px;background:#ff4444;color:#fff;border:none;border-radius:4px;cursor:pointer}}
    a{{color:#00ff88}}</style></head>
    <body>
    <h2>Search Results for: {q}</h2>
    <div class="box">
    <form method="GET" action="/search">
    <input name="q" value="{q}" placeholder="Search..."/>
    <button type="submit">Search</button>
    </form>
    <p>You searched for: {q}</p>
    </div>
    <a href="/">← Back</a>
    </body></html>
    """)

@app.route("/login", methods=["GET", "POST"])
def login():
    username = request.form.get("username", "")
    return render_template_string(f"""
    <!DOCTYPE html><html>
    <head><title>Login</title>
    <style>body{{font-family:sans-serif;background:#1a1a1a;color:#eee;padding:40px}}
    .box{{background:#222;padding:20px;border-radius:8px}}
    input{{padding:8px;width:300px;background:#333;border:1px solid #555;color:#eee;border-radius:4px;display:block;margin:8px 0}}
    button{{padding:8px 16px;background:#ff4444;color:#fff;border:none;border-radius:4px;cursor:pointer}}
    a{{color:#00ff88}}</style></head>
    <body>
    <h2>Login</h2>
    <div class="box">
    <form method="POST" action="/login">
    <input name="username" value="{username}" placeholder="Username"/>
    <input name="password" type="text" placeholder="Password"/>
    <button type="submit">Login</button>
    </form>
    <p>Welcome: {username}</p>
    </div>
    <a href="/">← Back</a>
    </body></html>
    """)

@app.route("/comment", methods=["GET", "POST"])
def comment():
    name    = request.form.get("name", "")
    comment = request.form.get("comment", "")
    return render_template_string(f"""
    <!DOCTYPE html><html>
    <head><title>Comments</title>
    <style>body{{font-family:sans-serif;background:#1a1a1a;color:#eee;padding:40px}}
    .box{{background:#222;padding:20px;border-radius:8px;margin:10px 0}}
    input{{padding:8px;width:300px;background:#333;border:1px solid #555;color:#eee;border-radius:4px;display:block;margin:8px 0}}
    button{{padding:8px 16px;background:#ff4444;color:#fff;border:none;border-radius:4px;cursor:pointer}}
    a{{color:#00ff88}}</style></head>
    <body>
    <h2>Comments</h2>
    <div class="box">
    <form method="POST" action="/comment">
    <input name="name" placeholder="Your name"/>
    <input name="comment" placeholder="Your comment"/>
    <button type="submit">Post</button>
    </form>
    </div>
    <div class="box">
    <p><strong>{name}</strong>: {comment}</p>
    </div>
    <a href="/">← Back</a>
    </body></html>
    """)

@app.route("/profile")
def profile():
    user = request.args.get("user", "guest")
    return render_template_string(f"""
    <!DOCTYPE html><html>
    <head><title>Profile</title>
    <style>body{{font-family:sans-serif;background:#1a1a1a;color:#eee;padding:40px}}
    .box{{background:#222;padding:20px;border-radius:8px}}
    a{{color:#00ff88}}</style></head>
    <body>
    <h2>Profile: {user}</h2>
    <div class="box"><p>Viewing profile of: {user}</p></div>
    <a href="/">← Back</a>
    </body></html>
    """)

@app.route("/page")
def page():
    name = request.args.get("name", "")
    pid  = request.args.get("id", "")
    return render_template_string(f"""
    <!DOCTYPE html><html>
    <head><title>Page {pid}</title>
    <style>body{{font-family:sans-serif;background:#1a1a1a;color:#eee;padding:40px}}
    .box{{background:#222;padding:20px;border-radius:8px}}
    a{{color:#00ff88}}</style></head>
    <body>
    <h2>Page ID: {pid}</h2>
    <div class="box"><p>Hello {name}, you are on page {pid}</p></div>
    <a href="/">← Back</a>
    </body></html>
    """)

if __name__ == "__main__":
    print("[*] Vulnerable test server running at http://localhost:8888")
    app.run(port=8888, debug=False)
