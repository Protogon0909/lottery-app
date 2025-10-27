import json
from os import environ as env
from urllib.parse import quote_plus, urlencode

from flask import Flask, render_template, redirect, session, url_for, request
from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv

import sqlite3, os
from random import sample
import uuid
import qrcode
from io import BytesIO
from flask import send_file

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")

# --- OAuth client ---
oauth = OAuth(app)
oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration'
)

DB_NAME = os.path.join(os.getcwd(), "lottery.db")

# --- DATABASE SETUP ---
def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS bets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        numbers TEXT,
                        ticket_code TEXT UNIQUE,
                        round_id INTEGER,
                        id_number TEXT,
                        FOREIGN KEY(round_id) REFERENCES rounds(id)
                    )''')
        c.execute('''CREATE TABLE IF NOT EXISTS rounds (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        betting_open INTEGER DEFAULT 0,
                        drawn_numbers TEXT
                    )''')
        conn.commit()

@app.before_request
def before_request():
    init_db()


# --- ROUTES ---

@app.route("/")
def home():
    user=session.get('user')
    return render_template("home.html", user=user, pretty=json.dumps(user, indent=4))

@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    userinfo = token['userinfo']
    roles = userinfo.get("https://marko-lottery-app.com/roles", [])

    session["user"] = {
        'id': userinfo['sub'],
        'username': userinfo.get('nickname'),
        'is_admin': 'Admin' in roles
    }
    return redirect("/")

@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://" + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )



@app.route('/bet', methods=['GET', 'POST'])
def bet():
    if 'user' not in session:
        return redirect('/login')
    user = session['user']

    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("SELECT id, betting_open FROM rounds WHERE betting_open=1 ORDER BY id DESC LIMIT 1")
        round_row = c.fetchone()

    if not round_row:
            betting_open = 0
            round_id = None
    else:
        round_id, betting_open = round_row

    error = None
    success = None

    if request.method == 'POST' and betting_open == 1:
        id_number = request.form.get('id_number', '').strip()
        numbers_str = request.form.get('numbers', '').strip()

        # --- validate ID ---
        if not id_number:
            error = "ID/passport cannot be empty."
        elif len(id_number) > 20:
            error = "ID/passport cannot exceed 20 characters."
        else:
            try:
                numbers = [int(n.strip()) for n in numbers_str.split(',')]
            except:
                error = "Numbers must be integers separated by commas."
            
            # --- validate numbers ---
            if not error:
                if len(numbers) < 6 or len(numbers) > 10:
                    error = "You must enter 6–10 numbers."
                elif any(n < 1 or n > 45 for n in numbers):
                    error = "Numbers must be between 1 and 45."
                elif len(set(numbers)) != len(numbers):
                    error = "Numbers cannot have duplicates."

        # --- store bet ---
        if not error:
            ticket_uuid = str(uuid.uuid4())
            with sqlite3.connect(DB_NAME) as conn:
                c = conn.cursor()
                c.execute("""
                    INSERT INTO bets (user_id, numbers, ticket_code, round_id, id_number)
                    VALUES (?,?,?,?,?)
                """, (user['id'], ','.join(map(str, numbers)), ticket_uuid, round_id, id_number))
                conn.commit()
                success = "Bet successfully placed!"

                qr_url = url_for('ticket', ticket_code=ticket_uuid, _external=True)
                img = qrcode.make(qr_url)
                buf = BytesIO()
                img.save(buf)
                buf.seek(0)
                return send_file(buf, mimetype='image/png')

    return render_template('bet.html', user=user, betting_open=betting_open, error=error, success=success)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'user' not in session or session['user']['is_admin'] == 0:
        return redirect('/')
    
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("SELECT id, betting_open FROM rounds ORDER BY id DESC LIMIT 1")
        round_row = c.fetchone()

    round_id = round_row[0] if round_row else None
    betting_open = round_row[1] if round_row else 0

    return render_template('admin.html', round_id=round_id, betting_open=betting_open)

@app.route('/new-round', methods=['POST'])
def new_round():
    if 'user' not in session or not session['user'].get('is_admin'):
        return "Forbidden", 403

    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM rounds WHERE betting_open=1")
        active_round = c.fetchone()

        if active_round:
            return '', 204

        c.execute("INSERT INTO rounds (betting_open) VALUES (1)")
        conn.commit()

    return redirect('/admin')

@app.route('/close', methods=['POST'])
def close_round():
    if 'user' not in session or not session['user'].get('is_admin'):
        return "Forbidden", 403

    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM rounds WHERE betting_open=1 ORDER BY id DESC LIMIT 1")
        row = c.fetchone()

        if not row:
            return '', 204

        round_id = row[0]
        drawn_numbers = ','.join(map(str, sample(range(1, 46), 6)))

        c.execute("UPDATE rounds SET betting_open=0, drawn_numbers=? WHERE id=?", (drawn_numbers, round_id))
        conn.commit()

    return redirect('/admin')

@app.route('/ticket/<ticket_code>')
def ticket(ticket_code):
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("""SELECT b.numbers, r.drawn_numbers, r.id 
                     FROM bets b JOIN rounds r ON b.round_id=r.id 
                     WHERE b.ticket_code=?""", (ticket_code,))
        row = c.fetchone()
        if not row:
            return "Ticket not found", 404
        ticket_numbers, drawn_numbers, round_id = row

    return render_template('ticket.html', ticket_numbers=ticket_numbers.split(','),
                           drawn_numbers=(drawn_numbers.split(',') if drawn_numbers else []),
                           round_id=round_id)

@app.route("/my-bets")
def my_bets():
    if 'user' not in session:
        return redirect('/login')
    
    user = session['user']
    with sqlite3.connect(DB_NAME) as conn:
        c = conn.cursor()
        c.execute("SELECT ticket_code, round_id FROM bets WHERE user_id=?", (user['id'],))
        bets = c.fetchall()

    return render_template("my_bets.html", bets=bets)
    


if __name__ == '__main__':
    app.run(debug=True)