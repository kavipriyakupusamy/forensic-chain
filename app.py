import os
from datetime import datetime
from functools import wraps

from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, send_file, jsonify, abort)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import database as db
from blockchain import Blockchain, hash_file

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-secret-change-in-production")
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB per upload

# ---------------------------------------------------------------- users
USERS = {
    "admin": {"name": "Admin", "role": "Administrator", "password": generate_password_hash("admin123")},
    "ravi": {"name": "Ravi", "role": "Investigator", "password": generate_password_hash("ravi123")},
    "kumar": {"name": "Kumar", "role": "Lab Technician", "password": generate_password_hash("kumar123")},
    "priya": {"name": "Priya", "role": "Forensic Analyst", "password": generate_password_hash("priya123")},
    "judge": {"name": "Judge", "role": "Court Officer", "password": generate_password_hash("judge123")},
}
UPLOAD_ROLES = {"Administrator", "Investigator"}
ACTIONS = {
    "TRANSFERRED": "Transferred",
    "ANALYZED": "Sent for analysis",
    "STORED": "Placed in storage",
    "PRESENTED": "Presented in court",
    "RELEASED": "Released / returned",
}


def label(username):
    u = USERS.get(username)
    return f"{u['name']} ({u['role']})" if u else str(username)


def short_name(username):
    u = USERS.get(username)
    return u["name"] if u else str(username)


def human_size(n):
    n = n or 0
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


app.jinja_env.globals.update(label=label, short_name=short_name, ACTIONS=ACTIONS)
app.jinja_env.filters["size"] = human_size
app.jinja_env.filters["short"] = lambda h, n=12: (h[:n] + "…" + h[-6:]) if h and len(h) > n + 6 else h


# ---------------------------------------------------------------- helpers
def bootstrap():
    db.init_db()
    if not db.load_blocks():
        db.save_block(Blockchain().chain[0])


bootstrap()


def get_chain():
    return Blockchain.from_rows(db.load_blocks())


def file_path(ev):
    return os.path.join(UPLOAD_FOLDER, ev["filepath"])


def file_status(ev):
    """Return (state, current_hash). state: intact | tampered | missing."""
    path = file_path(ev)
    if not os.path.exists(path):
        return "missing", None
    current = hash_file(path)
    return ("intact" if current == ev["sha256"] else "tampered"), current


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    @login_required
    def wrapper(*args, **kwargs):
        if USERS[session["user"]]["role"] != "Administrator":
            flash("Only the administrator can open the Tamper Lab.", "error")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return wrapper


@app.context_processor
def inject_user():
    user = session.get("user")
    return {"current_user": USERS.get(user), "current_username": user}


# ---------------------------------------------------------------- auth
@app.route("/")
def index():
    return redirect(url_for("dashboard") if "user" in session else url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        user = USERS.get(username)
        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user"] = username
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "error")
    return render_template("login.html", demo_users=USERS)


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("login"))


# ---------------------------------------------------------------- pages
@app.route("/dashboard")
@login_required
def dashboard():
    bc = get_chain()
    valid, bad_index = bc.is_chain_valid()
    evidence = db.get_all_evidence()
    for e in evidence:
        e["state"], _ = file_status(e)
    mine = [e for e in evidence if e["current_holder"] == session["user"]]
    recent = [b.to_dict() for b in reversed(bc.chain[-6:])]
    return render_template(
        "dashboard.html", evidence=evidence, mine=len(mine), valid=valid,
        bad_index=bad_index, total_blocks=len(bc.chain), recent=recent,
        tampered_files=sum(1 for e in evidence if e["state"] != "intact"),
    )


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    role = USERS[session["user"]]["role"]
    if role not in UPLOAD_ROLES:
        flash("Only Investigators and the Administrator can register new evidence.", "error")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        file = request.files.get("file")
        description = request.form.get("description", "").strip()
        if not file or file.filename == "":
            flash("Please choose an evidence file.", "error")
            return redirect(url_for("upload"))

        bc = get_chain()
        valid, bad_index = bc.is_chain_valid()
        if not valid:
            flash(f"Blockchain is tampered at block #{bad_index}. New evidence cannot be added until it is investigated.", "error")
            return redirect(url_for("chain"))

        evidence_id = f"EV{db.count_evidence() + 1:03d}"
        filename = secure_filename(file.filename) or "evidence_file"
        stored_name = f"{evidence_id}_{filename}"
        path = os.path.join(UPLOAD_FOLDER, stored_name)
        file.save(path)
        sha = hash_file(path)
        size = os.path.getsize(path)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        user = session["user"]

        db.save_evidence(evidence_id, filename, stored_name, sha, user,
                         description, now, size)
        block = bc.add_block(evidence_id, "COLLECTED", label(user), label(user),
                             sha, description or "Evidence collected")
        db.save_block(block)
        flash(f"{evidence_id} registered. Its SHA-256 fingerprint is now sealed in block #{block.index}.", "success")
        return redirect(url_for("evidence_detail", evidence_id=evidence_id))
    return render_template("upload.html")


@app.route("/evidence/<evidence_id>")
@login_required
def evidence_detail(evidence_id):
    ev = db.get_evidence(evidence_id)
    if not ev:
        abort(404)
    bc = get_chain()
    valid, bad_index = bc.is_chain_valid()
    history = bc.get_evidence_history(evidence_id)
    state, current_hash = file_status(ev)
    return render_template(
        "evidence.html", ev=ev, history=history, valid=valid, bad_index=bad_index,
        state=state, current_hash=current_hash,
        can_transfer=(ev["current_holder"] == session["user"]),
    )


@app.route("/transfer/<evidence_id>", methods=["GET", "POST"])
@login_required
def transfer(evidence_id):
    ev = db.get_evidence(evidence_id)
    if not ev:
        abort(404)
    user = session["user"]
    if ev["current_holder"] != user:
        flash("Only the current custodian can hand over this evidence.", "error")
        return redirect(url_for("evidence_detail", evidence_id=evidence_id))

    if request.method == "POST":
        to_user = request.form.get("to_user")
        action = request.form.get("action")
        notes = request.form.get("notes", "").strip()

        if to_user not in USERS or to_user == user or action not in ACTIONS:
            flash("Invalid transfer details.", "error")
            return redirect(url_for("transfer", evidence_id=evidence_id))

        state, _ = file_status(ev)
        if state != "intact":
            flash(f"Transfer blocked: the evidence file is {state}. Its hash no longer matches the sealed original.", "error")
            return redirect(url_for("evidence_detail", evidence_id=evidence_id))

        bc = get_chain()
        valid, bad_index = bc.is_chain_valid()
        if not valid:
            flash(f"Transfer blocked: blockchain is tampered at block #{bad_index}.", "error")
            return redirect(url_for("chain"))

        block = bc.add_block(evidence_id, action, label(user), label(to_user),
                             ev["sha256"], notes or ACTIONS[action])
        db.save_block(block)
        db.update_holder(evidence_id, to_user)
        flash(f"Custody of {evidence_id} passed to {label(to_user)} (block #{block.index}).", "success")
        return redirect(url_for("evidence_detail", evidence_id=evidence_id))

    others = {u: label(u) for u in USERS if u != user}
    return render_template("transfer.html", ev=ev, users=others)


@app.route("/verify/<evidence_id>")
@login_required
def verify(evidence_id):
    ev = db.get_evidence(evidence_id)
    if not ev:
        abort(404)
    state, _ = file_status(ev)
    valid, bad_index = get_chain().is_chain_valid()
    if state == "intact" and valid:
        flash(f"{evidence_id} VERIFIED: file hash matches the sealed original and the blockchain is intact.", "success")
    else:
        if state != "intact":
            flash(f"{evidence_id}: evidence file is {state.upper()}. Current hash differs from the sealed original.", "error")
        if not valid:
            flash(f"Blockchain TAMPERED at block #{bad_index}.", "error")
    return redirect(url_for("evidence_detail", evidence_id=evidence_id))


@app.route("/download/<evidence_id>")
@login_required
def download(evidence_id):
    ev = db.get_evidence(evidence_id)
    if not ev or not os.path.exists(file_path(ev)):
        abort(404)
    return send_file(file_path(ev), as_attachment=True, download_name=ev["filename"])


@app.route("/chain")
@login_required
def chain():
    bc = get_chain()
    valid, bad_index = bc.is_chain_valid()
    blocks = [b.to_dict() for b in bc.chain]
    return render_template("chain.html", blocks=blocks, valid=valid, bad_index=bad_index)


@app.route("/api/chain")
@login_required
def api_chain():
    bc = get_chain()
    valid, bad_index = bc.is_chain_valid()
    return jsonify({"valid": valid, "bad_index": bad_index,
                    "length": len(bc.chain),
                    "chain": [b.to_dict() for b in bc.chain]})


# ---------------------------------------------------------------- tamper lab
@app.route("/lab")
@admin_required
def lab():
    bc = get_chain()
    valid, bad_index = bc.is_chain_valid()
    evidence = db.get_all_evidence()
    for e in evidence:
        e["state"], _ = file_status(e)
    return render_template("lab.html", blocks=[b.to_dict() for b in bc.chain],
                           evidence=evidence, valid=valid, bad_index=bad_index)


@app.route("/lab/tamper-block", methods=["POST"])
@admin_required
def lab_tamper_block():
    try:
        index = int(request.form.get("block_index", ""))
    except ValueError:
        flash("Enter a valid block number.", "error")
        return redirect(url_for("lab"))
    db.tamper_block_directly(index)
    flash(f"Simulated attack: block #{index} was edited directly in the database. Open the Blockchain page to see it detected.", "info")
    return redirect(url_for("lab"))


@app.route("/lab/tamper-file", methods=["POST"])
@admin_required
def lab_tamper_file():
    ev = db.get_evidence(request.form.get("evidence_id", ""))
    if not ev or not os.path.exists(file_path(ev)):
        flash("Evidence file not found.", "error")
        return redirect(url_for("lab"))
    with open(file_path(ev), "ab") as f:
        f.write(b"\n# modified by attacker\n")
    flash(f"Simulated attack: bytes were appended to {ev['evidence_id']}. Run Verify on it to see the mismatch.", "info")
    return redirect(url_for("lab"))


@app.route("/lab/reset", methods=["POST"])
@admin_required
def lab_reset():
    db.reset_all()
    for name in os.listdir(UPLOAD_FOLDER):
        p = os.path.join(UPLOAD_FOLDER, name)
        if os.path.isfile(p):
            os.remove(p)
    bootstrap()
    flash("Demo data reset. A fresh genesis block was created.", "success")
    return redirect(url_for("dashboard"))


@app.errorhandler(404)
def not_found(_e):
    return render_template("404.html"), 404


@app.errorhandler(413)
def too_large(_e):
    flash("File is too large (limit 25 MB).", "error")
    return redirect(url_for("upload"))


if __name__ == "__main__":
    app.run(debug=True)
