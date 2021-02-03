import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")
# API VALUE -> export API_KEY=pk_20c94b1fe9344cde8084aca23b61ba82
# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    col = db.execute("SELECT * FROM transactions WHERE user_id = :id",
                          id=session["user_id"])
    stocks = 0
    for smb in col:
        uptodatetotal = (lookup(smb["symbol"])["price"]) * smb["shares"]
        stocks += uptodatetotal

    row = db.execute("SELECT * FROM users WHERE id = :id",
                          id=session["user_id"])
    cash = row[0]["cash"]
    grandtotal = stocks + cash

    return render_template("index.html", cash=usd(cash), col=col, lookup=lookup, grandtotal=grandtotal, usd=usd)



@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")

    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("Missing symbol", 400)

        if not lookup(request.form.get("symbol")):
            return apology("INVALID SYMBOL", 400)

        elif not request.form.get("shares"):
            return apology("Enter number of shares", 400)
        else:
            smbl = request.form.get("symbol")
            shares = float(request.form.get("shares"))
            name = lookup(smbl)["name"]
            symbol = lookup(smbl)["symbol"]
            price = lookup(smbl)["price"]
            total = price * shares
            row = db.execute("SELECT * FROM users WHERE id = :id",
                          id=session["user_id"])
            cash = row[0]["cash"]
            if total > cash:
                return apology("CAN'T AFFORD", 400)
            col = db.execute("SELECT * FROM transactions WHERE user_id = :id",
                          id=session["user_id"])
            i=0
            while i<len(col):
                for line in col:
                    if symbol == line["symbol"]:
                        shares += line["shares"]
                        db.execute("UPDATE transactions SET shares=? WHERE symbol=?", (shares, symbol))
                        rest = cash - total
                        db.execute("UPDATE users SET cash=? WHERE id =?", (rest, session["user_id"]))
                        now = datetime.utcnow()
                        db.execute("INSERT INTO history (user_id, symbol, shares, price, transacted) VALUES (?, ?, ?, ?, ?)",
                                    (session["user_id"], symbol, request.form.get("shares"), price, now))
                        flash('Bought')
                        return redirect("/")
                i += 1
            db.execute("INSERT INTO transactions (user_id, symbol, name, shares) VALUES (?, ?, ?, ?)",
                       (session["user_id"], symbol, name, shares))
            rest = cash - total
            db.execute("UPDATE users SET cash=? WHERE id =?", (rest, session["user_id"]))
            now = datetime.utcnow()
            db.execute("INSERT INTO history (user_id, symbol, shares, price, transacted) VALUES (?, ?, ?, ?, ?)",
                        (session["user_id"], symbol, shares, price, now))
            flash('Bought')
            return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    histrow = db.execute("SELECT * FROM history WHERE user_id = :id",
                          id=session["user_id"])
    return render_template("history.html", histrow=histrow, usd=usd)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
         return render_template("quote.html")

    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("MISSING SYMBOL", 400)
        if not lookup(request.form.get("symbol")):
            return apology("INVALID SYMBOL", 400)
        else:
            smpl = request.form.get("symbol")
            name = lookup(smpl)["name"]
            symbol = lookup(smpl)["symbol"]
            price = lookup(smpl)["price"]
            return render_template("quoted.html", name=name, symbol=symbol, price=price)



@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Matching passwords
        elif request.form.get("password") != request.form.get("confirm-password"):
            return apology("Passwords don't match", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) >= 1:
            return apology("Username is already registered", 403)

        # Inserting the values into the database
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)",
                       (request.form.get("username"), generate_password_hash(request.form.get("password"))))

        # Redirect user to home page
        return redirect("/login")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    col = db.execute("SELECT * FROM transactions WHERE user_id = :id",
                          id=session["user_id"])

    if request.method == "GET":
         return render_template("sell.html", col=col)

    row = db.execute("SELECT * FROM users WHERE id = :id",
                          id=session["user_id"])

    cash = row[0]["cash"]

    owned = db.execute("SELECT * FROM transactions WHERE user_id = :id AND symbol = :symbol",
                            id = session["user_id"], symbol=request.form.get("symbol"))

    if request.method == "POST":

        if not request.form.get("symbol"):
            return apology("MISSING SYMBOL", 400)

        if not request.form.get("shares"):
            return apology("MISSING SHARES", 400)

        requestshare = float(request.form.get("shares"))
        symb=request.form.get("symbol")
        ownedShares = float(owned[0]["shares"])

        if ownedShares < requestshare:
            return apology("TOO MANY SHARES", 400)

        if requestshare < 1:
            return apology("ENTER A VALID NUMBER OF SHARES", 400)

        else:
            #boughtShares = request.form.get("shares")
            #anotherrow = db.execute("SELECT * FROM transactions WHERE user_id = :id AND symbol= :symbol",
            #                id=session["user_id"], symbol=request.form.get("symbol"))

            price = lookup(symb)["price"]
            #total = owned[0]["total"]
            aftershares = ownedShares - requestshare
            boughtshareprice = requestshare * price
            #total -= boughtshareprice
            cash += boughtshareprice
            db.execute("UPDATE transactions SET shares=? WHERE user_id=? AND symbol=?",
                        (aftershares, session["user_id"], request.form.get("symbol")))
            db.execute("UPDATE users SET cash=? WHERE id =?", (cash, session["user_id"]))
            if ownedShares == 0:
                db.execute("DELETE FROM transactions WHERE user_id = :id AND symbol= :symbol",
                            id=session["user_id"], symbol=request.form.get("symbol"))
            now = datetime.utcnow()
            shares = -1 * requestshare
            symbol = lookup(symb)["symbol"]
            db.execute("INSERT INTO history (user_id, symbol, shares, price, transacted) VALUES (?, ?, ?, ?, ?)",
            (session["user_id"], symbol, shares, price, now))
            flash('Sold')
            return redirect("/")


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    """Change Your Password"""
    if request.method == "GET":
        return render_template("settings.html")

    # Query database for username
    rows = db.execute("SELECT * FROM users WHERE id = :id",
                            id=session["user_id"])

    if request.method == "POST":
        if not request.form.get("old-password"):
            return apology("Enter your old password", 403)

        # Ensure password was submitted
        elif not request.form.get("new-password"):
            return apology("Enter your new password", 403)

        # Ensure password was confirmed
        elif not request.form.get("confirm-password"):
            return apology("confirm your new password", 403)

        # Matching passwords
        elif request.form.get("new-password") != request.form.get("confirm-password"):
            return apology("Passwords don't match", 403)

        # Ensure username exists and password is correct
        if not check_password_hash(rows[0]["hash"], request.form.get("old-password")):
            return apology("invalid password", 403)

        else:
            db.execute("UPDATE users SET hash=? WHERE id =?", (generate_password_hash(request.form.get("new-password")), session["user_id"]))

            flash('Password Changed')
            return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
