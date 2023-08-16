from cs50 import SQL
from flask import Flask, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    symbols, shares, prices, averages, current = [],[],[],[],[]
    data = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
    name = data[0]["username"]
    cash = data[0]["cash"]
    table1 = db.execute("SELECT symbol, SUM(shares) FROM shares WHERE user_id = ? GROUP BY symbol ORDER BY symbol", session["user_id"])
    table2 = db.execute("SELECT symbol, shares, price FROM shares WHERE user_id = ? ORDER BY symbol", session["user_id"])

    #prices is a list of the total money spent on each stock, in alphabetical order

    for i in range(len(table2)):
        if i == 0:
            sum = (table2[0]["price"]) * (table2[0]["shares"])
            if len(table2) == 1:
                prices.append(sum)

        elif i == len(table2) - 1:

            if table2[i-1]["symbol"] != table2[i]["symbol"]:
                prices.append(sum)
                sum = (table2[i]["price"]) * (table2[i]["shares"])

            else:
                sum += (table2[i]["price"]) * (table2[i]["shares"])

            prices.append(sum)

        else:
            if table2[i-1]["symbol"] != table2[i]["symbol"]:
                prices.append(sum)
                sum = (table2[i]["price"]) * (table2[i]["shares"])

            else:
                sum += (table2[i]["price"]) * (table2[i]["shares"])

    value = 0
    invested = 0
    iterate = len(table1)
    for i in range(iterate):
        # symbols is a list of all the currently bought symbols
        # shares is a list of the number of shares of all the currently bought symbols
        # averages is a list of the average price of each share
        # current is a list of dictionaries which contains the current price of each symbol
        # all of these are arranged in alphabetical order
        # value is the total value of the portfolio
        # invested is the total input into the bought stocks of the portfolio
        symbols.append(table1[i]["symbol"])
        shares.append(table1[i]["SUM(shares)"])
        current.append(lookup(symbols[i]))
        value += (lookup(symbols[i]))["price"] * shares[i]
        averages.append(prices[i] / shares[i])
        invested += prices[i]

    return render_template("index.html", name=name, cash=cash, value=value, iterate=iterate, current=current, symbols=symbols, shares=shares, averages=averages, prices=prices, invested=invested)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        shares = request.form.get("shares")
        info = lookup(request.form.get("symbol"))
        symbol = request.form.get("symbol")

        if not lookup(symbol):
            return apology("Invalid symbol", 400)

        if not shares.isdigit() or int(shares) <= 0:
            return apology("Input a positive integer number of shares", 400)

        shares = int(shares)
        total = shares * info["price"]
        balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        balance = balance[0]["cash"]
        if balance < total:
            return apology("Cannot afford this purchase", 400)
        else:
            balance -= total
            time = datetime.now()
            db.execute("UPDATE users SET cash = ? WHERE id = ?", balance, session["user_id"])
            db.execute("INSERT INTO shares (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)", session["user_id"], symbol.upper(), shares, info["price"])
            db.execute("INSERT INTO history (user_id, symbol, shares, price, trans, date, time) VALUES (?, ?, ?, ?, ?, ?, ?)",
                       session["user_id"], symbol.upper(), shares, info["price"], "Buy", time.strftime("%Y-%m-%d"), time.strftime("%H:%M:%S"))

        return redirect("/")

    else:

        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute("SELECT * FROM history WHERE user_id = ? ORDER BY date DESC, time DESC", session["user_id"])
    iterate = len(history)

    return render_template("history.html", history=history, iterate=iterate)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

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
    if request.method == "POST":
        clicker = lookup(request.form.get("symbol"))
        if not clicker:
            return apology("Invalid symbol")
        else:
            return render_template("quoted.html", clicker=clicker)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirm = request.form.get("confirmation")
        current = db.execute("SELECT username FROM users WHERE username = ?", username)
        if (not username) or (not password) or (not confirm):
            return apology("Must fill out all fields", 400)
        if current:
            return apology("Username already taken", 400)
        if password != confirm:
            return apology("Passwords do not match", 400)
        hash = generate_password_hash(password)
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)
        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("You can only sell a share that you own", 400)
        count = request.form.get("shares")
        if not count.isdigit() or int(count) <= 0:
            return apology("Input a positive integer number of shares to sell", 400)

        balance = db.execute("SELECT SUM(shares) FROM shares WHERE user_id = ? AND symbol = ? GROUP BY symbol;",
                             session["user_id"], symbol)
        balance = balance[0]["SUM(shares)"]
        if count > balance:
            return apology("You do not have that many shares to sell", 400)
        rate = (lookup(symbol))["price"]
        price = rate * count
        money = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        money = money[0]["cash"]
        new = money + price
        db.execute("UPDATE users SET cash = ? WHERE id = ?", new, session["user_id"])
        time = datetime.now()
        if count == balance:
            db.execute("DELETE FROM shares WHERE user_id = ? AND symbol = ?", session["user_id"], symbol)
        elif count < balance:
            while (count > 0):
                hold = db.execute("SELECT * from shares WHERE user_id = ? AND symbol = ? ORDER BY date ASC, time ASC", session["user_id"], symbol)
                id = hold[0]["id"]
                if hold[0]["shares"] > count:
                    db.execute("UPDATE shares SET shares = ? WHERE id = ?", (hold[0]["shares"] - count) , id)
                    count = 0
                elif hold[0]["shares"] == count:
                    db.execute("DELETE from shares WHERE id = ?", id)
                    count = 0
                elif hold[0]["shares"] < count:
                    count -= hold[0]["shares"]
                    db.execute("DELETE from shares WHERE id = ?", id)

        db.execute("INSERT INTO history (user_id, symbol, shares, price, trans, date, time) VALUES (?, ?, ?, ?, ?, ?, ?)",
                       session["user_id"], symbol.upper(), count, rate, "Sell", time.strftime("%Y-%m-%d"), time.strftime("%H:%M:%S"))
        return redirect("/")

    else:
        info = []
        holdings = db.execute("SELECT symbol FROM shares WHERE user_id = ? GROUP BY symbol", session["user_id"])
        iterate = len(holdings)
        for i in range(iterate):
            info.append(holdings[i]["symbol"])
        return render_template("sell.html", info=info, iterate=iterate)


@app.route("/manage", methods=["GET", "POST"])
@login_required
def manage():
    if request.method == "GET":
        return render_template("manage.html")
    else:
        balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        balance = balance[0]["cash"]
        action = request.form.get("action")
        amount = request.form.get("amount")
        time = datetime.now()

        if not amount.replace(".", "").isnumeric():
            return apology("Input a positive number of shares to sell", 400)

        amount = float(amount)
        if action == "Withdraw":
            if amount > balance:
                return apology("Cannot withdraw more than current balance", 400)
            else:
                balance -= amount
                db.execute("UPDATE users SET cash = ? WHERE id = ?", balance, session["user_id"])
                db.execute("INSERT INTO history (user_id, price, trans, date, time) VALUES (?, ?, ?, ?, ?)",
                           session["user_id"], amount, "Withdraw",time.strftime("%Y-%m-%d"), time.strftime("%H:%M:%S"))
                return redirect("/")
        elif action == "Deposit":
            balance += amount
            db.execute("UPDATE users SET cash = ? WHERE id = ?", balance, session["user_id"])
            db.execute("INSERT INTO history (user_id, price, trans, date, time) VALUES (?, ?, ?, ?, ?)",
                       session["user_id"], amount, "Deposit",time.strftime("%Y-%m-%d"), time.strftime("%H:%M:%S"))
            return redirect("/")


@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    if request.method == "POST":
        password = request.form.get("password")
        confirm = request.form.get("confirmation")
        if (not password) or (not confirm):
            return apology("Must fill out all fields", 400)
        if password != confirm:
            return apology("Passwords do not match", 400)
        hash = generate_password_hash(password)
        db.execute("UPDATE users SET hash = ? WHERE id = ?", hash, session["user_id"])
        return redirect("/",)
    else:
        return render_template("change.html")




