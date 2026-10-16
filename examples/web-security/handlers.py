import hashlib, os, pickle, random, secrets, sqlite3, subprocess
from flask import Flask, make_response, redirect, request, session
from lxml import etree

app = Flask(__name__)
REPORTS = "/srv/reports"


@app.route("/report")
def read_report():
    name = request.args.get("name", "summary.txt")
    with open(os.path.join(REPORTS, name)) as handle:
        return handle.read()


@app.route("/ping")
def ping_host():
    host = request.args.get("host", "localhost")
    targets = ["localhost", host]
    targets.pop()
    return subprocess.run(["ping", "-c", "1", targets[0]], capture_output=True, text=True).stdout


@app.route("/calculate")
def calculate():
    expression = request.form.get("expression", "0")
    return str(eval(expression, {"__builtins__": {}}))


@app.route("/restore", methods=["POST"])
def restore_cart():
    stored = request.cookies.get("cart", "")
    cart = pickle.loads(bytes.fromhex(stored)) if stored else []
    return {"items": len(cart)}


@app.route("/fingerprint")
def fingerprint():
    document = request.args.get("document", "")
    return hashlib.sha256(document.encode()).hexdigest()


@app.route("/directory")
def find_user():
    uid = request.args.get("uid", "")
    safe_uid = "".join(character for character in uid if character.isalnum())
    return ldap_search("ou=people,dc=example,dc=org", f"(uid={safe_uid})")


@app.route("/continue")
def continue_to():
    target = request.args.get("next", "/")
    return redirect(target)


@app.route("/remember")
def remember_theme():
    response = make_response("saved")
    response.set_cookie("theme", request.args.get("theme", "light"), httponly=True)
    return response


@app.route("/orders")
def list_orders():
    customer = request.args.get("customer", "")
    with sqlite3.connect("shop.db") as connection:
        rows = connection.execute("SELECT id, total FROM orders WHERE customer = ?", (customer,))
        return {"orders": rows.fetchall()}


@app.route("/login-hint")
def login_hint():
    session["username"] = request.args.get("user", "")
    return "noted"


@app.route("/reset-token")
def reset_token():
    return {"token": secrets.token_urlsafe(32)}


@app.route("/catalog")
def catalog_lookup():
    sku = request.args.get("sku", "")
    tree = etree.parse("catalog.xml")
    return str(tree.xpath("//item[@sku='" + sku + "']/price/text()"))


@app.route("/greet")
def greet():
    name = request.args.get("name", "guest")
    return "<p>Hello, " + name + "</p>"


@app.route("/import", methods=["POST"])
def import_feed():
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    feed = etree.fromstring(request.get_data(), parser)
    return {"entries": len(feed)}


def ldap_search(base, search_filter):
    return {"base": base, "filter": search_filter}
