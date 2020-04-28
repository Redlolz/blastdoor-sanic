from sanic import Sanic
from sanic.response import json, html, redirect
from sanic_session import Session, InMemorySessionInterface
from jinja2 import Environment, PackageLoader, select_autoescape, FileSystemLoader
import urllib.parse
import random, string
import db

app = Sanic(__name__)
app.static('/static', './static')
session = Session(app, interface=InMemorySessionInterface())

db_file = 'users.db'
db = db.database(db_file)

env = Environment(
    loader=FileSystemLoader('templates'),
    autoescape=select_autoescape(['html','xml'])
)

def render_template(template, **kwargs):
    template = env.get_template(template)
    return html(template.render(kwargs, url_for=app.url_for))

def randomstr(length):
   letters = string.ascii_letters + string.digits
   return ''.join(random.choice(letters) for i in range(length))

def request_parse(body):
    return urllib.parse.parse_qs(body.decode('utf-8'))

@app.route('/')
async def main(request):
    if not request['session'].get('logged_in'):
        return redirect(app.url_for('login'))
    else:
        return redirect(app.url_for('dashboard'))

@app.route('/login', methods=['GET'])
async def login(request):
    if request.args.get('login_failed'):
        return render_template('login.html', error='error')
    elif request.args.get('verify_failed'):
        return render_template('login.html', verifyfailed='verifyfailed')
    else:
        return render_template('login.html')

@app.route('/loginattempt', methods=['GET', 'POST'])
async def loginattempt(request):
    request_form = request_parse(request.body)
    verify_pass = db.verify_password(request_form['username'][0], request_form['password'][0])
    if verify_pass:
        request['session']['password_ok'] = True
        request['session']['username'] = request_form['username'][0]
        return redirect(app.url_for('verify'))
    else:
        return redirect(app.url_for('login') + '?login_failed=true')

@app.route('/verify')
async def verify(request):
    if not request['session'].get('password_ok'):
        return redirect(app.url_for('login'))
    message = randomstr(20)
    request['session']['message'] = message
    return render_template('verify.html', message=message)

@app.route('/verifyattempt', methods=['POST'])
async def verifyattempt(request):
    request_form = request_parse(request.body)
    if 'signature' not in request_form:
        return redirect(app.url_for('login') + '?verify_failed=true')

    if db.verify_signature(request['session']['username'], request['session']['message'], request_form['signature'][0]):
        request['session']['logged_in'] = True
        return redirect(app.url_for('dashboard'))
    else:
        del request['session']['logged_in']
        return redirect(app.url_for('login') + '?verify_failed=true')

@app.route('/logout')
async def logout(request):
    del request['session']['logged_in']
    return redirect(app.url_for('main'))

@app.route('/dashboard')
async def dashboard(request):
    if not request['session'].get('logged_in'):
        return redirect(app.url_for('login'))

    return render_template('dashboard.html')

@app.route('/admin')
async def admin(request):
    if not db.isadmin(request['session']['username']):
        return redirect(app.url_for('/'))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)