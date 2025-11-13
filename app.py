from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_pymysql import MySQL
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import re
import os

app = Flask(__name__)
app.config.from_object('config.Config')
app.secret_key = app.config['SECRET_KEY']

# ✅ MySQL Configuration (Render friendly)
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST', 'your-db-host')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER', 'your-username')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD', 'your-password')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB', 'your-database-name')
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config['pymysql_kwargs'] = {}  # ✅ Prevents KeyError from Flask-PyMySQL

mysql = MySQL(app)

# ===============================================================
# Login required decorator
# ===============================================================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ===============================================================
# Utility functions
# ===============================================================
def get_db_cursor():
    return mysql.connection.cursor()

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    return len(password) >= 8

# ===============================================================
# Routes
# ===============================================================
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        cur = get_db_cursor()
        cur.execute("SELECT COUNT(*) as count FROM products")
        total_products = cur.fetchone()['count']

        cur.execute("SELECT COUNT(*) as count FROM products WHERE quantity < 10")
        low_stock = cur.fetchone()['count']

        cur.execute("""
            SELECT COUNT(*) as count, 
                   COALESCE(SUM(total_amount), 0) as total
            FROM sales
            WHERE DATE(sale_time) = CURDATE()
        """)
        sales_data = cur.fetchone()

        return render_template('dashboard.html',
                               total_products=total_products,
                               low_stock=low_stock,
                               daily_sales_count=sales_data['count'],
                               daily_sales_total=float(sales_data['total']))
    except Exception as e:
        flash('An error occurred while loading the dashboard.', 'danger')
        app.logger.error(f"Dashboard error: {str(e)}")
        return render_template('dashboard.html', error=True)
    finally:
        if 'cur' in locals():
            cur.close()

# ===============================================================
# User Registration
# ===============================================================
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not all([email, password, confirm_password]):
            flash('All fields are required.', 'danger')
            return render_template('register.html')

        if not validate_email(email):
            flash('Please enter a valid email address.', 'danger')
            return render_template('register.html')

        if not validate_password(password):
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('register.html')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')

        try:
            cur = get_db_cursor()
            cur.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cur.fetchone():
                flash('Email already registered.', 'danger')
                return render_template('register.html')

            hashed_password = generate_password_hash(password)
            cur.execute("INSERT INTO users (email, password) VALUES (%s, %s)", 
                       (email, hashed_password))
            mysql.connection.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            mysql.connection.rollback()
            flash('An error occurred during registration.', 'danger')
            app.logger.error(f"Registration error: {str(e)}")
        finally:
            if 'cur' in locals():
                cur.close()

    return render_template('register.html')

# ===============================================================
# User Login
# ===============================================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not all([email, password]):
            flash('Please enter both email and password.', 'danger')
            return render_template('login.html')

        try:
            cur = get_db_cursor()
            cur.execute("""
                SELECT id, email, password 
                FROM users 
                WHERE email = %s
            """, (email,))
            
            user = cur.fetchone()

            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['email'] = user['email']
                session.permanent = True
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid email or password.', 'danger')

        except Exception as e:
            app.logger.error(f"Login error: {str(e)}")
            flash('An error occurred during login.', 'danger')
        finally:
            if 'cur' in locals():
                cur.close()

    return render_template('login.html')

# ===============================================================
# User Logout
# ===============================================================
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# ===============================================================
# Add Product
# ===============================================================
@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if request.method == 'POST':
        try:
            product_name = request.form.get('product_name')
            price = request.form.get('price')
            quantity = request.form.get('quantity')
            user_id = session.get('user_id')

            if not all([product_name, price, quantity, user_id]):
                flash('All fields are required.', 'danger')
                return redirect(url_for('add_product'))

            cur = get_db_cursor()
            cur.execute("""
                INSERT INTO products 
                (product_name, price, quantity, user_id) 
                VALUES (%s, %s, %s, %s)
            """, (product_name, price, quantity, user_id))
            
            mysql.connection.commit()
            flash('Product added successfully!', 'success')
            return redirect(url_for('stock'))

        except Exception as e:
            mysql.connection.rollback()
            app.logger.error(f"Add product error: {str(e)}")
            flash('An error occurred while adding the product.', 'danger')
        finally:
            if 'cur' in locals():
                cur.close()

    return render_template('add_product.html')

# ===============================================================
# Remaining routes...
# (Edit, Delete, Stock, Sales, Reports, APIs, etc.)
# ===============================================================
# Keep all the rest of your functions exactly as they are.
# Just ensure any "finally" block uses:
# if 'cur' in locals():
#     cur.close()

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
