from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
import os

app = Flask(__name__)
app.secret_key = '12dbb49b86f1711732982450a8a69c36'

# Configure MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'shri'
app.config['MYSQL_PASSWORD'] = '1234'
app.config['MYSQL_DB'] = 'inventory_system'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config['UPLOAD_FOLDER'] = 'static/images'

mysql = MySQL(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, name, email, role):
        self.id = id
        self.name = name
        self.email = email
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", [user_id])
    user = cur.fetchone()
    if user:
        return User(id=user['id'], name=user['name'], email=user['email'], role=user['role'])
    return None

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:  # Check if the user is already logged in
        return redirect(url_for('dashboard'))  # Redirect to the dashboard if already logged in
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", [email])
        user = cur.fetchone()
        if user and bcrypt.check_password_hash(user['password'], password):
            user_obj = User(id=user['id'], name=user['name'], email=user['email'], role=user['role'])
            login_user(user_obj)
            session['role'] = user['role']
            session['user_id'] = user['id']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials.', 'danger')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        role = request.form['role']
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users (name, email, password, role) VALUES (%s, %s, %s, %s)",
                    (name, email, password, role))
        mysql.connection.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('sign_up.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif current_user.role == 'customer':
        return redirect(url_for('customer_dashboard'))
    else:
        flash('Invalid user role.', 'danger')
        return redirect(url_for('login'))

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if session.get('role') != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM products")
    products = cur.fetchall()

    # Check for low stock
    low_stock_threshold = 5  # Example threshold
    cur.execute("SELECT * FROM products WHERE quantity < %s", [low_stock_threshold])
    low_stock_products = cur.fetchall()

    return render_template('admin_dashboard.html', products=products, low_stock_products=low_stock_products)

@app.route('/customer_dashboard', methods=['GET', 'POST'])
@login_required
def customer_dashboard():
    if session.get('role') != 'customer':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    print("Session Data:", session)  # Debugging line
    
    cur = mysql.connection.cursor()
    
    if request.method == 'POST':
        product_id = request.form['product_id']
        quantity = int(request.form['quantity'])

        # Fetch product details
        cur.execute("SELECT * FROM products WHERE id = %s", [product_id])
        product = cur.fetchone()

        if not product:
            flash('Product not found.', 'danger')
        elif quantity > product['quantity']:
            flash(f'Only {product["quantity"]} units available for {product["name"]}.', 'danger')
        else:
            # Update product quantity
            new_quantity = product['quantity'] - quantity
            cur.execute("UPDATE products SET quantity = %s WHERE id = %s", (new_quantity, product_id))

            # Record the order
            cur.execute("INSERT INTO orders (product_id, customer_id, quantity) VALUES (%s, %s, %s)", 
                        (product_id, session['user_id'], quantity))
            mysql.connection.commit()

            flash(f'Order placed for {quantity} units of {product["name"]}.', 'success')

    # Show all products
    cur.execute("SELECT * FROM products")
    products = cur.fetchall()
    return render_template('customer_dashboard.html', products=products)

@app.route('/add_product', methods=['POST'])
@login_required
def add_product():
    if session.get('role') != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    
    name = request.form['name']
    category = request.form['category']
    price = request.form['price']
    quantity = request.form['quantity']
    supplier = request.form['supplier']
    image = request.files['image']
    
    # Save image to static/images folder
    if image:
        image_url = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
        image.save(image_url)
        image_url = 'images/' + image.filename  # Path to store in DB
    else:
        image_url = None
    
    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO products (name, category, price, quantity, supplier, image_url) VALUES (%s, %s, %s, %s, %s, %s)",
                (name, category, price, quantity, supplier, image_url))
    mysql.connection.commit()
    flash('Product added successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/refill_product', methods=['POST'])
@login_required
def refill_product():
    if session.get('role') != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    
    product_name = request.form['product_name']
    refill_quantity = int(request.form['quantity'])
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM products WHERE name = %s", [product_name])
    product = cur.fetchone()
    
    if not product:
        flash('Product not found.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    new_quantity = product['quantity'] + refill_quantity
    cur.execute("UPDATE products SET quantity = %s WHERE name = %s", (new_quantity, product_name))
    mysql.connection.commit()
    
    flash(f'{product["name"]} refilled by {refill_quantity} units. New quantity: {new_quantity}.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/remove_product', methods=['POST'])
@login_required
def remove_product():
    if session.get('role') != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    
    product_name = request.form['product_name']
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM products WHERE name = %s", [product_name])
    product = cur.fetchone()
    
    if not product:
        flash('Product not found.', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    cur.execute("DELETE FROM orders WHERE product_id = %s", [product['id']])
    cur.execute("DELETE FROM products WHERE name = %s", [product_name])
    mysql.connection.commit()
    
    flash(f'{product["name"]} has been removed from the inventory.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()  # Clear session to ensure no session-based issues
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
