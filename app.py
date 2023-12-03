# app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
import pyotp
import stripe
import secrets
app = Flask(__name__)

# SQLite configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
# Set a secret key for session management
app.config['SECRET_KEY'] = 'your_secret_key_here'
# Set your Stripe API key (replace with your actual Stripe API key)
stripe.api_key = 'sk_test_your_stripe_secret_key'

# Model for User
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

# Model for OTP
class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    otp_secret = db.Column(db.String(16), nullable=False)

# Model for Password Reset
class PasswordReset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    reset_code = db.Column(db.String(50), nullable=False)
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    images = db.Column(db.String(255), nullable=True)
    description = db.Column(db.Text, nullable=True)

# Model for Cart
class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    product_id = db.Column(db.Integer, nullable=False)

# Uncomment the following line if you want to see SQL queries in the console
app.config['SQLALCHEMY_ECHO'] = True



# Create the tables
with app.app_context():
    db.create_all()

# Model for Product

# Add some sample products to the database
with app.app_context():
    sample_products = [
        Product(name='Product 1', amount=19.99, description='Description for Product 1'),
        Product(name='Product 2', amount=29.99, description='Description for Product 2'),
        Product(name='Product 3', amount=39.99, description='Description for Product 3'),
    ]

    for product in sample_products:
        db.session.add(product)

    db.session.commit()

# Add a new route for the product catalog
@app.route('/product_catalog')
def product_catalog():
    # Retrieve all products from the database
    products = Product.query.all()
    return render_template('product_catalog.html', products=products)


@app.route('/')
def index():
    return 'Welcome to the Flask Registration and Login App with SQLite!'


# app.py (continued)
# ...

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Basic validation
        if not username or not password:
            return 'Please enter both username and password.'

        # Check if the username already exists
        if User.query.filter_by(username=username).first():
            return 'Username already exists. Please choose another one.'

        # Create a new user
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()

        # Redirect to the login page with a success message
        return redirect(url_for('login', message='Registration successful!'))

    return render_template('register.html')

# app.py (continued)
# ...

# Update the login route to store the username in the session
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Basic validation
        if not username or not password:
            return 'Please enter both username and password.'

        # Check if the user exists
        user = User.query.filter_by(username=username, password=password).first()

        if not user:
            return 'Invalid username or password. Please try again.'

        # Generate and store OTP for the user
        totp = pyotp.TOTP(pyotp.random_base32())
        user_otp = OTP(username=username, otp_secret=totp.secret)
        db.session.add(user_otp)
        db.session.commit()

         # Print the OTP value in the logs
        print(f"OTP generated for {username}: {totp.now()}")

        # Generate and store a reset code for password reset
        reset_code = secrets.token_urlsafe(20)
        password_reset = PasswordReset(username=username, reset_code=reset_code)
        db.session.add(password_reset)
        db.session.commit()

        # Store username and reset code in the session
        session['username'] = username
        session['reset_code'] = reset_code

        # Redirect to OTP verification page
        return redirect(url_for('verify_otp', username='some_username_value'))

    return render_template('login.html')
# Add a logout route
@app.route('/logout')
def logout():
    # Clear the session data
    session.pop('username', None)
    return redirect(url_for('index'))

# Update the change password route to get the username from the session
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    # Check if the user is logged in
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']

    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']

        # Basic validation
        if not old_password or not new_password:
            return 'Please enter both old and new passwords.'

        # Check if the user exists
        user = User.query.filter_by(username=username, password=old_password).first()

        if not user:
            return 'Invalid old password. Please try again.'

        # Update the password
        user.password = new_password
        db.session.commit()

        return f'Password changed successfully for {username}!'

    return render_template('change_password.html', username=username)

# Add a new route for requesting a password reset
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']

        # Basic validation
        if not username:
            return 'Please enter your username.'

        # Check if the username exists
        user = User.query.filter_by(username=username).first()

        if not user:
            return 'Username not found. Please try again.'

        # Generate and store a reset code for password reset
        reset_code = secrets.token_urlsafe(20)
        password_reset = PasswordReset(username=username, reset_code=reset_code)
        db.session.add(password_reset)
        db.session.commit()

        # TODO: Send a password reset link or code to the user's email (not implemented in this example)

        return f'Password reset link/code sent to {username}. Check your email.'

    return render_template('forgot_password.html')

# Add a new route for resetting the password
@app.route('/reset_password/<reset_code>', methods=['GET', 'POST'])
def reset_password(reset_code):
    # Check if the reset code is valid
    password_reset = PasswordReset.query.filter_by(reset_code=reset_code).first()

    if not password_reset:
        return 'Invalid reset code. Please try again.'

    if request.method == 'POST':
        new_password = request.form['new_password']

        # Basic validation
        if not new_password:
            return 'Please enter a new password.'

        # Update the user's password
        user = User.query.filter_by(username=password_reset.username).first()
        user.password = new_password

        # Delete the password reset entry
        db.session.delete(password_reset)
        db.session.commit()

        return 'Password reset successful. You can now login with your new password.'

    return render_template('reset_password.html', reset_code=reset_code)

@app.route('/verify_otp/<username>', methods=['GET', 'POST'])
def verify_otp(username):
    if request.method == 'POST':
        otp = request.form['otp']

        # Basic validation
        if not otp:
            return 'Please enter the OTP.'

        # Check if the OTP is valid
        user_otp = OTP.query.filter_by(username=username).first()

        if not user_otp or not pyotp.TOTP(user_otp.otp_secret).verify(otp):
            return 'Invalid OTP. Please try again.'

        return f'Login successful for {username}!'

    return render_template('verify_otp.html', username=username)

# Add a new route to handle adding products to the cart
@app.route('/add_to_cart/<int:product_id>')
def add_to_cart(product_id):
    # Check if the user is logged in
    if 'username' not in session:
        flash('Please log in to add products to your cart.', 'info')
        return redirect(url_for('login'))

    # Retrieve the username from the session
    username = session['username']

    # Check if the product is already in the cart
    existing_entry = Cart.query.filter_by(username=username, product_id=product_id).first()

    if existing_entry:
        flash('Product already in your cart.', 'info')
    else:
        # Add the product to the cart
        cart_entry = Cart(username=username, product_id=product_id)
        db.session.add(cart_entry)
        db.session.commit()
        flash('Product added to your cart.', 'success')

    return redirect(url_for('product_catalog'))


@app.route('/cart')
def cart():
    # Check if the user is logged in
    if 'username' not in session:
        flash('Please log in to view your cart.', 'info')
        return redirect(url_for('login'))

    # Retrieve the username from the session
    username = session['username']

    # Retrieve the user's cart items
    cart_entries = Cart.query.filter_by(username=username).all()

    # Retrieve product details for each cart item
    cart_products = []
    total_amount = 0.0

    for entry in cart_entries:
        product = Product.query.get(entry.product_id)
        if product:
            cart_products.append(product)
            total_amount += product.amount

    return render_template('cart.html', products=cart_products, total_amount=total_amount)

# Add a new route for the payment
@app.route('/payment', methods=['GET', 'POST'])
def payment():
    # Check if the user is logged in
    if 'username' not in session:
        flash('Please log in to complete the payment.', 'info')
        return redirect(url_for('login'))

    # Retrieve the username from the session
    username = session['username']

    # Retrieve the user's cart items
    cart_entries = Cart.query.filter_by(username=username).all()

    # Retrieve product details for each cart item
    cart_products = []
    total_amount = 0.0

    for entry in cart_entries:
        product = Product.query.get(entry.product_id)
        if product:
            cart_products.append(product)
            total_amount += product.amount

    if request.method == 'POST':
        # Process the payment using the Stripe API
        try:
            payment_intent = stripe.PaymentIntent.create(
                amount=int(total_amount * 100),  # Convert to cents
                currency='usd',
            )
            flash('Payment successful. Thank you!', 'success')
            return redirect(url_for('cart'))
        except stripe.error.CardError as e:
            # Handle card errors
            flash(f'Error: {e.error.message}', 'danger')
        except stripe.error.InvalidRequestError as e:
            # Handle invalid request errors
            flash(f'Error: {e.error.message}', 'danger')
        except stripe.error.AuthenticationError as e:
            # Handle authentication errors
            flash(f'Error: {e.error.message}', 'danger')
        except stripe.error.StripeError as e:
            # Handle other Stripe errors
            flash(f'Error: {e.error.message}', 'danger')

    return render_template('payment.html', products=cart_products, total_amount=total_amount)

if __name__ == '__main__':
    app.run(debug=True)
