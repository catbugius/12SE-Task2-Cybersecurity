from flask import Flask, render_template, request, redirect, session, jsonify, url_for, send_from_directory
from flask_cors import CORS
import json
import sqlite3
import os
import sys
import traceback
import time  
import bcrypt
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from markupsafe import escape
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect, generate_csrf
import secrets
import base64

app = Flask(__name__)

# ✅ Load environment variables
load_dotenv()

# ✅ Load and decode ENCRYPTION_KEY
key_string = os.getenv("ENCRYPTION_KEY")
if not key_string:
    raise ValueError("ENCRYPTION_KEY is missing from .env file!")
key = key_string.encode()  # It's already Base64, no need to decode
cipher_suite = Fernet(key)

# ✅ Load and decode SECRET_KEY
secret_key_string = os.getenv("SECRET_KEY")
if not secret_key_string:
    raise ValueError("SECRET_KEY is missing from .env file!")
app.secret_key = base64.urlsafe_b64decode(secret_key_string)

csrf = CSRFProtect(app)  # ✅ Enables CSRF protection

# ✅ Define the safe directory dynamically using os.getcwd()
SAFE_DIRECTORY = os.path.join(os.getcwd(), "12SE_Task2-main")

# ✅ Limits file types
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'txt', 'pdf'}
app.config["ALLOWED_EXTENSIONS"] = {'png', 'jpg', 'jpeg', 'gif', 'txt', 'pdf'}  
MAX_FILE_SIZE = 16 * 1024 * 1024  # ✅ Limits file size (adjust as needed!)


CORS(app, resources={r"/*": {"origins": "*"}})

DEFAULT_CREDENTIALS = {
    "admin": "admin123",
    "test": "test123",
    "demo": "demo123"
}

# Initialise database
def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    
    # Create users table with email field (if not exists)
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT UNIQUE
        )
    """)
    
    # Add profiles table with sensitive information
    # ✅ Change user_id to UNIQUE instead of PRIMARY KEY
    c.execute("""
        CREATE TABLE IF NOT EXISTS profiles (
            user_id TEXT UNIQUE, 
            full_name TEXT,
            email TEXT,  
            phone TEXT,
            credit_card TEXT,
            address TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    # ⚠️ NEVER STORE PLAINTEXT 
    #  Add default users if they don't exist
    #for username, password in DEFAULT_CREDENTIALS.items():
    #    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    #    if not c.fetchone():
    #        # Add email for each default user
    #        email = f"{username}@example.com"
    #        c.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
    #                 (username, password, email))

    # ✅ Hash and store default users securely
    # ✅ Encrypts emails
    for username, password in DEFAULT_CREDENTIALS.items():
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        if not c.fetchone():
            email = f"{username}@example.com"
            encrypted_email = cipher_suite.encrypt(email.encode())
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')  # Fix encoding
            c.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                      (username, hashed_password, encrypted_email))
            
        # HOW TO ACCESS EMAILS AGAIN cipher_suite.decrypt(encrypted_email).decode())
   
    conn.commit()
    conn.close()

# Load pizza data
def load_pizzas():
    try:
        with open("pizza.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return []

# Save pizza data
def save_pizzas(pizzas):
    # Ensure backup directory exists
    os.makedirs("static/backup", exist_ok=True)
    
    # Save to both main file and backup
    with open("pizza.json", "w") as f:
        json.dump(pizzas, f, indent=4)
    
    with open("static/backup/pizza.json.bak", "w") as f:
        json.dump(pizzas, f, indent=4)

reset_tokens = {}  # Temporary storage (should be in DB)

def generate_reset_token(username):
    token = secrets.token_urlsafe(32)  # Secure token
    expiry = time.time() + 900  # 15-minute expiration
    reset_tokens[username] = {"token": token, "expiry": expiry}
    return token 

# ✅ function to check file extension
def allowed_file(filename):
    # Check if the file has a valid extension (case insensitive)
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Vulnerable download route for directory traversal
#@app.route("/download")
#def download():
    #filename = request.args.get("file") ⚠️ Doesn't sanitise the file path!!
    #with open(filename, "r") as file:
        #return file.read()

@app.route("/download")
def download():
    # ✅ Get the filename from the query parameter
    filename = request.args.get("filename")
    
    if filename is None:
        return "No file specified", 400
    
    if not allowed_file(filename):
        return "File type not allowed", 400  # ✅ Reject disallowed file types
    
    # ✅ Construct the full safe path and normalize it
    safe_path = os.path.normpath(os.path.join(upload_dir, filename))
    
    # ✅ Prevent directory traversal attacks
    if not os.path.commonprefix([safe_path, SAFE_DIRECTORY]) == SAFE_DIRECTORY:
        return "Unable to access this file: Forbidden", 403

    # ✅ Check if the file exists
    if not os.path.isfile(safe_path):
        return f"File not found", 404  

    # Read and return the file contents
    try:
        with open(safe_path, "r") as file:
            return file.read()
    except Exception as e:
        return f"Error reading file: {str(e)}", 500
    
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        file = request.files.get("file")
        if not file:
            return "No file uploaded", 400  # ✅ Handle missing files properly
        
        # Check if the file has a valid extension
        if not allowed_file(file.filename):
            return "File type not allowed", 400  # ✅ Reject disallowed file types
        
        if len(file.read()) > MAX_FILE_SIZE:
            return "File is too large", 400  # ✅ Reject files that exceed size limit
        
        # ✅ Secure the file name
        filename = secure_filename(file.filename)

        # ✅ Safely save the file to the uploads directory
        upload_dir = os.path.join(SAFE_DIRECTORY, "uploads")
        os.makedirs(upload_dir, exist_ok=True)  # Ensure the uploads directory exists

        # ✅ Reject if file already exists
        if os.path.exists(os.path.join(upload_dir, filename)):
            return "File with the same name already exists", 400
        
        file_path = os.path.join(upload_dir, filename)  # ✅ Use secure filename
        file.save(file_path)

    return render_template("upload.html", allowedExtensions=ALLOWED_EXTENSIONS)

# Verbose error route
@app.route("/error_test")
def error_test():
    if "user" not in session or session["user"] != "admin":
        return "Access Denied! <a href='/'>Go back</a>"
    username = request.args.get("username")
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    # ⚠️ Passing a concatenated string instead of data
    #query = f"SELECT * FROM users WHERE username = '{username}'"
    # ✅ Parameterised placeholders
    try:
        query = c.execute("SELECT * FROM users WHERE username = ?", (username,))
        result = query.fetchall()  # Fetching the results of the query
    except sqlite3.Error as e:
        conn.close()  # Ensure the connection is closed in case of an error
        return f"An error occurred: {e}"

    conn.close()  # Always close the connection
    return f"Executed query: {result}"

@app.route("/")
def index():
    pizzas = load_pizzas()
    return render_template("index.html", pizzas=pizzas)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"].encode('utf-8')  # Convert to bytes

        # ⚠️ Try default credentials first
        #if username in DEFAULT_CREDENTIALS and DEFAULT_CREDENTIALS[username] == password:
        #    session['user'] = username
        #    return redirect(url_for('index'))
        # ⚠️ You should never keep usernames and passwords in plaintext!

        # If not default, check database
        conn = sqlite3.connect("users.db")
        c = conn.cursor()

        # ⚠️ DO NOT CONCATENATE STRING!! Vulnerable to SQL Injection
        # ⚠️ query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'" 
 
        # ⚠️ Allows the concatenated string to be processed as code. BAD!!
        # ⚠️ c.execute(query)

        # ✅ Parameterized placeholders
        query = "SELECT * FROM users WHERE username = ?" 

        # ✅ Executing query with parameters properly passed as a tuple
        c.execute(query, (username,))
        user = c.fetchone()

        conn.close()  # ✅ Close connection to avoid memory leaks

        if user and bcrypt.checkpw(password, user[2].encode('utf-8') if isinstance(user[2], str) else user[2]):  
            session['user'] = user[1]  
            return redirect(url_for('index'))
        else:
            return "Invalid credentials! <a href='/'>Try again</a>" # ✅ Return a GENERIC error if password or username fails (User Enumeration)

    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register_page():
    if request.method == "GET":
        return render_template("register.html")
    
    # ✅ Ensure the request method is POST before processing form data
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            return "Username and password are required", 400  # ✅ Better error handling
        
    # ✅ Hashing password before putting it in database
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')  

    conn = sqlite3.connect("users.db")
    c = conn.cursor()

    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    existing_user = c.fetchone()
    if existing_user:
        return "Registration failed. Please try again.", 400  # ✅ Return a GENERIC error if username exists (User enumeration)

    # Insert user
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    conn.commit()
    conn.close()

    return redirect(url_for("index"))  

@app.route("/reset", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        username = request.form["username"]
        token = request.form["token"]
        if reset_tokens.get(username) == token:
            return "Password reset successful!"
    return render_template("reset.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/add_to_cart", methods=["POST"])
def add_to_cart():
    pizza_name = request.form.get("pizza_name")
    pizzas = load_pizzas()
    pizza = next((p for p in pizzas if p["name"] == pizza_name), None)
    
    if pizza:
        cart_item = {
            "name": pizza["name"],
            "description": pizza["description"],
            "image": pizza["image"],
            "price": pizza["price"],
            "quantity": 1
        }
        
        if 'cart' not in session:
            session['cart'] = []
        
        existing_item = next((item for item in session['cart'] if item["name"] == pizza_name), None)
        if existing_item:
            existing_item["quantity"] += 1
        else:
            session['cart'].append(cart_item)
        
        session.modified = True
        return redirect(url_for('cart'))
    
    return "Pizza not found!", 404

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if "user" not in session or session["user"] != "admin":
        return "Access Denied! <a href='/'>Go back</a>"

    pizzas = load_pizzas()

    #if request.method == "POST":
    #⚠️    name = request.form["name"]
    #⚠️    description = request.form["description"]
    #⚠️    price = float(request.form.get("price", 0))  
    #⚠️    image_file = request.files.get("image")

    #    if image_file:
    #⚠️        image_filename = f"static/images/{image_file.filename}"
    #⚠️        image_file.save(image_filename)
    #    else:
    #⚠️        image_filename = None

    if request.method == "POST":
        name = escape(request.form["name"])  # ✅ Sanitize name input
        description = escape(request.form["description"])  # ✅ Sanitize description
        price = float(request.form.get("price", 0))  

        image_file = request.files.get("image")
        image_filename = None  # Default to None if no valid image is uploaded
        # Save the file to the safe directory
        if image_file:
            # Check if the file has a valid extension
            if not allowed_file(image_file.filename):
                return "File type not allowed", 400  # ✅ Reject disallowed file types
            
            # Read file data for size validation
            file_data = image_file.read()
            if len(file_data) > MAX_FILE_SIZE:
                print("File is too large")
                return "File is too large", 400  # ✅ Reject files that exceed size limit
            
            # ✅ Secure the file name
            filename = secure_filename(image_file.filename)

            # Define the full safe path where the image will be saved
            safe_image_path = f"{SAFE_DIRECTORY}/static/images/{filename}"

            # Save the image to the safe directory
            with open(safe_image_path, "wb") as f:
                f.write(file_data)

            # Store the relative image path for later use in HTML (for rendering)
            image_filename = f"static/images/{filename}"
        if "update" in request.form:
            pizza_id = int(request.form["update"])
            pizzas[pizza_id]["name"] = name
            pizzas[pizza_id]["description"] = description
            pizzas[pizza_id]["price"] = price  
            if image_filename:
                pizzas[pizza_id]["image"] = image_filename
        elif "delete" in request.form:
            pizza_id = int(request.form["delete"])
            if 0 <= pizza_id < len(pizzas):  
                pizzas.pop(pizza_id)
                save_pizzas(pizzas)
                return redirect("/admin")
        else:
            pizzas.append({
                "name": name,
                "description": description,
                "price": price,  
                "image": image_filename
            })

        save_pizzas(pizzas)
        return redirect("/admin")

    return render_template("admin.html", pizzas=pizzas)



@app.route("/cart")
def cart():
    cart_items = session.get('cart', [])
    return render_template("cart.html", cart_items=cart_items)

@app.route("/update_cart", methods=["POST"])
def update_cart():
    item_name = request.form.get("item")
    quantity = request.form.get("quantity")
    
    if 'cart' in session:
        for item in session['cart']:
            if item["name"] == item_name:
                # ✅ Ensures quantity is a valid integer.
                try:
                    item["quantity"] = int(quantity)
                    session.modified = True
                except ValueError:
                    return "Invalid quantity", 400
                break
    
    return "Updated", 200

@app.route("/remove_from_cart", methods=["POST"])
def remove_from_cart():
    item_name = request.form.get("item")
    
    if 'cart' in session:
        session['cart'] = [item for item in session['cart'] if item["name"] != item_name]
        session.modified = True
    
    return "Removed", 200

@app.route("/api/docs")
def api_docs():
    if "user" not in session or session["user"] != "admin":
        return "Access Denied! <a href='/'>Go back</a>"
    return render_template("api_docs.html")

@app.route("/user/<username>")
def get_user(username):
    if "user" not in session or session["user"] != "admin":
        return "Access Denied! <a href='/'>Go back</a>"
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}'"
        c.execute(query)  
        user = c.fetchone()
        conn.close()
        
        if user:
            return f"Found user: {user}"
        return "User not found"
    except Exception as e:
        return f"""
            <h2>Database Error</h2>
            <p>Query: {query}</p>
            <p>Error: {str(e)}</p>
        """, 500

@app.route("/debug/<path:file_path>")
def debug_file(file_path):
    if "user" not in session or session["user"] != "admin":
        return "Access Denied! <a href='/'>Go back</a>"
    try:
        import platform
        system_info = {
            'os': platform.system(),
            'version': platform.version(),
            'python': sys.version,
            'user': os.getlogin(),
            'cwd': os.getcwd(),
            'env': dict(os.environ)
        }
        
        with open(file_path, 'r') as f:
            content = f.read()
            
        return f"""
            <h2>File Content</h2>
            <pre>{content}</pre>
            <h3>System Information</h3>
            <pre>{json.dumps(system_info, indent=2)}</pre>
        """
    except Exception as e:
        return f"""
            <h2>Error Reading File</h2>
            <p>Path: {file_path}</p>
            <p>Error: {str(e)}</p>
            <h3>System Information</h3>
            <pre>{json.dumps(system_info, indent=2)}</pre>
        """, 500

@app.errorhandler(500)
def internal_error(error):
    if "user" not in session or session["user"] != "admin":
        return "Access Denied! <a href='/'>Go back</a>"
    import traceback
    error_details = {
        'error_type': str(type(error).__name__),
        'error_message': str(error),
        'stack_trace': traceback.format_exc(),
        'python_version': sys.version,
        'flask_version': Flask.__version__,
        'debug_mode': app.debug,
        'database_path': 'users.db'
    }
    return f"""
        <h1>Internal Server Error</h1>
        <pre>
        Error Type: {error_details['error_type']}
        Message: {error_details['error_message']}
        
        Full Stack Trace:
        {error_details['stack_trace']}
        
        System Information:
        Python Version: {error_details['python_version']}
        Flask Version: {error_details['flask_version']}
        Debug Mode: {error_details['debug_mode']}
        Database: {error_details['database_path']}
        </pre>
    """, 500

@app.errorhandler(404)
def page_not_found(e):
    error_message = """
    Page not found. Please check our documentation for valid URLs.
    """
    return error_message, 404

 
@app.route("/profile/<int:user_id>")
def view_profile(user_id):
    if "user" not in session or session["user"] != "admin":
        return "Access Denied! <a href='/'>Go back</a>"
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    
    c.execute("""
        SELECT u.username, p.* 
        FROM users u 
        LEFT JOIN profiles p ON u.id = p.user_id 
        WHERE u.id = ?
    """, (user_id,))
    
    data = c.fetchone()
    conn.close()
    
    if data:
        return f"""
            <h2>User Profile</h2>
            <pre>
            Username: {data[0]}
            Full Name: {data[2]}
            Email: {data[3]}
            Phone: {data[4]}
            Credit Card: {data[5]}
            Address: {data[6]}
            </pre>
            <p><a href="/profile/{user_id - 1}">Previous User</a> | 
               <a href="/profile/{user_id + 1}">Next User</a></p>
        """
    return "Profile not found", 404

@app.route("/create_profile", methods=["GET", "POST"])
def create_profile():
    if request.method == "POST":
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username = ?", (session.get('user'),))
        user = c.fetchone()
        
        if user:
            c.execute("""
                INSERT OR REPLACE INTO profiles 
                (user_id, full_name, email, phone, credit_card, address)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                user[0],
                request.form.get('full_name', 'John Doe'),
                request.form.get('email', 'john@example.com'),
                request.form.get('phone', '123-456-7890'),
                request.form.get('credit_card', '4111-1111-1111-1111'),
                request.form.get('address', '123 Main St, City, Country')
            ))
            conn.commit()
            conn.close()
            return redirect(f"/profile/{user[0]}")
            
    return """
        <h2>Create Profile</h2>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <p>Full Name: <input name="full_name" value="John Doe"></p>
            <p>Email: <input name="email" value="john@example.com"></p>
            <p>Phone: <input name="phone" value="123-456-7890"></p>
            <p>Credit Card: <input name="credit_card" value="4111-1111-1111-1111"></p>
            <p>Address: <input name="address" value="123 Main St, City, Country"></p>
            <p><input type="submit" value="Create Profile"></p>
        </form>
    """

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form.get("username")

        # Check if user exists
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT username FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        
        if not user: # ✅ Protection from user enumeration (generic message for every inputted username)
            return render_template("forgot_password.html", message="If this user exists, a password reset will be sent.") 

        # ✅ Generate secure reset token
        token = generate_reset_token(username)
        
        # ✅ Pass only the token and username
        return render_template("forgot_password.html", message="If this user exists, a password reset will be sent.", reset_token=token, username=username)

    return render_template("forgot_password.html", message=None)


@app.route("/password-reset", methods=["GET", "POST"])
def password_reset():
    token = request.args.get("token")  # Get token from URL
    username = request.args.get("username")  # Get username from URL

    if request.method == "POST":
        username = request.form.get("username")
        new_password = request.form.get("new_password")
        form_token = request.form.get("token")  # Get token from form

        if not username or not form_token or not new_password:
            return "Missing required fields", 400

        # Check token validity
        if username not in reset_tokens or reset_tokens[username]["token"] != form_token:
            return "Invalid or expired token", 400

        if time.time() > reset_tokens[username]["expiry"]:
            return "Invalid or expired token", 400

        # Securely hash the new password
        hashed_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode('utf-8')

        # Update password in database
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, username))
        conn.commit()
        conn.close()

        # Remove used token
        del reset_tokens[username]

        return redirect(url_for("index"))

    return render_template("password_reset.html", token=token, username=username)

@app.route('/uploads/<path:filename>')
def serve_file(filename):
    # Correct path to the 'uploads' folder inside the SAFE_DIRECTORY
    upload_folder = os.path.join(SAFE_DIRECTORY, 'uploads')
    return send_from_directory(upload_folder, filename)

if __name__ == "__main__":
    # Ensure the 'uploads' directory exists inside the safe directory
    upload_dir = os.path.join(SAFE_DIRECTORY, 'uploads')
    if not os.path.exists(upload_dir):
        os.mkdir(upload_dir)
    
    if not os.path.exists("pizza.json"):
        save_pizzas([])  
    
    init_db()
    app.run(debug=True)
