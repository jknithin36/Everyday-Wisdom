from flask import Flask, render_template, request, session, redirect, url_for, jsonify
from flask_bcrypt import Bcrypt
import re
from mongita import MongitaClientDisk
from datetime import datetime
from random import sample
from bson import ObjectId

app = Flask(__name__)
app.secret_key = 'nani_nithin'
bcrypt = Bcrypt(app)

# Initialize Mongita database
client = MongitaClientDisk("database")
db = client["my_database"]
users = db["users"]
quotes = db["quotes"]  # Collection for storing quotes
comments = db["comments"]

@app.route('/')
def index():
    return render_template('index.html')

# Update the signup route to validate password complexity
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        
        # Check if the email already exists in the database
        if users.find_one({'email': email}):
            return "Email already exists! Please use a different email."

        # Check if the username already exists in the database
        if users.find_one({'username': username}):
            return "Username already exists! Please choose a different one."

        # Validate password complexity
        if not re.match(r'^(?=.*[A-Z])(?=.*[!@#$%^&*])(?=.*[0-9])(?=.*[a-z]).{8,}$', password):
            return "Password must be at least 8 characters long and contain at least one uppercase letter, one special character, and one digit."

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Insert new user into the database with hashed password
        user_data = {'email': email, 'username': username, 'password': hashed_password}
        users.insert_one(user_data)
        
        # Render account created page
        return redirect(url_for('login'))
    
    return render_template('signup.html')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Retrieve user data from the database
        user = users.find_one({'email': email})

        if user and bcrypt.check_password_hash(user['password'], password):
            # If user exists and password matches, set the 'logged_in' session variable to True
            session['logged_in'] = True
            session['email'] = email
            return redirect(url_for('dashboard'))  # Redirect to dashboard route
        else:
            return "Invalid email or password. Please try again."

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'logged_in' in session:
        email = session['email']
        user = users.find_one({'email': email})  # Retrieve user data
        if user:
            # Pass the user data to the dashboard template
            return render_template('dashboard.html', user=user)
        else:
            # Handle the case where the user is not found (although this shouldn't happen if session is valid)
            return "User not found."
    else:
        return redirect(url_for('login'))
    

@app.route('/add_quote', methods=['GET', 'POST'])
def add_quote():
    if request.method == 'POST':
        quote_text = request.form['quote_text']
        author = request.form['author']
        
        # Get username from session
        if 'logged_in' in session:
            email = session['email']
            user = users.find_one({'email': email})
            if user:
                username = user['username']
                # Save the quote to the database
                quote_data = {'quote_text': quote_text, 'author': author, 'added_by': username, 'timestamp': datetime.now()}
                quotes.insert_one(quote_data)
                return redirect(url_for('dashboard'))  # Redirect to dashboard after adding the quote
        return "User not found."

    return render_template('addQuote.html')    


@app.route('/my_quotes')
def my_quotes():
    if 'logged_in' in session:
        email = session['email']
        user = users.find_one({'email': email})  # Retrieve user data
        if user:
            username = user['username']
            # Filter quotes by the username of the logged-in user
            user_quotes = list(quotes.find({'added_by': username}))
            return render_template('myQuotes.html', user_quotes=user_quotes)
        else:
            return "User not found."
    else:
        return redirect(url_for('login'))
    
@app.route('/try_our_app')
def try_our_app():
    all_quotes = list(quotes.find({}))  # Retrieve all quotes from the database
    random_quotes = sample(all_quotes, 10) if len(all_quotes) >= 10 else all_quotes  # Choose 10 random quotes
    return render_template('tryOurApp.html', random_quotes=random_quotes)



@app.route('/delete_quote', methods=['POST'])
def delete_quote():
    if 'logged_in' in session:
        quote_id = request.form.get('quote_id')

        if quote_id:
            # Find and delete the quote from the database based on the provided _id
            result = quotes.delete_one({'_id': ObjectId(quote_id)})

            if result.deleted_count > 0:
                # Quote successfully deleted
                return redirect(url_for('my_quotes'))
            else:
                # Quote not found or deletion failed
                return "Quote not found or deletion failed."
        else:
            return "Invalid quote ID."
    else:
        return redirect(url_for('login'))

@app.route('/edit_quote', methods=['GET', 'POST'])
def edit_quote():
    if request.method == 'GET':
        quote_id = request.args.get('quote_id')
        if quote_id:
            # Retrieve the quote from the database by ID
            quote = quotes.find_one({'_id': ObjectId(quote_id)})
            if quote:
                return render_template('edit_quote.html', quote=quote)
            else:
                return "Quote not found."
        else:
            return "Invalid quote ID."
    
    elif request.method == 'POST':
        quote_id = request.form['quote_id']
        quote_text = request.form['quote_text']
        author = request.form['author']

        # Update the quote in the database
        result = quotes.update_one({'_id': ObjectId(quote_id)}, {'$set': {'quote_text': quote_text, 'author': author}})
        if result.modified_count > 0:
            return redirect(url_for('my_quotes'))
        else:
            return "Failed to update quote."    

@app.route('/logout')
def logout():
    if 'logged_in' in session:
        session.pop('logged_in', None)
        session.pop('email', None)
    return redirect(url_for('login'))

# @app.route('/comment', methods=['GET', 'POST'])
# def comment():
#     if request.method == 'GET':
#         quote_id = request.args.get('quote_id')
#         if quote_id:
#             # Retrieve the quote from the database by ID
#             quote = quotes.find_one({'_id': ObjectId(quote_id)})
#             if quote:
#                 return render_template('comment.html', quote=quote)
#             else:
#                 return "Quote not found."
#         else:
#             return "Invalid quote ID."
    
#     elif request.method == 'POST':
#         quote_id = request.form['quote_id']
#         comment_text = request.form['comment_text']

#         # Insert the comment into the database
#         comment_data = {'quote_id': quote_id, 'comment_text': comment_text, 'timestamp': datetime.now()}
#         comments.insert_one(comment_data)
#         return redirect(url_for('try_our_app'))

from flask import session

@app.route('/comment', methods=['GET', 'POST'])
def comment():
    if request.method == 'GET':
        quote_id = request.args.get('quote_id')
        if quote_id:
            # Retrieve the quote from the database by ID
            quote = quotes.find_one({'_id': ObjectId(quote_id)})
            if quote:
                return render_template('comment.html', quote=quote)
            else:
                return "Quote not found."
        else:
            return "Invalid quote ID."
    
    elif request.method == 'POST':
        quote_id = request.form['quote_id']
        comment_text = request.form['comment_text']

        # Get the user's email from the session
        if 'email' in session:
            user_email = session['email']
        else:
            return redirect(url_for('login'))  # Redirect to login page if user is not logged in

        # Insert the comment into the database along with the user's email
        comment_data = {
            'quote_id': quote_id,
            'comment_text': comment_text,
            'user_email': user_email,  # Save user's email along with the comment
            'timestamp': datetime.now()
        }
        comments.insert_one(comment_data)
        return redirect(url_for('try_our_app'))



@app.route('/comments')
def view_comments():
    quote_id = request.args.get('quote_id')
    if quote_id:
        # Retrieve all comments for the given quote ID from the database
        quote_comments = list(comments.find({'quote_id': quote_id}))
        return render_template('viewComments.html', quote_comments=quote_comments)
    else:
        return "Invalid quote ID."

# @app.route('/view_user_comments')
# def view_user_comments():
#     if 'email' in session:
#         user_email = session['email']
#         # Query the comments collection to find comments entered by the user
#         user_comments = list(comments.find({'user_email': user_email}))
#         return render_template('view_user_comments.html', user_comments=user_comments)
#     else:
#         return redirect(url_for('login'))

@app.route('/view_user_comments')
def view_user_comments():
    if 'email' in session:
        user_email = session['email']
        # Query the comments collection to find comments entered by the user
        user_comments = list(comments.find({'user_email': user_email}))
        
        # Iterate over user's comments to fetch corresponding quote data
        for comment in user_comments:
            quote_id = comment['quote_id']
            # Query the quotes collection to get the quote data
            quote_data = quotes.find_one({'_id': ObjectId(quote_id)})
            # Add the quote data to the comment dictionary
            comment['quote_data'] = quote_data
        
        return render_template('view_user_comments.html', user_comments=user_comments)
    else:
        return redirect(url_for('login'))

# @app.route('/delete_comment/<comment_id>', methods=['POST'])
# def delete_comment(comment_id):
#     if 'email' in session:
#         user_email = session['email']
#         # Check if the logged-in user owns the comment
#         comment = comments.find_one({'_id': ObjectId(comment_id), 'user_email': user_email})
#         if comment:
#             # Delete the comment from the database
#             comments.delete_one({'_id': ObjectId(comment_id)})
#             return jsonify({'success': True, 'message': 'Comment deleted successfully'})
#         else:
#             return jsonify({'success': False, 'message': 'Unauthorized or Comment not found'}), 403
#     else:
#         return jsonify({'success': False, 'message': 'User not logged in'}), 401

@app.route('/delete_comment/<comment_id>', methods=['POST'])
def delete_comment(comment_id):
    if 'email' in session:
        user_email = session['email']
        # Check if the logged-in user owns the comment
        comment = comments.find_one({'_id': ObjectId(comment_id), 'user_email': user_email})
        if comment:
            # Delete the comment from the database
            comments.delete_one({'_id': ObjectId(comment_id)})
            return jsonify({'success': True, 'message': 'Comment deleted successfully'})
        else:
            return jsonify({'success': False, 'message': 'Unauthorized or Comment not found'}), 403
    else:
        return jsonify({'success': False, 'message': 'User not logged in'}), 401

if __name__ == '__main__':
    app.run(debug=True)
