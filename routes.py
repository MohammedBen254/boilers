from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from models import db, User, Boiler
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash, check_password_hash
# from flask_login import LoginManager, login_user, UserMixin
# from app import app
# login_manager = LoginManager()  
# login_manager.init_app(app)

main_routes = Blueprint('main', __name__)

@main_routes.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session.permanent = True  # Make session last as long as the PERMANENT_SESSION_LIFETIME
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            return redirect(url_for('main.dashboard'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@main_routes.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('main.login'))

@main_routes.route('/dashboard')
def dashboard():
    print(session)
    if 'user_id' not in session:
        return redirect(url_for('main.login'))
    
    search_query = request.args.get('search', '')
    
    if search_query:
        boilers = Boiler.query.filter(
            Boiler.matricul.ilike(f'%{search_query}%') |
            Boiler.client_name.ilike(f'%{search_query}%') |
            Boiler.responsible_person.ilike(f'%{search_query}%')
        ).all()
    else:
        boilers = Boiler.query.all()
    
    return render_template('dashboard.html', boilers=boilers)

@main_routes.route('/boiler/add', methods=['GET', 'POST'])
def add_boiler():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('main.login'))
    if request.method == 'POST':
        new_boiler = Boiler(
            matricul=request.form['boiler_id'],
            installation_date=request.form['installation_date'],
            warranty_end=request.form['warranty_end'],
            client_name=request.form['client_name'],
            responsible_person=request.form['responsible_person'],
            last_modified=request.form['last_modified']
        )
        db.session.add(new_boiler)
        db.session.commit()
        return redirect(url_for('main.dashboard'))
    return render_template('add_boiler.html')

@main_routes.route('/boiler/edit/<int:id>', methods=['GET', 'POST'])
def edit_boiler(id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('main.login'))
    boiler = Boiler.query.get(id)
    if request.method == 'POST':
        boiler.installation_date = request.form['installation_date']
        boiler.warranty_end = request.form['warranty_end']
        boiler.client_name = request.form['client_name']
        boiler.responsible_person = request.form['responsible_person']
        boiler.last_modified = request.form['last_modified']
        db.session.commit()
        return redirect(url_for('main.dashboard'))
    return render_template('edit_boiler.html', boiler=boiler)

@main_routes.route('/boiler/delete/<int:id>', methods=['GET', 'POST'])
def delete_boiler(id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('main.login'))
    boiler = Boiler.query.get(id)
    if request.method == 'POST':
        password = request.form['password']
        user = User.query.get(session['user_id'])
        if user.check_password(password):
            db.session.delete(boiler)
            db.session.commit()
            return redirect(url_for('main.dashboard'))
        else:
            flash('Incorrect password')
    return render_template('confirm_delete.html', boiler=boiler)
@main_routes.route('/users', methods=['GET'])
def users():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('main.login'))
    users = User.query.all()
    return render_template('users.html', users=users)

@main_routes.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        code = request.form['code']
        
        # Verify the registration code
        if code == '12345678':  # Replace with your actual code check
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password=hashed_password, is_admin=False)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful!')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Invalid registration code')
    
    return render_template('register.html')

@main_routes.route('/users/toggle_admin/<int:user_id>', methods=['POST'])
def toggle_admin(user_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('main.login'))

    user = User.query.get(user_id)
    if user:
        # Check if toggling will leave no admins
        if user.is_admin:
            admin_count = User.query.filter_by(is_admin=True).count()
            if admin_count <= 1:
                flash('Cannot remove the last remaining admin.')
                return redirect(url_for('main.users'))
        
        user.is_admin = not user.is_admin  # Toggle admin status
        db.session.commit()
        flash(f"User {user.username}'s admin status has been updated.")
    
    return redirect(url_for('main.users'))


@main_routes.route('/users/delete/<int:id>', methods=['GET', 'POST'])
def delete_user(id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('main.login'))
    
    user = User.query.get(id)
    
    if user.is_admin:
        admin_count = User.query.filter_by(is_admin=True).count()
        if admin_count <= 1:
            flash('Cannot delete the last remaining admin.')
            return redirect(url_for('main.users'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        if not password:
            flash('Password field is required.')
            return render_template('confirm_delete_user.html', user=user)
        
        current_user = User.query.get(session['user_id'])
        if current_user.check_password(password):
            db.session.delete(user)
            db.session.commit()
            flash('User deleted successfully.')
            return redirect(url_for('main.users'))
        else:
            flash('Incorrect password.')
    
    return render_template('confirm_delete_user.html', user=user)



@main_routes.route('/users/new', methods=['GET', 'POST'])
def new_user():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_admin = request.form['is_admin'] == 'True'
        
        # Hash the password before storing it
        hashed_password = generate_password_hash(password)
        
        # Create new user
        new_user = User(username=username, password=hashed_password, is_admin=is_admin)
        db.session.add(new_user)
        db.session.commit()

        flash(f"User {username} has been created successfully.")
        return redirect(url_for('main.users'))
    
    return render_template('add_user.html')

@main_routes.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('main.login'))
    
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_new_password = request.form['confirm_new_password']
        
        user = User.query.get(session['user_id'])
        
        if not user.check_password(current_password):
            flash('Current password is incorrect.')
        elif new_password != confirm_new_password:
            flash('New passwords do not match.')
        else:
            hashed_new_password = generate_password_hash(new_password)
            user.password = hashed_new_password
            db.session.commit()
            flash('Password changed successfully.')
            return redirect(url_for('main.dashboard'))
    
    return render_template('change_password.html')