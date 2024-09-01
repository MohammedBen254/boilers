from app import app
from models import db, User

with app.app_context():
    db.create_all()

    # Create an admin user
    admin = User(username='admin', is_admin=True)
    admin.set_password('admin_password')
    db.session.add(admin)
    db.session.commit()
