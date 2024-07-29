from app import app, db, bcrypt
from app import User

def create_user(username, email, password, role='user'):
    with app.app_context():
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            print(f"User '{username}' already exists.")
            if existing_user.role != role:
                existing_user.role = role
                db.session.commit()
                print(f"User '{username}' has been updated to the role '{role}'.")
            else:
                print(f"User '{username}' already has the role '{role}'.")
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=username, email=email, password=hashed_password, role=role)
            db.session.add(new_user)
            db.session.commit()
            print(f"User '{username}' with role '{role}' created successfully.")

if __name__ == '__main__':
    create_user('admin', 'admin@example.com', 'adminpass', 'admin')
    create_user('Rishe', 'rishekeshris@gmail.com', 'Rishe123', 'admin')
    #create_user('user2', 'user2@example.com', 'userpass')
