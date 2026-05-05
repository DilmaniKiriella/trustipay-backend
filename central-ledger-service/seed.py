from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from main import Base, User, CentralLedger

DATABASE_URL = "sqlite:///./ledger.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create tables if they don't exist
Base.metadata.create_all(bind=engine)

def seed_users():
    db = SessionLocal()

    # Check if users already exist
    existing_users = db.query(User).filter(User.user_id.in_([1, 2])).all()
    if not existing_users:
        # Add seed users
        user1 = User(user_id=1, phone_number="user_001", current_balance=10000)
        user2 = User(user_id=2, phone_number="user_002", current_balance=5000)
        db.add_all([user1, user2])
        db.commit()
        print("Seeded users successfully.")
    else:
        print("Users already exist. Skipping seeding.")

    db.close()

if __name__ == "__main__":
    seed_users()