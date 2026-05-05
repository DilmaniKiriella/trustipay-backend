from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import func
import hashlib

app = FastAPI()
Base = declarative_base()

DATABASE_URL = "sqlite:///./ledger.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class User(Base):
    __tablename__ = "users"
    user_id = Column(Integer, primary_key=True, index=True)
    phone_number = Column(String, unique=True, index=True)
    current_balance = Column(Float, default=0.0)

class CentralLedger(Base):
    __tablename__ = "central_ledger"
    tx_id = Column(String, primary_key=True, index=True)
    sender_id = Column(Integer, index=True)
    receiver_id = Column(Integer, index=True)
    amount = Column(Float)
    category = Column(String)
    location = Column(String)
    device_id = Column(String)
    device_type = Column(String)
    network_type = Column(String)
    nonce = Column(String)
    prev_hash = Column(String)
    status = Column(String)
    reason = Column(String)
    source = Column(String)
    timestamp = Column(DateTime, default=func.now())
    central_prev_hash = Column(String)
    central_hash = Column(String)

Base.metadata.create_all(bind=engine)

class Transaction(BaseModel):
    tx_id: str
    sender_id: int
    receiver_id: int
    amount: float
    category: str
    location: str
    device_id: str
    device_type: str
    network_type: str
    nonce: str
    prev_hash: str
    status: str
    reason: str
    source: str

def generate_central_hash(prev_hash, tx_data):
    data_string = f"{tx_data}{prev_hash}"
    return hashlib.sha256(data_string.encode()).hexdigest()

@app.get("/ledger/transactions/{tx_id}/exists")
def check_transaction_exists(tx_id: str):
    db = SessionLocal()
    exists = db.query(CentralLedger).filter(CentralLedger.tx_id == tx_id).first()
    db.close()
    return {"exists": exists is not None}

@app.get("/ledger/users/{user_id}")
def get_user_info(user_id: int):
    db = SessionLocal()
    user = db.query(User).filter(User.user_id == user_id).first()
    db.close()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"user_id": user.user_id, "phone_number": user.phone_number, "current_balance": user.current_balance}

@app.post("/ledger/transactions")
def append_transaction(transaction: Transaction):
    db = SessionLocal()
    last_tx = db.query(CentralLedger).order_by(CentralLedger.timestamp.desc()).first()
    central_prev_hash = last_tx.central_hash if last_tx else "GENESIS"

    tx_data = f"{transaction.tx_id}{transaction.sender_id}{transaction.receiver_id}{transaction.amount}{transaction.status}{transaction.reason}{func.now()}"
    central_hash = generate_central_hash(central_prev_hash, tx_data)

    new_tx = CentralLedger(
        tx_id=transaction.tx_id,
        sender_id=transaction.sender_id,
        receiver_id=transaction.receiver_id,
        amount=transaction.amount,
        category=transaction.category,
        location=transaction.location,
        device_id=transaction.device_id,
        device_type=transaction.device_type,
        network_type=transaction.network_type,
        nonce=transaction.nonce,
        prev_hash=transaction.prev_hash,
        status=transaction.status,
        reason=transaction.reason,
        source=transaction.source,
        central_prev_hash=central_prev_hash,
        central_hash=central_hash
    )

    db.add(new_tx)

    if transaction.status == "APPROVED":
        sender = db.query(User).filter(User.user_id == transaction.sender_id).first()
        receiver = db.query(User).filter(User.user_id == transaction.receiver_id).first()
        if sender:
            sender.current_balance -= transaction.amount
        if receiver:
            receiver.current_balance += transaction.amount

    db.commit()
    db.close()
    return {"message": "Transaction appended successfully", "central_hash": central_hash}

@app.get("/ledger/verify")
def verify_ledger():
    db = SessionLocal()
    transactions = db.query(CentralLedger).order_by(CentralLedger.timestamp).all()
    db.close()

    previous_hash = "GENESIS"
    for tx in transactions:
        tx_data = f"{tx.tx_id}{tx.sender_id}{tx.receiver_id}{tx.amount}{tx.status}{tx.reason}{tx.timestamp}"
        computed_hash = generate_central_hash(previous_hash, tx_data)
        if computed_hash != tx.central_hash:
            return {"status": "FAILED", "error": f"Tampering detected at transaction {tx.tx_id}"}