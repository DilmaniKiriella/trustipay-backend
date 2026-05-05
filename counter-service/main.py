from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ValidationError
import requests
import hashlib
import hmac
import json
from secrets import compare_digest

app = FastAPI()

CENTRAL_LEDGER_URL = "http://central-ledger-service:8001"
FRAUD_MODEL_URL = "http://fraud-model-service:8002"

HMAC_SECRET = "trustipay_demo_secret"

class MinifiedIOU(BaseModel):
    t: str
    s: int
    r: int
    ts: str
    a: float
    c: str
    l: str
    d: str
    dt: str
    nt: str
    n: str
    p: str
    sig: str

def expand_iou(data: MinifiedIOU):
    KEY_MAP = {
        "t": "tx_id",
        "s": "sender_id",
        "r": "receiver_id",
        "ts": "timestamp",
        "a": "amount",
        "c": "category",
        "l": "location",
        "d": "device_id",
        "dt": "device_type",
        "nt": "network_type",
        "n": "nonce",
        "p": "prev_hash",
        "sig": "signature",
    }
    return {KEY_MAP[key]: value for key, value in data.dict().items()}

def verify_signature(payload):
    # Remove the signature field
    signature = payload.pop("signature", None)
    if not signature:
        return False

    # Sort keys and create JSON compact format
    sorted_payload = json.dumps(payload, separators=(",", ":"), sort_keys=True)

    # Generate HMAC-SHA256 signature
    hmac_instance = hmac.new(HMAC_SECRET.encode(), sorted_payload.encode(), hashlib.sha256)
    computed_signature = hmac_instance.hexdigest()

    # Use compare_digest for constant-time comparison
    return compare_digest(computed_signature, signature)

def check_duplicate_tx(tx_id):
    response = requests.get(f"{CENTRAL_LEDGER_URL}/ledger/transactions/{tx_id}/exists")
    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Central ledger service error")
    return response.json().get("exists", False)

def check_sufficient_balance(sender_id, amount):
    response = requests.get(f"{CENTRAL_LEDGER_URL}/ledger/users/{sender_id}")
    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Central ledger service error")
    user_info = response.json()
    return user_info.get("current_balance", 0) >= amount

@app.get("/health")
def health_check():
    return {"status": "Counter Service is running"}

@app.get("/ledger-data")
def get_ledger_data():
    response = requests.get("http://central-ledger-service:8001/ledger")
    return response.json()

@app.post("/counter/transactions")
def process_transaction(iou: MinifiedIOU):
    try:
        # Expand IOU
        expanded_iou = expand_iou(iou)

        # Validate required fields (handled by Pydantic)
        if expanded_iou["amount"] <= 0:
            raise HTTPException(status_code=400, detail="Invalid transaction payload")

        # Validate HMAC signature
        if not verify_signature(expanded_iou):
            expanded_iou["status"] = "REJECTED"
            expanded_iou["reason"] = "Invalid signature"
            requests.post(f"{CENTRAL_LEDGER_URL}/ledger/transactions", json=expanded_iou)
            return {"message": "Transaction rejected", "reason": "Invalid signature"}

        # Check for duplicate transaction ID
        if check_duplicate_tx(expanded_iou["tx_id"]):
            expanded_iou["status"] = "REJECTED"
            expanded_iou["reason"] = "Duplicate transaction"
            requests.post(f"{CENTRAL_LEDGER_URL}/ledger/transactions", json=expanded_iou)
            return {"message": "Transaction rejected", "reason": "Duplicate transaction"}

        # Check for sufficient balance
        if not check_sufficient_balance(expanded_iou["sender_id"], expanded_iou["amount"]):
            expanded_iou["status"] = "REJECTED"
            expanded_iou["reason"] = "Insufficient balance"
            requests.post(f"{CENTRAL_LEDGER_URL}/ledger/transactions", json=expanded_iou)
            return {"message": "Transaction rejected", "reason": "Insufficient balance"}

        # Fetch sender and receiver details
        sender_response = requests.get(f"{CENTRAL_LEDGER_URL}/ledger/users/{expanded_iou['sender_id']}")
        receiver_response = requests.get(f"{CENTRAL_LEDGER_URL}/ledger/users/{expanded_iou['receiver_id']}")

        if sender_response.status_code != 200 or receiver_response.status_code != 200:
            raise HTTPException(status_code=500, detail="Central ledger service error")

        sender_info = sender_response.json()
        receiver_info = receiver_response.json()

        # Build fraud JSON
        fraud_payload = {
            **expanded_iou,
            "sender_current_balance": sender_info.get("current_balance"),
            "receiver_current_balance": receiver_info.get("current_balance"),
            "phone_number": sender_info.get("phone_number"),
        }

        # Call fraud model
        fraud_response = requests.post(f"{FRAUD_MODEL_URL}/fraud/check", json=fraud_payload)
        if fraud_response.status_code != 200:
            raise HTTPException(status_code=500, detail="Fraud model service error")

        fraud_result = fraud_response.json()
        expanded_iou["status"] = fraud_result.get("status", "REJECTED")
        expanded_iou["reason"] = fraud_result.get("reason", "Fraud model error")

        # Send final result to central ledger
        expanded_iou["source"] = "FRAUD_MODEL"
        ledger_response = requests.post(f"{CENTRAL_LEDGER_URL}/ledger/transactions", json=expanded_iou)
        if ledger_response.status_code != 200:
            raise HTTPException(status_code=500, detail="Central ledger service error")

        return {"message": "Transaction processed successfully", "ledger_response": ledger_response.json()}

    except ValidationError as e:
        raise HTTPException(status_code=400, detail="Invalid transaction payload")

def check_tx_exists(tx_id):
    """Check if a transaction exists in the central ledger."""
    response = requests.get(f"{CENTRAL_LEDGER_URL}/ledger/transactions/{tx_id}/exists")
    if response.status_code != 200:
        raise Exception("Error checking transaction existence")
    return response.json().get("exists", False)

def get_user(user_id):
    """Retrieve user details from the central ledger."""
    response = requests.get(f"{CENTRAL_LEDGER_URL}/ledger/users/{user_id}")
    if response.status_code != 200:
        raise Exception("Error retrieving user details")
    return response.json()

def append_transaction(transaction):
    """Append a transaction to the central ledger."""
    response = requests.post(f"{CENTRAL_LEDGER_URL}/ledger/transactions", json=transaction)
    if response.status_code != 200:
        raise Exception("Error appending transaction to ledger")
    return response.json()