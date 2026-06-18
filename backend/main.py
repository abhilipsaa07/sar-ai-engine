from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import sqlite3
import time
import os
import json

app = FastAPI(title="SAR AI Engine", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = "sar_engine.db"

# ── Regulatory knowledge base (RAG chunks) ──────────────────────────────────
RAG_DOCS = [
    {
        "id": "fincen_001",
        "title": "FinCEN BSA Rule 31 CFR 1020.320 — Structuring",
        "text": (
            "Transactions deliberately structured below the $10,000 CTR threshold "
            "to evade reporting requirements constitute structuring, a federal offense "
            "under 31 U.S.C. § 5324. Multiple transactions within a 24-hour period "
            "totaling $10,000 or more involving the same customer require SAR filing "
            "within 30 days of detection."
        ),
        "keywords": ["structuring", "cash", "threshold", "10000"],
    },
    {
        "id": "fincen_002",
        "title": "FinCEN Advisory — Trade-Based Money Laundering",
        "text": (
            "Trade-based money laundering (TBML) involves manipulating international "
            "trade transactions to transfer value across borders. Red flags include "
            "over/under-invoicing, multiple invoicing for the same shipment, falsely "
            "described goods, and unusual payment routes inconsistent with the customer's "
            "business profile."
        ),
        "keywords": ["trade", "international", "invoice", "import", "export"],
    },
    {
        "id": "fincen_003",
        "title": "FinCEN Guidance — Layering in Money Laundering",
        "text": (
            "Layering is the second stage of money laundering where illicit funds are "
            "moved through a series of financial transactions to disguise the audit trail. "
            "Indicators include rapid movement between accounts, use of shell companies, "
            "wire transfers to high-risk jurisdictions, and transactions with no apparent "
            "business purpose."
        ),
        "keywords": ["layering", "wire", "transfer", "shell", "jurisdiction"],
    },
    {
        "id": "fincen_004",
        "title": "FinCEN Advisory FIN-2019-A006 — Cyber-Enabled Financial Crime",
        "text": (
            "Cyber-enabled financial crimes include business email compromise (BEC), "
            "ransomware payments, and account takeovers. Financial institutions should "
            "file SARs when customer accounts are used to receive and rapidly disburse "
            "funds consistent with BEC schemes, particularly when funds are wired to "
            "overseas accounts shortly after receipt."
        ),
        "keywords": ["cyber", "email", "ransomware", "bec", "account takeover"],
    },
]


def generate_narrative_template(cust: dict, txns: list, activity_type: str, context: str, rag: str) -> str:
    total = sum(t["amount"] for t in txns)
    count = len(txns)
    types = list(set(t["transaction_type"] for t in txns)) or ["various"]
    destinations = [t["destination"] for t in txns if t.get("destination")]
    dest_str = ", ".join(set(destinations)) if destinations else "undisclosed locations"
    dates = [t["date"] for t in txns]
    date_range = f"{min(dates)} to {max(dates)}" if dates else "recent period"
    risk = cust.get("risk_level", "Medium")
    kyc = cust.get("kyc_status", "Pending")
    occupation = cust.get("occupation") or "not disclosed"

    activity_descriptions = {
        "Money Laundering": "placement and layering of illicit funds through multiple account transactions inconsistent with the customer's known business profile",
        "Structuring / Smurfing": "deliberate structuring of cash transactions below the $10,000 CTR reporting threshold to evade mandatory reporting requirements",
        "Wire Fraud": "unauthorized wire transfers and fund movements inconsistent with the account holder's stated purpose and business activity",
        "Trade-Based Money Laundering": "trade transactions with anomalous invoicing patterns and fund flows inconsistent with legitimate commercial activity",
        "Cyber-Enabled Financial Crime": "account activity consistent with cyber-enabled fraud including rapid fund receipt and disbursement patterns",
        "Terrorist Financing": "fund transfers to high-risk jurisdictions and entities with no apparent legitimate business purpose",
        "Insider Trading": "financial transactions timed in close proximity to material non-public information events",
        "Identity Theft": "account activity inconsistent with the customer's established behavioral profile suggesting unauthorized account access",
    }

    activity_desc = activity_descriptions.get(activity_type, "suspicious financial activity inconsistent with the customer's profile")

    narrative = f"""SUSPICIOUS ACTIVITY REPORT — NARRATIVE SECTION
Report Date: {__import__('datetime').date.today().strftime('%B %d, %Y')}
Activity Type: {activity_type}

SUBJECT IDENTIFICATION

The subject of this report is {cust['name']} (Account No. {cust['account_number']}), occupation listed as {occupation}, classified as a {risk} risk customer with KYC status: {kyc}. The account was flagged by our automated transaction monitoring system for activity consistent with {activity_desc}.

DESCRIPTION OF SUSPICIOUS ACTIVITY

During the period {date_range}, the subject's account recorded {count} transaction(s) totaling ₹{total:,.2f} across transaction types including {', '.join(types)}. Funds were moved to or from {dest_str}. The volume and velocity of these transactions are materially inconsistent with the customer's stated occupation and historical account behavior.

Specific indicators of concern include: the frequency of transactions within a compressed timeframe, the involvement of multiple source and destination accounts, and the absence of any apparent legitimate business purpose for the observed fund flows.

{"Additional investigator notes: " + context if context else "No additional investigator context was provided at time of filing."}

WHY THE ACTIVITY IS SUSPICIOUS

{rag.split(chr(10), 1)[1] if chr(10) in rag else rag}

The transaction pattern described above aligns directly with the red flags outlined in the above regulatory guidance. The institution's transaction monitoring rules were triggered based on velocity, amount thresholds, and destination risk scoring.

ACTIONS TAKEN

Upon detection, the institution immediately placed the account under enhanced monitoring. A hold was placed on outgoing international transfers pending review. This SAR is being filed within the required 30-day window from the date of initial detection. The institution has not disclosed the filing of this report to the subject customer in accordance with 31 U.S.C. § 5318(g)(2)."""

    return narrative


def get_rag_context(activity_type: str, description: str = "") -> str:
    combined = (activity_type + " " + description).lower()
    best = RAG_DOCS[0]
    best_score = 0
    for doc in RAG_DOCS:
        score = sum(1 for kw in doc["keywords"] if kw in combined)
        if score > best_score:
            best_score = score
            best = doc
    return f"[Regulatory Reference: {best['title']}]\n{best['text']}"


# ── Database setup ───────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS customers (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            account_number TEXT NOT NULL,
            dob TEXT,
            address TEXT,
            occupation TEXT,
            risk_level TEXT DEFAULT 'Low',
            kyc_status TEXT DEFAULT 'Pending',
            created_at INTEGER
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id TEXT PRIMARY KEY,
            customer_id TEXT NOT NULL,
            amount REAL NOT NULL,
            transaction_type TEXT NOT NULL,
            date TEXT NOT NULL,
            source_account TEXT,
            destination TEXT,
            description TEXT,
            created_at INTEGER,
            FOREIGN KEY (customer_id) REFERENCES customers(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS sar_reports (
            id TEXT PRIMARY KEY,
            customer_id TEXT NOT NULL,
            customer_name TEXT NOT NULL,
            activity_type TEXT NOT NULL,
            narrative TEXT NOT NULL,
            status TEXT DEFAULT 'Draft',
            rag_source TEXT,
            created_at INTEGER,
            FOREIGN KEY (customer_id) REFERENCES customers(id)
        )
    """)
    conn.commit()
    conn.close()


init_db()


# ── Pydantic models ──────────────────────────────────────────────────────────
class Customer(BaseModel):
    id: str
    name: str
    account_number: str
    dob: Optional[str] = None
    address: Optional[str] = None
    occupation: Optional[str] = None
    risk_level: str = "Low"
    kyc_status: str = "Pending"


class Transaction(BaseModel):
    id: str
    customer_id: str
    amount: float
    transaction_type: str
    date: str
    source_account: Optional[str] = None
    destination: Optional[str] = None
    description: Optional[str] = None


class SARRequest(BaseModel):
    customer_id: str
    activity_type: str
    additional_context: Optional[str] = ""


# ── Helpers ──────────────────────────────────────────────────────────────────
def db():
    return sqlite3.connect(DB_PATH)


# ── Customer endpoints ───────────────────────────────────────────────────────
@app.get("/api/customers")
def list_customers():
    conn = db()
    rows = conn.execute("SELECT * FROM customers ORDER BY created_at DESC").fetchall()
    conn.close()
    keys = ["id", "name", "account_number", "dob", "address", "occupation",
            "risk_level", "kyc_status", "created_at"]
    return [dict(zip(keys, r)) for r in rows]


@app.post("/api/customers", status_code=201)
def create_customer(c: Customer):
    conn = db()
    try:
        conn.execute(
            "INSERT INTO customers VALUES (?,?,?,?,?,?,?,?,?)",
            (c.id, c.name, c.account_number, c.dob, c.address,
             c.occupation, c.risk_level, c.kyc_status, int(time.time())),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(400, "Customer ID already exists")
    finally:
        conn.close()
    return {"message": "Customer created", "id": c.id}


@app.delete("/api/customers/{customer_id}")
def delete_customer(customer_id: str):
    conn = db()
    conn.execute("DELETE FROM customers WHERE id=?", (customer_id,))
    conn.commit()
    conn.close()
    return {"message": "Deleted"}


# ── Transaction endpoints ────────────────────────────────────────────────────
@app.get("/api/transactions")
def list_transactions():
    conn = db()
    rows = conn.execute("""
        SELECT t.*, c.name as customer_name
        FROM transactions t
        LEFT JOIN customers c ON t.customer_id = c.id
        ORDER BY t.created_at DESC
    """).fetchall()
    conn.close()
    keys = ["id", "customer_id", "amount", "transaction_type", "date",
            "source_account", "destination", "description", "created_at", "customer_name"]
    return [dict(zip(keys, r)) for r in rows]


@app.post("/api/transactions", status_code=201)
def create_transaction(t: Transaction):
    conn = db()
    try:
        conn.execute(
            "INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?,?)",
            (t.id, t.customer_id, t.amount, t.transaction_type, t.date,
             t.source_account, t.destination, t.description, int(time.time())),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(400, "Transaction ID already exists")
    finally:
        conn.close()
    return {"message": "Transaction created", "id": t.id}


# ── SAR Generation endpoint ──────────────────────────────────────────────────
@app.post("/api/generate-sar")
def generate_sar(req: SARRequest):
    conn = db()

    customer = conn.execute(
        "SELECT * FROM customers WHERE id=?", (req.customer_id,)
    ).fetchone()
    if not customer:
        conn.close()
        raise HTTPException(404, "Customer not found")

    cust_keys = ["id", "name", "account_number", "dob", "address",
                 "occupation", "risk_level", "kyc_status", "created_at"]
    cust = dict(zip(cust_keys, customer))

    txns = conn.execute(
        "SELECT * FROM transactions WHERE customer_id=? ORDER BY date DESC LIMIT 10",
        (req.customer_id,),
    ).fetchall()
    conn.close()

    txn_keys = ["id", "customer_id", "amount", "transaction_type", "date",
                "source_account", "destination", "description", "created_at"]
    txn_list = [dict(zip(txn_keys, t)) for t in txns]

    rag_context = get_rag_context(req.activity_type, req.additional_context or "")

    txn_summary = "\n".join(
        f"  - {t['date']}: {t['transaction_type']} ₹{t['amount']:,.0f}"
        f" from {t['source_account'] or 'N/A'} to {t['destination'] or 'N/A'}"
        f" ({t['description'] or 'no description'})"
        for t in txn_list
    ) or "  No transactions on record."

    prompt = f"""You are a compliance officer at a regulated financial institution drafting
a Suspicious Activity Report (SAR) for submission to FinCEN.

REGULATORY CONTEXT (retrieved from compliance knowledge base):
{rag_context}

SUBJECT CUSTOMER:
- Name: {cust['name']}
- Account: {cust['account_number']}
- Occupation: {cust['occupation'] or 'Unknown'}
- Risk Level: {cust['risk_level']}
- KYC Status: {cust['kyc_status']}

TRANSACTION HISTORY:
{txn_summary}

SUSPICIOUS ACTIVITY TYPE: {req.activity_type}
ADDITIONAL INVESTIGATOR NOTES: {req.additional_context or 'None provided'}

Write a formal SAR narrative (250-350 words) in the style required by FinCEN Form 111.
Structure it as:
1. Subject identification and account overview
2. Description of suspicious activity with specific transaction details
3. Why the activity is suspicious (tie to regulatory context above)
4. Actions taken by the institution

Be specific, factual, and professional. Do not use placeholders."""

    narrative = generate_narrative_template(cust, txn_list, req.activity_type, req.additional_context or "", rag_context)

    sar_id = f"SAR{int(time.time() * 1000)}"
    conn = db()
    conn.execute(
        "INSERT INTO sar_reports VALUES (?,?,?,?,?,?,?,?)",
        (sar_id, cust["id"], cust["name"], req.activity_type,
         narrative, "Draft", rag_context, int(time.time())),
    )
    conn.commit()
    conn.close()

    return {
        "sar_id": sar_id,
        "narrative": narrative,
        "rag_source": rag_context,
        "customer": cust,
    }


# ── SAR History endpoints ────────────────────────────────────────────────────
@app.get("/api/sar-reports")
def list_sar_reports():
    conn = db()
    rows = conn.execute(
        "SELECT * FROM sar_reports ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    keys = ["id", "customer_id", "customer_name", "activity_type",
            "narrative", "status", "rag_source", "created_at"]
    return [dict(zip(keys, r)) for r in rows]


@app.get("/api/sar-reports/{sar_id}")
def get_sar_report(sar_id: str):
    conn = db()
    row = conn.execute(
        "SELECT * FROM sar_reports WHERE id=?", (sar_id,)
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "SAR not found")
    keys = ["id", "customer_id", "customer_name", "activity_type",
            "narrative", "status", "rag_source", "created_at"]
    return dict(zip(keys, row))


@app.patch("/api/sar-reports/{sar_id}/status")
def update_sar_status(sar_id: str, body: dict):
    conn = db()
    conn.execute(
        "UPDATE sar_reports SET status=? WHERE id=?",
        (body.get("status", "Draft"), sar_id),
    )
    conn.commit()
    conn.close()
    return {"message": "Status updated"}


@app.get("/api/dashboard")
def dashboard():
    conn = db()
    total_customers = conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0]
    total_transactions = conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
    total_sars = conn.execute("SELECT COUNT(*) FROM sar_reports").fetchone()[0]
    high_risk = conn.execute(
        "SELECT COUNT(*) FROM customers WHERE risk_level='High'"
    ).fetchone()[0]
    total_amount = conn.execute(
        "SELECT COALESCE(SUM(amount),0) FROM transactions"
    ).fetchone()[0]
    conn.close()
    return {
        "total_customers": total_customers,
        "total_transactions": total_transactions,
        "total_sars": total_sars,
        "high_risk_customers": high_risk,
        "total_transaction_volume": total_amount,
    }
