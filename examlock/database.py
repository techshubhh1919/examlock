import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, Float
from sqlalchemy.orm import declarative_base, sessionmaker
from crypto_utils import crypto_service

DATABASE_URL = "sqlite:///examlock.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class ExamPaper(Base):
    __tablename__ = "exam_papers"
    id = Column(Integer, primary_key=True, index=True)
    exam_code = Column(String(50), unique=True, index=True)
    title = Column(String(100))
    encrypted_payload = Column(Text)
    nonce = Column(String(50))
    aes_key_b64 = Column(String(100)) # In production, key is split or shared via KMS
    digital_signature = Column(Text)
    center_id = Column(String(50))
    device_fingerprint = Column(String(100))
    release_timestamp = Column(Float)
    created_at = Column(String(50), default=lambda: str(datetime.datetime.now(datetime.timezone.utc)))

class AuditLedger(Base):
    __tablename__ = "audit_ledger"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String(50))
    event_type = Column(String(50))
    details = Column(Text)
    previous_hash = Column(String(64))
    block_hash = Column(String(64))

def init_db():
    Base.metadata.create_all(bind=engine)
    # Initialize Genesis block in audit ledger if empty
    db = SessionLocal()
    if db.query(AuditLedger).count() == 0:
        genesis_time = str(datetime.datetime.now(datetime.timezone.utc))
        raw = f"0|{genesis_time}|GENESIS|Audit Ledger Initialized"
        genesis_hash = crypto_service.calculate_sha256(raw)
        genesis_block = AuditLedger(
            timestamp=genesis_time,
            event_type="GENESIS",
            details="Audit Ledger Initialized",
            previous_hash="0" * 64,
            block_hash=genesis_hash
        )
        db.add(genesis_block)
        db.commit()
    db.close()

def append_audit_log(event_type: str, details: str) -> dict:
    """Appends an immutable tamper-evident block into the audit chain."""
    db = SessionLocal()
    try:
        last_block = db.query(AuditLedger).order_by(AuditLedger.id.desc()).first()
        prev_hash = last_block.block_hash if last_block else "0" * 64
        timestamp = str(datetime.datetime.now(datetime.timezone.utc))
        
        block_content = f"{prev_hash}|{timestamp}|{event_type}|{details}"
        block_hash = crypto_service.calculate_sha256(block_content)
        
        new_block = AuditLedger(
            timestamp=timestamp,
            event_type=event_type,
            details=details,
            previous_hash=prev_hash,
            block_hash=block_hash
        )
        db.add(new_block)
        db.commit()
        db.refresh(new_block)
        return {
            "id": new_block.id,
            "timestamp": new_block.timestamp,
            "event_type": new_block.event_type,
            "details": new_block.details,
            "previous_hash": new_block.previous_hash,
            "block_hash": new_block.block_hash
        }
    finally:
        db.close()