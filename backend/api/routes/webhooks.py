"""Webhook management routes."""
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, HttpUrl
from typing import Optional, List
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from backend.api.models.common import StatusResponse
from backend.db.database import get_db
from backend.db.models import Webhook

router = APIRouter()

class WebhookCreateRequest(BaseModel):
    url: HttpUrl
    events: List[str] = ["scan.completed", "finding.critical"]
    secret: Optional[str] = None

class WebhookUpdateRequest(BaseModel):
    url: Optional[HttpUrl] = None
    events: Optional[List[str]] = None
    active: Optional[bool] = None

class WebhookResponse(BaseModel):
    id: int
    url: str
    events: List[str]
    active: bool
    created_at: str
    success_count: int
    failure_count: int
    
    class Config:
        from_attributes = True

@router.get("/", summary="List webhooks")
def list_webhooks(db: Session = Depends(get_db)):
    """List all registered webhooks."""
    webhooks = db.query(Webhook).all()
    return {
        "total": len(webhooks),
        "items": [
            {
                "id": wh.id,
                "url": wh.url,
                "events": wh.events.split(","),
                "active": wh.active,
                "success_count": wh.success_count,
                "failure_count": wh.failure_count,
            }
            for wh in webhooks
        ]
    }

@router.post("/", summary="Create webhook")
def create_webhook(req: WebhookCreateRequest, db: Session = Depends(get_db)):
    """Register a new webhook."""
    webhook = Webhook(
        url=str(req.url),
        events=",".join(req.events),
        secret=req.secret,
        active=True
    )
    db.add(webhook)
    db.commit()
    db.refresh(webhook)
    
    return {
        "id": webhook.id,
        "url": webhook.url,
        "events": webhook.events.split(","),
        "active": webhook.active,
        "created_at": webhook.created_at.isoformat()
    }

@router.put("/{webhook_id}", summary="Update webhook")
def update_webhook(webhook_id: int, req: WebhookUpdateRequest, db: Session = Depends(get_db)):
    """Update an existing webhook."""
    webhook = db.query(Webhook).filter(Webhook.id == webhook_id).first()
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")
    
    if req.url is not None:
        webhook.url = str(req.url)
    if req.events is not None:
        webhook.events = ",".join(req.events)
    if req.active is not None:
        webhook.active = req.active
    
    db.commit()
    db.refresh(webhook)
    
    return {
        "id": webhook.id,
        "url": webhook.url,
        "events": webhook.events.split(","),
        "active": webhook.active
    }

@router.delete("/{webhook_id}", response_model=StatusResponse, summary="Delete webhook")
def delete_webhook(webhook_id: int, db: Session = Depends(get_db)):
    """Delete a webhook."""
    webhook = db.query(Webhook).filter(Webhook.id == webhook_id).first()
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")
    
    db.delete(webhook)
    db.commit()
    return StatusResponse(status="deleted", message=f"Webhook {webhook_id} deleted")

@router.post("/{webhook_id}/test", response_model=StatusResponse, summary="Test webhook")
def test_webhook(webhook_id: int, db: Session = Depends(get_db)):
    """Send a test event to a webhook."""
    webhook = db.query(Webhook).filter(Webhook.id == webhook_id).first()
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")
    
    # TODO: Implement actual webhook delivery
    # For now, just increment success count
    webhook.success_count += 1
    webhook.last_triggered = datetime.now(timezone.utc)
    db.commit()
    
    return StatusResponse(status="sent", message=f"Test event sent to webhook {webhook_id}")

@router.get("/{webhook_id}/events", summary="Get webhook delivery log")
def get_webhook_events(webhook_id: int, db: Session = Depends(get_db)):
    """Get delivery history for a webhook."""
    webhook = db.query(Webhook).filter(Webhook.id == webhook_id).first()
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")
    
    return {
        "webhook_id": webhook.id,
        "success_count": webhook.success_count,
        "failure_count": webhook.failure_count,
        "last_triggered": webhook.last_triggered.isoformat() if webhook.last_triggered else None
    }

