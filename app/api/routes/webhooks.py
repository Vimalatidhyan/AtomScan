"""Webhook management routes.

Delivery uses ``httpx`` for real HTTP POST with:
  - JSON payload + ``X-Technieum-Event`` header
  - Optional HMAC-SHA256 signature in ``X-Technieum-Signature``
  - 10-second connect/read timeout
  - success_count / failure_count / last_triggered persisted on every attempt
"""
import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone
from typing import Optional, List

import httpx
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, ConfigDict, HttpUrl
from sqlalchemy.orm import Session

from app.api.models.common import StatusResponse
from app.db.database import get_db
from app.db.models import Webhook

logger = logging.getLogger(__name__)
router = APIRouter()

_DELIVERY_TIMEOUT = httpx.Timeout(10.0)


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class WebhookCreateRequest(BaseModel):
    url: HttpUrl
    events: List[str] = ["scan.completed", "finding.critical"]
    secret: Optional[str] = None


class WebhookUpdateRequest(BaseModel):
    url: Optional[HttpUrl] = None
    events: Optional[List[str]] = None
    active: Optional[bool] = None


class WebhookResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    url: str
    events: List[str]
    active: bool
    success_count: int
    failure_count: int


# ---------------------------------------------------------------------------
# Delivery helper
# ---------------------------------------------------------------------------

def _build_signature(secret: str, body: bytes) -> str:
    """Return ``sha256=<hex>`` HMAC-SHA256 of *body* using *secret*."""
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={sig}"


def _deliver(webhook: Webhook, event_type: str, payload: dict) -> tuple[bool, str]:
    """POST *payload* to webhook URL.  Returns (success, error_message)."""
    body = json.dumps(payload, default=str).encode()
    headers = {
        "Content-Type": "application/json",
        "X-Technieum-Event": event_type,
        "User-Agent": "Technieum-Webhook/2.0",
    }
    if webhook.secret:
        headers["X-Technieum-Signature"] = _build_signature(webhook.secret, body)

    try:
        resp = httpx.post(
            str(webhook.url),
            content=body,
            headers=headers,
            timeout=_DELIVERY_TIMEOUT,
        )
        if resp.is_success:
            return True, ""
        return False, f"HTTP {resp.status_code}: {resp.text[:200]}"
    except httpx.TimeoutException:
        return False, "delivery timed out after 10s"
    except httpx.RequestError as exc:
        return False, f"request error: {exc}"


def _persist_delivery(db: Session, webhook: Webhook, success: bool) -> None:
    """Update delivery counters and last_triggered timestamp."""
    if success:
        webhook.success_count += 1
    else:
        webhook.failure_count += 1
    webhook.last_triggered = datetime.now(timezone.utc)
    db.commit()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

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
                "last_triggered": wh.last_triggered.isoformat()
                if wh.last_triggered
                else None,
            }
            for wh in webhooks
        ],
    }


@router.post("/", summary="Create webhook")
def create_webhook(req: WebhookCreateRequest, db: Session = Depends(get_db)):
    """Register a new webhook."""
    webhook = Webhook(
        url=str(req.url),
        events=",".join(req.events),
        secret=req.secret,
        active=True,
    )
    db.add(webhook)
    db.commit()
    db.refresh(webhook)
    return {
        "id": webhook.id,
        "url": webhook.url,
        "events": webhook.events.split(","),
        "active": webhook.active,
        "created_at": webhook.created_at.isoformat() if webhook.created_at else None,
    }


@router.put("/{webhook_id}", summary="Update webhook")
def update_webhook(
    webhook_id: int, req: WebhookUpdateRequest, db: Session = Depends(get_db)
):
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
        "active": webhook.active,
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


@router.post("/{webhook_id}/test", summary="Test webhook delivery")
def test_webhook(webhook_id: int, db: Session = Depends(get_db)):
    """Send a real test event to the webhook URL.

    The request is a genuine HTTP POST.  Delivery result (success or failure)
    is persisted to ``success_count`` / ``failure_count``.
    """
    webhook = db.query(Webhook).filter(Webhook.id == webhook_id).first()
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")
    if not webhook.active:
        raise HTTPException(status_code=400, detail="Webhook is inactive")

    payload = {
        "event": "webhook.test",
        "webhook_id": webhook.id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": "Technieum test delivery",
    }

    success, error = _deliver(webhook, "webhook.test", payload)
    _persist_delivery(db, webhook, success)

    if success:
        logger.info("webhook test delivered",
                    extra={"webhook_id": webhook.id, "url": webhook.url})
        return StatusResponse(
            status="delivered",
            message=f"Test event delivered to webhook {webhook_id}",
        )
    else:
        logger.warning("webhook test failed",
                       extra={"webhook_id": webhook.id, "error": error})
        # Return 200 with failure detail (delivery errors are not server errors)
        return StatusResponse(
            status="failed",
            message=f"Delivery failed: {error}",
        )


@router.get("/{webhook_id}/events", summary="Get webhook delivery summary")
def get_webhook_events(webhook_id: int, db: Session = Depends(get_db)):
    """Get delivery statistics for a webhook."""
    webhook = db.query(Webhook).filter(Webhook.id == webhook_id).first()
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return {
        "webhook_id": webhook.id,
        "url": webhook.url,
        "active": webhook.active,
        "success_count": webhook.success_count,
        "failure_count": webhook.failure_count,
        "last_triggered": webhook.last_triggered.isoformat()
        if webhook.last_triggered
        else None,
        "total_attempts": webhook.success_count + webhook.failure_count,
        "success_rate": (
            round(webhook.success_count / (webhook.success_count + webhook.failure_count) * 100, 1)
            if (webhook.success_count + webhook.failure_count) > 0
            else None
        ),
    }
