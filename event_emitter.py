"""Event bus for Technieum Enterprise."""
from typing import Callable, Dict, List, Any
import logging

logger = logging.getLogger(__name__)

class EventEmitter:
    """Simple pub/sub event bus."""

    def __init__(self) -> None:
        self._listeners: Dict[str, List[Callable]] = {}

    def on(self, event: str, callback: Callable) -> None:
        """Register a listener for an event."""
        self._listeners.setdefault(event, []).append(callback)

    def off(self, event: str, callback: Callable) -> None:
        """Remove a listener."""
        listeners = self._listeners.get(event, [])
        if callback in listeners:
            listeners.remove(callback)

    def emit(self, event: str, data: Any = None) -> None:
        """Emit an event to all registered listeners."""
        for cb in self._listeners.get(event, []):
            try:
                cb(data)
            except Exception as e:
                logger.error(f"Event handler error for {event}: {e}")
        logger.debug(f"Event emitted: {event}")

# Global emitter instance
emitter = EventEmitter()
