import asyncio
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

router = APIRouter(prefix="/stream", tags=["stream"])

# In production, attach to actual scan log stream
LOG_DIR = Path(__file__).resolve().parent.parent.parent / "logs"


@router.get("/logs/{scan_id}")
async def stream_logs(scan_id: str):
    """SSE stream of scan logs (placeholder: tail reconx.log)."""
    async def event_stream():
        log_file = LOG_DIR / "reconx.log"
        if not log_file.exists():
            yield f"data: {__import__('json').dumps({'msg': 'No log file yet.'})}\n\n"
            return
        with open(log_file) as f:
            f.seek(0, 2)  # end of file
            while True:
                line = f.readline()
                if line:
                    yield f"data: {__import__('json').dumps({'line': line.rstrip()})}\n\n"
                else:
                    await asyncio.sleep(0.5)
    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
