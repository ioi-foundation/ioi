# sdk/python/src/ioi/types.py
from enum import Enum
from pydantic import BaseModel, Field
from typing import Optional, List, Any, Dict

class ActionTarget(str, Enum):
    NET_FETCH = "net::fetch"
    FS_WRITE = "fs::write"
    FS_READ = "fs::read"
    UI_CLICK = "ui::click"
    SYS_EXEC = "sys::exec"
    WALLET_SIGN = "wallet::sign"
    CUSTOM = "custom"

class ActionContext(BaseModel):
    agent_id: str
    session_id: Optional[bytes] = None
    window_id: Optional[int] = None

class ActionRequest(BaseModel):
    target: ActionTarget
    params: bytes # Canonical JSON bytes
    context: ActionContext
    nonce: int

class Receipt(BaseModel):
    tx_hash: str
    block_height: int
    status: str