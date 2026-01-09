# sdk/python/src/ioi_swarm/client.py
import grpc
import json
import time
import hashlib
import sys
import os

# Robust import strategy for generated protobufs
try:
    # 1. Try absolute import (works when installed as package 'ioi_swarm')
    from ioi_swarm.proto import public_pb2, public_pb2_grpc
except ImportError:
    try:
        # 2. Try relative import (works during local development within the package)
        from .proto import public_pb2, public_pb2_grpc
    except ImportError as e:
        # 3. Last resort: Manually add the proto directory to sys.path
        # This fixes issues where the generated code tries to import 'blockchain_pb2' directly
        proto_path = os.path.join(os.path.dirname(__file__), 'proto')
        if proto_path not in sys.path:
            sys.path.append(proto_path)
        
        try:
            import public_pb2
            import public_pb2_grpc
        except ImportError as e2:
            print(f"[IOI-Swarm] CRITICAL IMPORT ERROR: {e}")
            print(f"[IOI-Swarm] SECONDARY IMPORT ERROR: {e2}")
            print("[IOI-Swarm] WARNING: Protobuf files not found or failed to load. Please run codegen.")
            public_pb2 = None
            public_pb2_grpc = None

class IoiClient:
    def __init__(self, address: str = "0.0.0.0:9000"):
        self.address = address
        self.channel = grpc.insecure_channel(address)
        
        if public_pb2_grpc:
            self.stub = public_pb2_grpc.PublicApiStub(self.channel)
        else:
            self.stub = None

    def _canonicalize_json(self, data: dict) -> bytes:
        """
        Implements RFC 8785 (JCS) logic as required by the Whitepaper §5.3.
        Ensures consistent hashing between Python Agent and Rust Kernel.
        """
        # Ensure tight packing (no spaces) and sorted keys
        return json.dumps(data, separators=(',', ':'), sort_keys=True).encode('utf-8')

    def submit_action(self, request: 'ActionRequest', signer_key: str = None) -> str:
        """
        Submits an ActionRequest to the local Orchestrator via gRPC.
        Maps to Whitepaper §2.4.1.
        """
        if not self.stub:
            print("[IOI-Swarm] Error: Client not initialized (missing protos).")
            return "0x0000"

        # 1. Construct the Payload (Canonical JSON)
        # In a full implementation, this matches the Rust `SystemPayload` struct structure.
        payload_dict = {
            "target": request.target.value,
            "params": json.loads(request.params.decode('utf-8')), 
            "context": {
                "agent_id": request.context.agent_id,
                "session_id": request.context.session_id.hex() if request.context.session_id else None,
                "window_id": request.context.window_id
            },
            "nonce": request.nonce
        }
        
        canonical_bytes = self._canonicalize_json(payload_dict)
        
        print(f"[IOI-Swarm] Connecting to Node at {self.address}...")
        print(f"[IOI-Swarm] Sending Action: {request.target.value}")

        # 2. Call the Node
        try:
            # Wrap the payload in the protobuf request object
            req = public_pb2.SubmitTransactionRequest(transaction_bytes=canonical_bytes)
            
            response = self.stub.SubmitTransaction(req)
            
            print(f"[IOI-Swarm] Node Accepted Transaction!")
            print(f"[IOI-Swarm] TxHash: {response.tx_hash}")
            
            return response.tx_hash
            
        except grpc.RpcError as e:
            # If the node is offline, this catches the connection error
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                 print(f"[IOI-Swarm] Error: Could not connect to IOI Node at {self.address}")
                 print(f"            Is 'ioi-local' running?")
            else:
                print(f"[IOI-Swarm] RPC Failed: {e.code()} - {e.details()}")
            return "0x0000"

    def wait_for_commit(self, tx_hash: str, timeout=5.0):
        """
        Polls the Orchestrator for transaction status (Whitepaper §13.1.1).
        """
        if not self.stub: return

        start = time.time()
        while time.time() - start < timeout:
            try:
                req = public_pb2.GetTransactionStatusRequest(tx_hash=tx_hash)
                status_resp = self.stub.GetTransactionStatus(req)
                
                # Map Enum: UNKNOWN=0, PENDING=1, IN_MEMPOOL=2, COMMITTED=3, REJECTED=4
                if status_resp.status == 3: # COMMITTED
                    return status_resp
                elif status_resp.status == 4: # REJECTED
                    raise Exception(f"Transaction rejected: {status_resp.error_message}")
                    
            except grpc.RpcError:
                pass
                
            time.sleep(0.5)
        raise TimeoutError(f"Transaction {tx_hash} timed out")