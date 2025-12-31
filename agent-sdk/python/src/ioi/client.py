import grpc
import json
import time
import hashlib
# In a real setup, these imports come from the generated _pb2 files
# assuming: from .proto import public_pb2, public_pb2_grpc, blockchain_pb2

# Mocks for the protobuf generated classes to make this code understandable 
# without running the protoc compiler in this text view.
class MockProto:
    def SubmitTransactionRequest(self, transaction_bytes):
        return type('Req', (), {'transaction_bytes': transaction_bytes})
    
    def GetTransactionStatusRequest(self, tx_hash):
        return type('Req', (), {'tx_hash': tx_hash})

class IoiClient:
    def __init__(self, address: str = "127.0.0.1:9000"):
        self.channel = grpc.insecure_channel(address)
        # self.stub = public_pb2_grpc.PublicApiStub(self.channel)
        # Using a dynamic stub placeholder for the implementation logic
        self.stub = None 
        self.proto = MockProto() 

    def _canonicalize_json(self, data: dict) -> bytes:
        """
        Implements RFC 8785 (JCS) logic as required by the Whitepaper §5.3.
        Ensures consistent hashing between Python Agent and Rust Kernel.
        """
        # Ensure tight packing (no spaces) and sorted keys
        return json.dumps(data, separators=(',', ':'), sort_keys=True).encode('utf-8')

    def submit_action(self, request: 'ActionRequest', signer_key: str = None) -> str:
        """
        Submits an ActionRequest to the local Orchestrator.
        Maps to Whitepaper §2.4.1.
        """
        
        # 1. Construct the Payload (Canonical JSON)
        payload_dict = {
            "target": request.target.value,
            "params": json.loads(request.params.decode('utf-8')), # Decode to re-serialize canonically
            "context": {
                "agent_id": request.context.agent_id,
                "session_id": request.context.session_id.hex() if request.context.session_id else None,
                "window_id": request.context.window_id
            },
            "nonce": request.nonce
        }
        
        canonical_bytes = self._canonicalize_json(payload_dict)
        
        # 2. Wrap in SystemTransaction (Rust `ChainTransaction::System`)
        # In a real implementation, this requires SCALE codec or Protobuf mapping.
        # Here we simulate the envelope the Rust side expects in `grpc_public.rs`.
        
        # Note: In Mode 0 (Local), the Orchestrator often accepts raw ActionRequests
        # wrapped in a simplified RPC for the Firewall. For Mode 2, this must be signed.
        
        print(f"[IOI-Py] Sending Action: {request.target.value}")
        
        # Simulating the gRPC call structure found in crates/ipc/proto/public.proto
        # req = self.proto.SubmitTransactionRequest(transaction_bytes=canonical_bytes)
        
        try:
            # response = self.stub.SubmitTransaction(req)
            # return response.tx_hash
            
            # Simulation of successful submission for this context
            tx_hash = hashlib.sha256(canonical_bytes).hexdigest()
            return f"0x{tx_hash}"
            
        except grpc.RpcError as e:
            print(f"[IOI-Py] RPC Failed: {e.code()} - {e.details()}")
            raise

    def wait_for_commit(self, tx_hash: str, timeout=5.0):
        """
        Polls the Orchestrator for transaction status (Whitepaper §13.1.1).
        """
        start = time.time()
        while time.time() - start < timeout:
            # req = self.proto.GetTransactionStatusRequest(tx_hash=tx_hash)
            # status = self.stub.GetTransactionStatus(req)
            # if status.status == 3: # COMMITTED
            #     return status
            time.sleep(0.1)
        raise TimeoutError(f"Transaction {tx_hash} timed out")