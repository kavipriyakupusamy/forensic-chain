import hashlib
import json
from datetime import datetime


def hash_file(filepath):
    """Return the SHA-256 hash of an evidence file."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


class Block:
    def __init__(self, index, evidence_id, action, from_user, to_user,
                 evidence_hash, details, previous_hash,
                 timestamp=None, stored_hash=None):
        self.index = index
        self.timestamp = timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.evidence_id = evidence_id
        self.action = action
        self.from_user = from_user
        self.to_user = to_user
        self.evidence_hash = evidence_hash
        self.details = details
        self.previous_hash = previous_hash
        # When loaded from the database we keep the stored hash, so that
        # any tampering with the stored data is detected by is_chain_valid().
        self.hash = stored_hash or self.calculate_hash()

    def calculate_hash(self):
        block_data = {
            "index": self.index,
            "timestamp": self.timestamp,
            "evidence_id": self.evidence_id,
            "action": self.action,
            "from_user": self.from_user,
            "to_user": self.to_user,
            "evidence_hash": self.evidence_hash,
            "details": self.details,
            "previous_hash": self.previous_hash,
        }
        encoded = json.dumps(block_data, sort_keys=True).encode()
        return hashlib.sha256(encoded).hexdigest()

    def to_dict(self):
        return dict(self.__dict__)


class Blockchain:
    def __init__(self, blocks=None):
        self.chain = blocks if blocks else [self.create_genesis_block()]

    @staticmethod
    def from_rows(rows):
        """Rebuild the chain from database rows."""
        blocks = [
            Block(
                index=r["block_index"], evidence_id=r["evidence_id"],
                action=r["action"], from_user=r["from_user"], to_user=r["to_user"],
                evidence_hash=r["evidence_hash"], details=r["details"],
                previous_hash=r["previous_hash"], timestamp=r["timestamp"],
                stored_hash=r["hash"],
            )
            for r in rows
        ]
        return Blockchain(blocks)

    def create_genesis_block(self):
        return Block(0, "GENESIS", "INIT", "system", "system", "0",
                     "Genesis Block", "0")

    def get_last_block(self):
        return self.chain[-1]

    def add_block(self, evidence_id, action, from_user, to_user,
                  evidence_hash, details=""):
        new_block = Block(
            index=len(self.chain),
            evidence_id=evidence_id,
            action=action,
            from_user=from_user,
            to_user=to_user,
            evidence_hash=evidence_hash,
            details=details,
            previous_hash=self.get_last_block().hash,
        )
        self.chain.append(new_block)
        return new_block

    def is_chain_valid(self):
        """Return (True, None) or (False, index_of_first_bad_block)."""
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]
            if current.hash != current.calculate_hash():
                return False, i
            if current.previous_hash != previous.hash:
                return False, i
        if self.chain and self.chain[0].hash != self.chain[0].calculate_hash():
            return False, 0
        return True, None

    def get_evidence_history(self, evidence_id):
        return [b.to_dict() for b in self.chain if b.evidence_id == evidence_id]
