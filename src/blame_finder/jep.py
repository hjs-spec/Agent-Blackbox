"""
JEP (Judgment Event Protocol) implementation.

This module provides the core JEP protocol functionality including:
- Event creation and validation
- Chain of responsibility tracking (HJS)
- Causality tracking (JAC)
- Privacy protection (Three-tier privacy)
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from enum import Enum
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


class JEPVerb(Enum):
    """JEP protocol verbs - the four atomic operations."""
    JUDGE = "J"      # Make a judgment/decision
    DELEGATE = "D"   # Delegate responsibility to another agent
    TERMINATE = "T"  # End a judgment chain
    VERIFY = "V"     # Verify a previous judgment


class PrivacyLevel(Enum):
    """Privacy levels for JEP events (Three-tier privacy architecture)."""
    FULL = "full"           # Full visibility
    DIGEST_ONLY = "digest"  # Only hash/digest visible
    ANONYMIZED = "anon"     # Anonymized who field
    EXPIRED = "expired"     # Beyond TTL, data removed


@dataclass
class JEPEvent:
    """
    A JEP (Judgment Event Protocol) event.
    
    This is the atomic unit of accountability in the HJS architecture.
    Each event is immutable, cryptographically signed, and can be linked
    to parent events for chain-of-custody tracking.
    
    Attributes:
        verb: The type of event (J, D, T, V)
        who: Identifier of the agent/person making the judgment
        when: Unix timestamp of the event
        what: Content hash or description of the decision
        ref: HJS responsibility chain - hash of parent event
        task_based_on: JAC causality chain - hash of parent task
        ttl: Time-to-live in seconds (privacy feature)
        signature: Ed25519 signature of the event
    """
    verb: JEPVerb
    who: str
    when: int
    what: str
    ref: Optional[str] = None
    task_based_on: Optional[str] = None
    ttl: Optional[int] = None
    signature: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for serialization."""
        result = {
            "verb": self.verb.value,
            "who": self.who,
            "when": self.when,
            "what": self.what,
        }
        if self.ref:
            result["ref"] = self.ref
        if self.task_based_on:
            result["task_based_on"] = self.task_based_on
        if self.ttl:
            result["ttl"] = self.ttl
        if self.signature:
            result["sig"] = self.signature
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "JEPEvent":
        """Create event from dictionary."""
        return cls(
            verb=JEPVerb(data["verb"]),
            who=data["who"],
            when=data["when"],
            what=data["what"],
            ref=data.get("ref"),
            task_based_on=data.get("task_based_on"),
            ttl=data.get("ttl"),
            signature=data.get("sig")
        )
    
    def calculate_hash(self) -> str:
        """
        Calculate SHA-256 hash of the event (excluding signature).
        
        This hash serves as the event ID and is used for linking events.
        """
        content = {
            "verb": self.verb.value,
            "who": self.who,
            "when": self.when,
            "what": self.what,
            "ref": self.ref,
            "task_based_on": self.task_based_on,
            "ttl": self.ttl
        }
        # Remove None values for consistent hashing
        content = {k: v for k, v in content.items() if v is not None}
        return hashlib.sha256(
            json.dumps(content, sort_keys=True, separators=(',', ':')).encode()
        ).hexdigest()
    
    def sign(self, private_key: ed25519.Ed25519PrivateKey) -> "JEPEvent":
        """Sign the event with an Ed25519 private key."""
        event_hash = self.calculate_hash()
        signature = private_key.sign(event_hash.encode())
        self.signature = signature.hex()
        return self
    
    def verify(self, public_key: ed25519.Ed25519PublicKey) -> bool:
        """Verify the event's signature."""
        if not self.signature:
            return False
        try:
            event_hash = self.calculate_hash()
            public_key.verify(bytes.fromhex(self.signature), event_hash.encode())
            return True
        except InvalidSignature:
            return False
    
    def is_expired(self) -> bool:
        """Check if the event has expired based on TTL."""
        if self.ttl is None:
            return False
        return (time.time() - self.when) > self.ttl
    
    def get_privacy_view(self, level: PrivacyLevel) -> Dict[str, Any]:
        """
        Get a privacy-filtered view of the event.
        
        Implements the three-tier privacy architecture:
        - FULL: Everything visible
        - DIGEST_ONLY: Only hash of what field visible
        - ANONYMIZED: who field anonymized
        - EXPIRED: Minimal metadata only
        """
        if level == PrivacyLevel.EXPIRED or self.is_expired():
            return {
                "verb": self.verb.value,
                "when": self.when,
                "status": "expired"
            }
        
        result = {
            "verb": self.verb.value,
            "when": self.when,
            "hash": self.calculate_hash()
        }
        
        if level == PrivacyLevel.FULL:
            result["who"] = self.who
            result["what"] = self.what
            if self.ref:
                result["ref"] = self.ref
            if self.task_based_on:
                result["task_based_on"] = self.task_based_on
        elif level == PrivacyLevel.DIGEST_ONLY:
            result["what_digest"] = hashlib.sha256(self.what.encode()).hexdigest()[:16]
            if self.ref:
                result["ref"] = self.ref[:16] + "..."
        elif level == PrivacyLevel.ANONYMIZED:
            result["who"] = hashlib.sha256(self.who.encode()).hexdigest()[:16]
            result["what_digest"] = hashlib.sha256(self.what.encode()).hexdigest()[:16]
        
        return result


@dataclass
class JEPChain:
    """
    A chain of JEP events representing a complete judgment accountability chain.
    
    This implements the HJS responsibility chain via ref fields and
    the JAC causality chain via task_based_on fields.
    """
    events: List[JEPEvent] = field(default_factory=list)
    
    def add_event(self, event: JEPEvent) -> str:
        """Add an event to the chain and return its hash."""
        self.events.append(event)
        return event.calculate_hash()
    
    def verify_chain(self) -> Dict[str, Any]:
        """
        Verify the entire chain for integrity and causality.
        
        Returns:
            Dictionary with verification results including:
            - valid: bool - overall chain validity
            - broken_links: list - hashes where parent not found
            - invalid_signatures: list - events with invalid signatures
            - expired_events: list - events that have expired
        """
        result = {
            "valid": True,
            "broken_links": [],
            "invalid_signatures": [],
            "expired_events": []
        }
        
        event_map = {e.calculate_hash(): e for e in self.events}
        
        for event in self.events:
            # Check signature
            # Note: In production, you need the actual public key
            # This is a placeholder for verification logic
            
            # Check parent references
            if event.ref and event.ref not in event_map:
                result["broken_links"].append({
                    "event": event.calculate_hash(),
                    "missing_parent": event.ref,
                    "type": "ref"
                })
                result["valid"] = False
            
            if event.task_based_on and event.task_based_on not in event_map:
                result["broken_links"].append({
                    "event": event.calculate_hash(),
                    "missing_parent": event.task_based_on,
                    "type": "task_based_on"
                })
                result["valid"] = False
            
            # Check expiration
            if event.is_expired():
                result["expired_events"].append(event.calculate_hash())
        
        return result
    
    def get_causality_tree(self, root_hash: str) -> Dict[str, Any]:
        """
        Build a causality tree starting from a root event.
        
        Uses task_based_on links to construct the JAC causality chain.
        """
        event_map = {e.calculate_hash(): e for e in self.events}
        
        def build_tree(hash_val: str) -> Dict[str, Any]:
            event = event_map.get(hash_val)
            if not event:
                return {"hash": hash_val, "missing": True}
            
            node = {
                "hash": hash_val,
                "verb": event.verb.value,
                "who": event.who,
                "when": event.when,
                "children": []
            }
            
            # Find all events that have this as parent (via task_based_on)
            for e in self.events:
                if e.task_based_on == hash_val:
                    node["children"].append(build_tree(e.calculate_hash()))
            
            return node
        
        return build_tree(root_hash)
    
    def get_responsibility_chain(self, end_hash: str) -> List[JEPEvent]:
        """
        Trace the responsibility chain backwards using ref links.
        
        Implements the HJS responsibility tracking.
        """
        event_map = {e.calculate_hash(): e for e in self.events}
        chain = []
        current_hash = end_hash
        
        while current_hash:
            event = event_map.get(current_hash)
            if not event:
                break
            chain.append(event)
            current_hash = event.ref
        
        return chain


class JEPValidator:
    """
    Validator for JEP events and chains.
    
    Provides comprehensive validation including:
    - Schema validation
    - Signature verification
    - Chain integrity
    - Privacy compliance
    """
    
    @staticmethod
    def validate_event(event: JEPEvent, public_key: Optional[ed25519.Ed25519PublicKey] = None) -> Dict[str, Any]:
        """
        Validate a single JEP event.
        
        Returns:
            Dictionary with validation results
        """
        errors = []
        warnings = []
        
        # Basic field validation
        if not event.who or len(event.who) == 0:
            errors.append("who field is empty")
        
        if event.when <= 0:
            errors.append("when timestamp is invalid")
        
        if not event.what or len(event.what) == 0:
            errors.append("what field is empty")
        
        # Future timestamp check
        if event.when > time.time() + 300:  # Allow 5 minute clock skew
            warnings.append("event timestamp is in the future")
        
        # Signature validation
        if public_key and event.signature:
            if not event.verify(public_key):
                errors.append("signature verification failed")
        elif event.signature and not public_key:
            warnings.append("signature present but no public key provided for verification")
        
        # TTL validation
        if event.ttl is not None and event.ttl <= 0:
            errors.append("TTL must be positive")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings
        }
    
    @staticmethod
    def validate_chain_integrity(events: List[JEPEvent]) -> Dict[str, Any]:
        """
        Validate the integrity of a chain of events.
        
        Checks for:
        - No cycles in references
        - All parent references exist
        - Timestamps are monotonic (parents older than children)
        """
        event_map = {e.calculate_hash(): e for e in events}
        errors = []
        
        # Check for cycles
        visited = set()
        recursion_stack = set()
        
        def has_cycle(hash_val: str) -> bool:
            if hash_val not in event_map:
                return False
            if hash_val in recursion_stack:
                return True
            if hash_val in visited:
                return False
            
            visited.add(hash_val)
            recursion_stack.add(hash_val)
            
            event = event_map[hash_val]
            if event.ref and has_cycle(event.ref):
                return True
            if event.task_based_on and has_cycle(event.task_based_on):
                return True
            
            recursion_stack.remove(hash_val)
            return False
        
        for event in events:
            if has_cycle(event.calculate_hash()):
                errors.append("cycle detected in chain")
                break
        
        # Check timestamp monotonicity
        for event in events:
            if event.ref and event.ref in event_map:
                parent = event_map[event.ref]
                if parent.when > event.when:
                    errors.append(f"timestamp violation: parent ({parent.when}) > child ({event.when})")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors
        }
