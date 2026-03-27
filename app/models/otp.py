import datetime
import uuid
from enum import Enum
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum as SqlEnum,
    Integer,
    String,
    ForeignKey,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.models.base import Base


class OTPTypeEnum(str, Enum):
    """OTP type enumeration."""
    EMAIL_VERIFICATION = "email_verification"
    PASSWORD_RESET = "password_reset"
    TWO_FACTOR_AUTH = "two_factor_auth"
    PHONE_NUMBER_VERIFICATION = "phone_number_verification"
    ACCOUNT_RECOVERY = "account_recovery"


class OTP(Base):
    """OTP model for storing One-Time Passwords."""
    __tablename__ = "otps"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False,
    )
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
        nullable=False,
    )
    code = Column(String(10), nullable=False, unique=False)
    otp_type = Column(
        SqlEnum(OTPTypeEnum),
        nullable=False,
        default=OTPTypeEnum.EMAIL_VERIFICATION,
    )
    is_used = Column(Boolean, default=False, nullable=False)
    attempts = Column(Integer, default=0, nullable=False)
    max_attempts = Column(Integer, default=5, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    
    # Relationship
    user = relationship("User", backref="otps")

    def is_expired(self) -> bool:
        """Check if OTP is expired."""
        return datetime.datetime.utcnow() >= self.expires_at

    def is_valid(self) -> bool:
        """Check if OTP is valid (not used, not expired, and attempts not exceeded)."""
        return not self.is_used and not self.is_expired() and self.attempts < self.max_attempts

    def __repr__(self):
        return f"<OTP id={self.id} user_id={self.user_id} type={self.otp_type} used={self.is_used}>"
