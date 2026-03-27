from typing import Optional, List
from sqlalchemy import select, desc, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.otp import OTP, OTPTypeEnum
from app.models.user import User


class OTPRepository:
    """Repository for OTP database operations."""
    
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(self, otp: OTP) -> OTP:
        """Create a new OTP record."""
        self.db.add(otp)
        await self.db.flush()
        return otp

    async def find_by_id(self, id: str) -> Optional[OTP]:
        """Find OTP by ID."""
        stmt = select(OTP).where(OTP.id == id)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def find_by_user_and_type(
        self, user_id: str, otp_type: OTPTypeEnum
    ) -> Optional[OTP]:
        """Find the most recent unused OTP for a user of a specific type."""
        stmt = (
            select(OTP)
            .where(
                and_(
                    OTP.user_id == user_id,
                    OTP.otp_type == otp_type,
                    not OTP.is_used,
                )
            )
            .order_by(desc(OTP.created_at))
            .limit(1)
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def find_by_user_id(self, user_id: str) -> List[OTP]:
        """Find all OTPs for a user."""
        stmt = select(OTP).where(OTP.user_id == user_id).order_by(desc(OTP.created_at))
        result = await self.db.execute(stmt)
        return result.scalars().all()

    async def find_by_code_and_email(
        self, code: str, email: str, otp_type: OTPTypeEnum
    ) -> Optional[OTP]:
        """Find OTP by code, email, and type."""
        stmt = (
            select(OTP)
            .join(User, OTP.user_id == User.id)
            .where(
                and_(
                    OTP.code == code,
                    User.email == email,
                    OTP.otp_type == otp_type,
                    not OTP.is_used,
                )
            )
            .order_by(desc(OTP.created_at))
            .limit(1)
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def update(self, otp: OTP) -> OTP:
        """Update an existing OTP record."""
        await self.db.merge(otp)
        await self.db.flush()
        return otp

    async def mark_as_used(self, id: str) -> bool:
        """Mark an OTP as used."""
        otp = await self.find_by_id(id)
        if otp:
            otp.is_used = True
            await self.update(otp)
            return True
        return False

    async def increment_attempts(self, id: str) -> bool:
        """Increment the number of failed attempts for an OTP."""
        otp = await self.find_by_id(id)
        if otp:
            otp.attempts += 1
            await self.update(otp)
            return True
        return False

    async def delete(self, id: str) -> bool:
        """Delete an OTP record."""
        otp = await self.find_by_id(id)
        if otp:
            await self.db.delete(otp)
            await self.db.flush()
            return True
        return False

    async def delete_expired_otps(self) -> int:
        """Delete all expired OTP records. Returns count of deleted records."""
        import datetime
        stmt = select(OTP).where(OTP.expires_at <= datetime.datetime.utcnow())
        result = await self.db.execute(stmt)
        expired_otps = result.scalars().all()
        for otp in expired_otps:
            await self.db.delete(otp)
        await self.db.flush()
        return len(expired_otps)

    async def delete_used_otps_by_user(self, user_id: str) -> int:
        """Delete all used OTPs for a user. Returns count of deleted records."""
        stmt = select(OTP).where(
            and_(OTP.user_id == user_id, OTP.is_used)
        )
        result = await self.db.execute(stmt)
        used_otps = result.scalars().all()
        for otp in used_otps:
            await self.db.delete(otp)
        await self.db.flush()
        return len(used_otps)
