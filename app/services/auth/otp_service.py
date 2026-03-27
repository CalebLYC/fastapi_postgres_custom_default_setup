import datetime
import random
import string
from fastapi import HTTPException, status

from app.core.security import SecurityUtils
from app.models.otp import OTP, OTPTypeEnum
from app.repositories.otp_repository import OTPRepository
from app.repositories.user_repository import UserRepository
from app.schemas.otp_schema import (
    OTPRequestSchema,
    OTPVerificationSchema,
    OTPVerificationResponseSchema,
    VerifyEmailWithOTPSchema,
    ResetPasswordWithOTPSchema,
)


class OTPService:
    """Service for OTP operations."""

    def __init__(
        self,
        otp_repos: OTPRepository,
        user_repos: UserRepository,
    ):
        self.otp_repos = otp_repos
        self.user_repos = user_repos
        self.otp_expiration_minutes = 10  # OTP valid for 10 minutes
        self.otp_length = 6  # 6-digit OTP
        self.max_attempts = 5  # Maximum failed attempts

    def _generate_otp_code(self, length: int = None) -> str:
        """Generate a random OTP code."""
        if length is None:
            length = self.otp_length
        return "".join(random.choices(string.digits, k=length))

    async def send_otp(
        self, request: OTPRequestSchema
    ) -> dict:
        """
        Generate and setup an OTP for a user.
        
        Args:
            request: OTP request containing email and OTP type
            
        Returns:
            Dictionary with success status and message
            
        Raises:
            HTTPException: If user not found
        """
        # Find user by email
        user = await self.user_repos.find_by_email(request.email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User with email {request.email} not found",
            )

        # Generate OTP code
        otp_code = self._generate_otp_code()

        # Calculate expiration time
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(
            minutes=self.otp_expiration_minutes
        )

        # Create OTP record
        otp = OTP(
            user_id=user.id,
            code=otp_code,
            otp_type=request.otp_type,
            is_used=False,
            attempts=0,
            max_attempts=self.max_attempts,
            expires_at=expires_at,
        )

        await self.otp_repos.create(otp)

        # TODO: Send OTP code to user email using email service
        # For now, returning the code for development purposes
        # In production, this should be sent via email and not returned

        return {
            "success": True,
            "message": f"OTP sent to {request.email}",
            "otp_code": otp_code,
            "user_id": str(user.id),
        }

    async def verify_otp(
        self, request: OTPVerificationSchema
    ) -> OTPVerificationResponseSchema:
        """
        Verify an OTP code for a user.
        
        Args:
            request: OTP verification request
            
        Returns:
            OTPVerificationResponseSchema with verification result
            
        Raises:
            HTTPException: If verification fails
        """
        # Find the OTP
        otp = await self.otp_repos.find_by_code_and_email(
            code=request.code, email=request.email, otp_type=request.otp_type
        )

        if not otp:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="OTP not found or invalid OTP type",
            )

        # Check if OTP is valid
        if not otp.is_valid():
            await self.otp_repos.increment_attempts(otp.id)

            if otp.is_expired():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="OTP has expired",
                )
            if otp.attempts >= otp.max_attempts:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Maximum OTP verification attempts exceeded",
                )
            if otp.is_used:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="OTP has already been used",
                )

        # Mark OTP as used
        await self.otp_repos.mark_as_used(otp.id)

        return OTPVerificationResponseSchema(
            success=True,
            message="OTP verified successfully",
            user_id=str(otp.user_id),
        )

    async def verify_email_with_otp(
        self, request: VerifyEmailWithOTPSchema
    ) -> dict:
        """
        Verify user email using OTP and mark user as verified.
        
        Args:
            request: Email verification request with OTP code
            
        Returns:
            Dictionary with success status and message
            
        Raises:
            HTTPException: If OTP verification fails or user not found
        """
        # First verify the OTP
        verification_request = OTPVerificationSchema(
            email=request.email,
            code=request.code,
            otp_type=OTPTypeEnum.EMAIL_VERIFICATION,
        )
        await self.verify_otp(verification_request)

        # Find user and mark as verified
        user = await self.user_repos.find_by_email(request.email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User with email {request.email} not found",
            )

        user.is_verified = True
        await self.user_repos.update(user)

        return {
            "success": True,
            "message": "Email verified successfully",
            "user_id": str(user.id),
        }

    async def reset_password_with_otp(
        self, request: ResetPasswordWithOTPSchema
    ) -> dict:
        """
        Reset user password using OTP verification.
        
        Args:
            request: Password reset request with OTP code and new password
            
        Returns:
            Dictionary with success status and message
            
        Raises:
            HTTPException: If OTP verification fails, passwords don't match, or user not found
        """
        # Validate password confirmation
        if request.new_password != request.new_password_confirmation:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Passwords do not match",
            )

        # Verify OTP
        verification_request = OTPVerificationSchema(
            email=request.email,
            code=request.code,
            otp_type=OTPTypeEnum.PASSWORD_RESET,
        )
        await self.verify_otp(verification_request)

        # Find user and reset password
        user = await self.user_repos.find_by_email(request.email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User with email {request.email} not found",
            )

        # Hash and update password
        user.password = SecurityUtils.hash_password(request.new_password)
        await self.user_repos.update(user)

        return {
            "success": True,
            "message": "Password reset successfully",
            "user_id": str(user.id),
        }

    async def verify_two_factor_otp(
        self, request: OTPVerificationSchema
    ) -> OTPVerificationResponseSchema:
        """
        Verify a two-factor authentication OTP.
        
        Args:
            request: OTP verification request for 2FA
            
        Returns:
            OTPVerificationResponseSchema with verification result
        """
        # Ensure it's a 2FA OTP type
        if request.otp_type != OTPTypeEnum.TWO_FACTOR_AUTH:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid OTP type for 2FA verification",
            )

        return await self.verify_otp(request)

    async def cleanup_expired_otps(self) -> dict:
        """
        Clean up expired OTP records from database.
        
        Returns:
            Dictionary with cleanup result
        """
        deleted_count = await self.otp_repos.delete_expired_otps()
        return {
            "success": True,
            "message": f"Deleted {deleted_count} expired OTPs",
            "deleted_count": deleted_count,
        }
