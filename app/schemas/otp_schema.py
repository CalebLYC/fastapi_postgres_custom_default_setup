import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.models.otp import OTPTypeEnum


class OTPReadSchema(BaseModel):
    """Schema for reading OTP data."""
    id: str
    code: str
    otp_type: OTPTypeEnum
    is_used: bool
    attempts: int
    max_attempts: int
    created_at: datetime.datetime
    expires_at: datetime.datetime

    model_config = ConfigDict(from_attributes=True)


class OTPRequestSchema(BaseModel):
    """Schema for requesting OTP (send OTP to user)."""
    email: EmailStr = Field(..., description="User email address")
    otp_type: OTPTypeEnum = Field(
        default=OTPTypeEnum.EMAIL_VERIFICATION,
        description="Type of OTP to generate",
    )

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "email": "jdoe@example.com",
                "otp_type": "email_verification",
            }
        },
    )


class OTPVerificationSchema(BaseModel):
    """Schema for verifying OTP code."""
    email: EmailStr = Field(..., description="User email address")
    code: str = Field(
        ...,
        min_length=4,
        max_length=10,
        description="The OTP code to verify",
    )
    otp_type: OTPTypeEnum = Field(
        default=OTPTypeEnum.EMAIL_VERIFICATION,
        description="Type of OTP being verified",
    )

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "email": "jdoe@example.com",
                "code": "123456",
                "otp_type": "email_verification",
            }
        },
    )


class OTPVerificationResponseSchema(BaseModel):
    """Schema for OTP verification response."""
    success: bool = Field(..., description="Whether the OTP was valid")
    message: str = Field(..., description="Response message")
    user_id: Optional[str] = Field(None, description="User ID if verification was successful")

    model_config = ConfigDict(from_attributes=True)


class VerifyEmailWithOTPSchema(BaseModel):
    """Schema for verifying email with OTP."""
    email: EmailStr = Field(..., description="User email address")
    code: str = Field(
        ...,
        min_length=4,
        max_length=10,
        description="The OTP code to verify",
    )

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "email": "jdoe@example.com",
                "code": "123456",
            }
        },
    )


class ResetPasswordWithOTPSchema(BaseModel):
    """Schema for resetting password with OTP."""
    email: EmailStr = Field(..., description="User email address")
    code: str = Field(
        ...,
        min_length=4,
        max_length=10,
        description="The OTP code to verify",
    )
    new_password: str = Field(..., min_length=8, description="New password")
    new_password_confirmation: str = Field(..., min_length=8, description="Password confirmation")

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "email": "jdoe@example.com",
                "code": "123456",
                "new_password": "newpassword123",
                "new_password_confirmation": "newpassword123",
            }
        },
    )
