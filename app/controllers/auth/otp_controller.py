from fastapi import APIRouter, Depends, status

from app.providers.service_providers import get_otp_service
from app.schemas.otp_schema import (
    OTPRequestSchema,
    OTPVerificationSchema,
    OTPVerificationResponseSchema,
    VerifyEmailWithOTPSchema,
    ResetPasswordWithOTPSchema,
)
from app.services.auth.otp_service import OTPService
from app.utils.constants import http_status


# Router
router = APIRouter(
    prefix="/otp",
    tags=["OTP"],
    dependencies=[],
    responses=http_status.router_responses,
)


@router.post(
    "/send",
    status_code=status.HTTP_200_OK,
    response_description="Send OTP to user email",
    summary="Send OTP",
)
async def send_otp(
    request: OTPRequestSchema,
    service: OTPService = Depends(get_otp_service),
):
    """
    Send an OTP to a user's email address.
    
    This endpoint generates a One-Time Password and prepares to send it to the user.
    The OTP will be valid for 10 minutes.
    
    Args:
        request (OTPRequestSchema): Contains email and OTP type
        service (OTPService): OTP service dependency
        
    Returns:
        Dictionary with success status, message, and user_id
        
    Raises:
        HTTPException: 404 if user not found
    """
    return await service.send_otp(request)


@router.post(
    "/verify",
    response_model=OTPVerificationResponseSchema,
    status_code=status.HTTP_200_OK,
    response_description="Verify OTP code",
    summary="Verify OTP",
)
async def verify_otp(
    request: OTPVerificationSchema,
    service: OTPService = Depends(get_otp_service),
):
    """
    Verify an OTP code for a user.
    
    This endpoint validates that the provided OTP code matches the one sent to the user.
    
    Args:
        request (OTPVerificationSchema): Contains email, code, and OTP type
        service (OTPService): OTP service dependency
        
    Returns:
        OTPVerificationResponseSchema with verification result
        
    Raises:
        HTTPException: 404 if OTP not found
        HTTPException: 400 if OTP is expired or has been used
        HTTPException: 429 if max attempts exceeded
    """
    return await service.verify_otp(request)


@router.post(
    "/verify-email",
    status_code=status.HTTP_200_OK,
    response_description="Verify email with OTP",
    summary="Verify Email",
)
async def verify_email_with_otp(
    request: VerifyEmailWithOTPSchema,
    service: OTPService = Depends(get_otp_service),
):
    """
    Verify a user's email address using an OTP code.
    
    This endpoint validates the OTP and marks the user's email as verified.
    
    Args:
        request (VerifyEmailWithOTPSchema): Contains email and OTP code
        service (OTPService): OTP service dependency
        
    Returns:
        Dictionary with success status, message, and user_id
        
    Raises:
        HTTPException: 404 if user or OTP not found
        HTTPException: 400 if OTP is invalid, expired, or already used
        HTTPException: 429 if max attempts exceeded
    """
    return await service.verify_email_with_otp(request)


@router.post(
    "/reset-password",
    status_code=status.HTTP_200_OK,
    response_description="Reset password with OTP",
    summary="Reset Password",
)
async def reset_password_with_otp(
    request: ResetPasswordWithOTPSchema,
    service: OTPService = Depends(get_otp_service),
):
    """
    Reset a user's password using an OTP code.
    
    This endpoint validates the OTP and user-provided password confirmation,
    then updates the user's password.
    
    Args:
        request (ResetPasswordWithOTPSchema): Contains email, OTP code, and new password
        service (OTPService): OTP service dependency
        
    Returns:
        Dictionary with success status, message, and user_id
        
    Raises:
        HTTPException: 404 if user or OTP not found
        HTTPException: 400 if OTP is invalid, expired, already used, or passwords don't match
        HTTPException: 429 if max attempts exceeded
    """
    return await service.reset_password_with_otp(request)


@router.post(
    "/verify-2fa",
    response_model=OTPVerificationResponseSchema,
    status_code=status.HTTP_200_OK,
    response_description="Verify two-factor authentication OTP",
    summary="Verify 2FA OTP",
)
async def verify_two_factor_otp(
    request: OTPVerificationSchema,
    service: OTPService = Depends(get_otp_service),
):
    """
    Verify a two-factor authentication (2FA) OTP code.
    
    This endpoint validates a 2FA OTP code for enhanced security.
    
    Args:
        request (OTPVerificationSchema): Contains email, code, and OTP type (must be two_factor_auth)
        service (OTPService): OTP service dependency
        
    Returns:
        OTPVerificationResponseSchema with verification result
        
    Raises:
        HTTPException: 400 if OTP type is not two_factor_auth
        HTTPException: 404 if OTP not found
        HTTPException: 400 if OTP is expired or has been used
        HTTPException: 429 if max attempts exceeded
    """
    return await service.verify_two_factor_otp(request)


@router.post(
    "/cleanup-expired",
    status_code=status.HTTP_200_OK,
    response_description="Cleanup expired OTPs",
    summary="Cleanup Expired OTPs",
)
async def cleanup_expired_otps(
    service: OTPService = Depends(get_otp_service),
):
    """
    Clean up all expired OTP records from the database.
    
    This is a maintenance endpoint that should ideally be called periodically
    or scheduled via a background task.
    
    Args:
        service (OTPService): OTP service dependency
        
    Returns:
        Dictionary with cleanup results including deleted count
    """
    return await service.cleanup_expired_otps()
