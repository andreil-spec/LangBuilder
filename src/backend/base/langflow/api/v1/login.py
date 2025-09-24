from __future__ import annotations

import time
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from loguru import logger

from langflow.api.utils import DbSession
from langflow.api.v1.schemas import Token
from langflow.initial_setup.setup import get_or_create_default_folder
from langflow.services.auth.utils import (
    authenticate_user,
    create_refresh_token,
    create_user_longterm_token,
    create_user_tokens,
)
from langflow.services.auth.rate_limiter import get_rate_limiter
from langflow.services.auth.session_manager import get_session_manager
from langflow.services.auth.brute_force_protection import get_brute_force_protection
from langflow.services.auth.enhanced_auth_middleware import login_security_required
from langflow.services.database.models.user.crud import get_user_by_id
from langflow.services.deps import get_settings_service, get_variable_service

router = APIRouter(tags=["Login"])


@router.post("/login", response_model=Token)
async def login_to_get_access_token(
    request: Request,
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: DbSession,
):
    """Enhanced login endpoint with comprehensive security controls."""
    auth_settings = get_settings_service().auth_settings
    rate_limiter = get_rate_limiter()
    session_manager = get_session_manager()
    brute_force_protection = get_brute_force_protection()

    start_time = time.time()
    username = form_data.username
    password_length = len(form_data.password) if form_data.password else 0

    try:
        # Check rate limiting for login attempts
        allowed, rate_info = await rate_limiter.check_rate_limit(request, "login")
        if not allowed:
            await brute_force_protection.record_attempt(
                request, username, False, password_length, time.time() - start_time
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "message": "Too many login attempts",
                    **rate_info
                },
                headers={"Retry-After": str(rate_info.get("retry_after", 300))}
            )

        # Check brute force protection
        bf_allowed, bf_info = await brute_force_protection.check_attempt_allowed(
            request, username, password_length
        )
        if not bf_allowed:
            await rate_limiter.record_attempt(request, "login", False)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "message": "Login blocked by security system",
                    **bf_info
                },
                headers={"Retry-After": str(bf_info.get("retry_after", 300))}
            )

        # Attempt authentication
        user = None
        auth_success = False

        try:
            user = await authenticate_user(username, form_data.password, db)
            auth_success = user is not None
        except Exception as exc:
            auth_success = False
            if isinstance(exc, HTTPException):
                # Record failed attempt before re-raising
                await rate_limiter.record_attempt(request, "login", False)
                await brute_force_protection.record_attempt(
                    request, username, False, password_length, time.time() - start_time
                )
                raise
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=str(exc),
            ) from exc

        # Record the attempt
        await rate_limiter.record_attempt(request, "login", auth_success)
        await brute_force_protection.record_attempt(
            request, username, auth_success, password_length, time.time() - start_time
        )

        if user and auth_success:
            # Create secure session
            session_info = await session_manager.create_session(
                request, user, login_method="password"
            )

            # Create tokens
            tokens = await create_user_tokens(user_id=user.id, db=db, update_last_login=True)

            # Set secure cookies with enhanced security headers
            response.set_cookie(
                "refresh_token_lf",
                tokens["refresh_token"],
                httponly=auth_settings.REFRESH_HTTPONLY,
                samesite=auth_settings.REFRESH_SAME_SITE,
                secure=auth_settings.REFRESH_SECURE,
                expires=auth_settings.REFRESH_TOKEN_EXPIRE_SECONDS,
                domain=auth_settings.COOKIE_DOMAIN,
            )
            response.set_cookie(
                "access_token_lf",
                tokens["access_token"],
                httponly=auth_settings.ACCESS_HTTPONLY,
                samesite=auth_settings.ACCESS_SAME_SITE,
                secure=auth_settings.ACCESS_SECURE,
                expires=auth_settings.ACCESS_TOKEN_EXPIRE_SECONDS,
                domain=auth_settings.COOKIE_DOMAIN,
            )
            response.set_cookie(
                "apikey_tkn_lflw",
                str(user.store_api_key),
                httponly=auth_settings.ACCESS_HTTPONLY,
                samesite=auth_settings.ACCESS_SAME_SITE,
                secure=auth_settings.ACCESS_SECURE,
                expires=None,  # Session cookie
                domain=auth_settings.COOKIE_DOMAIN,
            )

            # Set session ID cookie for session management
            response.set_cookie(
                "session_id",
                session_info.session_id,
                httponly=True,
                samesite="strict",
                secure=auth_settings.ACCESS_SECURE,
                expires=None,  # Session cookie
                domain=auth_settings.COOKIE_DOMAIN,
            )

            # Add security headers
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

            await get_variable_service().initialize_user_variables(user.id, db)
            # Create default project for user if it doesn't exist
            _ = await get_or_create_default_folder(db, user.id)

            logger.info(f"Successful login for user {username} from {request.client.host if request.client else 'unknown'}")

            return tokens

        # Authentication failed
        logger.warning(f"Failed login attempt for user {username} from {request.client.host if request.client else 'unknown'}")

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    except HTTPException:
        raise
    except Exception as exc:
        # Record failed attempt for any unexpected errors
        await rate_limiter.record_attempt(request, "login", False)
        await brute_force_protection.record_attempt(
            request, username, False, password_length, time.time() - start_time
        )

        logger.error(f"Login error for user {username}: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login service temporarily unavailable",
        ) from exc


@router.get("/auto_login")
async def auto_login(request: Request, response: Response, db: DbSession):
    """Enhanced auto login endpoint with security controls."""
    auth_settings = get_settings_service().auth_settings
    rate_limiter = get_rate_limiter()
    session_manager = get_session_manager()
    brute_force_protection = get_brute_force_protection()

    start_time = time.time()

    try:
        # Check rate limiting for auto login attempts
        allowed, rate_info = await rate_limiter.check_rate_limit(request, "login")
        if not allowed:
            await brute_force_protection.record_attempt(
                request, "auto_login", False, 0, time.time() - start_time
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "message": "Too many auto login attempts",
                    **rate_info
                },
                headers={"Retry-After": str(rate_info.get("retry_after", 300))}
            )

        # Check brute force protection
        bf_allowed, bf_info = await brute_force_protection.check_attempt_allowed(
            request, "auto_login", 0
        )
        if not bf_allowed:
            await rate_limiter.record_attempt(request, "login", False)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "message": "Auto login blocked by security system",
                    **bf_info
                },
                headers={"Retry-After": str(bf_info.get("retry_after", 300))}
            )

        if auth_settings.AUTO_LOGIN:
            try:
                user_id, tokens = await create_user_longterm_token(db)
                user = await get_user_by_id(db, user_id)

                if user:
                    # Create secure session
                    session_info = await session_manager.create_session(
                        request, user, login_method="auto_login"
                    )

                    # Set secure cookies with enhanced security
                    response.set_cookie(
                        "access_token_lf",
                        tokens["access_token"],
                        httponly=auth_settings.ACCESS_HTTPONLY,
                        samesite=auth_settings.ACCESS_SAME_SITE,
                        secure=auth_settings.ACCESS_SECURE,
                        expires=None,  # Set to None to make it a session cookie
                        domain=auth_settings.COOKIE_DOMAIN,
                    )

                    if user.store_api_key is None:
                        user.store_api_key = ""

                    response.set_cookie(
                        "apikey_tkn_lflw",
                        str(user.store_api_key),  # Ensure it's a string
                        httponly=auth_settings.ACCESS_HTTPONLY,
                        samesite=auth_settings.ACCESS_SAME_SITE,
                        secure=auth_settings.ACCESS_SECURE,
                        expires=None,  # Set to None to make it a session cookie
                        domain=auth_settings.COOKIE_DOMAIN,
                    )

                    # Set session ID cookie
                    response.set_cookie(
                        "session_id",
                        session_info.session_id,
                        httponly=True,
                        samesite="strict",
                        secure=auth_settings.ACCESS_SECURE,
                        expires=None,  # Session cookie
                        domain=auth_settings.COOKIE_DOMAIN,
                    )

                    # Add security headers
                    response.headers["X-Content-Type-Options"] = "nosniff"
                    response.headers["X-Frame-Options"] = "DENY"
                    response.headers["X-XSS-Protection"] = "1; mode=block"
                    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

                    # Record successful attempt
                    await rate_limiter.record_attempt(request, "login", True)
                    await brute_force_protection.record_attempt(
                        request, "auto_login", True, 0, time.time() - start_time
                    )

                    logger.info(f"Successful auto login for user {user_id} from {request.client.host if request.client else 'unknown'}")

                    return tokens

            except Exception as exc:
                # Record failed attempt
                await rate_limiter.record_attempt(request, "login", False)
                await brute_force_protection.record_attempt(
                    request, "auto_login", False, 0, time.time() - start_time
                )
                logger.error(f"Auto login error: {exc}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Auto login service temporarily unavailable",
                ) from exc

        # Auto login is disabled or failed
        await rate_limiter.record_attempt(request, "login", False)
        await brute_force_protection.record_attempt(
            request, "auto_login", False, 0, time.time() - start_time
        )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": "Auto login is disabled. Please enable it in the settings",
                "auto_login": False,
            },
        )

    except HTTPException:
        raise
    except Exception as exc:
        # Record failed attempt for any unexpected errors
        await rate_limiter.record_attempt(request, "login", False)
        await brute_force_protection.record_attempt(
            request, "auto_login", False, 0, time.time() - start_time
        )
        logger.error(f"Auto login error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Auto login service temporarily unavailable",
        ) from exc


@router.post("/refresh")
async def refresh_token(
    request: Request,
    response: Response,
    db: DbSession,
):
    """Enhanced token refresh endpoint with security controls."""
    auth_settings = get_settings_service().auth_settings
    rate_limiter = get_rate_limiter()
    session_manager = get_session_manager()
    brute_force_protection = get_brute_force_protection()

    start_time = time.time()
    refresh_token_present = request.cookies.get("refresh_token_lf") is not None

    try:
        # Check rate limiting for refresh attempts
        allowed, rate_info = await rate_limiter.check_rate_limit(request, "refresh")
        if not allowed:
            await brute_force_protection.record_attempt(
                request, "refresh", False, 0, time.time() - start_time
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "message": "Too many refresh attempts",
                    **rate_info
                },
                headers={"Retry-After": str(rate_info.get("retry_after", 300))}
            )

        # Check brute force protection
        bf_allowed, bf_info = await brute_force_protection.check_attempt_allowed(
            request, "refresh", 0
        )
        if not bf_allowed:
            await rate_limiter.record_attempt(request, "refresh", False)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "message": "Token refresh blocked by security system",
                    **bf_info
                },
                headers={"Retry-After": str(bf_info.get("retry_after", 300))}
            )

        token = request.cookies.get("refresh_token_lf")
        session_id = request.cookies.get("session_id")

        if token:
            try:
                # Validate session if session ID is present
                if session_id:
                    session_info = await session_manager.refresh_session(request, session_id)
                    if session_info is None:
                        logger.warning("Token refresh with invalid session")
                        await session_manager.record_failed_refresh(session_id)
                        raise HTTPException(
                            status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid or expired session",
                            headers={"WWW-Authenticate": "Bearer"},
                        )

                # Refresh the token
                tokens = await create_refresh_token(token, db)

                # Set secure cookies with enhanced security
                response.set_cookie(
                    "refresh_token_lf",
                    tokens["refresh_token"],
                    httponly=auth_settings.REFRESH_HTTPONLY,
                    samesite=auth_settings.REFRESH_SAME_SITE,
                    secure=auth_settings.REFRESH_SECURE,
                    expires=auth_settings.REFRESH_TOKEN_EXPIRE_SECONDS,
                    domain=auth_settings.COOKIE_DOMAIN,
                )
                response.set_cookie(
                    "access_token_lf",
                    tokens["access_token"],
                    httponly=auth_settings.ACCESS_HTTPONLY,
                    samesite=auth_settings.ACCESS_SAME_SITE,
                    secure=auth_settings.ACCESS_SECURE,
                    expires=auth_settings.ACCESS_TOKEN_EXPIRE_SECONDS,
                    domain=auth_settings.COOKIE_DOMAIN,
                )

                # Add security headers
                response.headers["X-Content-Type-Options"] = "nosniff"
                response.headers["X-Frame-Options"] = "DENY"
                response.headers["X-XSS-Protection"] = "1; mode=block"
                response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

                # Record successful attempt
                await rate_limiter.record_attempt(request, "refresh", True)
                await brute_force_protection.record_attempt(
                    request, "refresh", True, 0, time.time() - start_time
                )

                logger.debug(f"Successful token refresh from {request.client.host if request.client else 'unknown'}")

                return tokens

            except HTTPException:
                # Record failed refresh attempt
                if session_id:
                    await session_manager.record_failed_refresh(session_id)
                await rate_limiter.record_attempt(request, "refresh", False)
                await brute_force_protection.record_attempt(
                    request, "refresh", False, 0, time.time() - start_time
                )
                raise
            except Exception as exc:
                # Record failed refresh attempt
                if session_id:
                    await session_manager.record_failed_refresh(session_id)
                await rate_limiter.record_attempt(request, "refresh", False)
                await brute_force_protection.record_attempt(
                    request, "refresh", False, 0, time.time() - start_time
                )
                logger.error(f"Token refresh error: {exc}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Token refresh service temporarily unavailable",
                ) from exc

        # No refresh token provided
        await rate_limiter.record_attempt(request, "refresh", False)
        await brute_force_protection.record_attempt(
            request, "refresh", False, 0, time.time() - start_time
        )

        logger.warning(f"Refresh attempt without token from {request.client.host if request.client else 'unknown'}")

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    except HTTPException:
        raise
    except Exception as exc:
        # Record failed attempt for any unexpected errors
        await rate_limiter.record_attempt(request, "refresh", False)
        await brute_force_protection.record_attempt(
            request, "refresh", False, 0, time.time() - start_time
        )
        logger.error(f"Token refresh error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh service temporarily unavailable",
        ) from exc


@router.post("/logout")
async def logout(request: Request, response: Response):
    """Enhanced logout endpoint with session cleanup and security logging."""
    session_manager = get_session_manager()
    rate_limiter = get_rate_limiter()

    try:
        # Check rate limiting for logout attempts (prevent spam)
        allowed, rate_info = await rate_limiter.check_rate_limit(request, "api_key")
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "message": "Too many logout attempts",
                    **rate_info
                },
                headers={"Retry-After": str(rate_info.get("retry_after", 60))}
            )

        # Get session ID and invalidate session
        session_id = request.cookies.get("session_id")
        if session_id:
            session_invalidated = await session_manager.invalidate_session(session_id)
            if session_invalidated:
                logger.info(f"Session invalidated during logout: {session_id[:8]}...")
            else:
                logger.warning(f"Attempted to invalidate non-existent session: {session_id[:8]}...")

        # Clear all authentication cookies with secure attributes
        auth_settings = get_settings_service().auth_settings

        response.delete_cookie(
            "refresh_token_lf",
            domain=auth_settings.COOKIE_DOMAIN,
            path="/"
        )
        response.delete_cookie(
            "access_token_lf",
            domain=auth_settings.COOKIE_DOMAIN,
            path="/"
        )
        response.delete_cookie(
            "apikey_tkn_lflw",
            domain=auth_settings.COOKIE_DOMAIN,
            path="/"
        )
        response.delete_cookie(
            "session_id",
            domain=auth_settings.COOKIE_DOMAIN,
            path="/"
        )

        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

        # Record successful logout
        await rate_limiter.record_attempt(request, "api_key", True)

        logger.info(f"Successful logout from {request.client.host if request.client else 'unknown'}")

        return {"message": "Logout successful"}

    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Logout error: {exc}")
        # Still clear cookies even if session cleanup fails
        response.delete_cookie("refresh_token_lf")
        response.delete_cookie("access_token_lf")
        response.delete_cookie("apikey_tkn_lflw")
        response.delete_cookie("session_id")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout service temporarily unavailable",
        ) from exc
