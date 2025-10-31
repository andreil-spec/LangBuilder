from __future__ import annotations

import asyncio
import time
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid5

import httpx
from fastapi import HTTPException, status
from jose import JWTError, jwt
from loguru import logger

from langbuilder.services.deps import get_settings_service

if TYPE_CHECKING:
    from langbuilder.services.database.models.user.model import UserRead
    from langbuilder.services.settings.auth import AuthSettings

OIDC_NAMESPACE_UUID = UUID("2d217c46-2453-58a6-ae73-84a53f9745b0")
# The above UUID is a stable namespace (uuid5) derived from the ASCII string "langbuilder:oidc".


@dataclass(slots=True)
class OIDCIdentity:
    subject: str
    username: str | None
    display_name: str | None
    email: str | None
    groups: set[str]
    roles: set[str]
    issuer: str | None
    claims: dict[str, Any]
    token: str

    @property
    def derived_user_id(self) -> UUID:
        """Provide a deterministic UUID for RBAC checks."""
        subject = self.subject or ""
        if subject:
            try:
                return UUID(subject)
            except ValueError:
                pass
        issuer = self.issuer or "oidc"
        return uuid5(OIDC_NAMESPACE_UUID, f"{issuer}:{subject}")


@dataclass(slots=True)
class AuthenticatedCaller:
    """Unified representation of an authenticated caller (OIDC or API key)."""

    id: UUID | None
    username: str | None
    groups: set[str]
    roles: set[str]
    source: str
    user: UserRead | None = None
    token: str | None = None
    claims: dict[str, Any] | None = None
    identity: OIDCIdentity | None = None

    def has_group(self, group: str) -> bool:
        candidate = group.lower()
        return any(existing.lower() == candidate for existing in self.groups | self.roles)

    def all_memberships(self) -> set[str]:
        return {group.lower() for group in self.groups | self.roles}


class OIDCVerifier:
    """Fetch and cache JWKS material to validate bearer tokens issued by an IdP."""

    def __init__(self, settings: AuthSettings):
        self._settings_snapshot = settings
        self._jwks: dict[str, Any] | None = None
        self._jwks_expiry: float = 0.0
        self._jwks_uri: str | None = None
        self._lock = asyncio.Lock()

    @property
    def settings(self) -> AuthSettings:
        return self._settings_snapshot

    @property
    def enabled(self) -> bool:
        return bool(self.settings.OIDC_ENABLED and self.settings.OIDC_ISSUER)

    async def verify(self, token: str) -> OIDCIdentity:
        if not self.enabled:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="OIDC authentication is not enabled",
            )

        try:
            header = jwt.get_unverified_header(token)
        except JWTError as exc:  # pragma: no cover - jose raises JWTError subclasses
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bearer token") from exc

        kid = header.get("kid")
        if not kid:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing key identifier in token")

        jwk = await self._lookup_key(kid)
        claims = await self._decode_with_jwk(token, jwk)

        identity = self._build_identity(token, claims)
        logger.trace("OIDC token validated for subject={subject}", subject=identity.subject)
        return identity

    async def _decode_with_jwk(self, token: str, jwk: dict[str, Any]) -> dict[str, Any]:
        issuer = self.settings.OIDC_ISSUER
        audiences = [aud for aud in [self.settings.OIDC_AUDIENCE, *self.settings.OIDC_ADDITIONAL_AUDIENCES] if aud]
        options = {
            "verify_signature": True,
            "verify_aud": bool(audiences),
            "verify_exp": True,
        }
        if self.settings.OIDC_CLOCK_SKEW_SECONDS:
            options["leeway"] = self.settings.OIDC_CLOCK_SKEW_SECONDS

        algorithms = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]
        # python-jose will raise if algorithm does not match. Provide common defaults; IdP decides actual algorithm.

        if audiences:
            last_error: JWTError | None = None
            for audience in audiences:
                try:
                    return jwt.decode(
                        token,
                        jwk,
                        algorithms=algorithms,
                        audience=audience,
                        issuer=issuer,
                        options=options,
                    )
                except JWTError as exc:
                    last_error = exc
                    continue
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token audience") from (
                last_error
            )

        try:
            return jwt.decode(token, jwk, algorithms=algorithms, issuer=issuer, options=options)
        except JWTError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials"
            ) from (exc)

    async def _lookup_key(self, kid: str) -> dict[str, Any]:
        jwks = await self._load_jwks()
        key = self._find_key(jwks, kid)
        if key:
            return key
        # Refresh JWKS once if key not present (key rotation).
        jwks = await self._load_jwks(force_refresh=True)
        key = self._find_key(jwks, kid)
        if key:
            return key
        logger.error("Unable to find JWKS key %s for token header", kid)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown signing key")

    async def _load_jwks(self, *, force_refresh: bool = False) -> dict[str, Any]:
        cache_valid = self._jwks and time.time() < self._jwks_expiry
        if cache_valid and not force_refresh:
            return self._jwks  # type: ignore[return-value]

        async with self._lock:
            cache_valid = self._jwks and time.time() < self._jwks_expiry
            if cache_valid and not force_refresh:
                return self._jwks  # type: ignore[return-value]

            jwks_uri = await self._get_jwks_uri()
            timeout = httpx.Timeout(10.0, connect=5.0)
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                try:
                    response = await client.get(jwks_uri)
                    response.raise_for_status()
                except httpx.HTTPError as exc:
                    logger.error("Failed to fetch JWKS from %s: %s", jwks_uri, exc)
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail="Unable to contact identity provider",
                    ) from exc

            jwks = response.json()
            if not isinstance(jwks, dict) or "keys" not in jwks:
                logger.error("Invalid JWKS payload from %s", jwks_uri)
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Identity provider returned an invalid JWKS document",
                )

            cache_ttl = max(self.settings.OIDC_JWKS_CACHE_SECONDS, 60)
            self._jwks = jwks
            self._jwks_expiry = time.time() + cache_ttl
            return jwks

    async def _get_jwks_uri(self) -> str:
        if self._jwks_uri:
            return self._jwks_uri
        if self.settings.OIDC_JWKS_URL:
            self._jwks_uri = self.settings.OIDC_JWKS_URL
            return self._jwks_uri

        issuer = self.settings.OIDC_ISSUER
        if not issuer:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="OIDC issuer is not configured",
            )

        discovery_url = issuer.rstrip("/") + "/.well-known/openid-configuration"
        timeout = httpx.Timeout(10.0, connect=5.0)
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            try:
                response = await client.get(discovery_url)
                response.raise_for_status()
                data = response.json()
            except httpx.HTTPError as exc:
                logger.warning("Could not access OIDC discovery document: %s", exc)
                data = {}

        jwks_uri: str | None = data.get("jwks_uri") if isinstance(data, dict) else None
        if not jwks_uri:
            jwks_uri = issuer.rstrip("/") + "/protocol/openid-connect/certs"
            logger.debug("Using Keycloak-compatible JWKS URI fallback: %s", jwks_uri)

        self._jwks_uri = jwks_uri
        return jwks_uri

    def _find_key(self, jwks: dict[str, Any], kid: str) -> dict[str, Any] | None:
        keys = jwks.get("keys", [])
        if not isinstance(keys, Iterable):
            return None
        for key in keys:
            if isinstance(key, dict) and key.get("kid") == kid:
                return key
        return None

    def _build_identity(self, token: str, claims: dict[str, Any]) -> OIDCIdentity:
        groups = self._extract_memberships(claims, include_groups=True)
        roles = self._extract_memberships(claims, include_groups=False)

        subject = str(claims.get("sub") or "")
        username = self._get_claim(claims, self.settings.OIDC_USERNAME_CLAIM)
        display_name = self._get_claim(claims, self.settings.OIDC_NAME_CLAIM)
        email = self._get_claim(claims, self.settings.OIDC_EMAIL_CLAIM)

        return OIDCIdentity(
            subject=subject,
            username=username,
            display_name=display_name,
            email=email,
            groups=groups,
            roles=roles,
            issuer=self.settings.OIDC_ISSUER,
            claims=claims,
            token=token,
        )

    def _extract_memberships(self, claims: dict[str, Any], *, include_groups: bool) -> set[str]:
        values: set[str] = set()
        if include_groups and self.settings.OIDC_GROUPS_CLAIM:
            data = self._resolve_path(claims, self.settings.OIDC_GROUPS_CLAIM)
            values.update(self._to_str_set(data))

        role_paths = set(self.settings.OIDC_ROLES_PATHS or [])
        for client_id in [self.settings.OIDC_AUDIENCE, *self.settings.OIDC_RESOURCE_CLIENT_IDS]:
            if client_id:
                role_paths.add(f"resource_access.{client_id}.roles")

        if not include_groups:
            for path in role_paths:
                data = self._resolve_path(claims, path)
                values.update(self._to_str_set(data))

        return {value for value in values if value}

    def _resolve_path(self, data: Any, path: str | None) -> Any:
        if not path:
            return None
        current = data
        for part in path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current

    def _to_str_set(self, value: Any) -> set[str]:
        if value is None:
            return set()
        if isinstance(value, str):
            return {value}
        if isinstance(value, list | tuple | set):
            return {str(item) for item in value if str(item).strip()}
        return set()

    def _get_claim(self, claims: dict[str, Any], claim_path: str | None) -> str | None:
        if not claim_path:
            return None
        value = self._resolve_path(claims, claim_path)
        if value is None:
            return None
        if isinstance(value, list | tuple):
            # If claim is an array, join with space similar to Keycloak "given_name"/"family_name".
            return " ".join(str(item) for item in value if str(item).strip()) or None
        return str(value)


@lru_cache(maxsize=1)
def get_oidc_verifier() -> OIDCVerifier:
    settings_service = get_settings_service()
    settings = settings_service.auth_settings
    return OIDCVerifier(settings=settings)


def build_authenticated_caller_from_user(user: UserRead) -> AuthenticatedCaller:
    return AuthenticatedCaller(
        id=user.id,
        username=user.username,
        groups=set(),
        roles=set(),
        source="api_key",
        user=user,
    )


def build_authenticated_caller_from_oidc(identity: OIDCIdentity) -> AuthenticatedCaller:
    return AuthenticatedCaller(
        id=identity.derived_user_id,
        username=identity.username or identity.subject,
        groups=identity.groups,
        roles=identity.roles,
        source="oidc",
        token=identity.token,
        claims=identity.claims,
        identity=identity,
    )
