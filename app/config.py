from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env.app", extra="ignore")

    database_url: str
    session_secret: str
    oidc_client_id: str
    oidc_client_secret: str
    authentik_base_url: str = "http://localhost:9000"
    authentik_app_slug: str = "fastapi-app"
    enrollment_flow_slug: str = "app-enrollment"
    app_base_url: str = "http://localhost:8000"

    @property
    def issuer(self) -> str:
        # Authentik's default issuer mode: one issuer per application slug
        return f"{self.authentik_base_url}/application/o/{self.authentik_app_slug}/"

    @property
    def metadata_url(self) -> str:
        return f"{self.issuer}.well-known/openid-configuration"

    @property
    def jwks_url(self) -> str:
        return f"{self.issuer.rstrip('/')}/jwks/"

    @property
    def redirect_uri(self) -> str:
        return f"{self.app_base_url}/auth/callback"

    @property
    def secure_cookies(self) -> bool:
        return self.app_base_url.startswith("https://")


@lru_cache
def get_settings() -> Settings:
    return Settings()