"""Request/response shapes for users and login.

Pydantic checks every incoming field (type, length, allowed values) before
our code runs. Invalid input gets an automatic 422 response. Response models
control exactly which fields leave the server, so `password_hash` and
`token_version` can never leak by accident.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.enums import Role

# Letters, digits, dot, underscore, hyphen. 3-32 characters.
USERNAME_PATTERN = r"^[a-zA-Z0-9._-]{3,32}$"


class LoginRequest(BaseModel):
    # Loose limits here: we must not reveal the username rules to someone guessing.
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)  # build from ORM objects

    id: int
    username: str
    role: Role
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None


class UserCreate(BaseModel):
    username: str = Field(pattern=USERNAME_PATTERN)
    # NIST SP 800-63B: favour length over composition rules.
    password: str = Field(min_length=12, max_length=128)
    role: Role = Role.VIEWER

    @field_validator("username")
    @classmethod
    def normalise_username(cls, v: str) -> str:
        return v.lower()  # "Alice" and "alice" must not be two accounts


class UserUpdate(BaseModel):
    role: Role | None = None
    is_active: bool | None = None
