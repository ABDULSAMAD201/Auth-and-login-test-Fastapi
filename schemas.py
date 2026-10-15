import re
from typing import Self

from pydantic import BaseModel, ConfigDict, field_validator, model_validator


EMAIL_PATTERN = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


def validate_email(value: str, required_message: str = "Field is required.") -> str:
    email = value.strip().lower()
    if not email:
        raise ValueError(required_message)
    if not EMAIL_PATTERN.fullmatch(email):
        raise ValueError("Invalid email format.")
    return email


class Register(BaseModel):
    model_config = ConfigDict(extra="forbid")

    full_name: str
    email: str
    password: str
    phone: str
    state: str
    terms: bool = False

    @field_validator("full_name", "phone", "state", mode="before")
    @classmethod
    def required_string(cls, value: object) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("Field is required.")
        return value.strip()

    @field_validator("email", mode="before")
    @classmethod
    def valid_email(cls, value: object) -> str:
        if not isinstance(value, str):
            raise ValueError("Field is required.")
        return validate_email(value)

    @field_validator("password")
    @classmethod
    def valid_password(cls, value: str) -> str:
        if not value:
            raise ValueError("Field is required.")
        if len(value) < 6:
            raise ValueError("Password must be at least 6 characters.")
        return value

    @model_validator(mode="after")
    def accept_terms(self) -> Self:
        if not self.terms:
            raise ValueError(
                "You must accept the terms and conditions to register."
            )
        return self


class Login(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str
    password: str
    captcha: str = ""
    remember: bool = False

    @field_validator("email", mode="before")
    @classmethod
    def valid_email(cls, value: object) -> str:
        if not isinstance(value, str):
            raise ValueError("Email is required.")
        return validate_email(value, "Email is required.")

    @field_validator("password")
    @classmethod
    def required_password(cls, value: str) -> str:
        if not value:
            raise ValueError("Password is required.")
        return value


class ForgotPassword(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str

    @field_validator("email", mode="before")
    @classmethod
    def valid_email(cls, value: object) -> str:
        if not isinstance(value, str):
            raise ValueError("Field is required.")
        return validate_email(value)


class ResetPassword(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str
    password: str
    confirm_password: str

    @field_validator("token", "password", "confirm_password", mode="before")
    @classmethod
    def required_fields(cls, value: object) -> str:
        if not isinstance(value, str) or not value:
            raise ValueError("Field is required.")
        return value

    @field_validator("password")
    @classmethod
    def minimum_password_length(cls, value: str) -> str:
        if len(value) < 12:
            raise ValueError("Use at least 12 characters for your new password.")
        return value

    @model_validator(mode="after")
    def matching_passwords(self) -> Self:
        if self.password != self.confirm_password:
            raise ValueError("The passwords do not match.")
        return self


class ChangePassword(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current_password: str
    password: str
    confirm_password: str

    @field_validator("current_password", "password", "confirm_password", mode="before")
    @classmethod
    def required_fields(cls, value: object) -> str:
        if not isinstance(value, str) or not value:
            raise ValueError("Field is required.")
        return value

    @field_validator("password")
    @classmethod
    def minimum_password_length(cls, value: str) -> str:
        if len(value) < 12:
            raise ValueError("Use at least 12 characters for your new password.")
        return value

    @model_validator(mode="after")
    def matching_passwords(self) -> Self:
        if self.password != self.confirm_password:
            raise ValueError("The passwords do not match.")
        return self


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    email: str
    full_name: str | None = None
    phone: str | None = None
    state: str | None = None
    role: str | None = None


class BookingStatusField(BaseModel):
    value: str
    color: str


class BookingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    space_id: int
    lot_id: int
    start_time: datetime
    end_time: datetime
    status: str
    started_at: datetime | None = None
    ended_at: datetime | None = None
    status_field: BookingStatusField


class APIResponse(BaseModel):
    message: str
    user: UserResponse | None = None
    redirect_to: str | None = None
