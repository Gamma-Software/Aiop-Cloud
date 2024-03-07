from __future__ import annotations as _annotations

from pydantic import BaseModel, EmailStr, Field, SecretStr


class ResetPassForm(BaseModel):
    token: str = Field(
        init=True,
        title="Token",
        description="Le token qui vous a été envoyé par email",
    )
    new_password: SecretStr = Field(
        title="Nouveau mot de passe",
        description="Entrez votre nouveau mot de passe",
    )
    retry_new_password: SecretStr = Field(
        title="Nouveau mot de passe",
        description="Entrez votre nouveau mot de passe une seconde fois pour vérification",
    )


class ForgotPasswordForm(BaseModel):
    email: EmailStr = Field(
        title="Email Address", description="Entrez votre adresse email"
    )


class LoginForm(BaseModel):
    email: EmailStr = Field(
        title="Adresse Email",
        description="Entrez votre adresse email",
        json_schema_extra={"autocomplete": "email"},
    )
    password: SecretStr = Field(
        title="Mot de passe",
        description="Entrez votre mot de passe",
        json_schema_extra={"autocomplete": "current-password"},
    )


class RegisterForm(BaseModel):
    email: EmailStr = Field(
        title="Adresse Email",
        description="Entrez votre adresse email",
        json_schema_extra={"autocomplete": "email"},
    )
    password: SecretStr = Field(
        title="Mot de passe",
        description="Entrez votre mot de passe",
        json_schema_extra={"autocomplete": "current-password"},
    )
    retry_password: SecretStr = Field(
        title="Mot de passe",
        description="Entrez votre mot de passe une seconde fois pour vérification",
    )
