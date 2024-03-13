from __future__ import annotations as _annotations

import asyncio
import json
import requests
import os
from dataclasses import asdict
from typing import Annotated, Literal, TypeAlias

from fastapi import APIRouter, Depends, Request
from fastui import AnyComponent, FastUI
from fastui import components as c
from fastui.auth import AuthRedirect, GitHubAuthProvider
from fastui.events import AuthEvent, GoToEvent, PageEvent
from fastui.forms import fastui_form
from httpx import AsyncClient
from pydantic import BaseModel, EmailStr, Field, SecretStr

from .auth_user import User
from .shared import demo_page
from httpx import AsyncClient

from .models.forms import (
    LoginForm,
    RegisterForm,
    ForgotPasswordForm,
    ResetPassForm,
)

router = APIRouter()

GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "0d0315f9c2e055d032e2")
# this will give an error when making requests to GitHub, but at least the app will run
GITHUB_CLIENT_SECRET = SecretStr(os.getenv("GITHUB_CLIENT_SECRET", "dummy-secret"))
# use 'http://localhost:3000/auth/login/github/redirect' in development
GITHUB_REDIRECT = os.getenv("GITHUB_REDIRECT")


async def get_github_auth(request: Request) -> GitHubAuthProvider:
    client: AsyncClient = request.app.state.httpx_client
    return GitHubAuthProvider(
        httpx_client=client,
        github_client_id=GITHUB_CLIENT_ID,
        github_client_secret=GITHUB_CLIENT_SECRET,
        redirect_uri=GITHUB_REDIRECT,
        scopes=["user:email"],
    )


LoginKind: TypeAlias = Literal["password", "github", "register-password"]
client = AsyncClient()


@router.get("/login/{kind}", response_model=FastUI, response_model_exclude_none=True)
def auth_login(
    kind: LoginKind,
    user: Annotated[User | None, Depends(User.from_request_opt)],
) -> list[AnyComponent]:
    if user is not None:
        # already logged in
        raise AuthRedirect("/auth/profile")

    return demo_page(
        c.Navbar(
            title="Aiop Cloud",
            title_event=GoToEvent(url="/"),
            start_links=[
                c.Link(
                    components=[c.Text(text="Auth")],
                    on_click=GoToEvent(url="/auth/login/password"),
                    active="startswith:/auth",
                ),
                c.Link(
                    components=[c.Text(text="Contact")],
                    on_click=GoToEvent(url="https://aiop.fr/docs/contact"),
                    active="startswith:/forms",
                ),
            ],
        ),
        c.LinkList(
            links=[
                c.Link(
                    components=[c.Text(text="Authentification par mot de passe")],
                    on_click=PageEvent(
                        name="tab",
                        push_path="/auth/login/password",
                        context={"kind": "password"},
                    ),
                    active="/auth/login/password",
                ),
                c.Link(
                    components=[c.Text(text="Création de compte")],
                    on_click=PageEvent(
                        name="tab",
                        push_path="/auth/login/password",
                        context={"kind": "register-password"},
                    ),
                    active="/auth/login/register-password",
                ),
                # TODO : add GitHub login
                # c.Link(
                #    components=[c.Text(text="GitHub Login")],
                #    on_click=PageEvent(
                #        name="tab",
                #        push_path="/auth/login/github",
                #        context={"kind": "github"},
                #    ),
                #    active="/auth/login/github",
                # ),
            ],
            mode="tabs",
            class_name="+ mb-4",
        ),
        c.ServerLoad(
            path="/auth/login/content/{kind}",
            load_trigger=PageEvent(name="tab"),
            components=auth_login_content(kind),
        ),
        title="Authentication",
    )


# @router.get("/error/{kind}", response_model=FastUI, response_model_exclude_none=True)
# def display_error(kind: LoginKind) -> list[AnyComponent]:
#    return [
#        c.Div(
#            components=[
#                c.Heading(text="Erreur", level=1),
#                c.Paragraph(text="Adresse email ou mot de passe incorrect."),
#                c.Button(text="Ok", on_click=GoToEvent(url="/auth/profile")),
#            ],
#            class_name="border-top mt-3 pt-1",
#        ),
#    ]


@router.get(
    "/login/content/{kind}", response_model=FastUI, response_model_exclude_none=True
)
def auth_login_content(kind: LoginKind) -> list[AnyComponent]:
    match kind:
        case "password":
            return [
                c.Paragraph(text="Les mots de passes ne sont pas enregistrés."),
                c.ModelForm(
                    model=LoginForm, submit_url="/api/auth/login", display_mode="page"
                ),
                c.Heading(text="Mot de passe oublié ?", level=3),
                c.Markdown(
                    text=(
                        "En appuyant sur ce button, vous recevrez un email pour changer votre mot de passe."
                    )
                ),
                c.Div(
                    components=[
                        c.ModelForm(
                            model=ForgotPasswordForm,
                            display_mode="default",
                            submit_url="/api/auth/reset-password-email",
                        ),
                    ],
                    class_name="border-top mt-3 pt-1",
                ),
            ]
        case "github":
            return [
                c.Heading(text="GitHub Login", level=3),
                c.Paragraph(text="Demo of GitHub authentication."),
                c.Paragraph(
                    text="(Credentials are stored in the browser via a JWT only)"
                ),
                c.Button(
                    text="Login with GitHub",
                    on_click=GoToEvent(url="/auth/login/github/gen"),
                ),
            ]
        case "register-password":
            return [
                c.Heading(text="Création de compte", level=3),
                c.ModelForm(
                    model=RegisterForm,
                    submit_url="/api/auth/register",
                    display_mode="page",
                ),
            ]
        case _:
            raise ValueError(f"Invalid kind {kind!r}")


@router.post("/register", response_model=FastUI, response_model_exclude_none=True)
async def login_form_post(
    form: Annotated[RegisterForm, fastui_form(RegisterForm)]
) -> list[AnyComponent]:
    # Verify the password is the same
    if form.password != form.retry_password:
        raise ValueError("Les mots de passes ne sont pas identiques.")

    # Verify if the user exists in the database by calling backend api
    url = "https://api.aiop.fr/api/auth/register"
    headers = {"accept": "application/json", "Content-Type": "application/json"}
    data = {
        "email": form.email,
        "password": form.password.get_secret_value(),
        "is_active": True,
        "is_superuser": False,
        "is_verified": False,
    }
    response = requests.post(url, headers=headers, json=data)
    if response.status_code == 201:
        return [
            c.Div(
                components=[
                    c.Paragraph(text="Votre compte a été créé avec succès."),
                    c.Button(
                        text="Se connecter", on_click=GoToEvent(url="/auth/profile")
                    ),
                ],
                class_name="border-top mt-3 pt-1",
            ),
        ]
    if response.status_code == 400:
        return [
            c.Div(
                components=[
                    c.Heading(text="Erreur", level=1),
                    c.Paragraph(text="Un compte avec cette adresse email existe déjà."),
                    c.Button(text="Réessayer", on_click=GoToEvent(url="/auth/profile")),
                ],
                class_name="border-top mt-3 pt-1",
            ),
        ]
    return [
        c.Div(
            components=[
                c.Heading(text="Erreur", level=1),
                c.Paragraph(text="Erreur interne, veuillez réessayer plus tard."),
                c.Button(text="Ok", on_click=GoToEvent(url="/auth/profile")),
            ],
            class_name="border-top mt-3 pt-1",
        ),
    ]


@router.post("/login", response_model=FastUI, response_model_exclude_none=True)
async def login_form_post(
    form: Annotated[LoginForm, fastui_form(LoginForm)]
) -> list[AnyComponent]:
    # Verify if the user exists in the database by calling backend api
    response = await client.post(
        "https://api.aiop.fr/api/auth/jwt/login",
        data={
            "grant_type": "",
            "username": form.email,
            "password": form.password.get_secret_value(),
            "scope": "",
            "client_id": "",
            "client_secret": "",
        },
    )
    if response.status_code == 400:
        return [
            c.Div(
                components=[
                    c.Heading(text="Erreur", level=1),
                    c.Paragraph(text="Adresse email ou mot de passe incorrect."),
                    c.Button(text="Réessayer", on_click=GoToEvent(url="/auth/profile")),
                ],
                class_name="border-top mt-3 pt-1",
            ),
        ]
    if response.status_code == 422:
        return [
            c.Div(
                components=[
                    c.Heading(text="Erreur", level=1),
                    c.Paragraph(text="Erreur interne, veuillez réessayer plus tard."),
                    c.Button(text="Ok", on_click=GoToEvent(url="/auth/profile")),
                ],
                class_name="border-top mt-3 pt-1",
            ),
        ]
    data = response.json()
    user = User(
        email=form.email,
        extra={"pass": form.password.get_secret_value(), "token": data["access_token"]},
    )
    return [
        c.FireEvent(event=AuthEvent(token=user.encode_token(), url="/auth/profile"))
    ]


async def get_license_key(bearer_token: str):
    key = "Clée de license non trouvée."
    try:
        response = await client.get(
            "https://aiop-dev-backend.pival.fr/api/v1/license/",
            headers={"Authorization": f"Bearer {bearer_token}"},
        )
        response.raise_for_status()
        data = response.json()
        key = data["license_key"]
    except Exception as e:
        print("Request failed:", e)
    return key


@router.get("/reset-password", response_model=FastUI, response_model_exclude_none=True)
async def reset_password(
    user: Annotated[User, Depends(User.from_request)],
) -> list[AnyComponent]:
    url = "https://api.aiop.fr/api/auth/forgot-password"
    headers = {"accept": "application/json", "Content-Type": "application/json"}
    data = {"email": user.email}

    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("Request failed:", e)
        return [
            c.Paragraph(
                text=f"Nous avons rencontré un problème lors de l'envoi de l'email de réinitialisation de mot de passe. Veuillez réessayer plus tard."
            )
        ]
    return [
        c.Paragraph(
            text=f"Un email de réinitialisation de mot de passe a été envoyé à votre adresse email: {user.email}."
        )
    ]


@router.get(
    "/reset-password/{token}", response_model=FastUI, response_model_exclude_none=True
)
async def reset_password_page(
    token: str,
) -> list[AnyComponent]:
    return demo_page(
        c.Navbar(
            title="Aiop Cloud",
            title_event=GoToEvent(url="/"),
            start_links=[
                c.Link(
                    components=[c.Text(text="Auth")],
                    on_click=GoToEvent(url="/auth/login/password"),
                    active="startswith:/auth",
                ),
                c.Link(
                    components=[c.Text(text="Contact")],
                    on_click=GoToEvent(url="https://aiop.fr/docs/contact"),
                    active="startswith:/forms",
                ),
            ],
        ),
        c.Div(
            components=[
                c.ModelForm(
                    model=ResetPassForm,
                    display_mode="default",
                    submit_url="/api/auth/reset-password-token",
                ),
            ],
            class_name="border-top mt-3 pt-1",
        ),
        title="Changer de mot de passe",
    )


@router.post(
    "/reset-password-token", response_model=FastUI, response_model_exclude_none=True
)
async def reset_password_without_email(
    form: Annotated[ResetPassForm, fastui_form(ResetPassForm)]
) -> list[AnyComponent]:
    print(form)
    if form.new_password != form.retry_new_password:
        raise ValueError("Les mots de passes ne sont pas identiques.")

    url = "https://api.aiop.fr/api/auth/reset-password"
    headers = {"accept": "application/json", "Content-Type": "application/json"}
    data = {"token": form.token, "password": form.new_password.get_secret_value()}

    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("Request failed:", e)
        return [
            c.Paragraph(
                text=f"Nous avons rencontré un problème lors de l'envoi de l'email de réinitialisation de mot de passe. Veuillez réessayer plus tard."
            )
        ]
    return [
        c.Markdown(text="__Votre mot de passe est changé__"),
        c.Button(text="Se connecter", on_click=GoToEvent(url="/auth/login/password")),
    ]


@router.post(
    "/reset-password-email", response_model=FastUI, response_model_exclude_none=True
)
async def reset_password_without_email(
    form: Annotated[ForgotPasswordForm, fastui_form(ForgotPasswordForm)]
) -> list[AnyComponent]:
    url = "https://api.aiop.fr/api/auth/forgot-password"
    headers = {"accept": "application/json", "Content-Type": "application/json"}
    data = {"email": form.email}

    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("Request failed:", e)
        return [
            c.Paragraph(
                text=f"Nous avons rencontré un problème lors de l'envoi de l'email de réinitialisation de mot de passe. Veuillez réessayer plus tard."
            )
        ]
    return [
        c.Markdown(
            text="__Un email de réinitialisation de mot de passe a été envoyé à l’adresse email si elle existe:__"
        ),
        c.Paragraph(text=f"{form.email}"),
    ]


@router.get("/profile", response_model=FastUI, response_model_exclude_none=True)
async def profile(
    user: Annotated[User, Depends(User.from_request)]
) -> list[AnyComponent]:
    email = user.email
    password = user.extra.get("pass", "pas de password")
    token = user.extra.get("token", "pas de token")
    key = await get_license_key(token)
    return demo_page(
        c.Navbar(
            title="Aiop Cloud",
            title_event=GoToEvent(url="/"),
            start_links=[
                c.Link(
                    components=[c.Text(text="Compte")],
                    on_click=GoToEvent(url="/auth/profile"),
                    active="startswith:/auth/profile",
                ),
                c.Link(
                    components=[c.Text(text="Contact")],
                    on_click=GoToEvent(url="https://aiop.fr/docs/contact"),
                    active="startswith:/forms",
                ),
                c.Link(
                    components=[c.Text(text="Se déconnecter")],
                    on_click=PageEvent(name="submit-form"),
                    active="startswith:/forms",
                ),
            ],
        ),
        c.Paragraph(text=f"Vous êtes connecté avec: {user.email}"),
        c.Div(
            components=[
                c.Heading(text="Changer de mot de passe", level=2),
                c.Markdown(
                    text=(
                        "En appuyant sur ce button, vous recevrez un email pour changer votre mot de passe."
                    )
                ),
                c.Button(
                    text="Changer de mot de passe",
                    on_click=PageEvent(name="pass-reset"),
                ),
                c.Modal(
                    title="Changer de mot de passe",
                    body=[c.ServerLoad(path="/auth/reset-password")],
                    footer=[
                        c.Button(
                            text="Close",
                            on_click=PageEvent(name="pass-reset", clear=True),
                        ),
                    ],
                    open_trigger=PageEvent(name="pass-reset"),
                ),
            ],
            class_name="border-top mt-3 pt-1",
        ),
        c.Heading(text="Configuration de Aiop:", level=3),
        c.Paragraph(
            text="La configuration de license suivante est à renseigner dans votre fichier `~/.aiop/aiop.yml`:"
        ),
        c.Code(
            language="json",
            text=f"""license:
  key: '{key}'
  username: '{email}'
  password: '{password}'
  api_token: '{token}'
""",
        ),
        c.Paragraph(text="Le mot de passe est optionnel si vous avez un token."),
        c.Heading(text="Se déconnecter:", level=3),
        c.Button(text="Se déconnecter", on_click=PageEvent(name="submit-form")),
        c.Form(
            submit_url="/api/auth/logout",
            form_fields=[
                c.FormFieldInput(
                    name="test", title="", initial="data", html_type="hidden"
                )
            ],
            footer=[],
            submit_trigger=PageEvent(name="submit-form"),
        ),
        title="Mon compte",
    )


@router.post("/logout", response_model=FastUI, response_model_exclude_none=True)
async def logout_form_post(
    user: Annotated[User, Depends(User.from_request)]
) -> list[AnyComponent]:
    # Verify if the user exists in the database by calling backend api
    token = user.extra.get("token", "pas de token")
    response = await client.post(
        "https://api.aiop.fr/api/auth/jwt/logout",
        headers={"Authorization": f"Bearer {token}"},
    )
    if response.status_code == 401:
        return [
            c.Div(
                components=[
                    c.Heading(text="Erreur", level=1),
                    c.Paragraph(text="Token invalide ou utilisateur inexistant."),
                    c.Button(text="Ok", on_click=GoToEvent(url="/auth/profile")),
                    # c.Button(text="Contacter support", on_click=GoToEvent(url="/auth/profile")),
                ],
                class_name="border-top mt-3 pt-1",
            ),
        ]
    return [c.FireEvent(event=AuthEvent(token=False, url="/auth/login/password"))]


@router.get(
    "/login/github/gen", response_model=FastUI, response_model_exclude_none=True
)
async def auth_github_gen(
    github_auth: Annotated[GitHubAuthProvider, Depends(get_github_auth)]
) -> list[AnyComponent]:
    auth_url = await github_auth.authorization_url()
    return [c.FireEvent(event=GoToEvent(url=auth_url))]


@router.get(
    "/login/github/redirect", response_model=FastUI, response_model_exclude_none=True
)
async def github_redirect(
    code: str,
    state: str | None,
    github_auth: Annotated[GitHubAuthProvider, Depends(get_github_auth)],
) -> list[AnyComponent]:
    exchange = await github_auth.exchange_code(code, state)
    user_info, emails = await asyncio.gather(
        github_auth.get_github_user(exchange),
        github_auth.get_github_user_emails(exchange),
    )
    user = User(
        email=next((e.email for e in emails if e.primary and e.verified), None),
        extra={
            "github_user_info": user_info.model_dump(),
            "github_emails": [e.model_dump() for e in emails],
        },
    )
    token = user.encode_token()
    return [c.FireEvent(event=AuthEvent(token=token, url="/auth/profile"))]
