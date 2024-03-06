from __future__ import annotations as _annotations

from fastapi import APIRouter
from fastui import AnyComponent, FastUI
from fastui import components as c
from fastui.events import GoToEvent, PageEvent

from .shared import demo_page

router = APIRouter()


@router.get("/", response_model=FastUI, response_model_exclude_none=True)
def api_index() -> list[AnyComponent]:
    # Redirect to the password login page
    # return [c.FireEvent(event=GoToEvent(url="/auth/login/password"))]

    # language=markdown
    markdown = """\
Connectez-vous à votre compte Aiop Cloud pour modifier votre mot de passe, obtenir votre license et votre clée d’authentification de Aiop.
"""

    modal = c.Div(
        components=[
            c.Button(
                text="Se connecter",
                named_style="secondary",
                on_click=GoToEvent(url="/auth/login/password"),
            ),
        ],
        class_name="border-top mt-3 pt-1",
    )

    return demo_page(c.Markdown(text=markdown), modal, title="Aiop Cloud")


@router.get("/{path:path}", status_code=404)
async def api_404():
    # so we don't fall through to the index page
    return {"message": "Not Found"}
