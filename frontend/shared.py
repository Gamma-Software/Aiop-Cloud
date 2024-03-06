from __future__ import annotations as _annotations

from fastui import AnyComponent
from fastui import components as c
from fastui.events import GoToEvent


def demo_page(
    *components: AnyComponent, title: str | None = None
) -> list[AnyComponent]:
    return [
        c.PageTitle(text=f"Aiop Cloud — {title}" if title else "Aiop Cloud"),
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
                    on_click=GoToEvent(url="/contact"),
                    active="startswith:/forms",
                ),
            ],
        ),
        c.Page(
            components=[
                *((c.Heading(text=title),) if title else ()),
                *components,
            ],
        ),
        c.Footer(
            extra_text="Aiop Cloud - Leaptech (c) 2024",
            links=[
                c.Link(
                    components=[c.Text(text="Documentation")],
                    on_click=GoToEvent(url="https://aiop.fr/docs/"),
                ),
                c.Link(
                    components=[c.Text(text="Contact")],
                    on_click=GoToEvent(url="/contact"),
                ),
            ],
        ),
    ]
