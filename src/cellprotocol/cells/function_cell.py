from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

from ..general_cell import GeneralCell


class FunctionCell(GeneralCell):
    def __init__(self, owner: Any | None = None, name: str = "PythonFunction", uuid: str | None = None) -> None:
        super().__init__(owner=owner, name=name, uuid=uuid)

    def on_get(self, keypath: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            async def handler(requested_keypath: str, requester: Any | None) -> Any:
                return await _call(fn, requested_keypath=requested_keypath, requester=requester)

            self._get_handlers[keypath] = handler
            return fn

        return decorator

    def on_set(self, keypath: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            async def handler(requested_keypath: str, value: Any, requester: Any | None) -> Any:
                return await _call(fn, value, requested_keypath=requested_keypath, requester=requester)

            self._set_handlers[keypath] = handler
            return fn

        return decorator


def cell(name: str, scope: str = "scaffoldUnique") -> Callable[[type], type]:
    def decorator(cls: type) -> type:
        cls.__cell_name__ = name
        cls.__cell_scope__ = scope
        return cls

    return decorator


def get(keypath: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        fn.__cell_get_keypath__ = keypath
        return fn

    return decorator


def set(keypath: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        fn.__cell_set_keypath__ = keypath
        return fn

    return decorator


def function_cell_from_object(obj: Any, owner: Any | None = None) -> FunctionCell:
    name = getattr(obj, "__cell_name__", obj.__class__.__name__)
    cell_obj = FunctionCell(owner=owner, name=name)
    for attr_name in dir(obj):
        fn = getattr(obj, attr_name)
        get_keypath = getattr(fn, "__cell_get_keypath__", None)
        set_keypath = getattr(fn, "__cell_set_keypath__", None)
        if isinstance(get_keypath, str):
            cell_obj.on_get(get_keypath)(fn)
        if isinstance(set_keypath, str):
            cell_obj.on_set(set_keypath)(fn)
    return cell_obj


async def _call(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    signature = inspect.signature(fn)
    accepted_kwargs = {key: value for key, value in kwargs.items() if key in signature.parameters}
    value = fn(*args, **accepted_kwargs)
    if inspect.isawaitable(value):
        return await value
    return value
