from __future__ import annotations

from typing import Any

from cellprotocol.cells.function_cell import FunctionCell, function_cell_from_object
from cellprotocol.resolver import CellResolver, CellUsageScope


class ScaffoldRegistry:
    def __init__(self) -> None:
        self._objects: list[Any] = []
        self._cells: list[FunctionCell] = []

    def add_object(self, obj: Any) -> Any:
        self._objects.append(obj)
        return obj

    def add_cell(self, cell: FunctionCell) -> FunctionCell:
        self._cells.append(cell)
        return cell

    async def register_with(self, resolver: CellResolver, owner: Any | None = None) -> None:
        for obj in self._objects:
            cell = function_cell_from_object(obj, owner=owner)
            scope = getattr(obj, "__cell_scope__", CellUsageScope.scaffoldUnique)
            await resolver.register_named_emit_cell(cell.name, emit_cell=cell, scope=scope, identity=owner)
        for cell in self._cells:
            await resolver.register_named_emit_cell(cell.name, emit_cell=cell, scope=CellUsageScope.scaffoldUnique, identity=owner)
