"""
    Muhammad Rehan
    22P-9106
    BSE-8A | SRE
    Semester Project
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from .algorithms import Algorithm


class AlgorithmRegistry:
    # extracting algorithm registry responsibility from PyJWS
    # into its own class (Fowler: Extract Class)

    def __init__(
        self,
        algorithms: Sequence[str] | None = None,
    ) -> None:
        from .algorithms import get_default_algorithms

        # building the registry from defaults
        self._algorithms = get_default_algorithms()
        self._valid_algs = (
            set(algorithms) if algorithms is not None else set(self._algorithms)
        )

        # removing algorithms that aren't on the whitelist
        for key in list(self._algorithms.keys()):
            if key not in self._valid_algs:
                del self._algorithms[key]

    def register(self, alg_id: str, alg_obj: Algorithm) -> None:
        # registering a new algorithm in the registry
        from .algorithms import Algorithm as AlgorithmClass

        if alg_id in self._algorithms:
            raise ValueError("Algorithm already has a handler.")

        if not isinstance(alg_obj, AlgorithmClass):
            raise TypeError("Object is not of type `Algorithm`")

        self._algorithms[alg_id] = alg_obj
        self._valid_algs.add(alg_id)

    def unregister(self, alg_id: str) -> None:
        # unregistering an algorithm from the registry
        if alg_id not in self._algorithms:
            raise KeyError(
                "The specified algorithm could not be removed"
                " because it is not registered."
            )

        del self._algorithms[alg_id]
        self._valid_algs.remove(alg_id)

    def get_algorithm(self, alg_name: str) -> Algorithm:
        # looking up an algorithm by name
        from .algorithms import has_crypto, requires_cryptography

        try:
            return self._algorithms[alg_name]
        except KeyError as e:
            if not has_crypto and alg_name in requires_cryptography:
                raise NotImplementedError(
                    f"Algorithm '{alg_name}' could not be found. Do you have cryptography installed?"
                ) from e
            raise NotImplementedError("Algorithm not supported") from e

    def get_algorithms(self) -> list[str]:
        # returning the list of valid algorithm names
        return list(self._valid_algs)
