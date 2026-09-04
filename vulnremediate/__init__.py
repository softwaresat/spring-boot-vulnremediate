"""LangGraph-powered Spring Boot vulnerability remediation."""

__all__ = ["build_graph"]


def build_graph():
    """Lazily import LangGraph so scan/planning utilities remain lightweight."""
    from .graph import build_graph as _build_graph
    return _build_graph()
