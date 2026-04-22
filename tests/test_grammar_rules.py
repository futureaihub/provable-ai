import pytest

from app.core.compiler.grammar.context import CompilationContext
from app.core.compiler.grammar.rules.arrow_rule import ArrowRule
from app.core.compiler.grammar.rules.pass_before_rule import PassBeforeRule
from app.core.compiler.grammar.rules.role_rule import RoleApprovalRule


# -------------------------------------------------
# ARROW RULE
# -------------------------------------------------

def test_arrow_rule():

    rule = ArrowRule()
    ctx = CompilationContext()

    text = "submitted -> approved"

    assert rule.matches(text)
    rule.apply(text, ctx)

    assert "submitted" in ctx.states
    assert "approved" in ctx.states
    assert len(ctx.transitions) == 1


# -------------------------------------------------
# PASS BEFORE RULE
# -------------------------------------------------

def test_pass_before_rule():

    rule = PassBeforeRule()
    ctx = CompilationContext()

    text = "risk_review must pass before approval"

    assert rule.matches(text)
    rule.apply(text, ctx)

    assert "risk_review" in ctx.states
    assert "approval" in ctx.states
    assert ctx.states["approval"].terminal is True
    assert len(ctx.transitions) == 1


# -------------------------------------------------
# ROLE RULE
# -------------------------------------------------

def test_role_approval_rule():

    rule = RoleApprovalRule()
    ctx = CompilationContext()

    text = "legal_review requires approval by admin"

    assert rule.matches(text)
    rule.apply(text, ctx)

    assert "legal_review" in ctx.states
    assert "approved" in ctx.states

    transition = ctx.transitions[0]
    assert transition.allowed_roles == ["admin"]