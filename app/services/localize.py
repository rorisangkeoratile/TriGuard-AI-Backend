"""Translate a finished result into the user's language with one batched call."""

from app.languages import AUTO
from app.schemas import RiskAssessment
from app.services.llm import llm_available, translate_strings


async def localize(result: RiskAssessment, language: str, already_translated: set[str] = frozenset()) -> RiskAssessment:
    """Translate the English parts of `result` in place. Strings in `already_translated` are left alone."""
    if language in ("en", AUTO) or not llm_available():
        return result  # stays in English

    # (getter, setter) pairs for every user-facing string, so one call translates them all.
    slots = [
        (lambda: result.headline, lambda v: setattr(result, "headline", v)),
        (lambda: result.summary, lambda v: setattr(result, "summary", v)),
        (lambda: result.disclaimer, lambda v: setattr(result, "disclaimer", v)),
    ]
    for i in range(len(result.advice)):
        slots.append((lambda i=i: result.advice[i], lambda v, i=i: result.advice.__setitem__(i, v)))
    for ind in result.indicators:
        slots.append((lambda ind=ind: ind.title, lambda v, ind=ind: setattr(ind, "title", v)))
        slots.append((lambda ind=ind: ind.detail, lambda v, ind=ind: setattr(ind, "detail", v)))

    todo = [(get, set_) for get, set_ in slots if get() and get() not in already_translated]
    translated = await translate_strings([get() for get, _ in todo], language)
    for (get, set_), text in zip(todo, translated):
        set_(text)
    result.language = language
    return result
