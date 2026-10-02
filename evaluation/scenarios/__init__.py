"""Cenários de teste — ver CENARIOS-TESTE-AVALIACAO.md seção 1.

Cada cenário expõe `setup()`/`teardown()` (mexe na topologia IPsec real
do laboratório) e `traffic_plan()` (quais sondas de tráfego rodar e em
qual interface/fatia) — `run_experiment.py` chama os três.

**Regra metodológica da seção 0 do documento, respeitada em todos os
cenários abaixo**: o limite máximo de vida útil de uma SA
(`MAX_SA_LIFETIME_SECONDS`) é o mesmo em todos — só muda *como e quando*
a rotação é decidida dentro desse limite, nunca a frequência-base."""

from __future__ import annotations

MAX_SA_LIFETIME_SECONDS = 3600  # mesmo valor em todos os cenários — ver docstring acima
