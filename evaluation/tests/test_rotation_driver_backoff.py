"""O recuo entre tentativas de renovar PPK.

Estes testes existem porque o defeito que eles cobrem **passou por uma
campanha inteira sem aparecer como erro**: ele se manifestava só como um
número impossível numa tabela (a mIoT obtendo mais chaves de QKD que a
URLLC), e revalidar a mão custa ~20 h de recampanha.
"""

from __future__ import annotations

import itertools

import pytest

from evaluation import instrumentation, rotation_driver
from evaluation.rotation_driver import IdadesSa, RotationDriver
from kms.models import SliceType
from scheduler.models import TaskType

TR_PPK = 30.0
TR_CHILD = 12.0
TICK = 2.5


class _SchedulerFalso:
    def __init__(self):
        self.tarefas = []

    def enqueue_task(self, req):
        self.tarefas.append(req)

    def queue_size(self):
        return 0  # o dreno não é o objeto deste teste


class _RelogioFalso:
    """Avança só quando o teste manda, para o recuo ser medido em tempo
    simulado — um teste que dependesse de `sleep` real levaria minutos e
    seria instável sob carga."""

    def __init__(self):
        self.agora = 1000.0

    def __call__(self):
        return self.agora


@pytest.fixture
def ambiente(monkeypatch):
    relogio = _RelogioFalso()
    monkeypatch.setattr(rotation_driver.time, "monotonic", relogio)
    monkeypatch.setattr(rotation_driver, "find_charon_pid", lambda netns: 4242)
    sched = _SchedulerFalso()
    driver = RotationDriver(
        smo=None, scheduler=sched, check_interval_seconds=TICK,
        tr_child={s: TR_CHILD for s in SliceType},
        tr_ppk={s: TR_PPK for s in SliceType},
    )
    # O dreno lê a fila do scheduler falso, que reporta 0: sai na hora.
    return driver, sched, relogio


def _roda(driver, relogio, monkeypatch, segundos, idades_de):
    """Roda ticks por `segundos` de tempo simulado. `idades_de` recebe o
    instante corrente e devolve o mapa de idades que o `swanctl` daria."""
    for _ in range(int(segundos / TICK)):
        monkeypatch.setattr(rotation_driver, "_read_sa_ages",
                            lambda _pid, t=relogio.agora: idades_de(t))
        driver._tick()
        relogio.agora += TICK


def _tipos(sched, tipo):
    return [t for t in sched.tarefas if t.task_type is tipo]


def test_reauth_que_falha_nao_e_re_tentada_a_cada_tick(ambiente, monkeypatch):
    """O defeito em si: com a IKE_SA nunca reautenticada, a idade nunca
    zera e o portão de idade sozinho deixava a fatia tentar a cada tick.

    Em 300 s a 2,5 s por tick isso dava ~110 tentativas; o projetado é
    300/30 = 10.
    """
    inicio = ambiente[2].agora
    driver, sched, relogio = ambiente

    # idade da IKE_SA cresce para sempre: nenhuma reauth tem sucesso
    _roda(driver, relogio, monkeypatch, 300.0,
          lambda t: {SliceType.URLLC: IdadesSa(ike_seconds=TR_PPK + (t - inicio),
                                               child_seconds=0.0)})

    tentativas = _tipos(sched, TaskType.REAUTH_PPK)
    assert len(tentativas) == pytest.approx(300 / TR_PPK, abs=1), (
        f"esperado ~{300 / TR_PPK:.0f} tentativas em 300 s, veio {len(tentativas)}"
    )


def test_recuo_nao_impede_a_rotacao_do_esp(ambiente, monkeypatch):
    """Durante a janela de recuo não há tentativa, logo não há falha,
    logo `_drena` não rebaixa. Sem a queda para o rekey de Child SA a
    fatia ficaria sem rotação nenhuma — que é o defeito que o
    rebaixamento existe para evitar."""
    inicio = ambiente[2].agora
    driver, sched, relogio = ambiente

    # IKE_SA vencida e parada; Child SA também vencida e parada
    _roda(driver, relogio, monkeypatch, 300.0,
          lambda t: {SliceType.MIOT: IdadesSa(ike_seconds=TR_PPK + (t - inicio),
                                              child_seconds=TR_CHILD + (t - inicio))})

    assert _tipos(sched, TaskType.REKEY_CHILD), (
        "a fatia em recuo parou de rotacionar o ESP — é o defeito que o "
        "rebaixamento existe para evitar"
    )


def test_sucesso_mantem_o_periodo_projetado(ambiente, monkeypatch):
    """Quando a reauth dá certo a idade da IKE_SA zera, e os dois portões
    têm de concordar: uma tentativa por `Tr_ppk`, nem mais nem menos. O
    recuo não pode atrasar a fatia saudável."""
    driver, sched, relogio = ambiente
    estado = {"ultimo_sucesso": relogio.agora}

    def idades(t):
        # a reauth anterior zerou a idade da IKE_SA
        return {SliceType.URLLC: IdadesSa(
            ike_seconds=t - estado["ultimo_sucesso"], child_seconds=0.0)}

    for _ in range(int(300.0 / TICK)):
        antes = len(_tipos(sched, TaskType.REAUTH_PPK))
        monkeypatch.setattr(rotation_driver, "_read_sa_ages",
                            lambda _pid, t=relogio.agora: idades(t))
        driver._tick()
        if len(_tipos(sched, TaskType.REAUTH_PPK)) > antes:
            estado["ultimo_sucesso"] = relogio.agora  # sucesso: idade zera
        relogio.agora += TICK

    n = len(_tipos(sched, TaskType.REAUTH_PPK))
    assert n == pytest.approx(300 / TR_PPK, abs=1), (
        f"a fatia saudável devia renovar ~{300 / TR_PPK:.0f} vezes, veio {n}"
    )


def test_recuo_anuncia_uma_vez_por_janela_nao_por_tick(ambiente, monkeypatch, tmp_path):
    """Emitir o adiamento a cada tick repetiria o próprio volume que o
    recuo corta — o evento é por janela."""
    inicio = ambiente[2].agora
    driver, sched, relogio = ambiente
    caminho = tmp_path / "ev.jsonl"
    instrumentation.reset()
    instrumentation.configure(caminho, run_id="t")
    try:
        _roda(driver, relogio, monkeypatch, 300.0,
              lambda t: {SliceType.EMBB: IdadesSa(ike_seconds=TR_PPK + (t - inicio),
                                                  child_seconds=0.0)})
    finally:
        instrumentation.reset()

    adiamentos = [l for l in caminho.read_text().splitlines()
                  if '"ppk_retry_deferred"' in l]
    tentativas = len(_tipos(sched, TaskType.REAUTH_PPK))
    assert len(adiamentos) == pytest.approx(tentativas, abs=1), (
        f"{len(adiamentos)} anúncios para {tentativas} janelas — "
        f"o evento está saindo por tick, não por janela"
    )
