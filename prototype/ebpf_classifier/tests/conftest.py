import os
import subprocess
import uuid

import pytest

requires_root = pytest.mark.skipif(
    os.geteuid() != 0, reason="precisa de root (tc/bpf exigem CAP_NET_ADMIN/CAP_BPF)"
)


@pytest.fixture
def test_netns():
    """Cria um netns descartável com um par veth e **move a própria
    thread de teste pra dentro dele** (via `os.setns`, Python 3.12+) —
    não depende do laboratório OAI estar de pé, diferente dos testes
    `requires_live_lab` do ipsec_agent/pfcp_sniffer.

    Importante usar `os.setns` em vez de rodar tudo via `ip netns exec`
    (subprocess): `ip netns exec` também cria um mount namespace novo
    pro processo filho, e isso esconde `/sys/fs/bpf` (bpffs só fica
    visível no mount namespace onde foi montado — normalmente só o do
    host). `os.setns` troca só o namespace de rede, mantendo o mount
    namespace do host — scapy e os comandos `tc`/`bpftool` disparados
    depois enxergam a interface nova E o bpffs ao mesmo tempo."""
    ns = f"pqc-test-{uuid.uuid4().hex[:8]}"
    # nomes de interface Linux têm limite de 15 bytes (IFNAMSIZ) — usa só
    # um trecho curto do uuid, não o nome do netns inteiro.
    short = uuid.uuid4().hex[:8]
    veth_in = f"pqi{short}"
    veth_out = f"pqo{short}"

    original_netns_fd = os.open("/proc/self/ns/net", os.O_RDONLY)

    subprocess.run(["ip", "netns", "add", ns], check=True)
    subprocess.run(
        ["ip", "link", "add", veth_in, "type", "veth", "peer", "name", veth_out],
        check=True,
    )
    subprocess.run(["ip", "link", "set", veth_in, "netns", ns], check=True)
    subprocess.run(["ip", "netns", "exec", ns, "ip", "link", "set", veth_in, "up"], check=True)
    subprocess.run(["ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"], check=True)
    subprocess.run(["ip", "link", "set", veth_out, "up"], check=True)

    ns_fd = os.open(f"/var/run/netns/{ns}", os.O_RDONLY)
    os.setns(ns_fd, os.CLONE_NEWNET)
    os.close(ns_fd)

    try:
        yield ns, veth_in
    finally:
        os.setns(original_netns_fd, os.CLONE_NEWNET)
        os.close(original_netns_fd)
        subprocess.run(["ip", "netns", "del", ns], capture_output=True)
        subprocess.run(["ip", "link", "del", veth_out], capture_output=True)
