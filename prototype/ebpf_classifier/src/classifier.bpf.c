// Classificador TC (Módulo 3) — lê o TEID do GTP-U (udp/2152) e marca o
// skb pelo mark correspondente, consultando um BPF hash map que o
// Módulo 2 (pfcp_sniffer) popula. Ver docs/ARQUITETURA-PROTOTIPO-COMPLETA.md
// seção 4.
//
// **Limitação conhecida, encontrada e documentada ao testar isto (não
// escondida)**: este programa funciona corretamente pra tráfego onde o
// GTP-U chega/sai em claro na interface onde o hook TC está — mas não é
// esse o caso do enlace de saída (CU->UPF) nesta topologia depois que o
// IPsec entra em cena: o XFRM criptografa o pacote como parte da decisão
// de rota, ANTES de qualquer qdisc/TC do dispositivo de saída rodar, pra
// tráfego gerado localmente pelo processo da CU (o socket GTP-U do OAI).
// Um hook TC egress no `veth-cu-n2` só vê ESP, nunca o GTP-U em claro.
// Confirmado com captura real — ver prototype/ebpf_classifier/README.md
// pra detalhes e o caminho de correção proposto (ainda não implementado).
//
// Isso NÃO significa que o programa abaixo esteja errado — ele faz
// exatamente o que o Módulo 3 descreve, e funciona corretamente em
// qualquer ponto onde o GTP-U realmente trafegue em claro (confirmado
// com tráfego real de verdade, não só em teoria — ver o README).

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define GTPU_PORT 2152
// Offset do TEID dentro do header GTP-U: byte0=flags, byte1=msg type,
// bytes2-3=length, bytes4-7=TEID — fixo independente de extension
// headers (eles vêm DEPOIS do TEID, não antes). Confirmado com captura
// real, inclusive com a flag de extensão ligada — ver
// docs/ROTEIRO-MODULO2-SNIFFER-PFCP.md.
#define GTPU_TEID_OFFSET 4
#define GTPU_HEADER_MIN_LEN 8

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // TEID, host byte order
    __type(value, __u32); // mark (0x10/0x20/0x30 — ver pfcp_sniffer/models.py SST_TO_MARK)
} teid_to_mark SEC(".maps"); // nome <=15 bytes (limite do kernel) — "map_teid_to_mark" trunca

// Contadores simples pra observabilidade sem precisar de printk/trace
// pipe — ver tests/ pra como ler isso de fora.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} map_stats SEC(".maps");

#define STAT_MATCHED 0    // pacote GTP-U com TEID encontrado no map, marcado
#define STAT_UNKNOWN_TEID 1  // pacote GTP-U com TEID não classificado ainda
#define STAT_NOT_GTPU 2   // pacote que nem chegou a ser GTP-U/2152

static __always_inline void bump_stat(__u32 idx)
{
    __u64 *count = bpf_map_lookup_elem(&map_stats, &idx);
    if (count)
        __sync_fetch_and_add(count, 1);
}

SEC("tc")
int classify_gtpu(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    // ip->ihl é em palavras de 4 bytes; normalmente 5 (sem opções), mas
    // calcula certo em vez de assumir.
    __u32 ip_header_len = ip->ihl * 4;
    struct udphdr *udp = (void *)ip + ip_header_len;
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;
    if (udp->dest != bpf_htons(GTPU_PORT)) {
        bump_stat(STAT_NOT_GTPU);
        return TC_ACT_OK;
    }

    __u8 *gtpu = (void *)(udp + 1);
    if ((void *)(gtpu + GTPU_HEADER_MIN_LEN) > data_end)
        return TC_ACT_OK;

    __u32 teid_be;
    __builtin_memcpy(&teid_be, gtpu + GTPU_TEID_OFFSET, sizeof(teid_be));
    __u32 teid = bpf_ntohl(teid_be);

    __u32 *mark = bpf_map_lookup_elem(&teid_to_mark, &teid);
    if (!mark) {
        bump_stat(STAT_UNKNOWN_TEID);
        return TC_ACT_OK;
    }

    skb->mark = *mark;
    bump_stat(STAT_MATCHED);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
