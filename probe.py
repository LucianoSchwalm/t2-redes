from scapy.all import sniff
import psutil

# Função de callback para processar cada pacote capturado
def process_packet(packet):
    print(packet.summary())  # Exibe um resumo do pacote

# Captura pacotes na interface 'eth0', por exemplo
def start_sniffer(interface):
    print(f"Sniffing on {interface}...")
    sniff(iface=interface, prn=process_packet, count=10)  # Captura 10 pacotes


def get_interface_stats(interface):
    net_io = psutil.net_io_counters(pernic=True)
    if interface in net_io:
        stats = net_io[interface]
        print(f"Interface: {interface}")
        print(f"Bytes Sent: {stats.bytes_sent}")
        print(f"Bytes Received: {stats.bytes_recv}")
        print(f"Packets Sent: {stats.packets_sent}")
        print(f"Packets Received: {stats.packets_recv}")
        print(f"Errors In: {stats.errin}")
        print(f"Errors Out: {stats.errout}")
    else:
        print(f"Interface {interface} não encontrada!")


# Executa o sniffer na interface 'eth0'
if __name__ == "__main__":
    interface = 'en0'  # Pode mudar para qualquer interface, como 'lo'
    start_sniffer(interface)
    get_interface_stats(interface)
