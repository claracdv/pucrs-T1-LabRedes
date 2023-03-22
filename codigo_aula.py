import socket
import struct
import fcntl

BUFFSIZE = 1518

# Criacao do socket
# Todos os pacotes devem ser construidos a partir do protocolo Ethernet.
sockd = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
sockd.bind(('eth0', 0))

# O procedimento abaixo eh utilizado para "setar" a interface em modo promiscuo
# Observe que estamos utilizando a interface "eth0". Substitua conforme sua necessidade.
SIOCGIFINDEX = 0x8933
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914

ifr = struct.pack('256s', b'eth0')
ifindex = struct.unpack('i', fcntl.ioctl(sockd.fileno(), SIOCGIFINDEX, ifr[0:32]))[0]
ifflags = struct.unpack('H', fcntl.ioctl(sockd.fileno(), SIOCGIFFLAGS, ifr[0:32]))[0]
ifflags |= 0x100
fcntl.ioctl(sockd.fileno(), SIOCSIFFLAGS, struct.pack('16sH', b'eth0', ifflags))

# recepcao de pacotes
while True:
    buff1, _ = sockd.recvfrom(BUFFSIZE)
    # impressao do conteudo - exemplo Endereco Destino e Endereco Origem
    print(f"MAC Destino: {buff1[0]:02x}:{buff1[1]:02x}:{buff1[2]:02x}:{buff1[3]:02x}:{buff1[4]:02x}:{buff1[5]:02x}")
    print(f"MAC Origem:  {buff1[6]:02x}:{buff1[7]:02x}:{buff1[8]:02x}:{buff1[9]:02x}:{buff1[10]:02x}:{buff1[11]:02x}\n")