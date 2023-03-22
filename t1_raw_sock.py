import socket, sys, time
from socket import AF_PACKET, SOCK_RAW
from struct import *
import fcntl  
import threading
import os


node_list=[] 
# checksum functions needed for calculation checksum
def checksum(msg):
	s = 0
	# loop taking 2 characters at a time
	for i in range(0, len(msg)-1, 2):  
		w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
		s = s + w
	
	s = (s>>16) + (s & 0xffff);
	s = s + (s >> 16);
	
	#complement and mask to 4 byte short
	s = ~s & 0xffff
	
	return s

#Cria pacote de dados para envio 
def create_packet(data,src,dst): 
	try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
	except socket.error , msg:
        print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()
	
	#Cria pacote
	packet='';
	# src=fe:ed:fa:ce:be:ef, dst=52:54:00:12:35:02, type=0x0800 (IP)
	dst_mac = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
	src_mac = [0x00, 0x0a, 0x11, 0x11, 0x22, 0x22]
	
	# Ethernet header
	eth_header = pack('!6B6BH', dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5], 
		src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5], 0x0800)
	#Coloca os headers de IP
	ip_ihl=5
	ip_versao=4
	ip_tos=0
	ip_tot_len=0 #Lenght total vai ser preenchido pelo kernel
	ip_id=54321 #id para o pacote
	ip_frag_off=0
	ip_ttl=255
	ip_proto=socket.IPPROTO_TCP
	ip_check=0
	
	ip_send_addr=src
	ip_dest_addr=dst
	
	ip_ihl_ver=(ip_versao<<4)+ip_ihl
	
	#Faz o header de IP, onde ! indica a ordem da rede
	# the ! in the pack format string means network order
	ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_send_addr, ip_dest_addr)
	ip_check = checksum(ip_header) 
	# build the final ip header (with checksum)
	ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_send_addr, ip_dest_addr)
	
	#Criado o ip header, criamos o tcp header 
	source = 1234   # source port
	dest = 80   # destination port
	seq = 0
	ack_seq = 0
	doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
	#tcp flags
	fin = 0
	syn = 1
	rst = 0
	psh = 0
	ack = 0
	urg = 0
	window = socket.htons(5840)		# maximum allowed window size
	tcp_check = 0
	urg_ptr = 0
	offset_res = (doff << 4) + 0
	tcp_flags = fin + (syn << 1) + (rst << 2) + (psh <<3) + (ack << 4) + (urg << 5)
	 
	# the ! in the pack format string means network order
	tcp_header = pack('!HHLLBBHHH' , source, dest, seq, ack_seq, offset_res, tcp_flags,  window, tcp_check, urg_ptr)
	
	# pseudo header fields
   	source_address = socket.inet_aton( src )
   	dest_address = socket.inet_aton(dst)
    	placeholder = 0
    	protocol = socket.IPPROTO_TCP
    
    
    	#O tamanho do tcp da mensagem a ser enviada
    	tcp_length = len(tcp_header) + len(data)

    	psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
    	psh = psh + tcp_header + data; 
    	tcp_check = checksum(psh)
    	#print tcp_checksum

    	# make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
    	tcp_header = pack('!HHLLBBHHH' , source, dest, seq, ack_seq, offset_res, tcp_flags,  window, tcp_check, urg_ptr) + pack('H' , tcp_check) + pack('!H' , urg_ptr)

    	# final full packet - syn packets dont have any data
    	packet = eth_header+ip_header + tcp_header + data 
	return packet 
	



	
#Receptor de dados, deve funcionar como sniffer e rodar constantemente
def recv_raw(): 
	# Socket 
	s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)
	s.bind(("",9999))
	packet=s.recvfrom(65565)
	#Recebi pacote, tem que passar msg para string 
	packet=packet[0] 
	
	#Pega o header de ip 
	ip_header=packet[0:20] 
	iph=unpack("!BBHHHBBH4s4s",ip_header) 
	
	#pegar versao ihl 
	version_ihl=iph[0]
	version=version_ihl>>4
	ihl=version_ihl&0xF 
	ip_length=ihl*4
	
	#TTL 
	ttl=iph[5]
	#Protocolo
	protocol=iph[6]
	#Endereco do enviador 
	s_addr=socket.inet_ntoa(iph[8]);
	#Endereco de destino
	d_addr=socket.inet_ntoa(iph[9]);
	
	tcp_header=packet[ip_length:ip_length+20]
	tcph=unpack("!HHLLBBHHH",tcp_header)
	
	source_port=tcph[0]
	dest_port=tcph[1]
	sequence=tcph[2]
	acknowlegment=tcph[3]
	doff_reserved=tcph[4]
	tcph_length=doff_reserved>>4
	
	h_size=ip_length+tcph_length*4
	data_size=len(packet)-h_size
	
	data=packet[h_size:]  
	data=data[58:]     
	if("Start" in data):
		name_mach=data.split(" ")[1]
		ip_mach=data.split(" ")[2] 
		node_list.append((name_mach,ip_mach,0))
		print("Started received from ..."+name_mach)
	elif("Heartbeat" in data):   
		nome_maquia=data.split(" ")[1]
		ip_maquina=data.split(" ")[2]   
		print("Heartbeat received from..."+nome_maquia)
		if(get_id_from_mach(nome_maquia) == -1):
			node_list.append((nome_maquia,ip_maquina,0))
		else: 
			x=get_id_from_mach(nome_maquia)
			if(x!= -1):
				node_list[x]=(node_list[x][0],node_list[x][1],0) 
	else: 
		print(data)

def get_id_from_mach(nome):
	for i in range(0,len(node_list)):
		if(nome in node_list[i][0]):
			return i
	return -1
	
def get_data_from_user(HOST,HOST_NAME):
	#Pega conteudo da insercao do usuario
	content=raw_input()
	# Pega o nome da maquina
	
	if("quit" == content):
		os._exit(1)
	else: 
		dest=content.split(" ")[1]
		machi=get_id_from_mach(dest) 
		#Cria pacote com o IP DA MAQUINA ENCONTRADA!
		if(machi != -1): 
			mach=node_list[machi]
			mensagem=content.split(" ")[2:len(content.split(" "))]
			msg=""
			for i in range(0,len(mensagem)):
				msg+=mensagem[i]+" "
			packet=create_packet("Maquina "+HOST_NAME+" falou:"+msg,HOST,mach[1])
			#Envia!!
			send_msg(packet,mach[1])
		else:
			print("Nao foi possivel enviar pacote, maquina nao existe...")
		
def send_hb_message(HOST_NAME,HOST): 
	if(len(node_list)==0):
		print("Nao ha maquinas para contato...")
	else:
		for i in  range(0,len(node_list)): 
				node_list[i]=(node_list[i][0],node_list[i][1],node_list[i][2]+1)
				if(node_list[i][2]>=3):
					node_list.remove(node_list[i])  
					break
	msg_Heartbeat='Heartbeat '+HOST_NAME+" "+HOST
	#Cria pacote com mensagem de heartbeat  
	#Passa por todos os nodos conhecidos
	for i in range(0,len(node_list)):
		#Se ainda esta ativo 
		packet_hb=create_packet(msg_Heartbeat,HOST,node_list[i][1]) 
		#Envia a mensagem  
		send_msg(packet_hb,node_list[i][1]) 

def send_msg(msg,dst):
	s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP);
	s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)  
	s.sendto(msg, (dst , 0 ))


def thread_hb(HOST_NAME,HOST): 
	while(True):  
		#Envia mensagem para o servidor (Placeholder:127.0.0.1)  
		send_hb_message(HOST_NAME,HOST)
		time.sleep(5)

def thread_user(HOST,HOST_NAME):
	while(True):
		get_data_from_user(HOST,HOST_NAME)

def thread_rec():
	while(True):
		#Receptor de dados <- CONSTANTEMENTE RODANDO  
		recv_raw()

def ip_local():
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
	return socket.inet_ntoa(fcntl.ioctl(
		s.fileno(),
		0x8915,
		pack('256s',bytes('eth0'))
	)[20:24])
	
def netmask(): 
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
	return socket.inet_ntoa(fcntl.ioctl(
		s.fileno(),
		0x891b,
		pack('256s',bytes('eth0'))
	)[20:24])

def broadcast_IP(HOST,netmask):
	vec_ip=HOST.split(".")
	vec_net=netmask.split(".")
	ip_br=""
	for i in range(0,len(vec_ip)):
		if(vec_net[i]=='0' and i!=len(vec_ip)-1):
			ip_br+="255."
		elif(vec_net[i]=='0' and i==len(vec_ip)-1):
			ip_br+='255'
		elif(vec_net[i]!='0' and i!=len(vec_ip)-1):
			ip_br+=vec_ip[i]+'.'
		else:
			ip_br+=vec_ip[i]
	return ip_br
	
	
#O PACOTE START TEM QUE SER ENVIADO NA ATIVACAO!!  
HOST= ip_local()
#HOST=socket.gethostbyname(socket.gethostname())


HOST_NAME= socket.gethostname() 

#Netmask
netmask=netmask()

#SERVIDOR PARA MANDAR MENSAGEM
server=broadcast_IP(HOST,netmask)  

msg_start='Start '+HOST_NAME+" "+HOST  

#Cria pacote com mensagem de Start
packet_start=create_packet(msg_start,HOST,server)

#Manda a mensagem para o servidor
send_msg(packet_start,server) 

thread_heartbeat=threading.Thread(target=thread_hb,args=(HOST_NAME,HOST,))
thread_input=threading.Thread(target=thread_user,args=(HOST,HOST_NAME,))
thread_receive=threading.Thread(target=thread_rec,args=())



thread_heartbeat.start()
thread_input.start()
thread_receive.start() 


