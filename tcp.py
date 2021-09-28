import asyncio
from tcputils import *
from random import randint

class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
            # TODO: talvez você precise passar mais coisas para o construtor de conexão
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao)
            nseq_serv = randint(0, 0xffff)
            
            conexao.nseq_cl = seq_no + 1
            conexao.nseq_serv = nseq_serv + 1
            conexao.sendb = conexao.nseq_serv
            
            pac = make_header(dst_port, src_port, nseq_serv, conexao.nseq_cl, FLAGS_SYN + FLAGS_ACK)
            pac_fix = fix_checksum(pac, dst_addr, src_addr)
            self.rede.enviar(pac_fix, src_addr)

            if self.callback:
                self.callback(conexao)
                
        elif (flags & FLAGS_FIN) == FLAGS_FIN:
            dados= b''
            self.conexoes[id_conexao].nseq_cl = self.conexoes[id_conexao].nseq_cl + 1
            seq_no = seq_no + 1
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, dados)
            self.conexoes.pop(id_conexao)
                
        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        self.nseq_cl = None
        self.nseq_serv = None
        self.timer = None 
        #self.timer.cancel()   # é possível cancelar o timer chamando esse método; esta linha é só um exemplo e pode ser removida
        self.fila = []
        self.sendb = None      
        
    def timeout(self):
        if len(self.fila) > -1:
            pac_fix, src_addr = self.fila[0]
            self.servidor.rede.enviar(pac_fix, src_addr)

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
            if seq_no == self.nseq_cl:
              self.callback(self, payload)
              if (flags & FLAGS_ACK) == FLAGS_ACK and ack_no > self.sendb:
                self.sendb = ack_no           
                if len(self.fila) > -1:
                    self.fila.pop(0)
                    self.timer.cancel()
                    if len(self.fila) > -1:
                        self.timer = asyncio.get_event_loop().call_later(0.5, self.timeout)
              if (flags & FLAGS_FIN) == FLAGS_FIN:
                payload = b''
                
            elif len(payload) < 1:
                return
            
            self.nseq_cl = self.nseq_cl + len(payload)
            src_addr, src_port, dst_addr, dst_port = self.id_conexao
            pac = make_header(dst_port, src_port, self.sendb, self.nseq_cl, FLAGS_ACK)
            pac_fix = fix_checksum(pac, dst_addr, src_addr)
            self.servidor.rede.enviar(pac_fix, src_addr)
           
            print('recebido payload: %r' % payload)

    # Os métodos abaixo fazem parte da API

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        
        while(len(dados)):
            payload = dados[:MSS]
            dados = dados[MSS:len(dados)]
            pac = make_header(dst_port, src_port, self.nseq_serv, self.nseq_cl, FLAGS_ACK)
            pac_fix = fix_checksum(pac + payload, dst_addr, src_addr)
            self.servidor.rede.enviar(pac_fix, src_addr)
            self.nseq_serv = self.nseq_serv + len(payload)
            self.timer = asyncio.get_event_loop().call_later(0.5, self.timeout)
            self.fila.append((pac_fix, src_addr))

    def fechar(self):
        src_addr, src_port, dst_addr, dst_port = self.id_conexao
        pac = make_header(dst_port, src_port, self.nseq_serv, self.nseq_cl, FLAGS_FIN)
        pac_fix = fix_checksum(pac, dst_addr, src_addr)
        self.servidor.rede.enviar(pac_fix, src_addr)
