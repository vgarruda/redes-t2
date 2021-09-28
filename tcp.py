import asyncio, random
from tcputils import *

class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
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
            init_n = random.randint(1, 10000000)
            ack_no = seq_no + 1
            flags = FLAGS_ACK|FLAGS_SYN
            
            pac = make_header(self.porta, src_port, init_n, ack_no, flags)
            pac = fix_checksum(pac, src_addr, dst_addr)
            self.rede.enviar(pac, src_addr)            

            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, init_n, ack_no)
            # TODO: você precisa fazer o handshake aceitando a conexão. Escolha se você acha melhor
            # fazer aqui mesmo ou dentro da classe Conexao.
            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao, seq_no, n_seq):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.seq_no = seq_no + 1
        self.n_seq = n_seq
        self.callback = None
        self.timer = asyncio.get_event_loop().call_later(1, self._exemplo_timer)  # um timer pode ser criado assim; esta linha é só um exemplo e pode ser removida
        #self.timer.cancel()   # é possível cancelar o timer chamando esse método; esta linha é só um exemplo e pode ser removida
        self.ini = seq_no
        self.buff1 = b''
        self.buff2 = b''
        self.t = True
        self.f = False

    def _exemplo_timer(self):
        # Esta função é só um exemplo e pode ser removida
        print('Este é um exemplo de como fazer um timer')

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        # TODO: trate aqui o recebimento de segmentos provenientes da camada de rede.
        # Chame self.callback(self, dados) para passar dados para a camada de aplicação após
        # garantir que eles não sejam duplicados e que tenham sido recebidos em ordem.
        print('recebido payload: %r' % payload)
        
        if seq_no == self.n_seq and payload:
            self.n_seq = seq_no + len(payload)
            self.callback(self, payload)
            pac = make_header(self.id_conexao[3], self.id_conexao[1], self.seq_no, self.n_seq, flags)
            pac = fix_checksum(pac, self.id_conexao[0], self.id_conexao[2])
            self.servidor.rede.enviar(pac, self.id_conexao[0])

        elif not self.f:
            if (flags & FLAGS_FIN) == FLAGS_FIN:
                self.callback(self, b'')
                self.n_seq = self.n_seq + 1
                pac = make_header(self.id_conexao[3], self.id_conexao[1], self.seq_no, self.n_seq, FLAGS_ACK)
                pac = fix_checksum(pac, self.id_conexao[0], self.id_conexao[2])
                self.servidor.rede.enviar(pac, self.id_conexao[0])
                self.f = True

        elif self.f:
            if flags & FLAGS_ACK == FLAGS_ACK:
                del self.servidor.conexoes[self.id_conexao]

    # Os métodos abaixo fazem parte da API

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados):
        if len(dados)>MSS:
            while len(dados)>MSS:
                data0 = dados[:MSS]
                data1 = dados[MSS:]
                dados = data1
                self.seq_no = self.seq_no + len(data0)
                pac = make_header(self.id_conexao[1], self.id_conexao[3], self.seq_no, self.n_seq, FLAGS_ACK)
                pac = fix_checksum(pac, self.id_conexao[0], self.id_conexao[2])
                self.servidor.rede.enviar(pac + data0, self.id_conexao[0])
            self.seq_no = self.seq_no + len(dados)

        pac = make_header(self.id_conexao[1], self.id_conexao[3], self.seq_no, self.n_seq, FLAGS_ACK)
        pac = fix_checksum(pac, self.id_conexao[0], self.id_conexao[2])
        self.servidor.rede.enviar(pac+dados, self.id_conexao[0])


    def fechar(self):
        pac = make_header(self.id_conexao[1], self.id_conexao[3], self.seq_no, self.n_seq, FLAGS_FIN)
        pac = fix_checksum(pac, self.id_conexao[0], self.id_conexao[2])
        self.servidor.rede.enviar(pac, self.id_conexao[0])
