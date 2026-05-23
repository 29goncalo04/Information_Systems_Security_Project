import asyncio, sys, os, glob
from certificados import *
from utils import *
from ficheiro import *
from server_functions import *
from bson import BSON
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from functools import partial
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305



conn_cnt = 0
conn_port = 7777
max_msg_size = 9999

parameters = dh.generate_parameters(generator=2, key_size=2048)
active_pseudonyms = load_active()



class ServerWorker(object):
    """ Classe que implementa a funcionalidade do SERVIDOR. """
    def __init__(self, cnt, addr=None, private_key=None, certificado_server=None):
        """ Construtor da classe. """
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
        self.private_key = private_key
        self.certificado_server = certificado_server
        self.private_key_DH = parameters.generate_private_key()
        self.parameters_bytes = parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3
        )
        self.public_key_DH = self.private_key_DH.public_key().public_bytes(
                            encoding=serialization.Encoding.PEM, 
                            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        self.public_key_DH_client = None
        self.public_key_client = None
        self.secret_key = None
        self.pseudonym = None
        


    def process(self, msg):
        """ Processa uma mensagem (`bytestring`) enviada pelo CLIENTE.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        self.msg_cnt += 1
        # envia a sua chave pública DH e os parametros 'p' e 'g'
        if self.msg_cnt == 1:
            return mkpair(self.public_key_DH, self.parameters_bytes)
        # está a receber do cliente a sua chave DH, o certificado e a assinatura
        elif self.msg_cnt == 2:
            public_key_DH_client, cert_and_signature = unpair(msg)
            certificado_cliente, signature = unpair(cert_and_signature)
            # valida o certificado do cliente
            if valida_certificado(certificado_cliente, False):
                certificado_cliente_bytes = certificado_cliente.decode("utf-8")
                pseudonym = extract_pseudonym(certificado_cliente)
                # se um cliente que já estava conectado se estiver a tentar conectar novamente, essa conexão é recusada
                if pseudonym in active_pseudonyms:
                    return None
                else:
                    # guarda o PSEUDONYM do novo cliente no json
                    self.pseudonym = pseudonym
                    active_pseudonyms[pseudonym] = certificado_cliente_bytes
                    save_active(active_pseudonyms)
                    upload_certificates(active_pseudonyms)
                # extrai a chave pública do cliente
                self.public_key_client = extract_public_key(certificado_cliente)
                par_chavesDH = mkpair(public_key_DH_client, self.public_key_DH)
                par_chavesDH_and_paremeters = mkpair(par_chavesDH, self.parameters_bytes)
                # verifica a assinatura do par (chaves DH, parameters) feita pelo cliente
                try:
                    self.public_key_client.verify(
                        signature,
                        par_chavesDH_and_paremeters,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    # guarda a chave pública DH do cliente
                    self.public_key_DH_client = public_key_DH_client
                    # cria o par de chaves (chave DH pública do cliente, chave DH pública do server)
                    par_chavesDH = mkpair(self.public_key_DH_client, self.public_key_DH)
                    # assina esse par
                    signature = self.private_key.sign(
                        par_chavesDH,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    # serializa o seu proprio certificado
                    certificado_bytes = self.certificado_server.public_bytes(
                        encoding=serialization.Encoding.PEM
                    )
                    # faz um par do seu certificado com a assinatura
                    cert_and_signature = mkpair(certificado_bytes, signature)
                    # calcula a shared_key
                    shared_key = self.private_key_DH.exchange(serialization.load_pem_public_key(self.public_key_DH_client))
                    # calcula a secret_key
                    self.secret_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b'handshake data',
                    ).derive(shared_key)
                    escrever_ficheiro_logs(f"O cliente '{self.pseudonym}' conectou-se")
                    return cert_and_signature # (certificado, assinatura de (chave DH cliente, chave DH server))
                except:
                    print("Assinatura de chaves inválida")
                    return None
            else:
                # termina a conexão se o certificado do cliente for inválido
                print("Certificado do cliente inválido")
                return None
        else:
            aead = ChaCha20Poly1305(self.secret_key)
            nonce_chan, ciphertext_msg = unpair(msg)
            payload = aead.decrypt(nonce_chan, ciphertext_msg, None)
            bundle, metadados_serializados = unpair(payload)
            metadados_originais = BSON(metadados_serializados).decode()
            action = metadados_originais.get("action")

            if action == "CAN ADD PERSONAL":
                try:
                    can_add_personal_server(metadados_originais, self.pseudonym)
                    escrever_ficheiro_logs(f"O ficheiro com path '{metadados_originais.get("file_path")}' ainda não existe no sistema")
                    return send_message(self.secret_key, "Concluído".encode())
                except Exception as e:
                    escrever_ficheiro_logs(str(e))
                    return send_message(self.secret_key, str(e).encode())
            
            elif action == "CAN ADD GROUP":
                try:
                    can_add_group_server(metadados_originais, self.pseudonym)
                    escrever_ficheiro_logs(f"O ficheiro com path '{metadados_originais.get("file_path")}' ainda não existe no sistema")
                    return send_message(self.secret_key, "Concluído".encode())
                except Exception as e:
                    escrever_ficheiro_logs(str(e))
                    return send_message(self.secret_key, str(e).encode())
            
            elif action == "ADD":
                try:
                    file_id, file_path = add_file_personal_vault_server(metadados_originais, bundle, self.pseudonym)
                    add_util_informations(bundle, self.pseudonym, file_id, file_path)
                    escrever_ficheiro_logs(f"Foi adicionado o ficheiro '{file_id}' ao cofre do cliente '{self.pseudonym}'")
                    return send_message(self.secret_key, file_id.encode())
                except Exception as e:
                    escrever_ficheiro_logs(str(e))
                    return send_message(self.secret_key, str(e).encode())
                    
            elif action == "CREATE GROUP":
                try:
                    group_id = create_group_server(metadados_originais, self.pseudonym)
                    escrever_ficheiro_logs(f"Foi criado o grupo '{group_id}' pelo cliente '{self.pseudonym}'")
                    return send_message(self.secret_key, group_id.encode())
                except Exception as e:
                    escrever_ficheiro_logs(str(e))
                    return send_message(self.secret_key, str(e).encode())
                
            elif action == "GET CERTIFICATES":
                try:
                    certificates = send_certificates(metadados_originais, self.pseudonym)
                    return send_message(self.secret_key, certificates)
                except Exception as e:
                    escrever_ficheiro_logs(str(e))
                    return send_message(self.secret_key, str(e).encode())   
                            
            elif action == "GROUP ADD":
                try:
                    file_id = add_file_group_vault_server(metadados_originais, bundle, self.pseudonym)
                    escrever_ficheiro_logs(f"Foi adicionado o ficheiro '{file_id}' ao cofre do grupo '{metadados_originais.get("group_id")}'")
                    return send_message(self.secret_key, file_id.encode())
                except Exception as e:
                    escrever_ficheiro_logs(str(e))
                    return send_message(self.secret_key, str(e).encode())
                
            elif action == "GET CERTIFICATE ADD USER":
                try:
                    msg = send_certificate_add_user(metadados_originais, self.pseudonym)
                    return send_message(self.secret_key, msg)
                except Exception as e:
                    escrever_ficheiro_logs(str(e))
                    return send_message(self.secret_key, str(e).encode()) 
                
            elif action == "GROUP ADD-USER":
                try:
                    add_user_group_server(metadados_originais, bundle, self.pseudonym)
                    escrever_ficheiro_logs(f"Foi adicionado o user '{metadados_originais.get("user_id")}' ao grupo '{metadados_originais.get("group_id")}'")
                    return send_message(self.secret_key, "Concluído".encode())
                except Exception as e:
                    escrever_ficheiro_logs(str(e))
                    return send_message(self.secret_key, str(e).encode())
                
            elif action == "DELETE GROUP":
                try:
                    delete_group_server(metadados_originais, self.pseudonym)
                    escrever_ficheiro_logs(f"Foi apagado o grupo '{metadados_originais.get("group_id")}' pelo cliente '{self.pseudonym}'")
                    return send_message(self.secret_key, "Concluído".encode())
                except Exception as e:
                    escrever_ficheiro_logs(str(e))
                    return send_message(self.secret_key, str(e).encode())
                
            elif action == "REMOVE USER GROUP":
                try:
                    remove_user_group_server(metadados_originais, self.pseudonym)
                    escrever_ficheiro_logs(f"Foi removido o utilizador '{metadados_originais.get("user_id")}' do grupo '{metadados_originais.get("group_id")}'")
                    return send_message(self.secret_key, "Concluído".encode())
                except Exception as e:
                    escrever_ficheiro_logs(str(e))
                    return send_message(self.secret_key, str(e).encode())
                
            elif action == "GROUP LIST":
                try:
                    group_list = get_group_list_server(metadados_originais, self.pseudonym)
                    escrever_ficheiro_logs(f"Foram enviados ao '{self.pseudonym} os grupos a que pertence e respetivas permissões.'")
                    return send_message(self.secret_key, group_list)
                except Exception as e:
                    escrever_ficheiro_logs(str(e))
                    return send_message(self.secret_key, str(e).encode())

            elif action == "LIST FILES USER":
                try:
                    files_list = list_files_user_server(metadados_originais, self.pseudonym)
                    escrever_ficheiro_logs(f"Foram enviados ao '{self.pseudonym} os ficheiros a que o '{metadados_originais.get("user_id")}' tem acesso.'")
                    return send_message(self.secret_key, files_list)
                except Exception as e:
                    escrever_ficheiro_logs(str(e))
                    return send_message(self.secret_key, str(e).encode())
                
            elif action == "LIST FILES GROUP":
                try:
                    files_list = list_files_group_server(metadados_originais, self.pseudonym)
                    escrever_ficheiro_logs(f"Foram enviados ao '{self.pseudonym} os ficheiros que pertencem ao grupo '{metadados_originais.get("group_id")}'.'")
                    return send_message(self.secret_key, files_list)
                except Exception as e:
                    escrever_ficheiro_logs(str(e))
                    return send_message(self.secret_key, str(e).encode())
                
            elif action == "GET CERTIFICATE":
                try:
                    msg = send_certificate(metadados_originais, self.pseudonym)
                    return send_message(self.secret_key, msg)
                except Exception as e:
                    escrever_ficheiro_logs(str(e))
                    return send_message(self.secret_key, str(e).encode()) 
                
            elif action == "SHARE FILE":
                try:
                    share_file_server(metadados_originais, bundle, self.pseudonym)
                    escrever_ficheiro_logs(f"Foi partilhado o ficheiro '{metadados_originais.get("file_id")}' com o cliente '{metadados_originais.get("user_id")}' com as permissões '{metadados_originais.get("permissions")}'")
                    return send_message(self.secret_key, "Concluído".encode())
                except Exception as e:
                    escrever_ficheiro_logs(str(e))
                    return send_message(self.secret_key, str(e).encode())
                
            elif action == "DELETE FILE":
                try:
                    delete_file_server(metadados_originais, self.pseudonym)
                    escrever_ficheiro_logs(f"Foi apagado o ficheiro '{metadados_originais.get("file_id")}' pelo cliente '{self.pseudonym}'")
                    return send_message(self.secret_key, "Concluído".encode())
                except Exception as e:
                    escrever_ficheiro_logs(str(e))
                    return send_message(self.secret_key, str(e).encode())
            
            elif action == "ASK K FILE":
                try:
                    msg = ask_k_file_server(metadados_originais, self.pseudonym)
                    escrever_ficheiro_logs(f"Foi enviada a chave encriptada do ficheiro '{metadados_originais.get("file_id")}' ao cliente '{self.pseudonym}'")
                    return send_message(self.secret_key, msg)
                except Exception as e:
                    escrever_ficheiro_logs(str(e))
                    return send_message(self.secret_key, str(e).encode()) 
                
            elif action == "ASK REPLACE":
                try:
                    replace_file_server(metadados_originais, bundle, self.pseudonym)
                    escrever_ficheiro_logs(f"O ficheiro '{metadados_originais.get("file_id")}' foi substituído pelo cliente '{self.pseudonym}'")
                    return send_message(self.secret_key, "Concluído".encode())
                except Exception as e:
                    escrever_ficheiro_logs(str(e))
                    return send_message(self.secret_key, str(e).encode())
            
            elif action == "GET DETAILS":
                try:
                    details_list = get_details_server(metadados_originais, self.pseudonym)
                    escrever_ficheiro_logs(f"Foram enviados ao '{self.pseudonym} os detalhes do ficheiro '{metadados_originais.get("file_id")}'.")
                    return send_message(self.secret_key, details_list)
                except Exception as e:
                    escrever_ficheiro_logs(str(e))
                    return send_message(self.secret_key, str(e).encode())
                
            elif action == "REVOKE PERMISSIONS":
                try:
                    revoke_permissions_server(metadados_originais, self.pseudonym)
                    escrever_ficheiro_logs(f"As permissões do utilizador '{metadados_originais.get("user_id")}' sobre o ficheiro '{metadados_originais.get("file_id")}' foram revogadas pelo cliente '{self.pseudonym}'")
                    return send_message(self.secret_key, "Concluído".encode())
                except Exception as e:
                    escrever_ficheiro_logs(str(e))
                    return send_message(self.secret_key, str(e).encode())
            
            elif action == "READ FILE":
                try:
                    file = read_file_server(metadados_originais, self.pseudonym)
                    escrever_ficheiro_logs(f"Foi enviado ao '{self.pseudonym} o ficheiro '{metadados_originais.get("file_id")}' e a respetiva chave encriptada.")
                    return send_message(self.secret_key, file)
                except Exception as e:
                    escrever_ficheiro_logs(str(e))
                    return send_message(self.secret_key, str(e).encode())


async def handle_echo(reader, writer, private_key, certificado_server):
    global conn_cnt
    conn_cnt += 1
    addr = writer.get_extra_info('peername')
    srvwrk = ServerWorker(conn_cnt, addr, private_key=private_key, certificado_server=certificado_server)
    try:
        data = await reader.read(max_msg_size)
        while True:
            if not data: break
            if data[:1] == b'\n': break
            data = srvwrk.process(data)
            if not data: break
            writer.write(data)
            await writer.drain()
            data = await reader.read(max_msg_size)
    finally:
        # remover pseudonym
        if hasattr(srvwrk, "pseudonym") and srvwrk.pseudonym:
            escrever_ficheiro_logs(f"O cliente '{srvwrk.pseudonym}' desconectou-se")
            active_pseudonyms.pop(srvwrk.pseudonym, None)
            save_active(active_pseudonyms)
        writer.close()



async def monitor_exit(loop, server):
    while True:
        cmd = await asyncio.get_event_loop().run_in_executor(None, input, "")
        if cmd.strip().lower() == "exit":
            print("\nA terminar servidor e a eliminar ficheiros...")

            # Apagar ficheiros JSON, ficheiro logs.txt e ficheiros encriptados
            pastas = ["../JSONS_Server", "../file_test", ""]
            for pasta in pastas:
                for extensao in ("*.json", "logs.txt", "*.enc"):
                    for ficheiro in glob.glob(os.path.join(pasta, extensao)):
                        try:
                            os.remove(ficheiro)
                        except Exception as e:
                            print(f"Erro ao apagar {ficheiro}: {e}")

            server.close()
            await server.wait_closed()
            loop.stop()
            break



def run_server():
    if len(sys.argv) != 2:
        print("Uso: python3 Server.py <ficheiro.p12>")
        sys.exit(1)
    caminho = "../JSONS_Server"
    os.makedirs(caminho, exist_ok=True)
    p12_path = sys.argv[1]
    private_key, certificado_server, _ = get_userdata(p12_path)
    loop = asyncio.get_event_loop()
    try:
        handler = partial(handle_echo, private_key=private_key, certificado_server=certificado_server)
        coro = asyncio.start_server(handler, '127.0.0.1', conn_port)
        server = loop.run_until_complete(coro)

        asyncio.ensure_future(monitor_exit(loop, server))

    except OSError as e:
        print(f"Erro: já existe outro servidor em execução")
        sys.exit(1)

    print('Serving on {}'.format(server.sockets[0].getsockname()))
    print('  (escreva "exit" para terminar)\n')
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        loop.run_until_complete(server.wait_closed())
        loop.close()
        print('\nServidor terminado.')

run_server()