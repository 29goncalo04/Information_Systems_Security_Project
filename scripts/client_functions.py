import base64, os
from bson import BSON
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from utils import *
from ficheiro import *



def receive_message(secret_key, msg):
    nonce, ciphertext = unpair(msg)
    chacha = ChaCha20Poly1305(secret_key)
    msg_decrypted = chacha.decrypt(nonce, ciphertext, None)
    return msg_decrypted



def add_file_personal_vault(file_path, secret_key, public_key):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"O ficheiro '{file_path}' não existe.")
    file = ler_ficheiro(file_path)    # Ex.: ../file_test/file_test1.txt 

    pasta, nome_ficheiro = os.path.split(file_path)
    nome, extensao = os.path.splitext(nome_ficheiro)
    novo_nome = f"{nome}{extensao}.enc"
    novo_path = os.path.join(pasta, novo_nome)

    k_file = ChaCha20Poly1305.generate_key()
    nonce_file = os.urandom(12)
    aead_file = ChaCha20Poly1305(k_file)
    ciphertext_file = aead_file.encrypt(nonce_file, file, None)
    text = mkpair(nonce_file, ciphertext_file)  # ficheiro encriptado
    escrever_ficheiro(novo_path, text)

    encrypted_k_file = public_key.encrypt(  # encripta a k_file com a pública do destinatário
        k_file,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypted_k_file_base64 = base64.b64encode(encrypted_k_file).decode('utf-8')

    bundle = mkpair(novo_path.encode(), encrypted_k_file_base64.encode())

    metadados = {
        "action": "ADD",
        "file_name": nome
    }
    metadados_serializados = BSON.encode(metadados)
    payload = mkpair(bundle, metadados_serializados)
    nonce_chan = os.urandom(12)
    aead_chan = ChaCha20Poly1305(secret_key)
    ciphertext_msg = aead_chan.encrypt(nonce_chan, payload, None)
    encrypted_msg = mkpair(nonce_chan, ciphertext_msg)
    return encrypted_msg



def create_group(group_name, secret_key):
    metadados = {
        "action": "CREATE GROUP",
        "group_name": group_name
    }
    metadados_serializados = BSON.encode(metadados)
    payload = mkpair(b"", metadados_serializados)
    nonce_chan = os.urandom(12)
    aead_chan = ChaCha20Poly1305(secret_key)
    ciphertext_msg = aead_chan.encrypt(nonce_chan, payload, None)
    encrypted_msg = mkpair(nonce_chan, ciphertext_msg)
    return encrypted_msg



def get_certificates_clients(group_id, secret_key):
    metadados = {
        "action": "GET CERTIFICATES",
        "group_id": group_id
    }
    metadados_serializados = BSON.encode(metadados)
    payload = mkpair(b"", metadados_serializados)
    nonce_chan = os.urandom(12)
    aead_chan = ChaCha20Poly1305(secret_key)
    ciphertext_msg = aead_chan.encrypt(nonce_chan, payload, None)
    encrypted_msg = mkpair(nonce_chan, ciphertext_msg)
    return encrypted_msg



def add_file_group_vault (group_id, file_path, secret_key, public_keys):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"O ficheiro '{file_path}' não existe.")
    file = ler_ficheiro(file_path)    # Ex.: ../file_test/file_test1.txt 

    pasta, nome_ficheiro = os.path.split(file_path)
    nome, extensao = os.path.splitext(nome_ficheiro)
    novo_nome = f"{nome}{extensao}.enc"
    novo_path = os.path.join(pasta, novo_nome)

    k_file = ChaCha20Poly1305.generate_key()
    nonce_file = os.urandom(12)
    aead_file = ChaCha20Poly1305(k_file)
    ciphertext_file = aead_file.encrypt(nonce_file, file, None)
    text = mkpair(nonce_file, ciphertext_file)  # ficheiro encriptado
    escrever_ficheiro(novo_path, text)
    
    encrypted_k_files = []
    for pk in public_keys:
        encrypted_k_file = pk.encrypt(  # encripta a k_file com a pública do destinatário
            k_file,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_k_file_base64 = base64.b64encode(encrypted_k_file)
        encrypted_k_files.append(encrypted_k_file_base64)

    k_files_serializadas = BSON.encode({"encrypted_k_files": encrypted_k_files})

    bundle = mkpair(novo_path.encode(), k_files_serializadas)

    pasta, nome_ficheiro = os.path.split(file_path)
    nome, _ = os.path.splitext(nome_ficheiro)
    metadados = {
        "action": "GROUP ADD",
        "group_id": group_id,
        "file_name": nome
    }

    metadados_serializados = BSON.encode(metadados)
    payload = mkpair(bundle, metadados_serializados)
    nonce_chan = os.urandom(12)
    aead_chan = ChaCha20Poly1305(secret_key)
    ciphertext_msg = aead_chan.encrypt(nonce_chan, payload, None)
    encrypted_msg = mkpair(nonce_chan, ciphertext_msg)
    return encrypted_msg



def get_certificate_client_add_user(group_id, user_id, secret_key):
    metadados = {
        "action": "GET CERTIFICATE ADD USER",
        "group_id": group_id,
        "user_id": user_id
    }
    metadados_serializados = BSON.encode(metadados)
    payload = mkpair(b"", metadados_serializados)
    nonce_chan = os.urandom(12)
    aead_chan = ChaCha20Poly1305(secret_key)
    ciphertext_msg = aead_chan.encrypt(nonce_chan, payload, None)
    encrypted_msg = mkpair(nonce_chan, ciphertext_msg)
    return encrypted_msg



def add_user_group(group_id, user_id, permissions, secret_key, public_key, k_files):
    encrypted_k_files = []
    for k_file in k_files:
        encrypted_k_file = public_key.encrypt(  # encripta a k_file com a pública do destinatário
            k_file,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_k_file_base64 = base64.b64encode(encrypted_k_file)
        encrypted_k_files.append(encrypted_k_file_base64)

    k_files_serializadas = BSON.encode({"encrypted_k_files": encrypted_k_files})

    bundle = mkpair(b"", k_files_serializadas)

    metadados = {
        "action": "GROUP ADD-USER",
        "group_id": group_id,
        "user_id": user_id,
        "permissions": permissions
    }

    metadados_serializados = BSON.encode(metadados)
    payload = mkpair(bundle, metadados_serializados)
    nonce_chan = os.urandom(12)
    aead_chan = ChaCha20Poly1305(secret_key)
    ciphertext_msg = aead_chan.encrypt(nonce_chan, payload, None)
    encrypted_msg = mkpair(nonce_chan, ciphertext_msg)
    return encrypted_msg



def delete_group(group_id, secret_key):
    metadados = {
        "action": "DELETE GROUP",
        "group_id": group_id
    }
    metadados_serializados = BSON.encode(metadados)
    payload = mkpair(b"", metadados_serializados)
    nonce_chan = os.urandom(12)
    aead_chan = ChaCha20Poly1305(secret_key)
    ciphertext_msg = aead_chan.encrypt(nonce_chan, payload, None)
    encrypted_msg = mkpair(nonce_chan, ciphertext_msg)
    return encrypted_msg



def remove_user_group(group_id, user_id, secret_key):
    metadados = {
        "action": "REMOVE USER GROUP",
        "group_id": group_id,
        "user_id": user_id
    }
    metadados_serializados = BSON.encode(metadados)
    payload = mkpair(b"", metadados_serializados)
    nonce_chan = os.urandom(12)
    aead_chan = ChaCha20Poly1305(secret_key)
    ciphertext_msg = aead_chan.encrypt(nonce_chan, payload, None)
    encrypted_msg = mkpair(nonce_chan, ciphertext_msg)
    return encrypted_msg



def get_group_list(secret_key):
    metadados = {
        "action": "GROUP LIST"
    }
    metadados_serializados = BSON.encode(metadados)
    payload = mkpair(b"", metadados_serializados)
    nonce_chan = os.urandom(12)
    aead_chan = ChaCha20Poly1305(secret_key)
    ciphertext_msg = aead_chan.encrypt(nonce_chan, payload, None)
    encrypted_msg = mkpair(nonce_chan, ciphertext_msg)
    return encrypted_msg



def list_files_user(user_id, secret_key):
    metadados = {
        "action": "LIST FILES USER",
        "user_id": user_id
    }
    metadados_serializados = BSON.encode(metadados)
    payload = mkpair(b"", metadados_serializados)
    nonce_chan = os.urandom(12)
    aead_chan = ChaCha20Poly1305(secret_key)
    ciphertext_msg = aead_chan.encrypt(nonce_chan, payload, None)
    encrypted_msg = mkpair(nonce_chan, ciphertext_msg)
    return encrypted_msg



def list_files_group(group_id, secret_key):
    metadados = {
        "action": "LIST FILES GROUP",
        "group_id": group_id
    }
    metadados_serializados = BSON.encode(metadados)
    payload = mkpair(b"", metadados_serializados)
    nonce_chan = os.urandom(12)
    aead_chan = ChaCha20Poly1305(secret_key)
    ciphertext_msg = aead_chan.encrypt(nonce_chan, payload, None)
    encrypted_msg = mkpair(nonce_chan, ciphertext_msg)
    return encrypted_msg



def get_certificate_client(file_id, user_id, secret_key):
    metadados = {
        "action": "GET CERTIFICATE",
        "file_id": file_id,
        "user_id": user_id
    }
    metadados_serializados = BSON.encode(metadados)
    payload = mkpair(b"", metadados_serializados)
    nonce_chan = os.urandom(12)
    aead_chan = ChaCha20Poly1305(secret_key)
    ciphertext_msg = aead_chan.encrypt(nonce_chan, payload, None)
    encrypted_msg = mkpair(nonce_chan, ciphertext_msg)
    return encrypted_msg



def share_file(file_id, user_id, permissions, secret_key, public_key, k_file):
    encrypted_k_file = public_key.encrypt(  # encripta a k_file com a pública do destinatário
        k_file,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypted_k_file_base64 = base64.b64encode(encrypted_k_file)

    bundle = mkpair(b"", encrypted_k_file_base64)

    metadados = {
        "action": "SHARE FILE",
        "file_id": file_id,
        "user_id": user_id,
        "permissions": permissions
    }

    metadados_serializados = BSON.encode(metadados)
    payload = mkpair(bundle, metadados_serializados)
    nonce_chan = os.urandom(12)
    aead_chan = ChaCha20Poly1305(secret_key)
    ciphertext_msg = aead_chan.encrypt(nonce_chan, payload, None)
    encrypted_msg = mkpair(nonce_chan, ciphertext_msg)
    return encrypted_msg



def delete_file(file_id, secret_key):
    metadados = {
        "action": "DELETE FILE",
        "file_id": file_id
    }
    metadados_serializados = BSON.encode(metadados)
    payload = mkpair(b"", metadados_serializados)
    nonce_chan = os.urandom(12)
    aead_chan = ChaCha20Poly1305(secret_key)
    ciphertext_msg = aead_chan.encrypt(nonce_chan, payload, None)
    encrypted_msg = mkpair(nonce_chan, ciphertext_msg)
    return encrypted_msg



def can_add_personal(file_path, secret_key):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"O ficheiro '{file_path}' não existe.")
    pasta, nome_ficheiro = os.path.split(file_path)
    nome, extensao = os.path.splitext(nome_ficheiro)
    novo_nome = f"{nome}{extensao}.enc"
    novo_path = os.path.join(pasta, novo_nome)
    metadados = {
        "action": "CAN ADD PERSONAL",
        "file_path": novo_path,
        "file_name": nome
    }
    metadados_serializados = BSON.encode(metadados)
    payload = mkpair(b"", metadados_serializados)
    nonce_chan = os.urandom(12)
    aead_chan = ChaCha20Poly1305(secret_key)
    ciphertext_msg = aead_chan.encrypt(nonce_chan, payload, None)
    encrypted_msg = mkpair(nonce_chan, ciphertext_msg)
    return encrypted_msg



def can_add_group(group_id, file_path, secret_key):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"O ficheiro '{file_path}' não existe.")
    pasta, nome_ficheiro = os.path.split(file_path)
    nome, extensao = os.path.splitext(nome_ficheiro)
    novo_nome = f"{nome}{extensao}.enc"
    novo_path = os.path.join(pasta, novo_nome)
    metadados = {
        "action": "CAN ADD GROUP",
        "file_path": novo_path,
        "file_name": nome,
        "grupo": group_id
    }
    metadados_serializados = BSON.encode(metadados)
    payload = mkpair(b"", metadados_serializados)
    nonce_chan = os.urandom(12)
    aead_chan = ChaCha20Poly1305(secret_key)
    ciphertext_msg = aead_chan.encrypt(nonce_chan, payload, None)
    encrypted_msg = mkpair(nonce_chan, ciphertext_msg)
    return encrypted_msg



def ask_k_file(file_id, file_path, secret_key):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"O ficheiro '{file_path}' não existe.")
    pasta, nome_ficheiro = os.path.split(file_path)
    nome, extensao = os.path.splitext(nome_ficheiro)
    novo_nome = f"{nome}{extensao}.enc"
    novo_path = os.path.join(pasta, novo_nome)
    metadados = {
        "action": "ASK K FILE",
        "file_id": file_id,
        "file_path": novo_path
    }
    metadados_serializados = BSON.encode(metadados)
    payload = mkpair(b"", metadados_serializados)
    nonce_chan = os.urandom(12)
    aead_chan = ChaCha20Poly1305(secret_key)
    ciphertext_msg = aead_chan.encrypt(nonce_chan, payload, None)
    encrypted_msg = mkpair(nonce_chan, ciphertext_msg)
    return encrypted_msg    



def ask_replace(file_id, file_path, k_file, secret_key):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"O ficheiro '{file_path}' não existe.")
    file = ler_ficheiro(file_path)    # Ex.: ../file_test/file_test1.txt 

    pasta, nome_ficheiro = os.path.split(file_path)
    nome, extensao = os.path.splitext(nome_ficheiro)
    novo_nome = f"{nome}{extensao}.enc"
    novo_path = os.path.join(pasta, novo_nome)

    nonce_file = os.urandom(12)
    aead_file = ChaCha20Poly1305(k_file)
    ciphertext_file = aead_file.encrypt(nonce_file, file, None)
    text = mkpair(nonce_file, ciphertext_file)  # ficheiro encriptado
    escrever_ficheiro(novo_path, text)


    bundle = mkpair(novo_path.encode(), b"")

    metadados = {
        "action": "ASK REPLACE",
        "file_id": file_id
    }
    metadados_serializados = BSON.encode(metadados)
    payload = mkpair(bundle, metadados_serializados)
    nonce_chan = os.urandom(12)
    aead_chan = ChaCha20Poly1305(secret_key)
    ciphertext_msg = aead_chan.encrypt(nonce_chan, payload, None)
    encrypted_msg = mkpair(nonce_chan, ciphertext_msg)
    return encrypted_msg



def get_details(file_id, secret_key):
    metadados = {
        "action": "GET DETAILS",
        "file_id": file_id
    }
    metadados_serializados = BSON.encode(metadados)
    payload = mkpair(b"", metadados_serializados)
    nonce_chan = os.urandom(12)
    aead_chan = ChaCha20Poly1305(secret_key)
    ciphertext_msg = aead_chan.encrypt(nonce_chan, payload, None)
    encrypted_msg = mkpair(nonce_chan, ciphertext_msg)
    return encrypted_msg



def revoke_permissions(file_id, user_id, secret_key):
    metadados = {
        "action": "REVOKE PERMISSIONS",
        "file_id": file_id,
        "user_id": user_id
    }
    metadados_serializados = BSON.encode(metadados)
    payload = mkpair(b"", metadados_serializados)
    nonce_chan = os.urandom(12)
    aead_chan = ChaCha20Poly1305(secret_key)
    ciphertext_msg = aead_chan.encrypt(nonce_chan, payload, None)
    encrypted_msg = mkpair(nonce_chan, ciphertext_msg)
    return encrypted_msg



def read_file(file_id, secret_key):
    metadados = {
        "action": "READ FILE",
        "file_id": file_id
    }
    metadados_serializados = BSON.encode(metadados)
    payload = mkpair(b"", metadados_serializados)
    nonce_chan = os.urandom(12)
    aead_chan = ChaCha20Poly1305(secret_key)
    ciphertext_msg = aead_chan.encrypt(nonce_chan, payload, None)
    encrypted_msg = mkpair(nonce_chan, ciphertext_msg)
    return encrypted_msg