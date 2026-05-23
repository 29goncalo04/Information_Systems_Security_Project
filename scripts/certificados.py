from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization
import datetime



def get_userdata(p12_fname):
    with open(f"../projCA/{p12_fname}", "rb") as f:
        p12 = f.read()
    password = None
    (private_key, user_cert, [ca_cert]) = pkcs12.load_key_and_certificates(p12, password)
    return (private_key, user_cert, ca_cert)



def cert_load(fname):
    """lê certificado de ficheiro"""
    with open(fname, "rb") as fcert:
        cert = x509.load_pem_x509_certificate(fcert.read())
    return cert



def extract_public_key(cert):
    """Extrai a chave pública de um certificado X.509"""
    return x509.load_pem_x509_certificate(cert).public_key()



def extract_pseudonym(cert):
    return x509.load_pem_x509_certificate(cert).subject.get_attributes_for_oid(x509.ObjectIdentifier("2.5.4.65"))[0].value



def cert_validtime(cert, now=None):
    """valida que 'now' se encontra no período
    de validade do certificado."""
    if now is None:
        now = datetime.datetime.now(tz=datetime.timezone.utc)
    if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
        raise x509.verification.VerificationError(
            "Certificate is not valid at this time"
        )



def cert_validsubject(cert, attrs=[]):
    """verifica atributos do campo 'subject'. 'attrs'
    é uma lista de pares '(attr,value)' que condiciona
    os valores de 'attr' a 'value'."""
    for attr in attrs:
        if cert.subject.get_attributes_for_oid(attr[0])[0].value != attr[1]:
            raise x509.verification.VerificationError(
                "Certificate subject does not match expected value"
            )



def valida_certificado(elemCRT, isServer):
    try:
        ca_cert = cert_load("../projCA/VAULT_CA.crt")
        cert_validsubject(ca_cert, [(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, "SSI VAULT SERVICE"),
                                    (x509.ObjectIdentifier("2.5.4.65"), "VAULT_CA")
                                    ])
        elemCRT = x509.load_pem_x509_certificate(elemCRT)
        elemCRT.verify_directly_issued_by(ca_cert)
        # verificar período de validade
        cert_validtime(elemCRT)
        # verificar identidade
        if isServer:
            cert_validsubject(elemCRT, [(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, "SSI VAULT SERVICE"),
                                    (x509.ObjectIdentifier("2.5.4.65"), "VAULT_SERVER")
                                    ])
        else:
            valor = elemCRT.subject.get_attributes_for_oid(x509.ObjectIdentifier("2.5.4.65"))[0].value
            if not (valor.startswith("VAULT_CLI") and valor[9:].isdigit()):
                raise x509.verification.VerificationError()
            cert_validsubject(elemCRT, [(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, "SSI VAULT SERVICE"),
                                    ])
        return True
    except Exception as e:
        return False