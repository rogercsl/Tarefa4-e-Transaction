# Róger Cassol, Henrique Schuch Batalha Boeira e Eduardo de Oliveira Amaro Reis Pinto

# Bibliotecas necessárias
# pip install pyopenssl
# urllib - Vem por padrão com Python

import os
import warnings
from OpenSSL import crypto
from urllib.request import urlopen
warnings.filterwarnings("ignore", category=DeprecationWarning)

def carregarChavesConfiaveis(pastaCAConfiaveis):
    chavesConfiaveis = {}
    for nomeArquivo in os.listdir(pastaCAConfiaveis):
        caminhoArquivo = os.path.join(pastaCAConfiaveis, nomeArquivo)
        if os.path.isfile(caminhoArquivo):
            try:
                with open(caminhoArquivo, "rb") as arquivoCertificado:
                    dadosCertificado = arquivoCertificado.read()
                    try:
                        certificado = crypto.load_certificate(crypto.FILETYPE_PEM, dadosCertificado)
                    except crypto.Error:
                        certificado = crypto.load_certificate(crypto.FILETYPE_ASN1, dadosCertificado)
                    chavesConfiaveis[nomeArquivo] = certificado.get_pubkey()
            except Exception as e:
                print(f"Falha ao carregar o certificado {nomeArquivo}: {e}")
    return chavesConfiaveis

def buscarCertificadoIntermediario(certificado):
    for i in range(certificado.get_extension_count()):
        extensao = certificado.get_extension(i)
        if extensao.get_short_name().decode() == "authorityInfoAccess":
            dadosAIA = extensao.__str__()
            for linha in dadosAIA.split('\n'):
                if "CA Issuers" in linha:
                    url = linha.split(' - ')[-1].strip().replace("URI:", "")
                    try:
                        resposta = urlopen(url)
                        dadosCertificado = resposta.read()
                        return crypto.load_certificate(crypto.FILETYPE_ASN1, dadosCertificado)
                    except Exception as e:
                        print(f"Erro ao obter o intermediário via AIA: {e}")
    return None

def construirCadeiaDeCertificacao(certificadoUsuario):
    cadeia = [certificadoUsuario]
    while True:
        certificadoIntermediario = buscarCertificadoIntermediario(cadeia[-1])
        if certificadoIntermediario is None:
            break
        cadeia.append(certificadoIntermediario)
    return cadeia

def verificarConfiabilidadeDoCertificado(cadeia, chavesConfiaveis):
    certificadoRaiz = cadeia[-1]
    chaveRaiz = certificadoRaiz.get_pubkey()
    for chaveConfiavel in chavesConfiaveis.values():
        if chaveRaiz.to_cryptography_key().public_numbers() == chaveConfiavel.to_cryptography_key().public_numbers():
            return True
    return False

def verificarCRL(certificado):
    for i in range(certificado.get_extension_count()):
        extensao = certificado.get_extension(i)
        if extensao.get_short_name().decode() == "crlDistributionPoints":
            dadosCRL = extensao.__str__()
            for linha in dadosCRL.split('\n'):
                if "URI:" in linha:
                    urlCRL = linha.split('URI:')[-1].strip()
                    try:
                        resposta = urlopen(urlCRL)
                        dadosCRL = resposta.read()
                        crl = crypto.load_crl(crypto.FILETYPE_ASN1, dadosCRL)
                        listaRevogados = crl.get_revoked()
                        if listaRevogados:
                            numeroSerie = "{:X}".format(certificado.get_serial_number())
                            for revogado in listaRevogados:
                                if revogado.get_serial().decode() == numeroSerie:
                                    print(f"Este certificado foi revogado.")
                                    return False
                        return True
                    except Exception as e:
                        print(f"Erro ao processar a CRL: {e}")
    return None

def formatarCertificado(certificado):
    sujeito = certificado.get_subject()
    return f"CN: {sujeito.CN}, O: {sujeito.O}" if sujeito.O else f"CN: {sujeito.CN}"

def main():
    caminhoCertificadoUsuario = input("Informe o caminho para o certificado a ser verificado (.crt ou .cer): ").strip()
    pastaCAConfiaveis = input("Informe o caminho da pasta com as ACs confiáveis: ").strip()

    try:
        with open(caminhoCertificadoUsuario, "rb") as arquivoCertificadoUsuario:
            dadosCertificadoUsuario = arquivoCertificadoUsuario.read()
            try:
                certificadoUsuario = crypto.load_certificate(crypto.FILETYPE_PEM, dadosCertificadoUsuario)
            except crypto.Error:
                certificadoUsuario = crypto.load_certificate(crypto.FILETYPE_ASN1, dadosCertificadoUsuario)
    except Exception as e:
        print(f"Erro ao carregar o certificado do usuário: {e}")
        return

    cadeia = construirCadeiaDeCertificacao(certificadoUsuario)
    print("\nCadeia de Certificação:")
    for indice, certificado in enumerate(reversed(cadeia)):
        sujeito = certificado.get_subject()
        print(f"{indice + 1}: CN: {sujeito.CN}, O: {sujeito.O if sujeito.O else ''}")

    print("\nVerificando se o certificado é confiável...")
    chavesConfiaveis = carregarChavesConfiaveis(pastaCAConfiaveis)
    if verificarConfiabilidadeDoCertificado(cadeia, chavesConfiaveis):
        print("\nCertificado foi validado com sucesso!")
        if verificarCRL(certificadoUsuario):
            print("O certificado está ativo e não foi revogado.")
        else:
            print("Este certificado foi revogado ou não é válido.")
    else:
        print("\nEste certificado NÃO é confiável!")

if __name__ == "__main__":
    main()