
import csv
import sys

def limpar_csv(entrada, prefixo):
    arquivos = {}
    ignorados = 0

    with open(entrada, "r", encoding="utf-8-sig", newline="") as arquivo:
        leitor = csv.reader(arquivo)

        cabecalho = next(leitor, None)

        if not cabecalho:
            print("Arquivo vazio!")
            return

        indice_tipo = cabecalho.index("TIPO")

        for linha in leitor:
            if len(linha) < 10:
                continue

            tipo = linha[indice_tipo].strip().lower()

            if not tipo:
                continue

            dados = linha[1:7]

            pergunta = dados[0]
            respostas = dados[1:5]

            # Limites de caracteres
            if len(pergunta) > 80 or any(len(r) > 30 for r in respostas):
                ignorados += 1
                continue

            nome_arquivo = f"{prefixo}_{tipo}.txt"

            if tipo not in arquivos:
                arquivos[tipo] = open(
                    nome_arquivo,
                    "w",
                    encoding="utf-8"
                )

            # Grava sem cabeçalho e sem aspas
            arquivos[tipo].write("|".join(dados) + "\n")

    for arquivo in arquivos.values():
        arquivo.close()

    print("\nArquivos gerados:")

    for tipo in sorted(arquivos):
        print(f"{prefixo}_{tipo}.txt")

    print(f"\nRegistros ignorados: {ignorados}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python limpar.py entrada.csv nome_saida")
        sys.exit(1)

    limpar_csv(sys.argv[1], sys.argv[2])

