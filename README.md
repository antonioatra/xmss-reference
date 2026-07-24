# Delta-XMSS: Incremental State Optimization for Post-Quantum Hash-Based Signatures

Este repositório contém o artefato do artigo **"Delta-XMSS: Incremental State Optimization for Post-Quantum Hash-Based Signatures"**, aceito no XXVI Simpósio Brasileiro de Cibersegurança (SBSeg 2026).

**Resumo do artigo:** O XMSS (eXtended Merkle Signature Scheme) é um esquema de assinatura digital pós-quântica baseado em hash, padronizado na RFC 8391 e recomendado no NIST SP 800-208. Cada assinatura XMSS transmite um caminho de autenticação completo da folha até a raiz da árvore de Merkle. Este trabalho observa que caminhos de autenticação de folhas consecutivas compartilham a maioria de seus nós e propõe o **Delta-XMSS**, uma técnica de *delta encoding* que transmite apenas os nós que diferem entre assinaturas consecutivas. Os algoritmos DeltaEncode e DeltaDecode são apresentados com prova de correção, e a avaliação experimental demonstra redução de até 90% no tamanho do caminho de autenticação transmitido, com overhead computacional inferior a 80 ciclos de CPU — desprezível frente à mediana de 5.711.700 ciclos da operação de assinatura.

**Artefato:** implementação em C (C99) do Delta-XMSS como extensão da implementação de referência do XMSS (RFC 8391), acompanhada de benchmark que mede bytes transmitidos, tempo de codificação/decodificação e ciclos de CPU, com verificação de corretude da reconstrução dos caminhos. Este repositório é um fork da [implementação de referência do XMSS](https://github.com/XMSS/xmss-reference), de Andreas Hülsing e Joost Rijneveld.

# Estrutura do readme.md

Este readme.md está organizado da seguinte forma:

- **Selos Considerados:** selos solicitados ao Comitê Técnico de Artefatos;
- **Informações básicas:** ambiente de execução, requisitos de hardware e software;
- **Dependências:** bibliotecas e versões necessárias;
- **Preocupações com segurança:** riscos ao executar o artefato;
- **Instalação:** passo a passo para obter e compilar o artefato;
- **Teste mínimo:** execução rápida para verificar o funcionamento;
- **Experimentos:** reprodução das principais reivindicações do artigo;
- **LICENSE:** licença do artefato.

O repositório está organizado da seguinte forma:

| Arquivo/Diretório | Descrição |
|---|---|
| `delta_xmss.h` | API do Delta-XMSS — `delta_encode`, `delta_decode`, `delta_nu` e funções auxiliares |
| `delta_xmss.c` | Implementação dos algoritmos DeltaEncode e DeltaDecode (Algoritmos 1 e 2 do artigo) |
| `test/delta.c` | Benchmark: bytes transmitidos, tempo de encode/decode (µs), ciclos de CPU e verificação de corretude |
| `xmss*.c`, `wots.c`, `hash*.c`, `fips202.c`, `params.c`, `utils.c`, `randombytes.c` | Implementação de referência do XMSS (RFC 8391), de Hülsing e Rijneveld |
| `Makefile` | Alvos de compilação |
| `LICENSE` | Licença CC0 1.0 |

# Selos Considerados

Os selos considerados são: **Artefatos Disponíveis (SeloD)**, **Artefatos Funcionais (SeloF)**, **Artefatos Sustentáveis (SeloS)** e **Experimentos Reprodutíveis (SeloR)**.

# Informações básicas

O artefato foi desenvolvido e avaliado no seguinte ambiente:

- **Sistema operacional:** Ubuntu 22.04 LTS (executado sobre WSL2, arquitetura x86-64); qualquer distribuição Linux x86-64 recente é adequada;
- **Compilador:** GCC 13.3;
- **Hardware:** os experimentos do artigo foram executados em um Intel Core i5-12500H; qualquer máquina x86-64 de propósito geral é adequada, sem requisitos especiais.
- **Recursos estimados:** < 1 GB de RAM e < 100 MB de disco;
- **Tempo estimado:** compilação em segundos; execução completa do benchmark (`./test/delta 32`) em torno de um minuto, dominada pela geração do par de chaves.

Não é necessária infraestrutura de nuvem, acesso à rede durante a execução, nem privilégios de administrador (exceto para instalar dependências via gerenciador de pacotes). **Atenção:** o benchmark utiliza a instrução RDTSC para contagem de ciclos de CPU, portanto requer arquitetura x86-64 (nativa ou emulada).

# Dependências

- **OpenSSL** (headers de desenvolvimento, pacote `libssl-dev` em sistemas Debian/Ubuntu) — utilizado para as funções de hash SHA-2. Versão de referência: 3.0.2 (`libssl-dev 3.0.2-0ubuntu1.25`, Ubuntu 22.04); outras versões da série 3.x também funcionam;
- **GCC** ≥ 13 (versões anteriores com suporte a C99 também devem funcionar);
- **make** (opcional, caso utilize o Makefile).

Não há benchmarks de terceiros nem recursos externos: todos os dados dos experimentos são gerados pelo próprio artefato.

# Preocupações com segurança

A execução do artefato **não oferece riscos** aos avaliadores. O código executa localmente, não requer privilégios elevados, não realiza acesso à rede, não persiste dados fora do diretório do projeto e não interage com chaves criptográficas reais — todas as chaves são geradas em memória exclusivamente para fins de benchmark.

# Instalação

Tempo esperado: cerca de 2 minutos.

1. Instale as dependências (Debian/Ubuntu):

```bash
sudo apt update && sudo apt install -y build-essential libssl-dev git
```

2. Clone o repositório:

```bash
git clone https://github.com/antonioatra/xmss-reference.git
cd xmss-reference
```

3. Compile o benchmark do Delta-XMSS:

```bash
gcc -Wall -g -O3 -I. \
    -o test/delta \
    params.c hash.c fips202.c hash_address.c randombytes.c \
    wots.c xmss.c xmss_core.c xmss_commons.c utils.c \
    delta_xmss.c test/delta.c \
    -lcrypto
```

Ao final deste processo, o executável `test/delta` estará disponível e pronto para uso.

# Teste mínimo

Execute o benchmark com uma sequência curta de assinaturas consecutivas:

```bash
./test/delta 4
```

O programa gera uma árvore XMSS com altura h' = 10, assina 4 índices consecutivos e, para cada transição de índice, exibe: o número de nós transmitidos pelo Delta-XMSS versus o caminho completo, os bytes correspondentes, o tempo de encode/decode e o resultado da verificação de corretude (comparação do caminho reconstruído pelo DeltaDecode com o caminho original).

**Saída esperada:** o cabeçalho identifica a variante (`XMSS-SHA2_10_256`, h' = 10, caminho completo de 320 bytes) e, após a geração do par de chaves, uma tabela por transição de índice no formato:

```
idx    nu   XMSS(B)    Delta(B)   Enc(us)  Dec(us)  EncCycles  DecCycles  Match
------ ---- ---------- ---------- -------- -------- ---------- ---------- ------
0      0    320        32         0.0053   0.0112   5          11         PASS
1      1    320        64         0.0059   0.0108   5          10         PASS
2      0    320        32         0.0038   0.0086   3          8          PASS
```

Todas as linhas devem exibir `PASS` na coluna `Match`, e a execução deve terminar com `Errors : 0` e a mensagem `All checks PASSED.` Tempo de execução: segundos.

# Experimentos

As três principais reivindicações do artigo podem ser reproduzidas com uma única execução do benchmark com uma sequência mais longa:

```bash
./test/delta 32
```

Este comando assina 32 índices consecutivos (h' = 10, SHA-256) e reporta as métricas de cada reivindicação. Tempo esperado: em torno de um minuto. Recursos: < 1 GB RAM. Para testar outros comprimentos de sequência, ajuste o argumento.

## Reivindicação #1: Redução do tamanho de transmissão do caminho de autenticação

O artigo reivindica que o Delta-XMSS reduz significativamente os bytes transmitidos por assinatura, com redução de até 90% nos melhores casos. Em metade dos índices (ν = 0), apenas um nó do caminho difere do anterior.

**Como reproduzir:** na saída de `./test/delta 32`, compare as colunas `XMSS(B)` (320 bytes do caminho completo padrão) e `Delta(B)` (bytes efetivamente transmitidos pelo Delta-XMSS) em cada transição; o campo `Reduction` da seção `=== Summary ===` reporta a redução agregada. Os bytes transmitidos por transição seguem 32·(ν(idx) + 1), contra 320 bytes fixos do caminho completo (h' = 10, n = 32).

**Resultado esperado:** redução agregada de **81,6%** sobre a sequência de 32 assinaturas (31 transições: 1.824 bytes transmitidos contra 9.920 bytes do XMSS padrão), atingindo **90%** (32 B contra 320 B) nas transições com ν = 0, que correspondem a metade dos índices.

## Reivindicação #2: Overhead computacional desprezível

O artigo reivindica que o custo de DeltaEncode/DeltaDecode é inferior a 80 ciclos de CPU, contra uma mediana de 5.711.700 ciclos da operação de assinatura XMSS.

**Como reproduzir:** na saída de `./test/delta 32`, observe as colunas `EncCycles` e `DecCycles` por transição e as médias `Avg encode` / `Avg decode` na seção `=== Summary ===`. A mediana de ciclos da operação de assinatura XMSS completa (5.711.700 ciclos no Intel i5-12500H) é reportada no artigo.

**Resultado esperado:** ciclos de encode/decode consistentemente abaixo de 80. Na execução de referência: médias de 5 ciclos (encode) e 9 ciclos (decode), com máximo de 17 ciclos na pior transição (ν = 4). Os valores absolutos variam com o hardware, mas a razão overhead/assinatura permanece na ordem de 10⁻⁵.

## Reivindicação #3: Corretude da reconstrução (DeltaDecode)

O artigo apresenta o Lema 1, provando por indução que o DeltaDecode reconstrói exatamente o caminho de autenticação original a partir do caminho anterior em cache e do delta recebido.

**Como reproduzir:** o benchmark verifica, a cada transição, se o caminho reconstruído é idêntico ao caminho gerado pela assinatura XMSS padrão.

**Resultado esperado:** 100% das verificações de corretude com sucesso, para qualquer comprimento de sequência testado.

# LICENSE

Este artefato é distribuído sob a licença **CC0 1.0 Universal Public Domain Dedication**, a mesma da implementação de referência do XMSS de Andreas Hülsing e Joost Rijneveld, da qual este repositório é derivado. Veja o arquivo [LICENSE](LICENSE).