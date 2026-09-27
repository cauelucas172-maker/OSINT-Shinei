# OSINT-Shinei

Framework de investigacao OSINT — validacao anti-falso-positivo, async total, cases persistentes, relatorios HTML profissionais.

## Por que diferente

A maioria dos tools de username enumeration retorna 30-60% de falsos positivos (plataformas respondem 200 ate pra perfil inexistente). O OSINT-Shinei valida CADA plataforma com dupla assinatura: string de perfil real + string de perfil inexistente. Resultado tem nivel de confianca 1-3 por achado.

## Features

- **Validacao anti-falso-positivo** — weight 1-3 por resultado
- **Async** — todas plataformas em paralelo
- **5 scrapers** — GitHub API, Reddit, Telegram, Chess, HackerNews
- **Email intelligence** — Gravatar, leak check, correlacao automatica
- **10 dorks gerados por email** — com links de busca prontos
- **Cases persistentes** — pause e retome investigacoes
- **Relatorio HTML** — dark theme, stats, confianca visivel

## Instalacao

    pkg install python -y
    pip install aiohttp requests

## Uso

    osint new -n caso1 -t username_aqui email:alvo@gmail.com
    osint run caso1
    osint show caso1
    osint note caso1 "conta confirmada manualmente"
    osint report caso1

## Exemplo de saida

    === FASE 1 - USERNAME: caulucas172-maker ===
      + GitHub        [3] https://api.github.com/users/caulucas172-maker
      ? Steam         resposta ambigua (verificar manual)
      x Chess.com
      ? HackerNews    resposta ambigua (verificar manual)

    [+] 1 achados, 1 confirmados

## Uso etico

Informacao PUBLICA apenas. Sem bypass, sem dados privados, sem acesso nao autorizado. Ferramenta de triagem — todo achado deve ser verificado manualmente antes de qualquer conclusao.

## Autor

shinei — construido durante estudos de OSINT e web security.
