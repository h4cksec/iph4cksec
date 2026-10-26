# iph4cksec v2

Buscador de IP origen detrás de Cloudflare/CDN + inteligencia de superficie de ataque.
Sin API keys. Sin dependencias pagas.

## Instalación

```bash
cd iph4cksec
python3 -m pip install -r requirements.txt
```

## Uso directo

```bash
# una sola línea: fuentes pasivas + DNS + brute lógico + probes + verificación final
python3 iph4cksec.py ejemplo.com
```

Eso es equivalente a `python3 iph4cksec.py hunt ejemplo.com` con modo deep.
La herramienta hace todo el proceso y termina con el cartel de IP origen
y la verificación final (DNS, HTTP, certificado, body, SPF, rDNS).

## Uso con control

```bash
# descubrimiento (deep por defecto: todas las fuentes + AXFR + reverse-IP)
python3 iph4cksec.py hunt ejemplo.com

# rápido: solo fuentes pasivas veloces
python3 iph4cksec.py hunt ejemplo.com --fast

# fuerza bruta DNS con wordlist interna + permutaciones
python3 iph4cksec.py hunt ejemplo.com --brute

# wordlist propia
python3 iph4cksec.py hunt ejemplo.com --brute --wordlist /ruta/lista.txt

# reportes
python3 iph4cksec.py hunt ejemplo.com --json out.json --csv out.csv

# inteligencia IP / dominio
python3 iph4cksec.py intel 1.1.1.1
python3 iph4cksec.py intel ejemplo.com --json intel.json

# prefijos de un ASN (+ hostnames muestreados vía InternetDB)
python3 iph4cksec.py asn AS13335 --hosts --limit 20

# subdomain takeover
python3 iph4cksec.py takeover ejemplo.com
python3 iph4cksec.py takeover --file hosts.txt --json takeover.json
```

## Qué hace

**Passive sources (keyless):** crt.sh, Cert Spotter, HackerTarget, RapidDNS, AlienVault OTX,
urlscan.io, ThreatMiner, Wayback CDX, Common Crawl, DuckDuckGo, subdomain.center,
Mnemonic passive DNS, Anubis.

**DNS:** A/AAAA/MX/NS/TXT/SOA/CAA/DS, SPF recursivo (include/redirect/a/mx),
DKIM selectors, DMARC, MTA-STS, TLS-RPT, BIMI, DNSSEC, CNAME chains, wildcard detection,
AXFR contra cada NS autoritativo.

**Origin verification:** por cada IP candidata prueba Host header + SNI reales en 80/443
(y puertos altos en deep), y compara contra el baseline:

- similitud de texto (Jaccard) y shingles de 3 tokens
- título HTML
- favicon mmh3 (mismo hash = misma app)
- hashes de assets (script/link/img)
- cookies, meta generator, content-type, status
- certificado TLS (SHA-256 + SANs)
- ratio de longitud del body
- penalización por default page / respuesta de CDN / status mismatch

**Intel:** RDAP (IP/dominio), InternetDB (puertos, hostnames, CVEs), RIPEstat
(netblock/ASN/prefijos), Team Cymru DNS, geolocalización keyless, reverse DNS.

**Takeover:** ~40 fingerprints de servicios (GitHub Pages, Heroku, S3, Azure,
CloudFront, Fastly, Netlify, Vercel, Surge, Zendesk, Statuspage, Shopify, etc.)
sobre CNAMEs colgantes.

## Límites reales

- Si el origin solo acepta tráfico desde rangos de Cloudflare y no tiene ningún
  hostname/IP directo expuesto, **no hay forma de obtenerlo** desde fuera. La
  herramienta lo reporta como “no high-confidence origin”.
- Los IPs de CDN/anycast (Cloudflare, Vercel, Akamai, CloudFront, Fastly) se
  agrupan por provider+body hash para no listar 20 edges como 20 “origins”.
- Fuentes gratuitas caen, rate-limitean o devuelven HTML. Cada fuente falla en
  silencio y el resto continúa.
- El score es evidencia activa, no una garantía. 85+ = mismo contenido,
  favicon/cert/assets coherentes. 40-65 = revisar a mano.

## Estructura

```
iph4cksec.py             CLI
core/util.py             HTTP, logging, paralelismo, JSON/CSV
core/dnsx.py             DNS, SPF, email posture, AXFR, wildcard
core/sources.py          fuentes pasivas keyless
core/fingerprint.py      HTTP/TLS fingerprint + scoring
core/origin.py           candidatos, probes, verificación, clustering
core/intel.py            RDAP, InternetDB, RIPEstat, Cymru, geo
core/takeover.py         fingerprints de takeover
core/wordlist.py         wordlist + permutaciones
```
