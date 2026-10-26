"""Built-in subdomain wordlist and permutation engine (no external files needed)."""
from __future__ import annotations

COMMON = """
www mail webmail smtp smtp2 imap pop pop3 ftp sftp ssh vpn remote rdp citrix
gateway portal intranet extranet internal admin administrator manage management
console dashboard panel cpanel whm webdisk webmail roundcube squirrelmail
autodiscover autoconfig exchange owa outlook rpc ecp
api api1 api2 api3 api-v1 api-v2 api-v3 api-gw apigateway gateway rest graphql
app apps application web web1 web2 web3 static assets cdn media images img files
download downloads upload uploads docs doc documentation wiki help support
status statuspage monitor monitoring uptime health metrics grafana kibana
prometheus zabbix nagios icinga sensu
dev development develop staging stage stg test testing qa uat preprod preproduction
prod production live demo beta alpha preview sandbox lab labs experimental
old new legacy backup bak archive tmp temp
git gitlab github bitbucket gitea svn jenkins ci cd build builder drone argo
docker registry harbor k8s kubernetes kube helm rancher openshift
db database mysql mariadb postgres postgresql pgsql mssql sql oracle mongodb mongo
redis memcached elastic elasticsearch opensearch solr rabbitmq kafka zookeeper
ldap ad dc domaincontroller sso auth login id identity oauth accounts
s3 storage bucket minio nas nfs backup2
vpn1 vpn2 wireguard openvpn
proxy squid haproxy lb loadbalancer nginx apache webproxy
ns1 ns2 ns3 dns dns1 dns2 resolver
mx mx1 mx2 email mailer newsletter lists
shop store ecommerce cart checkout payment payments pay billing invoice
blog news press forum community crm erp hr finance accounting
mobile m wap ios android
client clients customer customers partner partners vendor
secure ssl tls pki ca ocsp crl
edge origin direct host server server1 server2 node1 node2
cloud aws azure gcp gcloud k8s1
jenkins2 jira confluence bamboo
sonar sonarqube nexus artifactory
sentry logs logging log elk splunk
smtp3 mail2 mail3
intra internal2
staging2 dev2 test2
api-dev api-staging api-test api-prod api-uat api-qa api-internal api-external
""".split()

ENVS = ["dev", "staging", "stage", "test", "uat", "qa", "prod", "demo", "old",
        "new", "backup", "internal", "external", "api", "admin", "beta", "v2", "v3"]


def default_wordlist() -> list[str]:
    return sorted(set(w.strip() for w in COMMON if w.strip()))


def permutations(hosts: list[str], domain: str, limit: int = 2500) -> list[str]:
    out: set[str] = set()
    for host in hosts:
        h = host.lower().rstrip(".")
        if not h.endswith("." + domain):
            continue
        sub = h[: -(len(domain) + 1)]
        if not sub or sub.count(".") > 1:
            continue
        out.add(f"{sub}1.{domain}")
        out.add(f"{sub}2.{domain}")
        out.add(f"{sub}-1.{domain}")
        out.add(f"{sub}-2.{domain}")
        for env in ENVS:
            out.add(f"{sub}-{env}.{domain}")
            out.add(f"{env}-{sub}.{domain}")
        if sub.startswith("api"):
            for suffix in ("gw", "gateway", "internal", "external", "v1", "v2", "v3",
                           "prod", "dev", "staging", "test"):
                out.add(f"api-{suffix}.{domain}")
        if "-" in sub:
            out.add(f"{sub.replace('-', '')}.{domain}")
            out.add(f"{sub.replace('-', '')}1.{domain}")
        if sub.isdigit():
            for n in range(1, 11):
                out.add(f"{sub}{n}.{domain}")
    return sorted(out)[:limit]


def load_wordlist(path: str | None) -> list[str]:
    if not path:
        return default_wordlist()
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return sorted({line.strip().lower() for line in fh
                           if line.strip() and not line.startswith("#")})
    except OSError:
        return default_wordlist()
