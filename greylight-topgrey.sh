#!/bin/bash
# Muestra los remitentes que más caen en greylist (450) EXCLUYENDO lo ya permitido
# Requisitos: gawk, sqlite3
set -euo pipefail

LOGFILE=${1:-/var/log/maillog}   # también podés pasar /var/log/maillog.1, etc
DB=${DB:-/var/lib/greylight/greylight.sqlite}
TOP=${TOP:-30}

# Dump de DB a archivos temporales (una sola vez)
tmp_wlip=$(mktemp)
tmp_wlcidr=$(mktemp)
tmp_pass=$(mktemp)
cleanup() { rm -f "$tmp_wlip" "$tmp_wlcidr" "$tmp_pass"; }
trap cleanup EXIT

sqlite3 "$DB" "SELECT ip FROM wl_ip;" > "$tmp_wlip"
sqlite3 "$DB" "SELECT cidr FROM wl_cidr;" > "$tmp_wlcidr"
sqlite3 "$DB" "SELECT key FROM passlist;" > "$tmp_pass"

# Parseo del log y filtrado contra lo volcado de DB
grep "450 Greylisted" "$LOGFILE" | \
gawk -v TOP="$TOP" -v WLIP="$tmp_wlip" -v WLCIDR="$tmp_wlcidr" -v PASS="$tmp_pass" '
function ip2int(s,   a) {
  if (split(s,a,".")!=4) return -1
  return (((a[1]*256)+a[2])*256+a[3])*256+a[4]
}
function mkmask(n) {
  # 32-bit mask: 0xFFFFFFFF - (2^(32-n)-1)
  return 4294967295 - (2^(32-n) - 1)
}
function in_wl_ip(ip) { return (ip in wl_ip) }

function load_wl_ip(file,  l) {
  while ((getline l < file) > 0) if (l!="") wl_ip[l]=1
  close(file)
}
function load_pass(file,  l) {
  while ((getline l < file) > 0) if (l!="") pass[l]=1
  close(file)
}
function load_wl_cidr(file,  l, a, addr, bits, m) {
  # Precalcular redes y máscaras
  n_cidr=0
  while ((getline l < file) > 0) {
    if (l=="") continue
    split(l, a, "/")
    addr=a[1]; bits=a[2]+0
    if (bits<0 || bits>32) continue
    ipi = ip2int(addr); if (ipi<0) continue
    m = mkmask(bits)
    net = and(ipi, m)
    n_cidr++
    cidr_net[n_cidr]=net
    cidr_mask[n_cidr]=m
  }
  close(file)
}
function in_wl_cidr(ip,   ipi, i) {
  ipi = ip2int(ip); if (ipi<0) return 0
  for (i=1;i<=n_cidr;i++) {
    if (and(ipi, cidr_mask[i]) == cidr_net[i]) return 1
  }
  return 0
}
function in_pass_pair(ip, dom,   a, cidr24, key) {
  # key_mode=pair => ip/24|dominio
  if (split(ip,a,".")!=4) return 0
  cidr24 = a[1]"."a[2]"."a[3]".0"
  key = cidr24 "|" tolower(dom)
  return (key in pass)
}

BEGIN {
  load_wl_ip(WLIP)
  load_pass(PASS)
  load_wl_cidr(WLCIDR)
}

{
  ip=""; dom=""

  # dominio remitente
  if (match($0,/from=<[^@]+@([^>]+)>/,m)) dom=tolower(m[1])
  # IP cliente (último bloque [x.x.x.x])
  if (match($0,/.*\[([0-9.]+)\]/,mi)) ip=mi[1]

  if (ip!="" && dom!="") {
    # Filtrar lo ya permitido
    if (in_wl_ip(ip)) next
    if (in_wl_cidr(ip)) next
    if (in_pass_pair(ip, dom)) next

    # Contar
    key=dom "|" ip
    cnt[key]++
  }
}

END {
  printf "%-40s %-16s %s\n","Dominio","IP","Hits"
  printf "%-40s %-16s %s\n","-------","--","----"
  # Volcar y ordenar (usamos un array auxiliar porque gawk no sortea por valor nativamente sin asorti)
  i=0
  for (k in cnt) { i++; K[i]=k; V[i]=cnt[k] }
  # sort por V desc (burbuja simple, i<=~cientos)
  for (a=1;a<=i;a++) for (b=a+1;b<=i;b++) if (V[a]<V[b]) { tmp=V[a]; V[a]=V[b]; V[b]=tmp; t=K[a]; K[a]=K[b]; K[b]=t }
  max = (i<TOP? i : TOP)
  for (j=1;j<=max;j++) {
    split(K[j],p,"|")
    printf "%-40s %-16s %d\n", p[1], p[2], V[j]
  }
}'
