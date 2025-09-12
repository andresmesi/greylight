#!/bin/bash
DB="/var/lib/greylight/greylight.sqlite"
NOW=$(date +%s)

case "$1" in
  wl-ip)
    note="${3:-manual}"
    sqlite3 "$DB" \
      "INSERT OR IGNORE INTO wl_ip(ip,note,added_at) VALUES('$2','$note',$NOW);"
    echo "Agregado IP $2 a wl_ip con nota '$note'"
    ;;

  rm-wl-ip)
    sqlite3 "$DB" "DELETE FROM wl_ip WHERE ip='$2';"
    echo "Eliminado IP $2 de wl_ip"
    ;;

  wl-cidr)
    note="${3:-manual}"
    sqlite3 "$DB" \
      "INSERT OR IGNORE INTO wl_cidr(cidr,note,added_at) VALUES('$2','$note',$NOW);"
    echo "Agregado CIDR $2 a wl_cidr con nota '$note'"
    ;;

  rm-wl-cidr)
    sqlite3 "$DB" "DELETE FROM wl_cidr WHERE cidr='$2';"
    echo "Eliminado CIDR $2 de wl_cidr"
    ;;

  wl-domain)
    note="${3:-manual whitelist}"
    sqlite3 "$DB" \
      "INSERT OR IGNORE INTO wl_domain(domain,note,added_at) VALUES('$2','$note',$NOW);"
    echo "Agregado dominio $2 a wl_domain con nota '$note'"
    ;;

  rm-wl-domain)
    sqlite3 "$DB" "DELETE FROM wl_domain WHERE domain='$2';"
    echo "Eliminado dominio $2 de wl_domain"
    ;;

  pass-pair)
    if [ $# -lt 3 ]; then
      echo "Uso: $0 pass-pair <ip> <dominio> [nota]"
      exit 1
    fi
    dom="$3"
    ip="$2"
    note="${4:-manual pair}"
    cidr24="$(echo $ip | cut -d. -f1-3).0"
    key="${cidr24}|${dom}"

    sqlite3 "$DB" "
      INSERT INTO passlist(key,last_seen,hits,kind)
      VALUES('$key',$NOW,1,'$note')
      ON CONFLICT(key) DO UPDATE SET
        last_seen=excluded.last_seen,
        hits=hits+1;
    "
    echo "Agregado par $ip + $dom a passlist con nota '$note'"
    ;;

  rm-pass-pair)
    if [ $# -ne 3 ]; then
      echo "Uso: $0 rm-pass-pair <ip> <dominio>"
      exit 1
    fi
    dom="$3"
    ip="$2"
    cidr24="$(echo $ip | cut -d. -f1-3).0"
    key="${cidr24}|${dom}"

    sqlite3 "$DB" "DELETE FROM passlist WHERE key='$key';"
    echo "Eliminado par $ip + $dom de passlist"
    ;;

  *)
    echo "Uso:"
    echo "  $0 wl-ip <ip> [nota]"
    echo "  $0 rm-wl-ip <ip>"
    echo "  $0 wl-cidr <bloque/xx> [nota]"
    echo "  $0 rm-wl-cidr <bloque/xx>"
    echo "  $0 wl-domain <dominio> [nota]"
    echo "  $0 rm-wl-domain <dominio>"
    echo "  $0 pass-pair <ip> <dominio> [nota]"
    echo "  $0 rm-pass-pair <ip> <dominio>"
    exit 1
    ;;
esac
