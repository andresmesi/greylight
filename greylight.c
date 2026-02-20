// greylight.c - Policy daemon de greylisting para Postfix
// Compilar: gcc -O2 -Wall -std=gnu11 greylight.c -lsqlite3 -o greylight

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sqlite3.h>

#define BUFSZ 8192
#define MAX_IGNORE_RCPT 128

typedef struct {
    char listen_ip[64];
    int  listen_port;
    char db_path[512];
    int  delay_sec;
    int  promote_hits;
    int  pass_ttl_days;
    int  cleanup_interval_sec;
    char key_mode[16];
    char only_rcpt_domain[256];
    char *ignore_rcpt_domains[MAX_IGNORE_RCPT];
    int  ignore_rcpt_domains_cnt;
    char log_path[512];
    int debug;
} Config;

typedef struct {
    char **ips;    int ip_cnt;
    char **doms;   int dom_cnt;
    char **cidrs;  int cidr_cnt;
} WLCache;

static sqlite3 *db = NULL;
static volatile sig_atomic_t running = 1;
static Config cfg;
static FILE *logf = NULL;
static WLCache cache = {NULL, 0, NULL, 0, NULL, 0};
static long last_cache_update = 0;

// ------------------- util -------------------
static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap); va_end(ap);
    fprintf(stderr, "\n"); exit(1);
}

static void onsig(int s){ (void)s; running=0; }

static char *trim(char *s){
    if(!s) return s;
    while(isspace((unsigned char)*s)) s++;
    if(*s==0) return s;
    char *e = s + strlen(s) - 1;
    while(e>s && isspace((unsigned char)*e)) *e--=0;
    return s;
}

static void log_msg(const char *level, const char *fmt, ...) {
    if (!logf) return;
    va_list ap; va_start(ap, fmt);
    time_t now = time(NULL);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
    fprintf(logf, "[%s] [%s] ", ts, level);
    vfprintf(logf, fmt, ap);
    fprintf(logf, "\n"); fflush(logf);
    va_end(ap);
}

static int ends_with_ci(const char *str, const char *suffix){
    if(!str || !suffix) return 0;
    size_t ls=strlen(str), lf=strlen(suffix);
    if(lf>ls) return 0;
    return strcasecmp(str+ls-lf, suffix)==0;
}

// ------------------- IPv4 helpers -------------------
static void ip_to_cidr24(const char *ip, char *out, size_t outsz) {
    struct in_addr addr;
    if (ip && inet_pton(AF_INET, ip, &addr) == 1) {
        unsigned int u = ntohl(addr.s_addr);
        u &= 0xFFFFFF00;
        struct in_addr net; net.s_addr = htonl(u);
        inet_ntop(AF_INET, &net, out, outsz);
    } else {
        snprintf(out, outsz, "%s", ip ? ip : "");
    }
}

static int parse_cidr_v4(const char *cidr, uint32_t *net_out, uint32_t *mask_out){
    if(!cidr) return 0;
    char tmp[64]; snprintf(tmp,sizeof(tmp), "%s", cidr);
    char *slash = strchr(tmp,'/');
    if(!slash) return 0;
    *slash = 0;
    int prefix = atoi(slash+1);
    if(prefix < 0 || prefix > 32) return 0;
    struct in_addr a;
    if(inet_pton(AF_INET, tmp, &a) != 1) return 0;
    uint32_t mask = (prefix==0) ? 0 : (0xFFFFFFFFu << (32 - (unsigned)prefix));
    mask = htonl(mask);
    *net_out  = a.s_addr & mask;
    *mask_out = mask;
    return 1;
}

static int ip_in_cidr_v4(const char *ip, const char *cidr){
    if(!ip || !cidr) return 0;
    struct in_addr ipa;
    if(inet_pton(AF_INET, ip, &ipa) != 1) return 0;
    uint32_t net, mask;
    if(!parse_cidr_v4(cidr, &net, &mask)) return 0;
    return (ipa.s_addr & mask) == net;
}

// ------------------- Cache Logic -------------------
static void free_wl_cache() {
    for(int i=0; i<cache.ip_cnt; i++) free(cache.ips[i]);
    for(int i=0; i<cache.dom_cnt; i++) free(cache.doms[i]);
    for(int i=0; i<cache.cidr_cnt; i++) free(cache.cidrs[i]);
    free(cache.ips); free(cache.doms); free(cache.cidrs);
    memset(&cache, 0, sizeof(WLCache));
}

static void load_wl_cache() {
    free_wl_cache();
    sqlite3_stmt *st;

    sqlite3_prepare_v2(db, "SELECT ip FROM wl_ip", -1, &st, NULL);
    while(sqlite3_step(st)==SQLITE_ROW) {
        cache.ips = realloc(cache.ips, sizeof(char*) * (cache.ip_cnt+1));
        cache.ips[cache.ip_cnt++] = strdup((const char*)sqlite3_column_text(st,0));
    }
    sqlite3_finalize(st);

    sqlite3_prepare_v2(db, "SELECT domain FROM wl_domain", -1, &st, NULL);
    while(sqlite3_step(st)==SQLITE_ROW) {
        cache.doms = realloc(cache.doms, sizeof(char*) * (cache.dom_cnt+1));
        cache.doms[cache.dom_cnt++] = strdup((const char*)sqlite3_column_text(st,0));
    }
    sqlite3_finalize(st);

    sqlite3_prepare_v2(db, "SELECT cidr FROM wl_cidr", -1, &st, NULL);
    while(sqlite3_step(st)==SQLITE_ROW) {
        cache.cidrs = realloc(cache.cidrs, sizeof(char*) * (cache.cidr_cnt+1));
        cache.cidrs[cache.cidr_cnt++] = strdup((const char*)sqlite3_column_text(st,0));
    }
    sqlite3_finalize(st);
    if(cfg.debug) log_msg("DEBUG", "Cache recargada (IPs:%d, Doms:%d, CIDRs:%d)", cache.ip_cnt, cache.dom_cnt, cache.cidr_cnt);
}

static void check_and_reload_cache() {
    sqlite3_stmt *st;
    if(sqlite3_prepare_v2(db, "SELECT value FROM wl_meta WHERE key='last_update'", -1, &st, NULL) != SQLITE_OK) return;
    if(sqlite3_step(st) == SQLITE_ROW) {
        long db_ver = sqlite3_column_int64(st, 0);
        if(db_ver > last_cache_update) {
            load_wl_cache();
            last_cache_update = db_ver;
        }
    }
    sqlite3_finalize(st);
}

// ------------------- Config & DB -------------------
static void config_defaults(){
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.listen_ip, sizeof(cfg.listen_ip), "127.0.0.1");
    cfg.listen_port = 10050;
    snprintf(cfg.db_path, sizeof(cfg.db_path), "/var/lib/greylight/greylight.sqlite");
    cfg.delay_sec = 420; cfg.promote_hits = 2; cfg.pass_ttl_days = 90;
    cfg.cleanup_interval_sec = 3600;
    snprintf(cfg.key_mode, sizeof(cfg.key_mode), "triplet");
    snprintf(cfg.log_path, sizeof(cfg.log_path), "/var/log/greylight.log");
}

static void parse_ignore_list(char *val){
    if(!val) return;
    char *p = val;
    while(p && *p && cfg.ignore_rcpt_domains_cnt < MAX_IGNORE_RCPT){
        char *comma = strchr(p, ',');
        if(comma) *comma = 0;
        char *tok = trim(p);
        if(*tok) cfg.ignore_rcpt_domains[cfg.ignore_rcpt_domains_cnt++] = strdup(tok);
        if(!comma) break;
        p = comma + 1;
    }
}

static void config_load(const char *path){
    config_defaults();
    FILE *f = fopen(path, "r"); if(!f) return;
    char line[2048], section[64]="";
    while(fgets(line, sizeof(line), f)){
        char *s = trim(line);
        if(*s=='#' || *s==';' || *s==0) continue;
        if(*s=='['){
            char *e = strchr(s, ']');
            if(e){ *e=0; snprintf(section,sizeof(section), "%s", s+1); }
            continue;
        }
        char *eq = strchr(s, '='); if(!eq) continue;
        *eq=0; char *k = trim(s); char *v = trim(eq+1);
        if(strcasecmp(section,"server")==0){
            if(strcasecmp(k,"listen")==0){
                char *colon = strrchr(v, ':');
                if(colon){ *colon=0; snprintf(cfg.listen_ip, sizeof(cfg.listen_ip), "%s", trim(v)); cfg.listen_port = atoi(trim(colon+1)); }
                else cfg.listen_port = atoi(v);
            } else if(strcasecmp(k,"log_file")==0) snprintf(cfg.log_path, sizeof(cfg.log_path), "%s", v);
            else if(strcasecmp(k,"debug")==0) cfg.debug = (strcasecmp(v,"yes")==0 || strcmp(v,"1")==0);
        } else if(strcasecmp(section,"db")==0){
            if(strcasecmp(k,"path")==0) snprintf(cfg.db_path, sizeof(cfg.db_path), "%s", v);
        } else if(strcasecmp(section,"logic")==0){
            if(strcasecmp(k,"delay_sec")==0) cfg.delay_sec = atoi(v);
            else if(strcasecmp(k,"promote_hits")==0) cfg.promote_hits = atoi(v);
            else if(strcasecmp(k,"pass_ttl_days")==0) cfg.pass_ttl_days = atoi(v);
            else if(strcasecmp(k,"cleanup_interval_sec")==0) cfg.cleanup_interval_sec = atoi(v);
            else if(strcasecmp(k,"only_rcpt_domain")==0) snprintf(cfg.only_rcpt_domain, sizeof(cfg.only_rcpt_domain), "%s", v);
            else if(strcasecmp(k,"ignore_rcpt_domains")==0){ char *dup = strdup(v); parse_ignore_list(dup); free(dup); }
            else if(strcasecmp(k,"key_mode")==0){ snprintf(cfg.key_mode, sizeof(cfg.key_mode), "%s", v); }
        }
    }
    fclose(f);
}

static int prepare_db(const char *path){
    if(sqlite3_open(path, &db)!=SQLITE_OK) return -1;
    char *err=NULL;
    const char *sql =
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;"
        "CREATE TABLE IF NOT EXISTS wl_ip(ip TEXT PRIMARY KEY, note TEXT, added_at INTEGER);"
        "CREATE TABLE IF NOT EXISTS wl_domain(domain TEXT PRIMARY KEY, note TEXT, added_at INTEGER);"
        "CREATE TABLE IF NOT EXISTS wl_cidr(cidr TEXT PRIMARY KEY, note TEXT, added_at INTEGER);"
        "CREATE TABLE IF NOT EXISTS wl_meta(key TEXT PRIMARY KEY, value INTEGER);"
        "CREATE TABLE IF NOT EXISTS passlist(key TEXT PRIMARY KEY, last_seen INTEGER, hits INTEGER, kind TEXT);"
        "CREATE TABLE IF NOT EXISTS grey(key TEXT PRIMARY KEY, first_seen INTEGER, last_seen INTEGER, count INTEGER);"
        "CREATE INDEX IF NOT EXISTS idx_passlist_last ON passlist(last_seen);"
        "CREATE INDEX IF NOT EXISTS idx_grey_last ON grey(last_seen);"
        "INSERT OR IGNORE INTO wl_meta VALUES('last_update', strftime('%s','now'));";
    if(sqlite3_exec(db, sql, NULL, NULL, &err)!=SQLITE_OK){ sqlite3_free(err); return -1; }
    return 0;
}

// ------------------- Handlers (RAM based) -------------------
static bool is_whitelisted_ip_exact(const char *ip){
    if(!ip) return false;
    for(int i=0; i<cache.ip_cnt; i++) if(!strcmp(ip, cache.ips[i])) return true;
    return false;
}
static bool is_whitelisted_domain(const char *domain){
    if(!domain) return false;
    for(int i=0; i<cache.dom_cnt; i++) if(!strcasecmp(domain, cache.doms[i])) return true;
    return false;
}
static bool is_whitelisted_cidr(const char *ip){
    if(!ip) return false;
    for(int i=0; i<cache.cidr_cnt; i++) if(ip_in_cidr_v4(ip, cache.cidrs[i])) return true;
    return false;
}

static void cleanup_expired() {
    char sql[256];
    snprintf(sql,sizeof(sql), "DELETE FROM passlist WHERE last_seen < strftime('%%s','now') - %d;", cfg.pass_ttl_days*86400);
    sqlite3_exec(db,sql,0,0,0);
    snprintf(sql,sizeof(sql), "DELETE FROM grey WHERE last_seen < strftime('%%s','now') - %d;", cfg.delay_sec*10);
    sqlite3_exec(db,sql,0,0,0);
    log_msg("INFO", "DB cleanup ejecutado");
}

// ------------------- Postfix Policy Handler -------------------
static int handle_request(int fd){
    char buf[BUFSZ];
    ssize_t n = recv(fd, buf, sizeof(buf)-1, 0);
    if (n <= 0) return 0;
    buf[n] = 0;

    check_and_reload_cache();

    char *saveptr=NULL, *line=strtok_r(buf, "\r\n", &saveptr);
    char *client_ip=NULL, *sender=NULL, *recipient=NULL;
    while(line){
        if(!*line) break;
        if(!strncmp(line,"client_address=",15)) client_ip=strdup(line+15);
        else if(!strncmp(line,"sender=",7)) sender=strdup(line+7);
        else if(!strncmp(line,"recipient=",10)) recipient=strdup(line+10);
        line=strtok_r(NULL,"\r\n",&saveptr);
    }

    const char *sender_domain=NULL;
    if(sender){ char *at = strrchr(sender,'@'); if(at && *(at+1)) sender_domain = at+1; }

    const char *resp=NULL;

    // Ignorar dominios destinatarios
    if(recipient && cfg.ignore_rcpt_domains_cnt>0){
        for(int i=0;i<cfg.ignore_rcpt_domains_cnt;i++){
            if(ends_with_ci(recipient, cfg.ignore_rcpt_domains[i])){
                resp="action=dunno\n\n"; goto send_resp;
            }
        }
    }

    if(cfg.only_rcpt_domain[0] != '\0' && !(recipient && ends_with_ci(recipient, cfg.only_rcpt_domain))){
        resp="action=dunno\n\n"; goto send_resp;
    }

    // Whitelists (AHORA EN RAM)
    if(client_ip && (is_whitelisted_ip_exact(client_ip) || is_whitelisted_cidr(client_ip))){
        resp="action=dunno\n\n"; goto send_resp;
    }
    if(sender_domain && is_whitelisted_domain(sender_domain)){
        resp="action=dunno\n\n"; goto send_resp;
    }

    char net24[64]; ip_to_cidr24(client_ip?client_ip:"", net24, sizeof(net24));
    char key[1024];
    if (!strcasecmp(cfg.key_mode,"pair")) snprintf(key,sizeof(key), "%s|%s", net24, sender_domain?sender_domain:"");
    else snprintf(key,sizeof(key), "%s|%s|%s", net24, sender_domain?sender_domain:"", recipient?recipient:"");

    time_t now = time(NULL);
    sqlite3_stmt *st=NULL;
    if(sqlite3_prepare_v2(db, "SELECT hits FROM passlist WHERE key=?1", -1, &st, NULL)==SQLITE_OK){
        sqlite3_bind_text(st,1,key,-1,SQLITE_TRANSIENT);
        if(sqlite3_step(st)==SQLITE_ROW){
            int hits=sqlite3_column_int(st,0); sqlite3_finalize(st);
            sqlite3_prepare_v2(db,"UPDATE passlist SET last_seen=?1,hits=?2 WHERE key=?3",-1,&st,NULL);
            sqlite3_bind_int64(st,1, now); sqlite3_bind_int(st,2, hits+1);
            sqlite3_bind_text(st,3, key,-1,SQLITE_TRANSIENT);
            sqlite3_step(st); sqlite3_finalize(st);
            resp="action=dunno\n\n"; goto send_resp;
        }
        sqlite3_finalize(st);
    }

    if(sqlite3_prepare_v2(db, "SELECT first_seen,count FROM grey WHERE key=?1", -1, &st, NULL)==SQLITE_OK){
        sqlite3_bind_text(st,1,key,-1,SQLITE_TRANSIENT);
        if(sqlite3_step(st)==SQLITE_ROW){
            time_t first = sqlite3_column_int64(st, 0);
            int count = sqlite3_column_int(st, 1); sqlite3_finalize(st);
            if((now - first) >= cfg.delay_sec){
                sqlite3_exec(db, "BEGIN", 0, 0, 0);
                sqlite3_prepare_v2(db,"INSERT OR REPLACE INTO passlist(key,last_seen,hits,kind) VALUES(?1,?2,?3,'grey')",-1,&st,NULL);
                sqlite3_bind_text(st,1,key,-1,SQLITE_TRANSIENT); sqlite3_bind_int64(st,2, now); sqlite3_bind_int(st,3, count+1);
                sqlite3_step(st); sqlite3_finalize(st);
                sqlite3_prepare_v2(db,"DELETE FROM grey WHERE key=?1",-1,&st,NULL);
                sqlite3_bind_text(st,1,key,-1,SQLITE_TRANSIENT); sqlite3_step(st); sqlite3_finalize(st);
                sqlite3_exec(db, "COMMIT", 0, 0, 0);
                resp="action=dunno\n\n";
            } else {
                sqlite3_prepare_v2(db,"UPDATE grey SET last_seen=?1, count=?2 WHERE key=?3",-1,&st,NULL);
                sqlite3_bind_int64(st,1, now); sqlite3_bind_int(st,2, count+1);
                sqlite3_bind_text(st,3, key,-1,SQLITE_TRANSIENT);
                sqlite3_step(st); sqlite3_finalize(st);
                resp="action=defer_if_permit 450 Greylisted, please retry\n\n";
            }
            goto send_resp;
        }
        sqlite3_finalize(st);
    }

    if(sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO grey(key,first_seen,last_seen,count) VALUES(?1,?2,?2,1)", -1, &st, NULL)==SQLITE_OK){
        sqlite3_bind_text(st,1,key,-1,SQLITE_TRANSIENT); sqlite3_bind_int64(st,2, now);
        sqlite3_step(st); sqlite3_finalize(st);
    }
    resp="action=defer_if_permit 450 Greylisted, please retry\n\n";

send_resp:
    if(resp) send(fd, resp, strlen(resp), 0);
    if(cfg.debug) log_msg("DEBUG","ip=%s from=%s rcpt=%s -> %s", client_ip?client_ip:"-", sender?sender:"-", recipient?recipient:"-", resp?resp:"error");

    free(client_ip);
    free(sender);
    free(recipient);
    return 0;
}

int main(int argc, char **argv){
    const char *conf = "/etc/greylight.conf";
    int opt;
    while((opt=getopt(argc, argv, "c:h"))!=-1){ if(opt=='c') conf = optarg; else { fprintf(stderr, "Uso: %s -c /conf\n", argv[0]); return 1; } }

    config_load(conf);
    logf = fopen(cfg.log_path, "a"); if (!logf) die("Log error %s", cfg.log_path);
    if(prepare_db(cfg.db_path)!=0) die("DB init failed");

    load_wl_cache(); // Carga inicial

    signal(SIGINT, onsig); signal(SIGTERM, onsig);
    int s=socket(AF_INET, SOCK_STREAM, 0);
    int one=1; setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
    struct sockaddr_in sa={0}; sa.sin_family=AF_INET; sa.sin_port=htons(cfg.listen_port);
    inet_pton(AF_INET, cfg.listen_ip, &sa.sin_addr);
    if(bind(s,(struct sockaddr*)&sa,sizeof(sa))<0) die("bind: %s", strerror(errno));
    listen(s, 128);

    log_msg("INFO", "greylight iniciado en %s:%d", cfg.listen_ip, cfg.listen_port);
    time_t last_cleanup = time(NULL);

    while(running){
        int c=accept(s,NULL,NULL);
        if(c<0){ if(errno==EINTR) continue; else break; }
        handle_request(c);
        close(c);
        time_t now = time(NULL);
        if (now - last_cleanup >= cfg.cleanup_interval_sec) { cleanup_expired(); last_cleanup = now; }
    }

    log_msg("INFO","greylight detenido");
    free_wl_cache();
    if(logf) fclose(logf);
    sqlite3_close(db);
    for(int i=0;i<cfg.ignore_rcpt_domains_cnt;i++) free(cfg.ignore_rcpt_domains[i]);
    return 0;
}