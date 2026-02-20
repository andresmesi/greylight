#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#define HASH_SIZE 131072 

typedef struct {
    char **ips;    int ip_cnt;
    char **doms;   int dom_cnt;
    char **cidrs;  int cidr_cnt;
} WLCache;

typedef struct PassEntry {
    char *key;
    time_t last_seen;
    int hits;
    struct PassEntry *next;
} PassEntry;

typedef struct GreyEntry {
    char *key;
    time_t first_seen;
    time_t last_seen;
    int count;
    struct GreyEntry *next;
} GreyEntry;

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

static sqlite3 *db = NULL;
static volatile sig_atomic_t running = 1;
static Config cfg;
static FILE *logf = NULL;
static WLCache wl_mem = {NULL, 0, NULL, 0, NULL, 0};
static long last_wl_update = 0;
static PassEntry *pass_table[HASH_SIZE] = {NULL};
static GreyEntry *grey_table[HASH_SIZE] = {NULL};

// ------------------- Utilidades -------------------
static unsigned int hash_key(const char *str) {
    unsigned int hash = 5381;
    int c;
    while ((c = *str++)) hash = ((hash << 5) + hash) + c;
    return hash % HASH_SIZE;
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

static void onsig(int s){ (void)s; running=0; }

static char *trim(char *s){
    if(!s) return s;
    while(isspace((unsigned char)*s)) s++;
    if(*s==0) return s;
    char *e = s + strlen(s) - 1;
    while(e>s && isspace((unsigned char)*e)) *e--=0;
    return s;
}

static int ends_with_ci(const char *str, const char *suffix){
    if(!str || !suffix) return 0;
    size_t ls=strlen(str), lf=strlen(suffix);
    if(lf>ls) return 0;
    return strcasecmp(str+ls-lf, suffix)==0;
}

// ------------------- Red e IP -------------------
static void ip_to_cidr24(const char *ip, char *out, size_t outsz) {
    struct in_addr addr;
    if (ip && inet_pton(AF_INET, ip, &addr) == 1) {
        unsigned int u = ntohl(addr.s_addr);
        u &= 0xFFFFFF00;
        struct in_addr net; net.s_addr = htonl(u);
        inet_ntop(AF_INET, &net, out, outsz);
    } else snprintf(out, outsz, "%s", ip ? ip : "");
}

static int parse_cidr_v4(const char *cidr, uint32_t *net, uint32_t *mask){
    char tmp[64]; snprintf(tmp,sizeof(tmp), "%s", cidr);
    char *slash = strchr(tmp,'/'); if(!slash) return 0;
    *slash = 0; int prefix = atoi(slash+1);
    struct in_addr a; if(inet_pton(AF_INET, tmp, &a) != 1) return 0;
    *mask = htonl((prefix==0) ? 0 : (0xFFFFFFFFu << (32 - prefix)));
    *net = a.s_addr & *mask; return 1;
}

static int ip_in_cidr_v4(const char *ip, const char *cidr){
    struct in_addr ipa; if(inet_pton(AF_INET, ip, &ipa) != 1) return 0;
    uint32_t net, mask; if(!parse_cidr_v4(cidr, &net, &mask)) return 0;
    return (ipa.s_addr & mask) == net;
}

// ------------------- Gestión RAM -------------------
static void free_wl_cache() {
    for(int i=0; i<wl_mem.ip_cnt; i++) free(wl_mem.ips[i]);
    for(int i=0; i<wl_mem.dom_cnt; i++) free(wl_mem.doms[i]);
    for(int i=0; i<wl_mem.cidr_cnt; i++) free(wl_mem.cidrs[i]);
    free(wl_mem.ips); free(wl_mem.doms); free(wl_mem.cidrs);
    memset(&wl_mem, 0, sizeof(WLCache));
}

static void load_wl_cache() {
    free_wl_cache();
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT ip FROM wl_ip", -1, &st, NULL);
    while(sqlite3_step(st)==SQLITE_ROW){
        wl_mem.ips = realloc(wl_mem.ips, sizeof(char*)*(wl_mem.ip_cnt+1));
        wl_mem.ips[wl_mem.ip_cnt++] = strdup((const char*)sqlite3_column_text(st,0));
    }
    sqlite3_finalize(st);
    sqlite3_prepare_v2(db, "SELECT domain FROM wl_domain", -1, &st, NULL);
    while(sqlite3_step(st)==SQLITE_ROW){
        wl_mem.doms = realloc(wl_mem.doms, sizeof(char*)*(wl_mem.dom_cnt+1));
        wl_mem.doms[wl_mem.dom_cnt++] = strdup((const char*)sqlite3_column_text(st,0));
    }
    sqlite3_finalize(st);
    sqlite3_prepare_v2(db, "SELECT cidr FROM wl_cidr", -1, &st, NULL);
    while(sqlite3_step(st)==SQLITE_ROW){
        wl_mem.cidrs = realloc(wl_mem.cidrs, sizeof(char*)*(wl_mem.cidr_cnt+1));
        wl_mem.cidrs[wl_mem.cidr_cnt++] = strdup((const char*)sqlite3_column_text(st,0));
    }
    sqlite3_finalize(st);
}

static void check_wl_reload() {
    sqlite3_stmt *st;
    if(sqlite3_prepare_v2(db, "SELECT value FROM wl_meta WHERE key='last_update'", -1, &st, NULL) != SQLITE_OK) return;
    if(sqlite3_step(st) == SQLITE_ROW) {
        long db_ver = sqlite3_column_int64(st, 0);
        if(db_ver > last_wl_update) {
            load_wl_cache();
            last_wl_update = db_ver;
            log_msg("INFO", "Whitelist RAM recargada (v%ld)", db_ver);
        }
    }
    sqlite3_finalize(st);
}

static void load_passlist_to_ram() {
    sqlite3_stmt *st;
    if(sqlite3_prepare_v2(db, "SELECT key, last_seen, hits FROM passlist", -1, &st, NULL) != SQLITE_OK) return;
    int count = 0;
    while(sqlite3_step(st) == SQLITE_ROW) {
        const char *key = (const char*)sqlite3_column_text(st, 0);
        unsigned int h = hash_key(key);
        PassEntry *e = malloc(sizeof(PassEntry));
        e->key = strdup(key);
        e->last_seen = sqlite3_column_int64(st, 1);
        e->hits = sqlite3_column_int(st, 2);
        e->next = pass_table[h];
        pass_table[h] = e;
        count++;
    }
    sqlite3_finalize(st);
    log_msg("INFO", "Passlist cargada: %d registros en RAM", count);
}

static void dump_passlist_to_db() {
    if (!db) return;
    log_msg("INFO", "Sincronizando hits a base de datos antes de salir...");
    sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL);
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "UPDATE passlist SET last_seen=?1, hits=?2 WHERE key=?3", -1, &st, NULL);
    for (int i = 0; i < HASH_SIZE; i++) {
        PassEntry *e = pass_table[i];
        while (e) {
            sqlite3_bind_int64(st, 1, e->last_seen);
            sqlite3_bind_int(st, 2, e->hits);
            sqlite3_bind_text(st, 3, e->key, -1, SQLITE_TRANSIENT);
            sqlite3_step(st); sqlite3_reset(st);
            e = e->next;
        }
    }
    sqlite3_finalize(st);
    sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL);
}

static void cleanup_ram() {
    time_t limit = time(NULL) - (cfg.pass_ttl_days * 86400);
    time_t g_limit = time(NULL) - 86400; 
    for (int i = 0; i < HASH_SIZE; i++) {
        PassEntry **cp = &pass_table[i];
        while (*cp) {
            if ((*cp)->last_seen < limit) {
                PassEntry *t = *cp; *cp = t->next;
                free(t->key); free(t);
            } else cp = &((*cp)->next);
        }
        GreyEntry **cg = &grey_table[i];
        while (*cg) {
            if ((*cg)->last_seen < g_limit) {
                GreyEntry *t = *cg; *cg = t->next;
                free(t->key); free(t);
            } else cg = &((*cg)->next);
        }
    }
}

// ------------------- Config -------------------
static void config_defaults(){
    memset(&cfg, 0, sizeof(cfg));
    strcpy(cfg.listen_ip, "127.0.0.1"); cfg.listen_port = 10050;
    strcpy(cfg.db_path, "/var/lib/greylight/greylight.sqlite");
    cfg.delay_sec = 420; cfg.pass_ttl_days = 90; cfg.cleanup_interval_sec = 3600;
    strcpy(cfg.key_mode, "triplet"); strcpy(cfg.log_path, "/var/log/greylight.log");
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
        if(!strcasecmp(section,"server")){
            if(!strcasecmp(k,"listen")){
                char *colon = strrchr(v, ':');
                if(colon){ *colon=0; strcpy(cfg.listen_ip, trim(v)); cfg.listen_port = atoi(trim(colon+1)); }
                else cfg.listen_port = atoi(v);
            } else if(!strcasecmp(k,"log_file")) strcpy(cfg.log_path, v);
            else if(!strcasecmp(k,"debug")) cfg.debug = (strcasecmp(v,"yes")==0 || strcmp(v,"1")==0);
        } else if(!strcasecmp(section,"db")){
            if(!strcasecmp(k,"path")) strcpy(cfg.db_path, v);
        } else if(!strcasecmp(section,"logic")){
            if(!strcasecmp(k,"delay_sec")) cfg.delay_sec = atoi(v);
            else if(!strcasecmp(k,"pass_ttl_days")) cfg.pass_ttl_days = atoi(v);
            else if(!strcasecmp(k,"cleanup_interval_sec")) cfg.cleanup_interval_sec = atoi(v);
            else if(!strcasecmp(k,"key_mode")) strcpy(cfg.key_mode, v);
            else if(!strcasecmp(k,"only_rcpt_domain")) strcpy(cfg.only_rcpt_domain, v);
        }
    }
    fclose(f);
}

// ------------------- Lógica Postfix -------------------
static int handle_request(int fd) {
    char buf[BUFSZ];
    ssize_t n = recv(fd, buf, sizeof(buf)-1, 0);
    if (n <= 0) return 0;
    buf[n] = 0;

    check_wl_reload();

    char *saveptr=NULL, *line=strtok_r(buf, "\r\n", &saveptr);
    char *client_ip=NULL, *sender=NULL, *recipient=NULL;
    while(line){
        if(!strncmp(line,"client_address=",15)) client_ip=strdup(line+15);
        else if(!strncmp(line,"sender=",7)) sender=strdup(line+7);
        else if(!strncmp(line,"recipient=",10)) recipient=strdup(line+10);
        line=strtok_r(NULL,"\r\n",&saveptr);
    }

    const char *resp = "action=dunno\n\n";
    const char *sender_dom = (sender && strrchr(sender,'@')) ? strrchr(sender,'@')+1 : NULL;

    // 1. Whitelists
    bool whitelisted = false;
    if(client_ip){
        for(int i=0; i<wl_mem.ip_cnt; i++) if(!strcmp(client_ip, wl_mem.ips[i])) whitelisted=true;
        for(int i=0; i<wl_mem.cidr_cnt; i++) if(ip_in_cidr_v4(client_ip, wl_mem.cidrs[i])) whitelisted=true;
    }
    if(sender_dom){
        for(int i=0; i<wl_mem.dom_cnt; i++) if(!strcasecmp(sender_dom, wl_mem.doms[i])) whitelisted=true;
    }
    
    if(whitelisted) goto send_it;

    // 2. Ignore/Only RCPT logic
    if(cfg.only_rcpt_domain[0] != '\0' && !(recipient && ends_with_ci(recipient, cfg.only_rcpt_domain))) goto send_it;

    // 3. Key Logic
    char net24[64], key[1024];
    ip_to_cidr24(client_ip?client_ip:"", net24, sizeof(net24));
    if(!strcasecmp(cfg.key_mode,"pair")) 
        snprintf(key, sizeof(key), "%s|%s", net24, sender_dom?sender_dom:"");
    else 
        snprintf(key, sizeof(key), "%s|%s|%s", net24, sender_dom?sender_dom:"", recipient?recipient:"");

    unsigned int h = hash_key(key);
    time_t now = time(NULL);

    // 4. Passlist (RAM)
    PassEntry *pe = pass_table[h];
    while(pe){
        if(!strcmp(pe->key, key)){ pe->last_seen = now; pe->hits++; goto send_it; }
        pe = pe->next;
    }

    // 5. Grey (RAM)
    GreyEntry **pg = &grey_table[h];
    while(*pg){
        if(!strcmp((*pg)->key, key)){
            if((now - (*pg)->first_seen) >= cfg.delay_sec){
                PassEntry *npe = malloc(sizeof(PassEntry));
                npe->key = strdup(key); npe->last_seen = now; npe->hits = (*pg)->count + 1;
                npe->next = pass_table[h]; pass_table[h] = npe;
                
                sqlite3_stmt *st;
                sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO passlist VALUES(?1,?2,?3,'grey')", -1, &st, NULL);
                sqlite3_bind_text(st,1,key,-1,SQLITE_TRANSIENT);
                sqlite3_bind_int64(st,2,now); sqlite3_bind_int(st,3,npe->hits);
                sqlite3_step(st); sqlite3_finalize(st);

                GreyEntry *t = *pg; *pg = t->next; free(t->key); free(t);
            } else {
                (*pg)->last_seen = now; (*pg)->count++;
                resp = "action=defer_if_permit 450 Greylisted, retry later\n\n";
            }
            goto send_it;
        }
        pg = &((*pg)->next);
    }

    // 6. Nuevo
    GreyEntry *nge = malloc(sizeof(GreyEntry));
    nge->key = strdup(key); nge->first_seen = now; nge->last_seen = now; nge->count = 1;
    nge->next = grey_table[h]; grey_table[h] = nge;
    resp = "action=defer_if_permit 450 Greylisted, first time\n\n";

send_it:
    send(fd, resp, strlen(resp), 0);
    free(client_ip); free(sender); free(recipient);
    return 0;
}

// ------------------- Main -------------------
int main(int argc, char **argv){
    const char *conf_path = "/etc/greylight.conf";
    int opt;
    while((opt=getopt(argc, argv, "c:h"))!=-1){ if(opt=='c') conf_path = optarg; }

    config_load(conf_path);
    logf = fopen(cfg.log_path, "a");
    if(sqlite3_open(cfg.db_path, &db) != SQLITE_OK) return 1;

    load_wl_cache();
    load_passlist_to_ram();

    signal(SIGINT, onsig); signal(SIGTERM, onsig);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one=1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa = {0}; sa.sin_family = AF_INET; 
    sa.sin_port = htons(cfg.listen_port); inet_pton(AF_INET, cfg.listen_ip, &sa.sin_addr);
    if(bind(s, (struct sockaddr*)&sa, sizeof(sa)) < 0) return 1;
    listen(s, 128);

    log_msg("INFO", "Greylight iniciado (RAM mode)");
    time_t last_cl = time(NULL);

    while(running){
        int c = accept(s, NULL, NULL);
        if(c >= 0) { handle_request(c); close(c); }
        time_t now = time(NULL);
        if(now - last_cl >= cfg.cleanup_interval_sec){
            cleanup_ram();
            char sql[256];
            snprintf(sql, sizeof(sql), "DELETE FROM passlist WHERE last_seen < strftime('%%s','now') - %d;", cfg.pass_ttl_days*86400);
            sqlite3_exec(db, sql, NULL, NULL, NULL);
            last_cl = now;
        }
    }

    dump_passlist_to_db();
    free_wl_cache();
    sqlite3_close(db);
    if(logf) fclose(logf);
    return 0;
}