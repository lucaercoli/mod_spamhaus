/*
 *
 * Date:        2008/11/02
 * Info:        mod_spamhaus Apache 2.2 module
 * Contact:     mailto: <luca [at] lucaercoli.it>
 * Version:     0.7
 * Author:      Luca Ercoli
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License versione 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 *
 */


#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_protocol.h"
#include "http_core.h"
#include "http_main.h"
#include "http_log.h"
#include "ap_mpm.h"
#include "apr_strings.h"
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netdb.h>


#define MODULE_NAME "mod_spamhaus"
#define MODULE_VERSION "0.7"
#define WHITELIST_SIZE	2048
#define MAX_CACHE_SIZE	8192	

module AP_MODULE_DECLARE_DATA spamhaus_module;

static void *spamhaus_create_config(apr_pool_t *p, server_rec *s);
static void *spamhaus_create_dir_config(apr_pool_t *p, char *path);
static int spamhaus_handler(request_rec *r);
static int spamhaus_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s);
static void register_hooks(apr_pool_t *p);
int check_whitelist(char *conf,request_rec *r);
void update_whitelist(char *file);
int add_cache(char *indirizzo,int num);

char lookup_this[512];
int oct1,oct2,oct3,oct4;

char *brokenfeed;
unsigned bitmask;
unsigned long a = 0, b = 0, c = 0, d = 0;
int a_min,b_min,c_min,d_min;
int a_max,b_max,c_max,d_max;
int a_daverificare,b_daverificare,c_daverificare,d_daverificare;

char lista[WHITELIST_SIZE][19];

struct stat statdata;
struct tm *access_time;
char timestamp[9],old_timestamp[9];

int cache_size;
char cached_ip[MAX_CACHE_SIZE][15];
int nip=0;

typedef struct {
	char *methods;
	char *whitelist;
	char *dnshost;
	int nip_incache;
	char *c_err;
} mod_config;


static mod_config *create_config(apr_pool_t *p)
{
	mod_config *cfg = (mod_config *)
		apr_pcalloc(p, sizeof (*cfg));

	cfg->methods="POST,PUT,OPTIONS";
	cfg->whitelist="no-white-list";
	cfg->dnshost="sbl-xbl.spamhaus.org";
	cfg->nip_incache=512;
	cfg->c_err="Access Denied! Your address is blacklisted. More information about this error may be available in the server error log.";
	return cfg;
}




/* per-server configuration structure */
static void *spamhaus_create_config(apr_pool_t *p, server_rec *s)
{
	return create_config(p);
}



/* per-directory configuration structure */
static void *spamhaus_create_dir_config(apr_pool_t *p, char *path)
{
	return create_config(p);
}


void update_whitelist(char *file)
{

	int count = 0;
	FILE *effeppi;

	for (count; count < WHITELIST_SIZE; count++) memset(lista[count],'\0',19);

	count = 0;

	effeppi = fopen(file,"r");

	if(effeppi)
	{
		while (!feof(effeppi))
		{
			if (count < WHITELIST_SIZE) 
			{
				fgets(lista[count], 19, effeppi);
				count++;
			}

			else break;
		}
		fclose(effeppi);
	}

}


int check_whitelist(char *conf, request_rec *r)
{
	unsigned long first;
	unsigned long last;
	unsigned long mask;
	char ippi[16];
	struct in_addr in;


	stat(conf,&statdata);
	access_time = localtime(&statdata.st_mtime);
	snprintf(timestamp,9,"%d:%d:%d",access_time->tm_hour,access_time->tm_min,access_time->tm_sec);

	if (strcmp(old_timestamp,timestamp) != 0)
	{
		ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "Reloading whitelist");
		strncpy(old_timestamp,timestamp,9);
		update_whitelist(conf);
	}


	int count = 0;

	for (count; count < WHITELIST_SIZE; count++)
	{

		if (lista[count][0] == '\0') return 0;

		brokenfeed = strchr(lista[count], '\n');
		if ( brokenfeed ) *brokenfeed =  '\0';

		if ( (strchr(lista[count],'/') == NULL )){
			if ( strcmp(lista[count],r->connection->remote_ip) == 0  ) return 1;
		}
		else {

			sscanf(lista[count], "%[^/]/%u", ippi, &bitmask);
			sscanf(ippi, "%lu.%lu.%lu.%lu", &a, &b, &c, &d);

			first = (a << 24) + (b << 16) + (c << 8) + d;

			mask = (0xFFFFFFFF << (32 - bitmask));

			last = first + (~mask);
			first = htonl(first);
			last = htonl(last);

			in.s_addr = first;

			sscanf(inet_ntoa(in), "%d.%d.%d.%d", &a_min, &b_min, &c_min, &d_min);

			in.s_addr = last;

			sscanf(inet_ntoa(in), "%d.%d.%d.%d", &a_max, &b_max, &c_max, &d_max);
			sscanf(r->connection->remote_ip, "%d.%d.%d.%d", &a_daverificare, &b_daverificare, &c_daverificare, &d_daverificare);

			if (

					((d_daverificare <=  d_max) && (d_daverificare >=  d_min)) &&
					((c_daverificare <=  c_max) && (c_daverificare >=  c_min)) &&
					((b_daverificare <=  b_max) && (b_daverificare >=  b_min)) &&
					((a_daverificare <=  a_max) && (a_daverificare >=  a_min))

			   ) return 1;


		}

	}

	return 0;
}


int add_cache(char *indirizzo,int num)
{

	int cx;

	for (cx = 0; cx < num; cx++) if (strcmp(cached_ip[cx],indirizzo) == 0 ) return 0;

	strncpy(cached_ip[nip],indirizzo,15);
	if (nip == (num - 1)) nip = 0;
	else nip++;


}


static int core(request_rec *r, mod_config *cfg)
{

	int counter = 0;


	if (  strstr(cfg->methods,r->method) != NULL   )
	{

		for (counter; counter < cfg->nip_incache; counter++) if (strcmp(cached_ip[counter],r->connection->remote_ip) == 0 )	return DECLINED;	       


		struct hostent *hp = 0;

		memset(lookup_this,'\0',512);

		sscanf(r->connection->remote_ip, "%d.%d.%d.%d",&oct1, &oct2, &oct3, &oct4);

		snprintf(lookup_this,512,"%d.%d.%d.%d.%s",oct4,oct3,oct2,oct1,cfg->dnshost);

		hp = gethostbyname(lookup_this);


		if (hp != NULL)
		{

			struct in_addr addr;
			addr.s_addr = *(u_long *) hp->h_addr_list[0];

			sscanf(inet_ntoa(addr),"%d.%d.%d.%d",&oct1, &oct2, &oct3, &oct4);

			if (oct1 != 127)
			{

				ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "mod_spamhaus: address %s is blacklisted but it's not in the 127.0.0.0/8 range. POSSIBLE WILD-CARDING TYPOSQUATTERS ATTACK! IP address will not get filtered",r->connection->remote_ip);
				return DECLINED;
			}

			if ( (strcmp(cfg->whitelist,"no-white-list")!= 0)   )
			{
				if ( check_whitelist(cfg->whitelist,r) ) {
					ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "mod_spamhaus: address %s is whitelisted. Allow connection to %s%s", r->connection->remote_ip,r->hostname,r->uri);
					add_cache(r->connection->remote_ip,cfg->nip_incache);
					return DECLINED;

				}
			}


			ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "mod_spamhaus: address %s is blacklisted. Deny connection to %s%s", lookup_this,r->hostname,r->uri);

			r->content_type = "text/plain"; 
			ap_custom_response(r, HTTP_UNAUTHORIZED, cfg->c_err); 
			return HTTP_UNAUTHORIZED;
		}


	}


	add_cache(r->connection->remote_ip,cfg->nip_incache);

	return DECLINED;



}


static int spamhaus_handler(request_rec *r)
{
	mod_config *cfg = (mod_config *)
		ap_get_module_config(r->per_dir_config, &spamhaus_module);

	int result;

	result = core(r, cfg);

	return result;
}



static const char *white_list_conf(cmd_parms *parms, void *dummy,
		const char *arg)
{

	mod_config *cfg = (mod_config *)dummy;
	ap_get_module_config(parms->server->module_config, &spamhaus_module);

	cfg->whitelist =(char *)arg;

	update_whitelist(cfg->whitelist);

	stat(cfg->whitelist,&statdata);
	access_time = localtime(&statdata.st_mtime);
	snprintf(old_timestamp,9,"%d:%d:%d",access_time->tm_hour,access_time->tm_min,access_time->tm_sec);

	int count = 0;
	for (count; count < cfg->nip_incache; count++) memset(cached_ip[count],'\0',15);


	return NULL;
}


static const char *dns_to_query(cmd_parms *parms, void *dummy,
		const char *arg)
{

	mod_config *cfg = (mod_config *)dummy;
	ap_get_module_config(parms->server->module_config, &spamhaus_module);

	cfg->dnshost = (char *)arg;
	return NULL;
}


static const char *looking_for(cmd_parms *parms, void *dummy,
		const char *arg)
{

	mod_config *cfg = (mod_config *)dummy;
	ap_get_module_config(parms->server->module_config, &spamhaus_module);

	cfg->methods = (char *)arg;
	return NULL;
}

static const char *num_cached_ip(cmd_parms *parms, void *dummy,
		 const char *arg)
{

	mod_config *cfg = (mod_config *)dummy;
	ap_get_module_config(parms->server->module_config, &spamhaus_module);
        int nInCache = atoi(arg);
	cfg->nip_incache = nInCache;

	if (cfg->nip_incache > MAX_CACHE_SIZE) cfg->nip_incache = MAX_CACHE_SIZE; 

	return NULL;
}

static const char *custom_err_cfg(cmd_parms *parms, void *dummy,
		const char *arg)
{

	mod_config *cfg = (mod_config *)dummy;
	ap_get_module_config(parms->server->module_config, &spamhaus_module);

	char *my_err = (char *)arg;
	cfg->c_err = my_err;
	return NULL;
}


static command_rec spamhaus_cmds[] = {

	AP_INIT_TAKE1("MS_Methods", looking_for, NULL, RSRC_CONF,"HTTP methods to monitor. Default Value: POST,PUT,OPTIONS"),
	AP_INIT_TAKE1("MS_Dns", dns_to_query, NULL, RSRC_CONF,"Blacklist name server (Default: sbl-xbl.spamhaus.org)"),
	AP_INIT_TAKE1("MS_WhiteList", white_list_conf, NULL, RSRC_CONF,"The path of your whitelist file"),
	AP_INIT_TAKE1("MS_CacheSize", num_cached_ip, NULL, RSRC_CONF,"Number of cache entries. Default:512 Max:8192"),
	AP_INIT_TAKE1("MS_CustomError", custom_err_cfg, NULL, RSRC_CONF,"Custom error message"),
	{NULL}
};

static int spamhaus_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
	ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
			MODULE_NAME " " MODULE_VERSION " started.");
	return OK;
}

static void register_hooks(apr_pool_t *p)
{

	ap_hook_post_config(spamhaus_init, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_access_checker(spamhaus_handler,NULL,NULL,APR_HOOK_MIDDLE);

}


module AP_MODULE_DECLARE_DATA spamhaus_module = {
	STANDARD20_MODULE_STUFF,
	spamhaus_create_dir_config, /* create per-dir config structures */
	NULL,                       /* merge  per-dir    config structures */
	spamhaus_create_config,  /* create per-server config structures */
	NULL,                       /* merge  per-server config structures */
	spamhaus_cmds,           /* table of config file commands       */
	register_hooks
};
