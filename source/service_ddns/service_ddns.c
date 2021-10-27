/*********************************************************************************
* Copyright 2021 Liberty Global B.V.

* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at

* http://www.apache.org/licenses/LICENSE-2.0

* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*********************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include "syscfg/syscfg.h"
#include "sysevent/sysevent.h"

#define TRACE_FILE "/tmp/ddns-general.trace"
#define RETRY_SOON_FILENAME "/etc/cron/cron.everyminute/ddns_retry.sh"
 
typedef enum {
    CLIENT_CONNECTING = 1,
    CLIENT_AUTHENTICATING = 2,
    CLIENT_UPDATED = 3,
    CLIENT_ERROR_MISCONFIGURED = 4,
    CLIENT_ERROR = 5,
    CLIENT_DISABLED = 6,
} client_status_t;

typedef enum {
    NO_ERROR = 1,
    MISCONFIGURATION_ERROR = 2,
    DNS_ERROR = 3,
    CONNECTION_ERROR = 4,
    AUTHENTICATION_ERROR = 5,
    TIMEOUT_ERROR = 6,
    PROTOCOL_ERROR = 7,
} client_lasterror_t;

typedef enum {
    HOST_REGISTERED = 1,
    HOST_UPDATE_NEEDED = 2,
    HOST_UPDATING = 3,
    HOST_ERROR = 4,
    HOST_DISABLED = 5,
} host_status_t;

enum {
    CHANGEIP = 0,
    NOIP,
    DYNDNS,
    DUCKDNS,
    AFRAID,
    SERVICE_LIMIT
};

static char *markers[][8] = {
    // name, register success, update success, hostname error, username error, password error, general error, token error
    { "changeip", "Successful Update", "Successful Update", "Hostname pattern does not exist", "badauth", "badauth", "", "" },
    { "no-ip", "good", "nochg", "nohost", "badauth", "badauth", "", "" },
    { "dyndns", "good", "nochg", "nohost", "badauth", "badauth", "", "" },
    { "duckdns", "OK", "", "", "", "", "KO", "" },
    { "afraid", "Updated", "has not changed", "", "", "", "Unable to locate this record", "" },
};

static char bin2hex (unsigned int a)
{
    a &= 0x0F;

    if ((a >= 0) && (a <= 9))
        return '0' + a;
    if ((a >= 10) && (a <= 15))
        return 'a' + (a - 10);
}

static int update_ddnsserver (void)
{
    char buf[64];
    char command[512];
    char *cmd;

    int i;
    int ret;
    int dslite_enable = 0;
    int dynamic_dns_enable = 0;
    char wan_ipaddr[64];

    int client_enable = 0;
    char client_username[64];
    char client_password[64];

    int host_enable = 0;
    char host_name[64];

    int server_index;
    int server_enabled = 0;
    int server_service;
    char server_servicename[16];

    token_t se_token;
    int se_fd = -1;

    struct timeval tv;
    time_t t;
    struct tm *info;

    char *return_status = "error";
    int ddns_return_status_success = 0;
    client_status_t client_status = CLIENT_ERROR;
    client_lasterror_t client_Lasterror = DNS_ERROR;
    host_status_t host_status_1 = HOST_ERROR;

    system ("touch /var/tmp/updating_ddns_server.txt");

    se_fd = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "service_ddns", &se_token);
    if (se_fd < 0) {
        printf("%s: FAILED to connect sysevent\n", __FUNCTION__);
        goto EXIT;
    }

    //set initializing status?
    //system("sysevent set ddns_return_status");
    //vsystem("sysevent set ddns_check_maxretries 0"); //TO DO
    //vsystem("sysevent set ddns_updated_time 0");
    //vsystem("sysevent set ddns_failure_time 0");

    /************************************************************************/

    strcpy (wan_ipaddr, "0.0.0.0");

    sysevent_get(se_fd, se_token, "current_wan_ipaddr", wan_ipaddr, sizeof(wan_ipaddr));

    syscfg_set(NULL, "wan_last_ipaddr", wan_ipaddr); //avoid service_check_interval from script ???

    if (strcmp(wan_ipaddr, "0.0.0.0") == 0) {
        printf("%s: FAILED because wan_ipaddr is %s\n", __FUNCTION__, wan_ipaddr);
        client_status = CLIENT_ERROR_MISCONFIGURED;
        client_Lasterror = MISCONFIGURATION_ERROR;
        goto EXIT;
    }

    printf("%s: wan_ipaddr is %s\n", __FUNCTION__, wan_ipaddr);

    /************************************************************************/

    syscfg_get("arddnsclient_1", "Server", command, sizeof(command));

    if (sscanf(command, "Device.DynamicDNS.Server.%d", &server_index) != 1) {
        printf("%s: FAILED because client_server undefined or invalid\n", __FUNCTION__);
        client_status = CLIENT_DISABLED;
        client_Lasterror = MISCONFIGURATION_ERROR;
        goto EXIT;
    }

    printf("%s: server_index is %d\n", __FUNCTION__, server_index);

    /************************************************************************/

    if (syscfg_get(NULL, "dslite_enable", command, sizeof(command)) == 0) {
        dslite_enable = atol(command);
    }
    if (dslite_enable != 0) {
        printf("%s: FAILED because %s is %d\n", __FUNCTION__, "dslite_enable", dslite_enable);
        client_status = CLIENT_DISABLED;
        client_Lasterror = MISCONFIGURATION_ERROR;
        goto EXIT;
    }

    /************************************************************************/

    if (syscfg_get(NULL, "dynamic_dns_enable", command, sizeof(command)) == 0) {
        dynamic_dns_enable = atol(command);
    }
    if (dynamic_dns_enable == 0) {
        printf("%s: FAILED because %s is %d\n", __FUNCTION__, "dynamic_dns_enable", dynamic_dns_enable);
        client_status = CLIENT_DISABLED;
        client_Lasterror = MISCONFIGURATION_ERROR;
        goto EXIT;
    }

    /************************************************************************/

    if (syscfg_get("arddnsclient_1", "enable", command, sizeof(command)) == 0) {
        client_enable = atol(command);
    }
    if (client_enable == 0) {
        printf("%s: FAILED because %s is %d\n", __FUNCTION__, "client_enable", client_enable);
        client_status = CLIENT_DISABLED;
        client_Lasterror = MISCONFIGURATION_ERROR;
        goto EXIT;
    }

    /************************************************************************/

    if (syscfg_get(NULL, "ddns_host_enable_1", command, sizeof(command)) == 0) {
        host_enable = atol(command);
    }
    if (host_enable == 0) {
        printf("%s: FAILED because %s is %d\n", __FUNCTION__, "host_enable", host_enable);
        client_status = CLIENT_DISABLED;
        client_Lasterror = MISCONFIGURATION_ERROR;
        goto EXIT;
    }

    /************************************************************************/

    if (syscfg_get(NULL, "ddns_host_enable_1", command, sizeof(command)) == 0) {
        host_enable = atol(command);
    }
    if (host_enable == 0) {
        printf("%s: FAILED because %s is %d\n", __FUNCTION__, "host_enable", host_enable);
        client_status = CLIENT_DISABLED;
        client_Lasterror = MISCONFIGURATION_ERROR;
        goto EXIT;
    }

    /************************************************************************/

    snprintf(buf, sizeof(buf), "ddns_server_enable_%d", server_index);

    if (syscfg_get (NULL, buf, command, sizeof(command)) == 0) {
        server_enabled = atol(command);
    }
    if (server_enabled == 0) {
        printf("%s: FAILED because %s is %d\n", __FUNCTION__, "server_enabled", server_enabled);
        client_status = CLIENT_DISABLED;
        client_Lasterror = MISCONFIGURATION_ERROR;
        goto EXIT;
    }

    /************************************************************************/

    snprintf(buf, sizeof(buf), "ddns_server_servicename_%d", server_index);

    syscfg_get(NULL, buf, server_servicename, sizeof(server_servicename));

    printf("%s: server_servicename %s\n", __FUNCTION__, server_servicename);

    server_service = -1;
    for (i = 0; i < SERVICE_LIMIT; i++) {
        if (strcmp (server_servicename, markers[i][0]) == 0) {
            server_service = i;
            break;
        }
    }
    if (server_service == -1) {
        printf("%s: FAILED because server_servicename is invalid\n", __FUNCTION__);
        client_status = CLIENT_ERROR_MISCONFIGURED;
        client_Lasterror = MISCONFIGURATION_ERROR;
        goto EXIT;
    }

    /************************************************************************/

    syscfg_get("arddnsclient_1", "Username", client_username, sizeof(client_username));

    printf("%s: client_username %s\n", __FUNCTION__, client_username);

    if (client_username[0] == 0) {
        printf("%s: FAILED because client_username %s\n", __FUNCTION__, "undefined");
        client_Lasterror = AUTHENTICATION_ERROR;
        return_status = "error-auth";
        goto EXIT;
    }

    if ((server_service == NOIP) && (strchr (client_username, '@'))) {
        printf("%s: FAILED because client_username %s\n", __FUNCTION__, "contains '@' for no-ip");
        client_Lasterror = AUTHENTICATION_ERROR;
        return_status = "error-auth";
        goto EXIT;
    }

    /************************************************************************/

    syscfg_get(NULL, "ddns_host_name_1", host_name, sizeof(host_name));

    printf("%s: host_name %s\n", __FUNCTION__, host_name);

    if (host_name[0] == 0) {
        printf("%s: FAILED because hostname %s\n", __FUNCTION__, "undefined");
        goto EXIT;
    }

    /************************************************************************/

    // Read and encode password (except for duckdns, which does not use a password)

    client_password[0] = 0;

    if (server_service != DUCKDNS)
    {
        char inch;
        char *s, *d;
        int space_available;

        syscfg_get("arddnsclient_1", "Password", command, sizeof(command));

        if (command[0] == 0) {
            printf("%s: FAILED client_password %s\n", __FUNCTION__, "undefined");
            client_Lasterror = AUTHENTICATION_ERROR;
            return_status = "error-auth";
            goto EXIT;
        }

        s = command;
        d = client_password;
        space_available = sizeof(client_password) - 1;

        // https://www.urlencoder.io/

        while (1) {
            if ((inch = *s++) == 0)
                break;

            if ((!((inch >= '0') && (inch <= '9'))) &&
                (!((inch >= 'a') && (inch <= 'z'))) &&
                (!((inch >= 'A') && (inch <= 'Z'))) &&
                (inch != '-') &&
                (inch != '_') &&
                (inch != '.') &&
                (inch != '~'))
            {
                if (space_available < 3)
                    break;
                *d++ = '%';
                *d++ = bin2hex(inch >> 4);
                *d++ = bin2hex(inch & 0x0F);
                space_available -= 3;
            }
            else {
                if (space_available < 1)
                    break;
                *d++ = inch;
                space_available -= 1;
            }
        }

        *d = 0;
    }

    /************************************************************************/

    // create the command line

    cmd = command;
    cmd += sprintf(cmd, "rm -f /var/tmp/ipupdate.%s ; /usr/bin/curl --interface erouter0 -o /var/tmp/ipupdate.%s ", server_servicename, server_servicename);

    if (server_service == CHANGEIP)
        cmd += sprintf(cmd, "--url 'http://nic.changeip.com/nic/update?u=%s&p=%s&hostname=%s&ip=%s'", client_username, client_password, host_name, wan_ipaddr);
    else if (server_service == NOIP)
        cmd += sprintf(cmd, "--url 'http://%s:%s@dynupdate.no-ip.com/nic/update?hostname=%s&myip=%s'", client_username, client_password, host_name, wan_ipaddr);
    else if (server_service == DYNDNS)
        cmd += sprintf(cmd, "--user %s:%s --url 'http://members.dyndns.org/nic/update?hostname=%s&myip=%s'", client_username, client_password, host_name, wan_ipaddr);
    else if (server_service == DUCKDNS)
        cmd += sprintf(cmd, "-g --insecure --url 'https://www.duckdns.org/update?domains=%s&token=%s&ip=%s&verbose=true'", host_name, client_username, wan_ipaddr);
    else if (server_service == AFRAID)
        cmd += sprintf(cmd, "--user %s:%s --insecure --url 'https://freedns.afraid.org/nic/update?hostname=%s&myip=%s'", client_username, client_password, host_name, wan_ipaddr);
    else
        goto EXIT;

    cmd += sprintf(cmd, " --trace-ascii %s >/dev/null 2>&1", TRACE_FILE);

    printf("%s: command %s\n", __FUNCTION__, command);

    // Execute command + analyze result and set syscfg ddns_client_Lasterror / sysevent ddns_return_status here based on the error etc

    ret = system(command);

    if (ret == 0) {
        FILE *output_file;

        printf("%s: servicename %s command %s\n", __FUNCTION__, server_servicename, "succeeded");

        sprintf(buf, "/var/tmp/ipupdate.%s", server_servicename);
        output_file = fopen(buf, "r");
        if (output_file == NULL) {
            printf("%s: failed to open %s\n", __FUNCTION__, buf);
            goto EXIT;
        }

        char *register_success = markers[server_service][1];
        char *update_success = markers[server_service][2];
        char *hostname_error = markers[server_service][3];
        char *username_error = markers[server_service][4];
        char *password_error = markers[server_service][5];
        char *general_error = markers[server_service][6];
        char *token_error = markers[server_service][7];

        while (fgets (command, sizeof(command), output_file) != NULL) {

            if (register_success[0] && strstr(command, register_success)) {
                  printf("%s: found %s in %s\n", __FUNCTION__, "register_success", buf);
                  ddns_return_status_success = 1;
                  break;
            }
            else if (update_success[0] && strstr(command, update_success)) {
                  printf("%s: found %s in %s\n", __FUNCTION__, "update_success", buf);
                  ddns_return_status_success = 1;
                  break;
            }
            else if (hostname_error[0] && strstr(command, hostname_error)) {
                  printf("%s: found %s in %s\n", __FUNCTION__, "hostname_error", buf);
                  client_Lasterror = MISCONFIGURATION_ERROR;
            }
            else if (username_error[0] && strstr(command, username_error)) {
                  printf("%s: found %s in %s\n", __FUNCTION__, "username_error", buf);
                  client_Lasterror = AUTHENTICATION_ERROR;
                  return_status = "error-auth";
            }
            else if (password_error[0] && strstr(command, password_error)) {
                  printf("%s: found %s in %s\n", __FUNCTION__, "password_error", buf);
                  client_Lasterror = AUTHENTICATION_ERROR;
                  return_status = "error-auth";
            }
            else if (general_error[0] && strstr(command, general_error)) {
                  printf("%s: found %s in %s\n", __FUNCTION__, "general_error", buf);
                  client_Lasterror = AUTHENTICATION_ERROR;
                  return_status = "error-auth";
            }
            else if (token_error[0] && strstr(command, token_error)) {
                  printf("%s: found %s in %s\n", __FUNCTION__, "token_error", buf);
                  client_Lasterror = AUTHENTICATION_ERROR;
                  return_status = "error-auth";
            }
            else {
                  printf("%s: didn't find expected result in %s\n", __FUNCTION__, buf);
                  client_Lasterror = AUTHENTICATION_ERROR;
                  return_status = "error-auth";
            }
        }

        fclose(output_file);
    }
    else {
        FILE *output_file;

        printf("%s: servicename %s command %s\n", __FUNCTION__, server_servicename, "failed");

        output_file = fopen(TRACE_FILE, "r");
        if (output_file == NULL) {
             printf("%s: failed to open %s\n", __FUNCTION__, TRACE_FILE);
             goto EXIT;
        }

        while (fgets(command, sizeof(command), output_file) != NULL) {

             if (strstr(command, "Failed to connect to")) {
                 printf("%s: found '%s' error in %s\n", __FUNCTION__, "Failed to connect to", TRACE_FILE);
                 client_Lasterror = CONNECTION_ERROR;
                 return_status = "error-connect";
             }
             else if (strstr(command, "connect fail")) {
                 printf("%s: found '%s' error in %s\n", __FUNCTION__, "connect fail", TRACE_FILE);
                 client_Lasterror = CONNECTION_ERROR;
                 return_status = "error-connect";
             }
             else if (strstr(command, "Couldn't resolve host")) {
                 printf("%s: found '%s' error in %s\n", __FUNCTION__, "Couldn't resolve host", TRACE_FILE);
                 client_Lasterror = CONNECTION_ERROR;
             }
             else {
                 printf("%s: no error keywords found in %s\n", __FUNCTION__, TRACE_FILE);
                 client_Lasterror = CONNECTION_ERROR;
             }
        }

        fclose(output_file);
    }

EXIT:

    if (ddns_return_status_success) {
        client_status = CLIENT_UPDATED;
        client_Lasterror = NO_ERROR;
        host_status_1 = HOST_REGISTERED;
        return_status = "success";
    }

    printf("%s: ddns_return_status_success %d return_status %s, client_status %d, host_status_1 %d, client_Lasterror %d\n", __FUNCTION__, ddns_return_status_success, return_status, client_status, host_status_1, client_Lasterror);

    snprintf(buf, sizeof(buf), "ddns_return_status%d", server_index);
    sysevent_set(se_fd, se_token, buf, return_status, 0);
    sysevent_set(se_fd, se_token, "ddns_return_status", return_status, 0);

    syscfg_set_u (NULL, "ddns_client_Status", client_status);
    syscfg_set_u (NULL, "ddns_client_Lasterror", client_Lasterror);
    syscfg_set_u (NULL, "ddns_host_status_1", host_status_1);

    gettimeofday(&tv, NULL);
    t = tv.tv_sec;
    info = localtime(&t);
    strftime (buf, sizeof(buf), "%m:%d:%y_%H:%M:%S\n", info); //format: 04:09:21_22:15:43

    if (ddns_return_status_success) {
        printf("%s: ddns_return_status_success, update status", __FUNCTION__);

        sysevent_set(se_fd, se_token, "ddns_failure_time", "0", 0);
        sysevent_set(se_fd, se_token, "ddns_updated_time", buf, 0);

        syscfg_set(NULL, "ddns_host_lastupdate_1", buf);
        
        /* Remove retry file  if update success and file exist */
        if (!access(RETRY_SOON_FILENAME, F_OK )) {
            unlink(RETRY_SOON_FILENAME);
        }

        printf("%s: return 0 because everything looks good\n", __FUNCTION__);
        ret = 0;
    }
    else {
        sysevent_set(se_fd, se_token, "ddns_failure_time", buf, 0);
        sysevent_set(se_fd, se_token, "ddns_updated_time", "0", 0);

        printf("%s: return -1 because curl command return !0 or found error message in output file\n", __FUNCTION__);

        if (!strcmp(return_status,"error-connect")) {
           /* Create retry file in cron.everyminute if file not exist.
              else decrement the retry count till it reach maxretries.
              Remove the file once it reach maxretries.
           */
           int max_retry_count = 0;
           if (!access(RETRY_SOON_FILENAME, F_OK )) {
              memset(buf, 0, sizeof(buf));
              syscfg_get(NULL,"max_retry_count",buf,sizeof(buf));
              max_retry_count = atol (buf);
              if (max_retry_count > 0) {
                  max_retry_count--;
                  syscfg_set_u(NULL,"max_retry_count", max_retry_count);
              } 
              else {
                  unlink(RETRY_SOON_FILENAME);
              }
           } 
           else {
             FILE *fp = NULL;
             fp = fopen(RETRY_SOON_FILENAME,"w");
             if (fp != NULL) {
                fprintf(fp,"#! /bin/sh\n");
                fprintf(fp,"/usr/bin/service_ddns restart &\n");
                fclose(fp);
             }
             sprintf(command,"chmod 777 %s",RETRY_SOON_FILENAME);
             system (command);
             int max_retries = 0;
             sprintf(command,"ddns_server_maxretries_%d",server_index);
             syscfg_get( NULL, command, buf, sizeof(buf));
             max_retries = atol(buf);
             syscfg_set_u(NULL,"max_retry_count", max_retries);
           }

        }
        else {
          /* Remove retry file  if error is not error-connect and file exist */
          if (!access(RETRY_SOON_FILENAME, F_OK )) {
              unlink(RETRY_SOON_FILENAME);
          }
        }
        ret = -1;
    }
    syscfg_commit();

    if (unlink("/var/tmp/updating_ddns_server.txt") != 0)
       ret = -1;

    return ret;

}

int main (int argc, char *argv[])
{
    int retval = 0;

    if (argc < 2)
    {
        printf("DDNS:Not enough parameters\n");
        exit (1);
    }

    if (strcmp(argv[1], "restart") == 0)
    {
        retval = update_ddnsserver();
    }

    return retval;
}
