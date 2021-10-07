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
#include <time.h>
#include "syscfg/syscfg.h"
#include "sysevent/sysevent.h"

#define COMMAND_BUFFER_LENGTH 512
#define FUNC_NAME "update_ddns_server"
//#CLIENT Status
#define CLIENT_CONNECTING 1
#define CLIENT_AUTHENTICATING 2
#define CLIENT_UPDATED 3
#define CLIENT_ERROR_MISCONFIGURED 4
#define CLIENT_ERROR 5
#define CLIENT_DISABLED 6

//#LAST Error Status
#define NO_ERROR 1
#define MISCONFIGURATION_ERROR 2
#define DNS_ERROR 3
#define CONNECTION_ERROR 4
#define AUTHENTICATION_ERROR 5
#define TIMEOUT_ERROR 6
#define PROTOCOL_ERROR 7

//#Host Status
#define HOST_REGISTERED 1
#define HOST_UPDATE_NEEDED 2
#define HOST_UPDATING 3
#define HOST_ERROR 4
#define HOST_DISABLED 5

#define FALSE 0
#define TRUE  1

//For other service except dyndns: when curl command return !0, search the keywords in GENERAL_FILE /tmp/ddns-general.trace
#define RESOLVE_ERRO "Couldn't resolve host"
#define CONNECTING1_ERROR "Failed to connect to"
#define CONNECTING2_ERROR "connect fail"

#define GENERAL_FILE "/tmp/ddns-general.trace"
#define OUTPUT_FILE "/var/tmp/ipupdate.out"
#define UPDATING_CHECK_FILE "/var/tmp/updating_ddns_server.txt"
//For other service except dyndns: when curl command return 0 searching keywords in /var/tmp/ipupdate.'$server_servicename'
//changeip
#define REGISTER_SUCCESS_changeip "Successful Update"
#define UPDATE_SUCCESS_changeip "Successful Update"
#define HOSTNAME_ERROR_changeip "Hostname pattern does not exist"
#define USERNAME_ERROR_changeip "badauth"
#define PASSWORD_ERROR_changeip "badauth"
#define GENERAL_ERROR_changeip ""
#define TOKEN_ERROR_changeip ""

//no-ip
#define REGISTER_SUCCESS_noip "good"
#define UPDATE_SUCCESS_noip "nochg"
#define HOSTNAME_ERROR_noip "nohost"
#define USERNAME_ERROR_noip "badauth"
#define PASSWORD_ERROR_noip "badauth"
#define GENERAL_ERROR_noip ""
#define TOKEN_ERROR_noip ""

//dyndns
#define REGISTER_SUCCESS_dyndns "good"
#define UPDATE_SUCCESS_dyndns "nochg"
#define HOSTNAME_ERROR_dyndns "nohost"
#define USERNAME_ERROR_dyndns "badauth"
#define PASSWORD_ERROR_dyndns "badauth"
#define GENERAL_ERROR_dyndns ""
#define TOKEN_ERROR_dyndns ""

//duckdns
#define REGISTER_SUCCESS_duckdns "OK"
#define UPDATE_SUCCESS_duckdns ""
#define HOSTNAME_ERROR_duckdns ""
#define USERNAME_ERROR_duckdns ""
#define PASSWORD_ERROR_duckdns ""
#define GENERAL_ERROR_duckdns "KO"
#define TOKEN_ERROR_duckdns ""

//afraid,
#define REGISTER_SUCCESS_afraid "Updated"
#define UPDATE_SUCCESS_afraid "has not changed"
#define HOSTNAME_ERROR_afraid ""
#define USERNAME_ERROR_afraid ""
#define PASSWORD_ERROR_afraid ""
#define GENERAL_ERROR_afraid "Unable to locate this record"
#define TOKEN_ERROR_afraid ""

#define REGISTER_SUCCESS(x) REGISTER_SUCCESS_##x
#define UPDATE_SUCCESS(x) UPDATE_SUCCESS_##x
#define HOSTNAME_ERROR(x) HOSTNAME_ERROR_##x
#define USERNAME_ERROR(x) USERNAME_ERROR_##x
#define PASSWORD_ERROR(x) PASSWORD_ERROR_##x
#define GENERAL_ERROR(x) GENERAL_ERROR_##x
#define TOKEN_ERROR(x) TOKEN_ERROR_##x


static char register_success(char *service_name, char *buf)
{
    if(0 == strcmp(service_name,"changeip")) {
        strcpy(buf,REGISTER_SUCCESS(changeip));
    } else if(0 == strcmp(service_name,"no-ip")) {
        strcpy(buf,REGISTER_SUCCESS(noip));
    } else if(0 == strcmp(service_name,"dyndns")) {
        strcpy(buf,REGISTER_SUCCESS(dyndns));
    } else if(0 == strcmp(service_name,"duckdns")) {
        strcpy(buf,REGISTER_SUCCESS(duckdns));
    } else if(0 == strcmp(service_name,"afraid")) {
        strcpy(buf,REGISTER_SUCCESS(afraid));
    }
    return buf[0];
}

static char update_success(char *service_name, char *buf)
{
    if(0 == strcmp(service_name,"changeip")) {
        strcpy(buf, UPDATE_SUCCESS(changeip));
    } else if(0 == strcmp(service_name,"no-ip")) {
        strcpy(buf, UPDATE_SUCCESS(noip));
    } else if(0 == strcmp(service_name,"dyndns")) {
        strcpy(buf, UPDATE_SUCCESS(dyndns));
    } else if(0 == strcmp(service_name,"duckdns")) {
        strcpy(buf, UPDATE_SUCCESS(duckdns));
    } else if(0 == strcmp(service_name,"afraid")) {
        strcpy(buf, UPDATE_SUCCESS(afraid));
    }
    return buf[0];
}

static char hostname_error(char *service_name, char *buf)
{
    if(0 == strcmp(service_name,"changeip")) {
        strcpy(buf, HOSTNAME_ERROR(changeip));
    } else if(0 == strcmp(service_name,"no-ip")) {
        strcpy(buf, HOSTNAME_ERROR(noip));
    } else if(0 == strcmp(service_name,"dyndns")) {
        strcpy(buf, HOSTNAME_ERROR(dyndns));
    } else if(0 == strcmp(service_name,"duckdns")) {
        strcpy(buf, HOSTNAME_ERROR(duckdns));
    } else if(0 == strcmp(service_name,"afraid")) {
        strcpy(buf, HOSTNAME_ERROR(afraid));
    }
    return buf[0];
}

static char username_error(char *service_name, char *buf)
{
    if(0 == strcmp(service_name,"changeip")) {
        strcpy(buf, USERNAME_ERROR(changeip));
    } else if(0 == strcmp(service_name,"no-ip")) {
        strcpy(buf, USERNAME_ERROR(noip));
    } else if(0 == strcmp(service_name,"dyndns")) {
        strcpy(buf, USERNAME_ERROR(dyndns));
    } else if(0 == strcmp(service_name,"duckdns")) {
        strcpy(buf, USERNAME_ERROR(duckdns));
    } else if(0 == strcmp(service_name,"afraid")) {
        strcpy(buf, USERNAME_ERROR(afraid));
    }
    return buf[0];
}

static char password_error(char *service_name, char *buf)
{
    if(0 == strcmp(service_name,"changeip")) {
        strcpy(buf, PASSWORD_ERROR(changeip));
    } else if(0 == strcmp(service_name,"no-ip")) {
        strcpy(buf, PASSWORD_ERROR(noip));
    } else if(0 == strcmp(service_name,"dyndns")) {
        strcpy(buf, PASSWORD_ERROR(dyndns));
    } else if(0 == strcmp(service_name,"duckdns")) {
        strcpy(buf, PASSWORD_ERROR(duckdns));
    } else if(0 == strcmp(service_name,"afraid")) {
        strcpy(buf, PASSWORD_ERROR(afraid));
    }
    return buf[0];
}

static char general_error(char *service_name, char *buf)
{
    if(0 == strcmp(service_name,"changeip")) {
        strcpy(buf, GENERAL_ERROR(changeip));
    } else if(0 == strcmp(service_name,"no-ip")) {
        strcpy(buf, GENERAL_ERROR(noip));
    } else if(0 == strcmp(service_name,"dyndns")) {
        strcpy(buf, GENERAL_ERROR(dyndns));
    } else if(0 == strcmp(service_name,"duckdns")) {
        strcpy(buf, GENERAL_ERROR(duckdns));
    } else if(0 == strcmp(service_name,"afraid")) {
        strcpy(buf, GENERAL_ERROR(afraid));
    }
    return buf[0];
}

static char token_error(char *service_name, char *buf)
{
    if(0 == strcmp(service_name,"changeip")) {
        strcpy(buf, TOKEN_ERROR(changeip));
    } else if(0 == strcmp(service_name,"no-ip")) {
        strcpy(buf, TOKEN_ERROR(noip));
    } else if(0 == strcmp(service_name,"dyndns")) {
        strcpy(buf, TOKEN_ERROR(dyndns));
    } else if(0 == strcmp(service_name,"duckdns")) {
        strcpy(buf, TOKEN_ERROR(duckdns));
    } else if(0 == strcmp(service_name,"afraid")) {
        strcpy(buf, TOKEN_ERROR(afraid));
    }
    return buf[0];
}

static char bin2hex (unsigned int a)
{
    a &= 0x0F;

    if ((a >= 0) && (a <= 9))
        return '0' + a;
    if ((a >= 10) && (a <= 15))
        return 'a' + (a - 10);
}

static int update_ddnsserver(void)
{
    int ret;
    char command[COMMAND_BUFFER_LENGTH],buf[128];

    int dslite_enable=1;
    int dynamic_dns_enable=0;

    int client_enable=0;
    char client_username[64]={0};
    char client_password[64]={0};
    char client_server[64]={0};

    int host_enable=0;
    char host_name[64]={0};

    int server_enabled=0;
    char server_servicename[64]={0};
    int server_index;

    char wan_ipaddr[64]="0.0.0.0";

    token_t se_token;
    int     se_fd = -1;

    struct timeval tv;
    time_t t;
    struct tm *info;

    FILE *output_file;

    int ddns_return_status_success = FALSE;
    char client_status = 0;
    char host_status_1 = 0;
    char client_Lasterror = 0;
    char return_status[16]={0};

    sprintf(buf, "touch %s",UPDATING_CHECK_FILE);
    system(buf);
    memset(buf, 0, sizeof(buf));

    se_fd =  sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, "service_ddns", &se_token);
    if (se_fd < 0) {
        printf("%s: FAILED to connect sysevent\n",FUNC_NAME);
        ddns_return_status_success = FALSE;
        goto EXIT;
    }
    //set initializing status?
    //system("sysevent set ddns_return_status");
    //vsystem("sysevent set ddns_check_maxretries 0"); //TO DO
    //vsystem("sysevent set ddns_updated_time 0");
    //vsystem("sysevent set ddns_failure_time 0");

    //get and check wan ip address
    sysevent_get(se_fd, se_token, "current_wan_ipaddr", wan_ipaddr, sizeof(wan_ipaddr));
    syscfg_set(NULL, "wan_last_ipaddr",wan_ipaddr); //avoid service_check_interval from script
    if(0==strcmp(wan_ipaddr, "0.0.0.0")) {
        ddns_return_status_success = FALSE;
        client_status = CLIENT_ERROR_MISCONFIGURED;
        host_status_1 = HOST_ERROR;
        client_Lasterror = MISCONFIGURATION_ERROR;
        printf("%s: FAILED because wan_ipaddr is 0.0.0.0\n",FUNC_NAME);
        goto EXIT;
    }
    printf("%s 8: wan_ipaddr is %s\n",FUNC_NAME,wan_ipaddr);

    if(syscfg_get( "arddnsclient_1", "Server", client_server, sizeof(client_server)) == 0) {
        printf("%s 1: client_server %s\n",FUNC_NAME,client_server);
    }

    if (sscanf(client_server,"Device.DynamicDNS.Server.%d",&server_index) != 1) {
        ddns_return_status_success = FALSE;
        client_status = CLIENT_DISABLED;
        host_status_1 = HOST_ERROR;
        client_Lasterror = MISCONFIGURATION_ERROR;
        printf("%s: FAILED because client_server is NULL or wrong format\n",FUNC_NAME);
        goto EXIT;
    }
    printf("%s: 2: server_index is %d\n",FUNC_NAME,server_index);

    //get and check if dslite, dynamic_dns, client, server, host are enabled.
    //get and check if server is set to client.
    if(syscfg_get( NULL, "dslite_enable", command, sizeof(command)) == 0) {
        dslite_enable = atol(command);
    }
    else {
        dslite_enable = 0;
    }
    printf("%s: 3: dslite_enable %d\n",FUNC_NAME,dslite_enable);

    if(syscfg_get( NULL, "dynamic_dns_enable", command, sizeof(command)) == 0) {
        dynamic_dns_enable = atol(command);
        printf("%s 4: dynamic_dns_enable %d\n",FUNC_NAME,dynamic_dns_enable);
    }
    if(syscfg_get( "arddnsclient_1", "enable", command, sizeof(command)) == 0) {
        client_enable = atol(command);
        printf("%s 5: client_enable %d\n",FUNC_NAME,client_enable);
    }
    if(syscfg_get( NULL, "ddns_host_enable_1", buf, sizeof(buf)) == 0) {
        host_enable = atol(buf);
        printf("%s 6: host_enable %d\n",FUNC_NAME,host_enable);
    }
    sprintf(command,"ddns_server_enable_%d",server_index);
    if(syscfg_get( NULL, command, buf, sizeof(buf)) == 0) {
        server_enabled = atol(buf);
        printf("%s 7: server_enabled %d\n",FUNC_NAME,server_enabled);
    }

    if((dslite_enable == 1) || (dynamic_dns_enable == 0) || (client_enable == 0) || (host_enable == 0) || (server_enabled == 0)) {
        printf("%s: FAILED because dslite_enable is %d\n or dynamic_dns_enable is %d\n or server_enabled %d\n or host_enable %d\n",FUNC_NAME,dslite_enable,dynamic_dns_enable,server_enabled,host_enable);
        ddns_return_status_success = FALSE;
        client_status = CLIENT_DISABLED;
        host_status_1 = HOST_ERROR;
        client_Lasterror = MISCONFIGURATION_ERROR;
        goto EXIT;
    }

    //get and check Server.Name
    sprintf(command,"ddns_server_servicename_%d",server_index);
    if(syscfg_get( NULL, command, server_servicename, sizeof(server_servicename)) == 0) { //1:no-ip 2:dyndns 3:duckdns 4:afraid 5:changeip
        printf("%s 12: server_servicename %s\n",FUNC_NAME,server_servicename);
    }
    if(server_servicename[0] == '\0') {
        printf("%s: FAILED because server_servicename is NULL\n",FUNC_NAME);
        ddns_return_status_success = FALSE;
        client_status = CLIENT_ERROR_MISCONFIGURED;
        host_status_1 = HOST_ERROR;
        client_Lasterror = MISCONFIGURATION_ERROR;
        goto EXIT;
    }



    //get and check Client.Username
    if(syscfg_get( "arddnsclient_1", "Username", client_username, sizeof(client_username)) == 0) {
        printf("%s 9: client_username %s\n",FUNC_NAME,client_username);
    }

    /*Throw Authentication error if the username is NULL or username contains '@' for no-ip*/
    if((client_username[0] == '\0')|| ((!strcmp(server_servicename,"no-ip"))&& (strchr(client_username,'@')))) {
        printf("%s: FAILED because client_username is NULL or username contains '@' for no-ip\n",FUNC_NAME);
        ddns_return_status_success = FALSE;
        client_status = CLIENT_ERROR;
        host_status_1 = HOST_ERROR;
        client_Lasterror = AUTHENTICATION_ERROR;
        strcpy(return_status,"error-auth");
        goto EXIT;
    }

    /*Do password validation if the service is not duckdns. Duckdns not required any password for login*/
    if(strcmp(server_servicename,"duckdns")) {
        if(syscfg_get( "arddnsclient_1", "Password", client_password, sizeof(client_password)) == 0) {
            int i,j;
            char pwd;
            size_t len = strlen(client_password);
            j=0;
            command[0] = '\0';
            for(i=0;i<len;i++){
                pwd = client_password[i];
                if((pwd!='-') && (pwd != '_') && (pwd!='.') && (pwd!='~') && (!((pwd>='0')&&(pwd<='9'))) && (!((pwd>='A')&&(pwd<='Z'))) && (!((pwd>='a')&&(pwd<='z')))) {
                    command[j] = '%';
                    command[j+1] = bin2hex(pwd >> 4);
                    command[j+2] = bin2hex(pwd & 0x0F);
                    command[j+3] = 0;
                    j+=3;
                } else {
                    command[j] = pwd;
                    command[j+1] = '\0';
                    j++;
                }
            }
            strcpy(client_password, command);
        }
        if(client_password[0] == '\0') {
            printf("%s: FAILED because client_password is NULL \n",FUNC_NAME);
            ddns_return_status_success = FALSE;
            client_status = CLIENT_ERROR;
            host_status_1 = HOST_ERROR;
            client_Lasterror = AUTHENTICATION_ERROR;
            strcpy(return_status,"error-auth");
            goto EXIT;
        }
    }

    //get and check Host.hostname
    if(syscfg_get( NULL, "ddns_host_name_1", host_name, sizeof(host_name)) == 0) {
        printf("%s 11: host_name %s\n",FUNC_NAME,host_name);
    }
    if(host_name[0] == '\0') {
        printf("%s: FAILED because hostname is NULL\n",FUNC_NAME);
        ddns_return_status_success = FALSE;
        client_status = CLIENT_ERROR;
        host_status_1 = HOST_ERROR;
        client_Lasterror = DNS_ERROR;
        goto EXIT;
    }

    //remove ipupdate.$server_servicename
    sprintf(command," rm /var/tmp/ipupdate.%s",server_servicename);
    system(command);

    //create the command line
    if(strcmp(server_servicename,"changeip") == 0) {
        sprintf(command,"/usr/bin/curl --interface erouter0 -o /var/tmp/ipupdate.%s --url 'http://nic.changeip.com/nic/update?u=%s&p=%s&hostname=%s&ip=%s' --trace-ascii %s > %s 2>&1",
                server_servicename,client_username,client_password,host_name,wan_ipaddr,GENERAL_FILE,OUTPUT_FILE);
    } else if (strcmp(server_servicename,"dyndns") == 0) {
        sprintf(command, "/usr/bin/curl --interface erouter0 -o /var/tmp/ipupdate.%s --user %s:%s --url 'http://members.dyndns.org/nic/update?hostname=%s&myip=%s' --trace-ascii %s > %s 2>&1",
                server_servicename,client_username,client_password,host_name,wan_ipaddr,GENERAL_FILE,OUTPUT_FILE);
    } else if (strcmp(server_servicename,"afraid") == 0) {
        sprintf(command, "/usr/bin/curl --interface erouter0 -o /var/tmp/ipupdate.%s --user %s:%s --insecure --url 'https://freedns.afraid.org/nic/update?hostname=%s&myip=%s' --trace-ascii %s > %s 2>&1",
                server_servicename,client_username,client_password,host_name,wan_ipaddr,GENERAL_FILE,OUTPUT_FILE);
    } else if(strcmp(server_servicename,"no-ip") == 0) {
        sprintf(command,"/usr/bin/curl --interface erouter0 -o /var/tmp/ipupdate.%s --url 'http://%s:%s@dynupdate.no-ip.com/nic/update?hostname=%s&myip=%s' --trace-ascii %s > %s 2>&1",
                server_servicename,client_username,client_password,host_name,wan_ipaddr,GENERAL_FILE,OUTPUT_FILE);
    } else if(strcmp(server_servicename,"duckdns")==0) {
        sprintf(command, "/usr/bin/curl --interface erouter0 -o /var/tmp/ipupdate.%s -g --insecure --url 'https://www.duckdns.org/update?domains=%s&token=%s&ip=%s&verbose=true' --trace-ascii %s > %s 2>&1",
                server_servicename,host_name,client_username,wan_ipaddr,GENERAL_FILE,OUTPUT_FILE);
    }
    printf("%s: servicename %s\n, command is %s\n",FUNC_NAME,server_servicename,command);

    //execute command
    ret = system(command);

    //analyze the result of command and set syscfg ddns_client_Lasterror / sysevent ddns_return_status here based on the error
    if(0 == ret) { ///usr/bin/curl succeed
        printf("%s: servicename %s command succeed\n",FUNC_NAME,server_servicename);

        sprintf(buf, "/var/tmp/ipupdate.%s",server_servicename);
        output_file = fopen(buf, "r");
        if (output_file == NULL) {
            ddns_return_status_success = FALSE;
            client_Lasterror = DNS_ERROR;
            strcpy(return_status,"error");
            printf("%s: failed to open %s\n",FUNC_NAME, buf);
            goto EXIT;
        }
        while(fgets(command,COMMAND_BUFFER_LENGTH, output_file) != NULL) {
            if((register_success(server_servicename,buf) && strstr(command, buf))
                 || (update_success(server_servicename,buf) && strstr(command, buf))) {
                  printf("%s: found succeed register_success or update_success string in file /var/tmp/ipupdate.%s\n",FUNC_NAME,server_servicename);
                  ddns_return_status_success = TRUE;
                  break;
            } else if(hostname_error(server_servicename,buf) && strstr(command, buf)) {
                  printf("%s: found hostname_error string in file /var/tmp/ipupdate.%s\n",FUNC_NAME,server_servicename);
                  ddns_return_status_success = FALSE;
                  client_Lasterror = MISCONFIGURATION_ERROR;
                  strcpy(return_status,"error");
            } else if((username_error(server_servicename,buf) && strstr(command, buf))
                  || (password_error(server_servicename,buf) && strstr(command, buf))
                  || (general_error(server_servicename,buf) && strstr(command, buf))
                  || (token_error(server_servicename,buf) && strstr(command, buf))
				|| (strstr(command, "KO"))) {
                  printf("%s: found username_error or password_error or general_error or token_error string in file /var/tmp/ipupdate.%s\n",FUNC_NAME,server_servicename);
                  ddns_return_status_success = FALSE;
                  client_Lasterror = AUTHENTICATION_ERROR;
                  strcpy(return_status,"error-auth");
            } else {
                  ddns_return_status_success = FALSE;
                  printf("%s: didn't find expected result in file /var/tmp/ipupdate.%s\n",FUNC_NAME,server_servicename);
                  client_Lasterror = AUTHENTICATION_ERROR;
                  strcpy(return_status,"error-auth");
            }
        }
        fclose(output_file);
    } else {    ///usr/bin/curl failed
        printf("%s: servicename %s command failed\n",FUNC_NAME,server_servicename);
        ddns_return_status_success = FALSE;

        output_file = fopen(GENERAL_FILE, "r");
        if (output_file == NULL) {
             client_Lasterror = DNS_ERROR;
             strcpy(return_status,"error");
             printf("%s: failed to open %s\n",FUNC_NAME, GENERAL_FILE);
             goto EXIT;
        }
        while(fgets(command,COMMAND_BUFFER_LENGTH, output_file) != NULL) {
             if((strstr(command, CONNECTING1_ERROR)) || (strstr(command, CONNECTING2_ERROR))) {
                 printf("%s: found error %s or %s in file %s\n",FUNC_NAME,CONNECTING1_ERROR,CONNECTING2_ERROR, GENERAL_FILE);
                 client_Lasterror = CONNECTION_ERROR;
                 strcpy(return_status,"error-connect");
             } else {
                 printf("%s: found error %s or no keyword in file %s\n",FUNC_NAME,RESOLVE_ERRO,GENERAL_FILE);
                 client_Lasterror = CONNECTION_ERROR;
                 strcpy(return_status,"error");
             }
        }
        fclose(output_file);
    }
 
EXIT:

    if(ddns_return_status_success == TRUE) {
        client_status = CLIENT_UPDATED;
        host_status_1 = HOST_REGISTERED;
        client_Lasterror = NO_ERROR;
        strcpy(return_status,"success");
    }

    sprintf(command, "ddns_return_status%d",server_index);
    if(return_status[0] == 0) {
        sysevent_set(se_fd, se_token, "ddns_return_status", "error", 0);
        sysevent_set(se_fd, se_token, command, "error", 0);
    } else {
        sysevent_set(se_fd, se_token, "ddns_return_status", return_status, 0);
        sysevent_set(se_fd, se_token, command, return_status, 0);
    }

    if((client_status == 0 ) || (client_status > 9))
        client_status = CLIENT_ERROR;

    buf[0] = '0' + client_status;
    buf[1] = '\0';
    syscfg_set(NULL,"ddns_client_Status", buf);

    if((host_status_1 == 0 ) || (host_status_1 > 9))
        host_status_1 = HOST_ERROR;

    buf[0] = '0' + host_status_1;
    buf[1] = '\0';
    syscfg_set(NULL,"ddns_host_status_1", buf);

    if((client_Lasterror == 0 ) || (client_Lasterror > 9)) {
        client_Lasterror = DNS_ERROR;
    }
    buf[0] = '0' + client_Lasterror;
    buf[1] = '\0';
    syscfg_set(NULL,"ddns_client_Lasterror", buf);

    printf("%s: ddns_return_status_success %d return_status %s, client_status %d host_status_1 %d client_Lasterror %d\n",FUNC_NAME, ddns_return_status_success, return_status,client_status,host_status_1,client_Lasterror);

    //update the sysevent or syscfg based on the analyzing result
    gettimeofday(&tv, NULL);
    t = tv.tv_sec;
    info = localtime(&t);

    if(ddns_return_status_success == TRUE) {
        printf("%s: ddns_return_status_success, update status",FUNC_NAME);
        //system("/etc/utopia/service.d/service_ddns/ddns_success.sh");

        strftime (buf, sizeof(buf), "%m:%d:%y_%H:%M:%S\n",info); //format: 04:09:21_22:15:43
        sysevent_set(se_fd, se_token, "ddns_failure_time", "0", 0);
        sysevent_set(se_fd, se_token, "ddns_updated_time", buf, 0);
        syscfg_set(NULL,"ddns_host_lastupdate_1",buf);
/*
        //to do
        //echo "   rm -f $CHECK_INTERVAL_FILENAME" >> $CHECK_INTERVAL_FILENAME;
        //echo "#! /bin/sh" > $CHECK_INTERVAL_FILENAME;
        //echo "   /etc/utopia/service.d/service_dynamic_dns.sh ${SERVICE_NAME}-check" >> $CHECK_INTERVAL_FILENAME;
        //chmod 700 $CHECK_INTERVAL_FILENAME;
        //break
*/
        syscfg_commit();
        printf("%s: return 0 because everything looks good\n",FUNC_NAME);
        ret = 0;
    } else {

        strftime (buf, sizeof(buf), "%m:%d:%y_%H:%M:%S\n",info); //format: 04:09:21_22:15:43
        sysevent_set(se_fd, se_token, "ddns_failure_time", buf, 0);
        sysevent_set(se_fd, se_token, "ddns_updated_time", "0", 0);

        syscfg_commit();
        printf("%s: return -1 because curl command return !0 or found error message in output file\n",FUNC_NAME);
        ret = -1;
    }

    if (unlink(UPDATING_CHECK_FILE) != 0)
       ret = -1;

    return ret;

#if 0
/*
   #If there is no error-connect for any provider, then delete the $RETRY_SOON_FILENAME.
   RETRY_SOON_NEEDED=0
   ddns_enable_x=`syscfg get ddns_server_enable_${DnsIdx}`
   if [ "1" = "$ddns_enable_x" ]; then
       tmp_status=`sysevent get ddns_return_status${DnsIdx}`
       if [ "error-connect" = "$tmp_status" ] ; then
           sysevent set ddns_return_status
           sysevent set ddns_failure_time `date "+%s"`
           sysevent set ddns_updated_time
           RETRY_SOON_NEEDED=1
           break
       fi
   fi
   if [ "0" = "$RETRY_SONN_NEEDED" ]; then
       rm -f $RETRY_SOON_FILENAME
   fi
*/
#endif
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
