/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2015 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]
 
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
 
       http://www.apache.org/licenses/LICENSE-2.0
 
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/

/*
===================================================================
    This programs will compare syscfg database and sysevent database
    against a default database. If any tuple in syscfg or sysevent is
    not already set, then this program will set it according to the
    default value
===================================================================
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <syscfg/syscfg.h>
#include "sysevent/sysevent.h"
#include "secure_wrapper.h"
#include <sys/stat.h>
#include <unistd.h>
#include <stdbool.h>

#include <telemetry_busmessage_sender.h>

static int   syscfg_dirty;

#define DEFAULT_FILE "/etc/utopia/system_defaults"
#define SE_NAME "system_default_set"

static int global_fd = 0;
static token_t global_id;

/*
   By default the variable "convert" will be set if $Version is found in
   system_defaults and its value does not match the currently configured value
   (the actual value isn't important, it just needs to be a different string).

   However, during development we want changes in system_defaults to be applied
   without the need to repeatedly update $Version. Setting ALWAYS_CONVERT
   effectively does that (ie it's the same as forcing the $Version check to
   always detect a difference even if the values match).

   The end result should be that values in system_defaults defined with $$ will
   always over-ride any setting which may have already been configured.
*/

//#define ALWAYS_CONVERT

#if ! defined (ALWAYS_CONVERT)
//Flag to indicate a db conversion is necessary
static int convert = 0;
#endif

#define RETRY_COUNT 3

#if defined (_CBR_PRODUCT_REQ_) || defined (_XB6_PRODUCT_REQ_)
        #define LOG_FILE "/rdklogs/logs/Consolelog.txt.0"
#else
	#define LOG_FILE "/rdklogs/logs/ArmConsolelog.txt.0"
#endif

#define APPLY_PRINT(fmt ...)   {\
   FILE *logfp = fopen ( LOG_FILE , "a+");\
   if (logfp)\
   {\
        fprintf(logfp,fmt);\
        fclose(logfp);\
   }\
}\


static char *trim (char *in)
{
    int len;

    /*
       Drop leading spaces (although there are not expected to be any).
    */
    while (isspace(*in)) {
        in++;
    }

    /*
       Drop trailing spaces (there will always be a newline at the end
       of lines read by fgets() and trim() is used to remove it).
    */
    len = (int) strlen(in);
    while (len > 0) {
        if (isspace(in[len - 1])) {
            in[len - 1] = 0;
            len--;
        }
        else
            break;
    }

    return in;
}

static int split_line (char *in, char **name, char **value)
{
   char *tok;

   tok = strchr(in, '=');
   if (tok == NULL)
      return -1;

   *tok = '\0';
   *name = in;
   *value = tok + 1;

   return 0;
}

/*
 * Procedure     : set_sysevent
 * Purpose       : sets a sysevent tuple if it is not already set
 * Parameters    :
 *    name       : the name of the tuple
 *    value      : the value to set the tuple to
 * Return Value  : 0 if ok, -1 if not
 */
static int set_sysevent(char *name, char *value, int flags) 
{
   char get_val[512];
   int rc;

   get_val[0] = 0;

   rc = sysevent_get (global_fd, global_id, name, get_val, sizeof(get_val));

   if (get_val[0] == 0)
   {
      if (flags != 0x00000000)
      {
         rc = sysevent_set_options (global_fd, global_id, name, flags);
      }

      // if the value is prefaced by '$' then we use the
      // current value of syscfg
      char *trimmed_val = trim(value);

      if (trimmed_val[0] == '$')
      {
         syscfg_get (NULL, trimmed_val+1, get_val, sizeof(get_val));
         rc = sysevent_set (global_fd, global_id, name, get_val, 0);
//       printf("[utopia] [init] apply_system_defaults set <@%s, %s, 0x%x>\n", name, get_val, flags);
      }
      else
      {
         rc = sysevent_set (global_fd, global_id, name, value, 0);
         APPLY_PRINT("[utopia] [init] apply_system_defaults set <@%s, %s, 0x%x>\n", name, value, flags);
         printf ("[utopia] [init] apply_system_defaults set <@%s, %s, 0x%x>\n", name, value, flags);
      }
   }
   else
   {
      rc = 0;
   }

   return rc;
}

/*
 * Procedure     : set_syscfg
 * Purpose       : sets a syscfg tuple if it is not already set
 * Parameters    :
 *    name       : the name of the tuple
 *    value      : the value to set the tuple to
 * Return Value  : 0 if ok, -1 if not
 */
static int set_syscfg (char *name, char *value) 
{
    int force = 0;
    int rc = 0;

    if ((value == NULL) || (value[0] == 0))
    {
        return 0;
    }

    /* Check for second $ (ie values defined with $$ prefix) */
    if (name[0] == '$')
    {
        name++;
#if defined (ALWAYS_CONVERT)
        force = 1;
#else
        if (convert)
            force = 1;
#endif
    }

    if (force)
    {
        printf ("[utopia] [init] apply_system_defaults set <$%s, %s> force=%d\n", name, value, force);
        rc = syscfg_set (NULL, name, value);
        syscfg_dirty++;
    }
    else
    {
        char get_val[512];

        rc = syscfg_get (NULL, name, get_val, sizeof(get_val));

        /*
           There are 3 possible results from syscfg_get():

             1) The previous value is set to a non-empty string : get_val[0] will be non-zero and rc will be 0
             2) The previous value is set to an empty string    : get_val[0] will be 0 and rc will be 0
             3) The previous value is not set                   : get_val[0] will be 0 and rc will be -1

           Only set a new value here (ie when force is 0) in case 3.
        */

        if (rc != 0)
        {
            printf ("[utopia] [init] apply_system_defaults set <$%s, %s> force=%d\n", name, value, force);
            rc = syscfg_set (NULL, name, value);
            syscfg_dirty++;
        }
        else
        {
            printf ("[utopia] [init] syscfg_get <$%s, %s>\n", name, get_val);
        }
    }

    return rc;
}

#if ! defined (ALWAYS_CONVERT)
static int handle_version (char* name, char* value)
{
    char get_val[128];
    int ret = 0;
    int rc;

    if (strcmp (name, "$Version") == 0)
    {
        ret = 1;
        name++;

        rc = syscfg_get (NULL, name, get_val, sizeof(get_val));

        if ((rc != 0) || (get_val[0] == 0) || (strcmp (value, get_val) != 0))
        {
            convert = 1;
        }
    }

    return ret;
}

static int check_version (void)
{
   char buf[1024];
   char *line;
   char *name;
   char *value;
   FILE *fp;

   fp = fopen (DEFAULT_FILE, "r");

   if (fp == NULL)
   {
      printf ("[utopia] no system default file (%s) found\n", DEFAULT_FILE);
      return -1;
   }

   /*
    * The default file must contain one default per line in the format
    * name=value (whitespace is allowed)
    * If the default is for a syscfg tuple, then name must be preceeded with a $
    * If the default is for a sysevent tuple, then name must be preceeded with a @
    * If the first character in the line is # then the line will be ignored
    */

   while (fgets (buf, sizeof(buf), fp) != NULL)
   {
      line = trim (buf);

      if (line[0] == '#')
      {
         // this is a comment
      }
      else if (line[0] == 0)
      {
         // this is an empty line
      }
      else if (line[0] == '$')
      {
         if (split_line (line + 1, &name, &value) != 0)
         {
            printf("[utopia] [error] check_version failed to parse line (%s)\n", line);
         }
         else
         {
            if (handle_version (trim(name), trim(value)))
            {
                break;
            }
         }
      }
      else if (line[0] == '@')
      {
         // this is a sysevent line
      }
      else
      {
         // this is a malformed line
         printf("[utopia] set_defaults found a malformed line (%s)\n", line);
      }
   }

   fclose (fp);

   return 0;
}
#endif


/* TODO: Currently only one parameter (i.e. default_LanAllowedSubnet) is needed to reset (without factory-reset).
 * Later if multiple pararameters require force update, will create a separate file or separator.
 */
static int set_customer_defaults (void)
{
    char customer_index[12];
    char buf[256];
    char *value = NULL;
    unsigned int temp[4];
    FILE *fp;

    if ((syscfg_get (NULL, "Customer_Index", customer_index, sizeof(customer_index)) == 0) && (customer_index[0] != '0'))
    {
        snprintf(buf, sizeof(buf), "/etc/utopia/defaults/lg_syscfg_cust_%s.db", customer_index);

        if ((fp = fopen(buf, "r")))
        {
            while (fgets (buf, sizeof(buf), fp) != NULL)
            {
                if (strncmp(buf, "default_LanAllowedSubnet=", 25) == 0)
                {
                    value = buf + 25;
                    break;
                }
            }

            fclose(fp);
        }
    }

    /*
       If no customer specific value was found (e.g. if Customer ID is 0) then for now
       we still want to over-ride the default arLanAllowedSubnet_1::SubnetIP with an
       appropriate value rather than leaving the default. Fixme: Why?
    */
    if (value == NULL)
    {
        value = "192.168.0.0";
    }

    /*
       Transfer default_LanAllowedSubnet to arLanAllowedSubnet_1::SubnetIP
       The last byte of arLanAllowedSubnet_1 is forced to 1 for
       non legacy (see MVXREQ-675) platforms, but for legacy platforms,
       the last two bytes are forced to 0 (see MVXREQ-1360)
    */
    if ((sscanf(value, "%u.%u.%u.%u", &temp[0], &temp[1], &temp[2], &temp[3]) == 4) &&
        (temp[0] < 256) && (temp[1] < 256) && (temp[2] < 256) && (temp[3] < 256))
    {
        char SubnetIp[32];

#ifdef _PUMA6_ARM_
        sprintf(SubnetIp, "%u.%u.%u.%u", temp[0], temp[1], 0, 0);
#else
        sprintf(SubnetIp, "%u.%u.%u.%u", temp[0], temp[1], temp[2], 1);
#endif
        syscfg_set ("arLanAllowedSubnet_1", "SubnetIP", SubnetIp);
        syscfg_dirty++;
    }

    return 0;
}

/*
 * Procedure     : set_syscfg_defaults
 * Purpose       : Go through a file, parse it into <name, value> tuples,
 *                 and set syscfg namespace (iff not already set),
 * Parameters    :
 * Return Value  : 0 if ok, -1 if not
 */
static int set_syscfg_defaults (void)
{
   char buf[1024];
   char *line;
   char *name;
   char *value;
   FILE *fp;

   fp = fopen (DEFAULT_FILE, "r");

   if (fp == NULL)
   {
      printf ("[utopia] no system default file (%s) found\n", DEFAULT_FILE);
      return -1;
   }

   /*
    * The default file must contain one default per line in the format
    * name=value (whitespace is allowed)
    * If the default is for a syscfg tuple, then name must be preceeded with a $
    * If the default is for a sysevent tuple, then name must be preceeded with a @
    * If the first character in the line is # then the line will be ignored
    */

   while (fgets (buf, sizeof(buf), fp) != NULL)
   {
      line = trim (buf);

      if (line[0] == '#')
      {
         // this is a comment
      }
      else if (line[0] == 0)
      {
         // this is an empty line
      }
      else if (line[0] == '$')
      {
         if (split_line (line + 1, &name, &value) != 0)
         {
            printf("[utopia] [error] set_syscfg_defaults failed to parse line (%s)\n", line);
         }
         else
         {
            set_syscfg(trim(name), trim(value));
         }
      }
      else if (line[0] == '@')
      {
         // this is a sysevent line
      }
      else
      {
         // this is a malformed line
         printf("[utopia] set_syscfg_defaults found a malformed line (%s)\n", line);
      }
   }

   fclose (fp);

   set_customer_defaults();

   return 0;
}

/*
 * Procedure     : set_sysevent_defaults
 * Purpose       : Go through a file, parse it into <name, value> tuples,
 *                 and set sysevent namespace
 * Parameters    :
 * Return Value  : 0 if ok, -1 if not
 */
static int set_sysevent_defaults (void)
{
   char buf[1024];
   char *line;
   char *name;
   char *value;
   FILE *fp;

   fp = fopen (DEFAULT_FILE, "r");

   if (fp == NULL)
   {
      printf ("[utopia] no system default file (%s) found\n", DEFAULT_FILE);
      return -1;
   }

   /*
    * The default file must contain one default per line in the format
    * name=value (whitespace is allowed)
    * If the default is for a syscfg tuple, then name must be preceeded with a $
    * If the default is for a sysevent tuple, then name must be preceeded with a @
    * If the first character in the line is # then the line will be ignored
    */

   while (fgets (buf, sizeof(buf), fp) != NULL)
   {
      line = trim (buf);

      if (line[0] == '#')
      {
         // this is a comment
      }
      else if (line[0] == 0)
      {
         // this is an empty line
      }
      else if (line[0] == '$')
      {
         // this is a syscfg line
      }
      else if (line[0] == '@')
      {
         if (split_line (line + 1, &name, &value) != 0)
         {
            printf("[utopia] set_sysevent_defaults failed to parse line (%s)\n", line);
         }
         else
         {
            char *val = trim(value);
            char *flagstr;
            int flags = 0x00000000;

            int i;
            int len = strlen(val);
            for (i=0; i<len; i++) {
               if (isspace(val[i])) {
                  flagstr = (&(val[i])+1);
                  val[i] = '\0';
                  flags = strtol(flagstr, NULL, 16);
                  break;
               }
            }
            set_sysevent(trim(name), val, flags);
         }
      }
      else
      {
         // this is a malformed line
         printf("[utopia] set_sysevent_defaults found a malformed line (%s)\n", line);
      }
   }

   fclose (fp);

   return 0;
}

/*
 * Procedure     : set_defaults
 * Purpose       : Go through a file twice, first for syscfg variables 
 *                 (because sysevent might use syscfg values for initialization),
 *                 and then again for sysevent variables
 * Parameters    :
 * Return Value  : 0 if ok, -1 if not
 */
static int set_defaults(void)
{
#if ! defined (ALWAYS_CONVERT)
   check_version();
#endif

   set_syscfg_defaults();
   set_sysevent_defaults();

   return 0;
}

/*
 * main()
 */
int main( int argc, char **argv )
{
   int retryCount = RETRY_COUNT + 1;

   t2_init("apply_system_defaults");

   syscfg_dirty = 0;

   while ( retryCount && ((global_fd = sysevent_open("127.0.0.1", SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, SE_NAME, &global_id)) <= 0 ))
   {
      struct timeval t;

      APPLY_PRINT("[Utopia] global_fd is %d\n",global_fd);

      APPLY_PRINT("[Utopia] %s unable to register with sysevent daemon.\n", argv[0]);
      printf("[Utopia] %s unable to register with sysevent daemon.\n", argv[0]);

      //sleep with subsecond precision
      t.tv_sec = 0;
      t.tv_usec = 100000;
      select(0, NULL, NULL, NULL, &t);

      retryCount--;
   }

   set_defaults();
   
   if (syscfg_dirty) 
   {
      printf("[utopia] [init] committing default syscfg values\n");
      syscfg_commit();
      APPLY_PRINT("Number_Of_Entries_Commited_to_Sysconfig_Database=%d\n",syscfg_dirty);
   }

   sysevent_close(global_fd, global_id);

   return(0);
}

