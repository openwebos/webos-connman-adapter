/* @@@LICENSE
*
* Copyright (c) 2012 Hewlett-Packard Development Company, L.P.
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
*
* LICENSE@@@ */

/**
 * @file  main.c
 *
 */


#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <glib.h>
#include <pthread.h>
#include <stdbool.h>
#include <getopt.h>
#include <stdlib.h>
#include <luna-service2/lunaservice.h>

#include "logging.h"
#include "wifi_service.h"
#include "connectionmanager_service.h"

static GMainLoop *mainloop = NULL;

int initialize_wifi_ls2_calls();

/**
 * Our PmLogLib logging context
 */
PmLogContext gLogContext;

static const char* const kLogContextName = "webos-connman-adapter";

void
term_handler(int signal)
{
    g_main_loop_quit(mainloop);
}

int
main(int argc, char **argv)
{

    signal(SIGTERM, term_handler);
    signal(SIGINT, term_handler);

    mainloop = g_main_loop_new(NULL, FALSE);

    (void)PmLogGetContext(kLogContextName, &gLogContext);

    WCA_LOG_INFO("Starting webos-connman-adapter");

    if(initialize_wifi_ls2_calls(mainloop) < 0)
    {
        WCA_LOG_FATAL("Error in initializing com.palm.wifi service");
        return -1;
    }  

    if(initialize_connectionmanager_ls2_calls(mainloop) < 0)
    {
        WCA_LOG_FATAL("Error in initializing com.palm.connectionmanager service");
        return -1;
    }

    g_main_loop_run(mainloop);

    g_main_loop_unref(mainloop);

     return 0;
}
