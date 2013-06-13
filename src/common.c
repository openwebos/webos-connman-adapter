/* @@@LICENSE
*
*      Copyright (c) 2012-2013 LG Electronics, Inc.
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
 * @file  common.c
 *
 * @brief Implements some of the common utility functions
 *
 */

#include <glib.h>

#include "common.h"

/**
 *  @brief Check if the connman manager is not in offline mode
 *   Send an error luna message if it is in offline mode
 *
 *  @param manager
 *  @param sh
 *  @param message
 */


gboolean connman_status_check(connman_manager_t *manager, LSHandle *sh, LSMessage *message)
{
        if(!connman_manager_is_manager_available(manager))
        {
                LSMessageReplyCustomError(sh, message, "Connman service unavailable");
                return false;
        }
        return true;
}

