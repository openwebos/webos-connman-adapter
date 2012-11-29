/* @@@LICENSE
*
*      Copyright (c) 2012 Hewlett-Packard Development Company, L.P.
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


#ifndef _COMMON_H_
#define _COMMON_H_

#include "connman_manager.h"
#include "lunaservice_utils.h"

extern connman_manager_t *manager;
extern gboolean connman_status_check(connman_manager_t *manager, LSHandle *sh, LSMessage *message);

#endif /* _COMMON_H_ */

