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


#ifndef CONNMAN_MANAGER_H_
#define CONNMAN_MANAGER_H_

#include "connman_service.h"
#include "connman_technology.h"

#define CONNMAN_WIFI_INTERACE_NAME	"wlan0"

typedef struct connman_manager
{
	ConnmanInterfaceManager	*remote;
	GSList	*services;
	GSList	*technologies;	
	gboolean services_updated;
	gboolean technologies_updated;
}connman_manager_t;

gboolean connman_manager_is_manager_available (connman_manager_t *manager);
void connman_manager_update_services(connman_manager_t *manager);
void connman_manager_update_technologies(connman_manager_t *manager);

connman_technology_t *connman_manager_find_wifi_technology(connman_manager_t *manager);
connman_service_t *connman_manager_get_connected_service(connman_manager_t *manager);
connman_manager_t *connman_manager_new(void);
void connman_manager_free (connman_manager_t *manager);

#endif /* CONNMAN_MANAGER_H_ */

