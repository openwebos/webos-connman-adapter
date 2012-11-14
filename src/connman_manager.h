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


/**
 * @file  connman_manager.h
 *
 * @brief Header file defining functions and data structures for interacting with connman manager
 *
 */

#ifndef CONNMAN_MANAGER_H_
#define CONNMAN_MANAGER_H_

#include "connman_common.h"
#include "connman_service.h"
#include "connman_technology.h"

typedef void (*connman_services_changed_cb)(gpointer);

typedef struct connman_manager
{
	ConnmanInterfaceManager	*remote;
	GSList	*services;
	GSList	*technologies;
	connman_property_changed_cb	handle_property_change_fn;
	connman_services_changed_cb	handle_services_change_fn;
}connman_manager_t;


extern gboolean connman_manager_is_manager_available (connman_manager_t *manager);
extern connman_technology_t *connman_manager_find_wifi_technology(connman_manager_t *manager);
extern connman_service_t *connman_manager_get_connected_service(connman_manager_t *manager);
extern void connman_manager_register_property_changed_cb(connman_manager_t *manager, connman_property_changed_cb func);
extern void connman_manager_register_services_changed_cb(connman_manager_t *manager, connman_services_changed_cb func);

extern connman_manager_t *connman_manager_new(void);
extern void connman_manager_free (connman_manager_t *manager);

#endif /* CONNMAN_MANAGER_H_ */

