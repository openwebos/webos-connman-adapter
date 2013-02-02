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

/**
 * Callback function for handling any changes in connman services
 *
 * @param[IN] gpointer Any data to pass to this function
 */
typedef void (*connman_services_changed_cb)(gpointer);


/**
 * Local instance of a connman manager
 *
 * Stores all required information, including current services and technologies
 */

typedef struct connman_manager
{
	ConnmanInterfaceManager	*remote;
	GSList	*wifi_services;
	GSList	*wired_services;
	GSList	*technologies;
	connman_property_changed_cb	handle_property_change_fn;
	connman_services_changed_cb	handle_services_change_fn;
}connman_manager_t;

/**
 * Check if the manager is NOT in offline mode, i.e available to enable network 
 * connections
 *
 * @param[IN]  manager A manager instance
 *
 * @return TRUE if manager's "offlineMode" property is FALSE
 */
extern gboolean connman_manager_is_manager_available (connman_manager_t *manager);

/**
 * Check if the manager's state is "online"
 *
 * @param[IN]  manager A manager instance
 *
 * @return TRUE if manager's state is "online"
 */
extern gboolean connman_manager_is_manager_online (connman_manager_t *manager);

/**
 * Go through the manager's technologies list and get the technology with type "wifi"
 *
 * @param[IN]  manager A manager instance
 *
 * @return Technology with type "wifi"
 */
extern connman_technology_t *connman_manager_find_wifi_technology(connman_manager_t *manager);

/**
 * Go through the manager's technologies list and get the technology with type "wired"
 *
 * @param[IN]  manager A manager instance
 *
 * @return Technology with type "wired"
 */
extern connman_technology_t *connman_manager_find_ethernet_technology(connman_manager_t *manager);

/**
 * Go through the manager's given services list and get the one which is in "ready" or 
 * "online" state , i.e  one of the connected states.
 *
 * @param[IN]  service_list Manager's service list (wired of wifi)
 *
 * @return Service which is in one of the connected states
 */
extern connman_service_t *connman_manager_get_connected_service(GSList *service_list);

/**
 * Register for manager's "properties_changed" signal, calling the provided function whenever the callback function
 * for the signal is called
 *
 * @param[IN] manager A manager instance
 * @param[IN] func User function to register
 */
extern void connman_manager_register_property_changed_cb(connman_manager_t *manager, connman_property_changed_cb func);

/**
 * Register for manager's state changed case, calling the provided function whenever the callback function
 * for the signal is called
 *
 * @param[IN] manager A manager instance
 * @param[IN] func User function to register
 */
extern void connman_manager_register_services_changed_cb(connman_manager_t *manager, connman_services_changed_cb func);

/**
 * Register a agent instance on the specified dbus path with the manager
 *
 * @param[IN] DBus object path where the agents is available
 *
 * @return TRUE, if agent was successfully registered with the manager, FALSE otherwise.
 **/
extern gboolean connman_manager_register_agent(connman_manager_t *manager, const gchar *path);

/**
 * Unegister a agent instance on the specified dbus path from the manager
 *
 * @param[IN] DBus object path where the agents is available
 *
 * @return TRUE, if agent was successfully unregistered from the manager, FALSE otherwise.
 **/
extern gboolean connman_manager_unregister_agent(connman_manager_t *manager, const gchar *path);

/**
 * Initialize a new manager instance and update its services and technologies list
 */
extern connman_manager_t *connman_manager_new(void);

/**
 * Free the manager instance
 *
 * @param[IN]  manager A manager instance
 */
extern void connman_manager_free (connman_manager_t *manager);

#endif /* CONNMAN_MANAGER_H_ */

