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
 * @file  connman_technology.h
 *
 * @brief Header file defining functions and data structures for interacting with connman technologies
 *
 */


#ifndef CONNMAN_TECHNOLOGY_H_
#define CONNMAN_TECHNOLOGY_H_

#include <gio/gio.h>
#include <glib-object.h>

#include "connman_common.h"

/**
 * Local instance of a connman technology
 * Caches all required information for a technology
 */
typedef struct connman_technology
{
	ConnmanInterfaceTechnology *remote;
  	gchar *type;
  	gchar *name;
	gchar *path;
	gboolean powered;
	gulong sighandler_id;
	connman_property_changed_cb     handle_property_change_fn;
}connman_technology_t;

/**
 * Power on/off the given technology
 *
 * @param[IN]  technology A technology instance
 * @param[IN]  state TRUE for power on, FALSE for off
 *
 * @return FALSE for any error, TRUE otherwise
 */
extern gboolean connman_technology_set_powered(connman_technology_t *technology, gboolean state);

/**
 * Scan the network for available services
 * This is usually called to scan all wifi APs whenever the list of APs is requested
 *
 * @param[IN]  technology A technology instance
 *
 * @return FALSE for any error, TRUE otherwise
 */
extern gboolean connman_technology_scan_network(connman_technology_t *technology);

/**
 * Register for technology's "properties_changed" signal, calling the provided function whenever the callback function
 * for the signal is called
 *
 * @param[IN] manager A technology instance
 * @param[IN] func User function to register
 *
 */
extern void connman_technology_register_property_changed_cb(connman_technology_t *technology, connman_property_changed_cb func);

/**
 * Create a new technology instance and set its properties
 *
 * @param[IN]  variant List of properties for a new technology
 *
 */
extern connman_technology_t *connman_technology_new(GVariant *variant);

/**
 * Free the connman manager instance
 *
 * @param[IN] data Pointer to the manager to be freed
 * @param[IN] user_data User data if any
 */

extern void connman_technology_free (gpointer data, gpointer user_data);

#endif /* CONNMAN_TECHNOLOGY_H_ */

