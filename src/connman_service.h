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
 * @file  connman_service.h
 *
 * @brief Header file defining functions and data structures for interacting with connman services
 *
 */

#ifndef CONNMAN_SERVICE_H_
#define CONNMAN_SERVICE_H_

#include "connman_common.h"

/** 
 * IPv4 information structure for the service
 *
 * Includes method (dhcp/manual), ip address, netmask and gateway address
 */
typedef struct ipv4info
{
	gchar *method;
	gchar *address;
	gchar *netmask;
	gchar *gateway;
}ipv4info_t;

/**
 * IP information for the service
 *
 * Includes interface name and dns server list along with IPv4 information
 */
typedef struct ipinfo
{
	gchar *iface;
	ipv4info_t ipv4;
	GStrv dns;
}ipinfo_t;

/**
 * Local instance of a connman service
 *
 * Caches all the required information about a service
 */

typedef struct connman_service
{
	/** Remote instance */
	ConnmanInterfaceService *remote;
	gchar *path;
  	gchar *name;
  	gchar *state;

  	guchar strength;
	GStrv security;
  	gboolean auto_connect;
  	gboolean immutable;
  	gboolean favorite;
	gboolean hidden;
  	gint type;
	ipinfo_t ipinfo;
	gulong sighandler_id;
	connman_state_changed_cb handle_state_change_fn;
}connman_service_t;

/**
 * Enum for service types
 */
enum {
	CONNMAN_SERVICE_TYPE_UNKNOWN = 0,
	CONNMAN_SERVICE_TYPE_ETHERNET,
	CONNMAN_SERVICE_TYPE_WIFI,
	CONNMAN_SERVICE_TYPE_MAX
};

/**
 * Enum for service states
 */
enum {
        CONNMAN_SERVICE_STATE_UNKNOWN       = 0,
        CONNMAN_SERVICE_STATE_IDLE,
        CONNMAN_SERVICE_STATE_ASSOCIATION,
        CONNMAN_SERVICE_STATE_CONFIGURATION,
        CONNMAN_SERVICE_STATE_READY,
        CONNMAN_SERVICE_STATE_ONLINE,
        CONNMAN_SERVICE_STATE_DISCONNECT,
        CONNMAN_SERVICE_STATE_FAILURE
};

/**
 * Callback function letting callers handle remote "connect" call responses
 */
typedef void (*connman_service_connect_cb)(gboolean success, gpointer user_data);

/**
 * Check if the type of the service is wifi
 *
 * @param[IN]  service A service instance
 *
 * @return TRUE if the service has "wifi" type
 */
extern gboolean connman_service_type_wifi(connman_service_t *service);

/**
 * Check if the type of the service is ethernet
 *
 * @param[IN]  service A service instance
 *
 * @return TRUE if the service has "ethernet" type
 */
extern gboolean connman_service_type_ethernet(connman_service_t *service);

/**
 * Stringify the service connection status to corresponding webos state
 * This function is required to send appropriate connection status to the webos world.
 *
 * @param[IN]  connman_state Enum representing service state
 *
 * @return String representing connection state in webos world.
 */
extern gchar *connman_service_get_webos_state(int connman_state);

/**
 * Convert the connection state string to its enum value
 *
 * @param[IN]  state String from service's "State" property
 *
 * @return Enum value
 */
extern int connman_service_get_state(const gchar *state);

/**
 * Connect to a remote connman service
 *
 * @param[IN]  service A service instance (to connect)
 * @param[IN]  cb Callback called when connect call returns
 * @param[IN]  user_data User data (if any) to pass with the callback function
 *             See "connman_service_connect_cb" function pointer above
 *
 * @return FALSE if the connect call failed , TRUE otherwise
 */
extern gboolean connman_service_connect(connman_service_t *service, connman_service_connect_cb cb, gpointer user_data);

/**
 * Disconnect from a remote connman service
 *
 * @param[IN]  service A service instance
 *
 * @return FALSE if the disconnect call failed, TRUE otherwise
 */
extern gboolean connman_service_disconnect(connman_service_t *service);

/**
 * @brief  Sets ipv4 properties for the connman service
 *
 * @param[IN]  service A service instance
 * @param[IN]  ipv4 Ipv4 structure
 *
 * @return FALSE if the call to set "IPv4.Configuration" property failed, TRUE otherwise
 */
extern gboolean connman_service_set_ipv4(connman_service_t *service, ipv4info_t *ipv4);

/**
 * @brief  Sets nameservers for the connman service
 *
 * @param[IN]  service A service instance
 * @param[IN]  dns DNS server list
 *
 * @return FALSE if the call to set "Nameservers.Configuration" property failed, TRUE otherwise
 */
extern gboolean connman_service_set_nameservers(connman_service_t *service, GStrv dns);

/**
 * Set the "autoconnect" flag for a service
 *
 * @param[IN]  service A service instance
 * @param[IN]  value New autoconnet value (TRUE/FALSE)
 *
 * @return FALSE if the call to set "AutoConnect" property failed, TRUE otherwise
 */
extern gboolean connman_service_set_autoconnect(connman_service_t *service, gboolean value);

/**
 * Get all the network related information for a connected service (in online state)
 *
 * @param[IN]  service A service instance
 *
 * @return FALSE if the call to get properties failed, TRUE otherwise
 */
extern gboolean connman_service_get_ipinfo(connman_service_t *service);

/** 
 * Retrieve the list of properties for a service
 *
 * @param[IN] service A service instance
 * 
 * @return GVariant pointer listing service properties, NULL if the call to 
           get service properties failed
 */

extern GVariant *connman_service_fetch_properties(connman_service_t *service);

/**
 * Update service properties from the supplied variant
 *
 * @param[IN] service A service instance
 * @param[IN] service_v GVariant structure listing service properties
 */
extern void connman_service_update_properties(connman_service_t *service, GVariant *service_v);

/**
 * Register for service's state changed case, calling the provided function whenever the callback function
 * for the signal is called
 *
 * @param[IN] service A service instance
 * @param[IN] func User function to register
 *
 */
extern void connman_service_register_state_changed_cb(connman_service_t *service, connman_state_changed_cb func);

/**
 * Create a new connman service instance and set its properties
 *
 * @param[IN] variant List of properties for a new service
 */
extern connman_service_t *connman_service_new(GVariant *variant);

/**
 * Free the connman service instance
 *
 * @param[IN] data Pointer to the service to be freed
 * @param[IN] user_data User data if any
 */
extern void connman_service_free (gpointer data, gpointer user_data);

#endif /* CONNMAN_SERVICE_H_ */

