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

typedef struct ipv4info
{
	gchar *method;
	gchar *address;
	gchar *netmask;
	gchar *gateway;
}ipv4info_t;

typedef struct ipinfo
{
	gchar *iface;
	ipv4info_t ipv4;
	GStrv dns;
}ipinfo_t;


typedef struct connman_service
{
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

enum {
	CONNMAN_SERVICE_TYPE_UNKNOWN = 0,
	CONNMAN_SERVICE_TYPE_ETHERNET,
	CONNMAN_SERVICE_TYPE_WIFI,
	CONNMAN_SERVICE_TYPE_MAX
};

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

typedef void (*connman_service_connect_cb)(gboolean success, gpointer user_data);
extern gboolean connman_service_type_wifi(connman_service_t *service);
extern gboolean connman_service_type_ethernet(connman_service_t *service);
extern gchar *connman_service_get_webos_state(int connman_state);
extern int connman_service_get_state(const gchar *state);

extern gboolean connman_service_connect(connman_service_t *service, connman_service_connect_cb cb, gpointer user_data);
extern gboolean connman_service_disconnect(connman_service_t *service);
extern gboolean connman_service_set_ipv4(connman_service_t *service, ipv4info_t *ipv4);
extern gboolean connman_service_set_nameservers(connman_service_t *service, GStrv dns);
extern gboolean connman_service_get_ipinfo(connman_service_t *service);
extern GVariant *connman_service_fetch_properties(connman_service_t *service);
extern void connman_service_update_properties(connman_service_t *service, GVariant *service_v);
extern void connman_service_register_state_changed_cb(connman_service_t *service, connman_state_changed_cb func);

extern connman_service_t *connman_service_new(GVariant *variant);
extern void connman_service_free (gpointer data, gpointer user_data);

#endif /* CONNMAN_SERVICE_H_ */

