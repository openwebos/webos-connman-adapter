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


#ifndef CONNMAN_SERVICE_H_
#define CONNMAN_SERVICE_H_

#include <gio/gio.h>
#include <glib-object.h>

#include "connman-interface.h"

typedef struct ipinfo
{
	gchar *iface;
	gchar *address;
	gchar *netmask;
	gchar *gateway;
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
  	gint type;
	ipinfo_t ipinfo;
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


gboolean is_service_type_wifi(connman_service_t *service);
gboolean is_service_type_ethernet(connman_service_t *service);
gchar *get_webos_state(int connman_state);

int connman_service_get_state(const gchar *state);
connman_service_t *connman_service_new(GVariant *variant);
void connman_service_free (gpointer data, gpointer user_data);

#endif /* CONNMAN_SERVICE_H_ */

