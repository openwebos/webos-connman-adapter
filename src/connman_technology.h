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


#ifndef CONNMAN_TECHNOLOGY_H_
#define CONNMAN_TECHNOLOGY_H_

#include <gio/gio.h>
#include <glib-object.h>

#include "connman-interface.h"

typedef struct connman_technology
{
	ConnmanInterfaceTechnology *remote;
  	gchar *type;
  	gchar *name;
	gchar *path;
	gboolean powered;
}connman_technology_t;

gboolean connman_technology_set_powered(connman_technology_t *technology, gboolean state);
void connman_technology_scan_network(connman_technology_t *technology);

connman_technology_t *connman_technology_new(GVariant *variant);
void connman_technology_free (gpointer data, gpointer user_data);

#endif /* CONNMAN_TECHNOLOGY_H_ */

