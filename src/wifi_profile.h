/* @@@LICENSE
*
* Copyright (c) 2012 Hewlett-Packard Development Company, L.P.
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
 * @file  wifi_profile.h
 *
 */


#ifndef _WIFI_PROFILE_H_
#define _WIFI_PROFILE_H_

typedef struct wifi_profile
{
	// Lot more fields to be added when we connect to secure networks
	// For open networks these 2 fields are sufficient
	guint profile_id;
	gchar *ssid;
}wifi_profile_t;


extern void init_wifi_profile_list(void);
extern wifi_profile_t * get_profile_by_id(guint profile_id);
extern wifi_profile_t * get_profile_by_ssid(gchar *ssid);
extern void create_new_profile(gchar *ssid);
extern void delete_profile(wifi_profile_t *profile);
extern gboolean profile_list_is_empty(void);
extern wifi_profile_t *get_next_profile(wifi_profile_t *curr_profile);
extern void move_profile_to_head(wifi_profile_t *new_head);


#endif /* _WIFI_PROFILE_H_ */
