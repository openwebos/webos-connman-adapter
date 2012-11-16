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
 * @file  wifi_setting.h
 *
 */

#ifndef _WIFI_SETTING_H_
#define _WIFI_SETTING_H_

#define WIFI_LUNA_PREFS_ID      WIFI_LUNA_SERVICE_NAME

typedef enum
{
	WIFI_NULL_SETTING,
	WIFI_PROFILELIST_SETTING,
	WIFI_LAST_SETTING,
} wifi_setting_type_t;

extern gboolean load_wifi_setting(wifi_setting_type_t setting, void *data);
extern gboolean store_wifi_setting(wifi_setting_type_t setting, void *data);

#endif /* _WIFI_SETTING_H_ */
