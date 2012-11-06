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
 * @file  wifi_service.h
 *
 */


#ifndef _WIFI_SERVICE_H_
#define _WIFI_SERVICE_H_

#include <luna-service2/lunaservice.h>

#define WIFI_LUNA_SERVICE_NAME "com.palm.wifi"

/**
 * @name Luna WiFi Method Names
 * @{
 */
#define LUNA_METHOD_CONNECT                 "connect"
#define LUNA_METHOD_FINDNETWORKS            "findnetworks" 
#define LUNA_METHOD_DELETEPROFILE           "deleteprofile"
#define LUNA_METHOD_GETINFO                 "getinfo"
#define LUNA_METHOD_GETPROFILE              "getprofile"
#define LUNA_METHOD_GETPROFILELIST          "getprofilelist"
#define LUNA_METHOD_GETSTATUS               "getstatus"
#define LUNA_METHOD_SETSTATE                "setstate"

#endif /* _WIFI_SERVICE_H_ */
