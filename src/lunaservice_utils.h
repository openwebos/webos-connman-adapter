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
 * @file lunaservice_utils.h
 *
 * @brief Header file defining convenience functions for sending luna error messages
 *
 */


#ifndef __LUNASERVICE_UTILS_H__
#define __LUNASERVICE_UTILS_H__

#include <luna-service2/lunaservice.h>

extern void LSMessageReplyErrorUnknown(LSHandle *sh, LSMessage *message);
extern void LSMessageReplyErrorInvalidParams(LSHandle *sh, LSMessage *message);
extern void LSMessageReplyErrorBadJSON(LSHandle *sh, LSMessage *message);
extern void LSMessageReplyCustomError(LSHandle *sh, LSMessage *message, const char *errormsg);
extern void LSMessageReplySuccess(LSHandle *sh, LSMessage *message);

#endif
