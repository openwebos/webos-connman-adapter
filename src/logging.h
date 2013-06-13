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
 * @file logging.h
 *
 * @brief  Logging utilities
 *
 */


#ifndef _LOGGING_H_
#define _LOGGING_H_

#include <stdlib.h>
#include <PmLogLib.h>

extern PmLogContext gLogContext;

/**
 * WCA_LOG_XXXX Usage Guidelines
 *
 * The following comments are a set of guidelines for deciding
 * which log level to use for a particular event of interest. To
 * enable a predictable experience when debugging, it's
 * important to use the logging levels consistently.
 *
 * WCA_LOG_DEBUG: (Linux mapping: debug) Almost everything that
 * is of interest to log should be logged at the DEBUG level;
 * NOTE: this level will normally be disabled in production at
 * PmLogLib level, but will still incur a fair amount of
 * overhead in PmLogLib's atomic check of the logging context.
 *
 * WCA_LOG_INFO: (Linux mapping: info) Informational;
 *
 * WCA_LOG_NOTICE: (Linux mapping: notice) Normal, but
 * significant condition
 *
 * WCA_LOG_WARNING: (Linux mapping: warning) Warning conditions;
 *
 * WCA_LOG_ERROR: (Linux mapping: err); Error condition
 *
 * WCA_LOG_CRITICAL: (Linux mapping: crit); Critical condition.
 *
 * WCA_LOG_FATAL: (Linux mapping: crit); Fatal condition,
 * will also abort the process.
 */

#define WCA_LOG_HELPER(palmLevel__, ...) \
     PmLogPrint(gLogContext, (palmLevel__), __VA_ARGS__)

#define WCA_LOG_DEBUG(...) \
    WCA_LOG_HELPER(kPmLogLevel_Debug, __VA_ARGS__)

#define WCA_LOG_INFO(...) \
    WCA_LOG_HELPER(kPmLogLevel_Info, __VA_ARGS__)

#define WCA_LOG_NOTICE(...) \
    WCA_LOG_HELPER(kPmLogLevel_Notice, __VA_ARGS__)

#define WCA_LOG_WARNING(...) \
    WCA_LOG_HELPER(kPmLogLevel_Warning, __VA_ARGS__)

#define WCA_LOG_ERROR(...) \
    WCA_LOG_HELPER(kPmLogLevel_Error, __VA_ARGS__)

#define WCA_LOG_CRITICAL(...) \
    WCA_LOG_HELPER(kPmLogLevel_Critical, __VA_ARGS__)

#define WCA_LOG_FATAL(...) \
    { WCA_LOG_HELPER(kPmLogLevel_Critical, __VA_ARGS__); abort(); }

#endif // _LOGGING_H_
