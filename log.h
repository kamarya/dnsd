/*
 * Copyright (C) 2016  Behrooz Aliabadi

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _LOG_H_
#define _LOG_H_

#include <time.h>
#include <string.h>

static inline char *get_timestamp();

#define _FILE strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__

#define LEV_NO_DEV_LOG  0x00
#define LEV_EMRRGENCY   0x01
#define LEV_ALERT       0x02
#define LEV_CRITICAL    0x03
#define LEV_ERROR       0x04
#define LEV_WARNING     0x05
#define LEV_NOTICE      0x06
#define LEV_INFO        0x07
#define LEV_DEBUG       0x08

#ifndef LOG_LEVEL
#define LOG_LEVEL   LEV_DEBUG
#endif

#define PRINTLOG(format, ...)      fprintf(stderr, format, __VA_ARGS__)

#define LOG_FMT             "[%s] [%s] [%s] [%s:%d] : "
#define LOG_ARGS(LOG_TAG)   get_timestamp(), LOG_TAG, _FILE, __FUNCTION__, __LINE__

#define CR     "\n"

#define ERROR_TAG   "ERROR"
#define WARNING_TAG "WARNING"
#define NOTICE_TAG  "NOTICE"
#define INFO_TAG    "INFO"
#define DEBUG_TAG   "DEBUG"

#if LOG_LEVEL >= LEV_DEBUG
#define LOG_DEBUG(msg, args...)     PRINTLOG(LOG_FMT msg CR, LOG_ARGS(DEBUG_TAG), ## args)
#else
#define LOG_DEBUG(msg, args...)
#endif

#if LOG_LEVEL >= LEV_INFO
#define LOG_INFO(msg, args...)      PRINTLOG(LOG_FMT msg CR, LOG_ARGS(INFO_TAG), ## args)
#else
#define LOG_INFO(msg, args...)
#endif

#if LOG_LEVEL >= LEV_ERROR
#define LOG_ERROR(msg, args...)     PRINTLOG(LOG_FMT msg CR, LOG_ARGS(ERROR_TAG), ## args)
#else
#define LOG_ERROR(msg, args...)
#endif


static inline char *get_timestamp()
{
    static char buffer[128];
    time_t      ttime;
    struct tm  *timeinfo;
    time(&ttime);
    timeinfo = localtime(&ttime);
    strftime(buffer, sizeof buffer, "%Y-%m-%d %H:%M:%S", timeinfo);
    return buffer;
}


#endif
