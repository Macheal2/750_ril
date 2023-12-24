/* //device/system/meig-ril/misc.h
**
** Copyright 2006, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/


#include <stdbool.h>

/*[zhaopf@meigsmart-2020-1217]add for modem state { */
void set_modem_state_connected(bool connected);
/*[zhaopf@meigsmart-2020-1217]add for modem state } */
/** returns 1 if line starts with prefix, 0 if it does not */
int strStartsWith(const char *line, const char *prefix);

bool isInEmulator(void);
