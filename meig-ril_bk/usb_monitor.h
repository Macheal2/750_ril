/* //device/system/meig-ril/at_tok.h
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

#ifndef USB_MONITOR_H
#define USB_MONITOR_H 1


#define MAX_TRACKED_DEV_NAME_LEN    (10)
typedef enum {
    USB_PLUGGED = 0,
    USB_UNPLUGGED
} USB_STATE;

typedef struct {
    int tracked;
    int fd;
    char *name;
    USB_STATE state;
} TRACKED_DEV;

typedef void (*usb_lost_callback) (void);

USB_STATE flush_usb_state(void);
void start_usb_monitor(usb_lost_callback  on_usb_lost_fun);
void set_track_dev(const char* devname, int fd);

#endif /*USB_MONITOR_H */

