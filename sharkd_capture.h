#ifndef __SHARKD_CAPTURE_H
#define __SHARKD_CAPTURE_H

#include <epan/epan.h>

void sharkd_capture_init(void);
int sharkd_capture_start(e_prefs *prefs_p);
int sharkd_list_linklayer_types(int caps_queries);
int sharkd_capture_start_with_if(const char *capture_device);
int sharkd_capture_stop(void);

#endif /* __SHARKD_CAPTURE_H */