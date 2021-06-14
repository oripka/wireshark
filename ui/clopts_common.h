/* clopts_common.h
 * Handle command-line arguments common to various programs
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __UI_CLOPTS_COMMON_H__
#define __UI_CLOPTS_COMMON_H__

#include <wsutil/jsmn.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Long options.
 * For long options with no corresponding short options, we define values
 * outside the range of ASCII graphic characters, make that the last
 * component of the entry for the long option, and have a case for that
 * option in the switch statement.
 */
// Base value for capture related long options
#define LONGOPT_BASE_CAPTURE        1000
// Base value for dissector related long options
#define LONGOPT_BASE_DISSECTOR      2000
// Base value for application specific long options
#define LONGOPT_BASE_APPLICATION    3000
// Base value for GUI specific long options
#define LONGOPT_BASE_GUI            4000
#include <stdlib.h>

struct select_item_range
{
  gboolean inclusive;
  guint first, second;
};

extern int
get_natural_int(const char *string, const char *name);

extern int
get_positive_int(const char *string, const char *name);

extern guint32
get_guint32(const char *string, const char *name);

extern guint32
get_nonzero_guint32(const char *string, const char *name);

extern double
get_positive_double(const char *string, const char *name);

void parse_add_print_only(const char *buf, const jsmntok_t *tokens, int count);
int selected_for_dissect(guint recno);
int printonly(guint val);
void add_print_only(unsigned int val);
void add_string_selection(char * sel);
void parse_selected_frames(const char *buf, const jsmntok_t *tokens, int count);
void parse_frame_range(const char *buf, const jsmntok_t *tokens, int count, struct select_item_range selections[], size_t maxlen, guint32 *numselections);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UI_CLOPTS_COMMON_H__ */
