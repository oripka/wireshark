/* clopts_common.c
 * Handle command-line arguments common to various programs
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdlib.h>
#include <errno.h>

#include <wsutil/strtoi.h>
#include <ui/cmdarg_err.h>


// #include <glib.h>
#include <stdio.h>


#include "clopts_common.h"

int
get_natural_int(const char *string, const char *name)
{
  gint32 number;

  if (!ws_strtoi32(string, NULL, &number)) {
    if (errno == EINVAL) {
      cmdarg_err("The specified %s \"%s\" isn't a decimal number", name, string);
      exit(1);
    }
    if (number < 0) {
      cmdarg_err("The specified %s \"%s\" is a negative number", name, string);
      exit(1);
    }
    cmdarg_err("The specified %s \"%s\" is too large (greater than %d)",
               name, string, number);
    exit(1);
  }
  if (number < 0) {
    cmdarg_err("The specified %s \"%s\" is a negative number", name, string);
    exit(1);
  }
  return (int)number;
}

int
get_positive_int(const char *string, const char *name)
{
  int number;

  number = get_natural_int(string, name);

  if (number == 0) {
    cmdarg_err("The specified %s is zero", name);
    exit(1);
  }

  return number;
}

guint32
get_guint32(const char *string, const char *name)
{
  guint32 number;

  if (!ws_strtou32(string, NULL, &number)) {
    if (errno == EINVAL) {
      cmdarg_err("The specified %s \"%s\" isn't a decimal number", name, string);
      exit(1);
    }
    cmdarg_err("The specified %s \"%s\" is too large (greater than %d)",
               name, string, number);
    exit(1);
  }
  return number;
}

guint32
get_nonzero_guint32(const char *string, const char *name)
{
  guint32 number;

  number = get_guint32(string, name);

  if (number == 0) {
    cmdarg_err("The specified %s is zero", name);
    exit(1);
  }

  return number;
}

double
get_positive_double(const char *string, const char *name)
{
  double number = g_ascii_strtod(string, NULL);

  if (errno == EINVAL) {
    cmdarg_err("The specified %s \"%s\" isn't a floating point number", name, string);
    exit(1);
  }
  if (number < 0.0) {
    cmdarg_err("The specified %s \"%s\" is a negative number", name, string);
    exit(1);
  }

  return number;
}

/* packet selection support, taken from editcap.c */
#define MAX_SELECTIONS 51200
static struct select_item_range selectfrm[MAX_SELECTIONS];
static guint max_selected = 0;
guint max_packet_number = 0;

gboolean use_selections = FALSE;

static gboolean print_only = FALSE;
static unsigned int print_only_packet = 0;

int verbose=1;

static const char *
json_find_attr(const char *buf, const jsmntok_t *tokens, int count, const char *attr)
{
	int i;

	for (i = 0; i < count; i += 2)
	{
		const char *tok_attr  = &buf[tokens[i + 0].start];
		const char *tok_value = &buf[tokens[i + 1].start];

		if (!strcmp(tok_attr, attr))
			return tok_value;
	}

	return NULL;
}

void
parse_add_print_only(const char *buf, const jsmntok_t *tokens, int count)
{
  char *tok_print = (char *)json_find_attr(buf, tokens, count, "print");
	if(tok_print == NULL)
    return;
  add_print_only(get_positive_int(tok_print, "packet number"));
}

void
add_print_only(unsigned int val){
  if(verbose)
    fprintf(stderr, "print: frame=%i\n", val);
  
  print_only = TRUE;
   print_only_packet = val;
}

int printonly(guint val){
  if(!use_selections){
    return TRUE;
  }
  int print= FALSE;
    if(val == print_only_packet)
      print = TRUE;

    if(verbose)
      fprintf(stderr,"Selected for print %i \n", val);

    return print;
}

/* Add a selection item, a simple parser for now */
gboolean
add_selection(char *sel, guint *max_selection)
{
  char *locn;
  char *next;

  if (max_selected >= MAX_SELECTIONS)
  {
    /* Let the user know we stopped selecting */
    fprintf(stderr, "Out of room for packet selections.\n");
    return (FALSE);
  }

  if (verbose)
    fprintf(stderr, "Add_Selected: %s\n", sel);

  if ((locn = strchr(sel, '-')) == NULL)
  { /* No dash, so a single number? */
    if (verbose)
      fprintf(stderr, "Not inclusive ...");

    selectfrm[max_selected].inclusive = FALSE;
    ws_strtou32(sel, NULL, &(selectfrm[max_selected].first));
    if (selectfrm[max_selected].first > *max_selection)
      *max_selection = selectfrm[max_selected].first;

    if (verbose)
      fprintf(stderr, " %u\n", selectfrm[max_selected].first);
  }
  else
  {
    if (verbose)
      fprintf(stderr, "Inclusive ...");

    *locn = '\0'; /* split the range */
    next = locn + 1;
    selectfrm[max_selected].inclusive = TRUE;
    ws_strtou32(sel, NULL, &(selectfrm[max_selected].first));
    ws_strtou32(next, NULL, &(selectfrm[max_selected].second));

    if (selectfrm[max_selected].second == 0)
    {
      /* Not a valid number, presume all */
      selectfrm[max_selected].second = *max_selection = G_MAXUINT;
    }
    else if (selectfrm[max_selected].second > *max_selection)
      *max_selection = selectfrm[max_selected].second;

    if (verbose)
      fprintf(stderr, " %u, %u\n", selectfrm[max_selected].first,
              selectfrm[max_selected].second);
  }

  max_selected++;
  return (TRUE);
}

/* Was the packet selected? */

int
selected_for_dissect(guint recno)
{

  int selected = 0;
  guint i;

  if(!use_selections)
    return TRUE;

  if(verbose)
    fprintf(stderr,"Input is %i \n", recno);

  for (i = 0; i < max_selected; i++)
  {
    if (selectfrm[i].inclusive)
    {
      if (selectfrm[i].first <= recno && selectfrm[i].second >= recno)
        selected = 1;
    }
    else
    {
      if (recno == selectfrm[i].first)
        selected = 1;
    }
  }

  if(selected && verbose){
    fprintf(stderr,"Selected for dissection %i \n", recno);
  } else {
    ;
    // fprintf(stderr,"Not selected for dissection %i \n", recno);
  }
  return selected;
}

void add_string_selection(char * sel) {
    char *pch;
    pch = strtok(sel, " ");
    while (pch != NULL)
    {
        add_selection(pch, &max_packet_number);
        pch = strtok(NULL, " ");
    }
}

void
parse_selected_frames(const char *buf, const jsmntok_t *tokens, int count)
{
	char *pch;

	char *tok_frames = (char *)json_find_attr(buf, tokens, count, "frames");
  if(verbose)
	  fprintf(stderr, "decode: frames=%s\n", tok_frames);

	if (tok_frames == NULL)
	{
		use_selections = FALSE;
		return;
	}

	use_selections = TRUE;
	pch = strtok(tok_frames, " ");
	while (pch != NULL)
	{
		// printf("%s\n", pch);
		add_selection(pch, &max_packet_number);
		pch = strtok(NULL, " ");
	}
}


/* Add a selection item, a simple parser for now */
gboolean
add_selection_new(char *sel, guint *maxs, guint * current, struct select_item_range *selection, size_t selectionlen)
{
  char *locn;
  char *next;

  if (*current >= selectionlen)
  {
    /* Let the user know we stopped selecting */
    fprintf(stderr, "Out of room for packet selections.\n");
    return (FALSE);
  }

  if (verbose)
    fprintf(stderr, "Add_Selected: %s\n", sel);

  if ((locn = strchr(sel, '-')) == NULL)
  { /* No dash, so a single number? */
    if (verbose)
      fprintf(stderr, "Not inclusive ...");

    selection[*current].inclusive = FALSE;
    ws_strtou32(sel, NULL, &(selection[*current].first));
    ws_strtou32(sel, NULL, &(selection[*current].second));
    if (selection[*current].first > *maxs)
      *maxs = selection[*current].first;

    if (verbose)
      fprintf(stderr, " %u\n", selection[*current].first);
  }
  else
  {
    if (verbose)
      fprintf(stderr, "Inclusive ...");

    *locn = '\0'; /* split the range */
    next = locn + 1;
    selection[*current].inclusive = TRUE;
    ws_strtou32(sel, NULL, &(selection[*current].first));
    ws_strtou32(next, NULL, &(selection[*current].second));

    if (selection[*current].second == 0)
    {
      /* Not a valid number, presume all */
      selection[*current].second = *maxs = G_MAXUINT;
    }
    else if (selection[*current].second > *maxs)
      *maxs = selection[*current].second;

    if (verbose)
      fprintf(stderr, " %u, %u\n", selection[*current].first,
              selection[*current].second);
  }

  (*current)++;
  return (TRUE);
}

void
parse_frame_range(const char *buf, const jsmntok_t *tokens, int count, struct select_item_range selections[], size_t maxlen, guint32 *numselections)
{
	char *pch;
  guint current = 0;
  guint maxs = 0;
  *numselections = 0;

	char *tok_frames = (char *)json_find_attr(buf, tokens, count, "range");
  if(verbose)
	  fprintf(stderr, "decode: range=%s\n", tok_frames);

	if (tok_frames == NULL)
	{
		return;
	}

	pch = strtok(tok_frames, " ");
	while (pch != NULL && (g_ascii_isdigit(*pch) || *pch == '-'))
	{
		// printf("%s\n", pch);
    *numselections++;
		add_selection_new(pch, &maxs, &current, selections, maxlen);
		pch = strtok(NULL, " ");
	}
}







/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
