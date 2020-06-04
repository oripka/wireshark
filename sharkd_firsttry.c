/* sharkd.c
 *
 * Daemon variant of Wireshark
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>

#include <glib.h>

#include <epan/exceptions.h>
#include <epan/epan.h>

#include <ui/clopts_common.h>
#include <ui/cmdarg_err.h>
#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/privileges.h>
#include <wsutil/report_message.h>
#include <version_info.h>
#include <wiretap/wtap_opttypes.h>
#include <wiretap/pcapng.h>

#include <epan/decode_as.h>
#include <epan/timestamp.h>
#include <epan/packet.h>
#include "frame_tvbuff.h"
#include <epan/disabled_protos.h>
#include <epan/prefs.h>
#include <epan/column.h>
#include <epan/print.h>
#include <epan/addr_resolv.h>
#include "ui/util.h"
#include "ui/ws_ui_util.h"
#include "ui/decode_as_utils.h"
#include "ui/filter_files.h"
#include "ui/tap_export_pdu.h"
#include "ui/failure_message.h"
#include <epan/epan_dissect.h>
#include <epan/tap.h>
#include <epan/uat-int.h>
#include <epan/secrets.h>

#include <wsutil/codecs.h>

#include "sharkd_session.h"
#include "log.h"

#include <wsutil/str_util.h>
#include <wsutil/utf8_entities.h>

#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif

#include "sharkd.h"

#define INIT_FAILED 1
#define EPAN_INIT_FAIL 2

capture_file cfile;

static guint32 cum_bytes;
static frame_data ref_frame;

static void failure_warning_message(const char *msg_format, va_list ap);
static void open_failure_message(const char *filename, int err,
    gboolean for_writing);
static void read_failure_message(const char *filename, int err);
static void write_failure_message(const char *filename, int err);
static void failure_message_cont(const char *msg_format, va_list ap);

static void
print_current_user(void) {
  gchar *cur_user, *cur_group;

  if (started_with_special_privs()) {
    cur_user = get_cur_username();
    cur_group = get_cur_groupname();
    fprintf(stderr, "Running as user \"%s\" and group \"%s\".",
      cur_user, cur_group);
    g_free(cur_user);
    g_free(cur_group);
    if (running_with_special_privs()) {
      fprintf(stderr, " This could be dangerous.");
    }
    fprintf(stderr, "\n");
  }
}

int
main(int argc, char *argv[])
{
  char                *init_progfile_dir_error;

  char                *err_msg = NULL;
  e_prefs             *prefs_p;
  int                  ret = EXIT_SUCCESS;

  cmdarg_err_init(failure_warning_message, failure_message_cont);

  /*
   * Get credential information for later use, and drop privileges
   * before doing anything else.
   * Let the user know if anything happened.
   */
  init_process_policies();
  relinquish_special_privs_perm();
  print_current_user();

  /*
   * Attempt to get the pathname of the executable file.
   */
  init_progfile_dir_error = init_progfile_dir(argv[0]);
  if (init_progfile_dir_error != NULL) {
    fprintf(stderr, "sharkd: Can't get pathname of sharkd program: %s.\n",
            init_progfile_dir_error);
  }

  /* Initialize the version information. */
  ws_init_version_info("Sharkd (Wireshark)", NULL,
                       epan_get_compiled_version_info,
                       epan_get_runtime_version_info);

  if (sharkd_init(argc, argv) < 0)
  {
    printf("cannot initialize sharkd\n");
    ret = INIT_FAILED;
    goto clean_exit;
  }

  init_report_message(failure_warning_message, failure_warning_message,
                      open_failure_message, read_failure_message,
                      write_failure_message);

  timestamp_set_type(TS_RELATIVE);
  timestamp_set_precision(TS_PREC_AUTO);
  timestamp_set_seconds_type(TS_SECONDS_DEFAULT);

  wtap_init(TRUE);

  /* Register all dissectors; we must do this before checking for the
     "-G" flag, as the "-G" flag dumps information registered by the
     dissectors, and we must do it before we read the preferences, in
     case any dissectors register preferences. */
  if (!epan_init(NULL, NULL, TRUE)) {
    ret = EPAN_INIT_FAIL;
    goto clean_exit;
  }

  codecs_init();

  /* Load libwireshark settings from the current profile. */
  prefs_p = epan_load_settings();

  read_filter_list(CFILTER_LIST);

  if (!color_filters_init(&err_msg, NULL)) {
     fprintf(stderr, "%s\n", err_msg);
     g_free(err_msg);
  }

  cap_file_init(&cfile);

  /* Notify all registered modules that have had any of their preferences
     changed either from one of the preferences file or from the command
     line that their preferences have changed. */
  prefs_apply_all();

  /* Build the column format array */
  build_column_format_array(&cfile.cinfo, prefs_p->num_cols, TRUE);

#ifdef HAVE_MAXMINDDB
  /* mmdbresolve is started from mmdb_resolve_start(), which is called from epan_load_settings via: read_prefs -> (...) uat_load_all -> maxmind_db_post_update_cb.
   * Need to stop it, otherwise all sharkd will have same mmdbresolve process, including pipe descriptors to read and write. */
  uat_clear(uat_get_table_by_name("MaxMind Database Paths"));
#endif

  ret = sharkd_loop();
clean_exit:
  col_cleanup(&cfile.cinfo);
  free_filter_lists();
  codecs_cleanup();
  wtap_cleanup();
  free_progdirs();
  return ret;
}

static const nstime_t *
sharkd_get_frame_ts(struct packet_provider_data *prov, guint32 frame_num)
{
  if (prov->ref && prov->ref->num == frame_num)
    return &prov->ref->abs_ts;

  if (prov->prev_dis && prov->prev_dis->num == frame_num)
    return &prov->prev_dis->abs_ts;

  if (prov->prev_cap && prov->prev_cap->num == frame_num)
    return &prov->prev_cap->abs_ts;

  if (prov->frames) {
     frame_data *fd = frame_data_sequence_find(prov->frames, frame_num);

     return (fd) ? &fd->abs_ts : NULL;
  }

  return NULL;
}

static epan_t *
sharkd_epan_new(capture_file *cf)
{
  static const struct packet_provider_funcs funcs = {
    sharkd_get_frame_ts,
    cap_file_provider_get_interface_name,
    cap_file_provider_get_interface_description,
    cap_file_provider_get_user_comment
  };

  return epan_new(&cf->provider, &funcs);
}


static gboolean
process_packet(capture_file *cf, epan_dissect_t *edt,
               gint64 offset, wtap_rec *rec, Buffer *buf, gint64 nump)
{
  frame_data     fdlocal;
  gboolean       passed;
  gboolean create_proto_tree;

  gboolean dissect = selected_for_dissect(nump);
  gboolean output_packet = printonly(nump);

  /* If we're not running a display filter and we're not printing any
     packet information, we don't need to do a dissection. This means
     that all packets can be marked as 'passed'. */
  passed = TRUE;

  /* The frame number of this packet, if we add it to the set of frames,
     would be one more than the count of frames in the file so far. */
  frame_data_init(&fdlocal, cf->count + 1, rec, offset, cum_bytes);

  /* If we're going to print packet information, or we're going to
     run a read filter, or display filter, or we're going to process taps, set up to
     do a dissection and do so. */
  if (edt && dissect) {
    if (gbl_resolv_flags.mac_name || gbl_resolv_flags.network_name ||
        gbl_resolv_flags.transport_name)
      /* Grab any resolved addresses */
      host_name_lookup_process();

    /* If we're running a read filter, prime the epan_dissect_t with that
       filter. */
    if (cf->rfcode)
      epan_dissect_prime_with_dfilter(edt, cf->rfcode);

    if (cf->dfcode)
      epan_dissect_prime_with_dfilter(edt, cf->dfcode);

    /* This is the first and only pass, so prime the epan_dissect_t
       with the hfids postdissectors want on the first pass. */
    prime_epan_dissect_with_postdissector_wanted_hfids(edt);

    frame_data_set_before_dissect(&fdlocal, &cf->elapsed_time,
                                  &cf->provider.ref, cf->provider.prev_dis);
    if (cf->provider.ref == &fdlocal) {
      ref_frame = fdlocal;
      cf->provider.ref = &ref_frame;
    }


    create_proto_tree = /*(dissect_color && color_filters_used()) ||*/ (&cf->cinfo && have_custom_cols(&cf->cinfo));

    epan_dissect_init(&edt, cfile.epan, create_proto_tree, FALSE /* proto_tree_visible */);
    
    if (&cf->cinfo)
      col_custom_prime_edt(edt, &cf->cinfo);

    epan_dissect_run(edt, cf->cd_t, rec,
                     frame_tvbuff_new_buffer(&cf->provider, &fdlocal, buf),
                     &fdlocal, NULL);

    /* Run the read filter if we have one. */
    if (cf->rfcode  && output_packet)
      passed = dfilter_apply_edt(cf->rfcode, edt);
  }

  if (passed) {
    frame_data_set_after_dissect(&fdlocal, &cum_bytes);
    cf->provider.prev_cap = cf->provider.prev_dis = frame_data_sequence_add(cf->provider.frames, &fdlocal);

    // print packet 
    if(TRUE){

      epan_dissect_fill_in_columns(edt, FALSE, TRUE/* fill_fd_columns */);
      sharkd_print_packet(&cf->cinfo);
      // print_packet(capture_file *cf, epan_dissect_t *edt)
      // print_packet(cf, edt);
    }

    /* If we're not doing dissection then there won't be any dependent frames.
     * More importantly, edt.pi.dependent_frames won't be initialized because
     * epan hasn't been initialized.
     * if we *are* doing dissection, then mark the dependent frames, but only
     * if a display filter was given and it matches this packet.
     */
    if (edt && cf->dfcode && output_packet) {
      if (dfilter_apply_edt(cf->dfcode, edt)) {
        g_slist_foreach(edt->pi.dependent_frames, find_and_mark_frame_depended_upon, cf->provider.frames);
      }
    }

    cf->count++;
  } else {
    /* if we don't add it to the frame_data_sequence, clean it up right now
     * to avoid leaks */
    frame_data_destroy(&fdlocal);
  }

  if (edt && dissect)
    epan_dissect_reset(edt);

  return passed;
}


static int
load_cap_file(capture_file *cf, int max_packet_count, gint64 max_byte_count)
{
  int          err;
  gchar       *err_info = NULL;
  gint64       data_offset;
  wtap_rec     rec;
  Buffer       buf;
  epan_dissect_t *edt = NULL;
  gint64       nump = 1;

  {
    /* Allocate a frame_data_sequence for all the frames. */
    cf->provider.frames = new_frame_data_sequence();

    {
      gboolean create_proto_tree;

      /*
       * Determine whether we need to create a protocol tree.
       * We do if:
       *
       *    we're going to apply a read filter;
       *
       *    we're going to apply a display filter;
       *
       *    a postdissector wants field values or protocols
       *    on the first pass.
       */
      create_proto_tree =
        (cf->rfcode != NULL || cf->dfcode != NULL || postdissectors_want_hfids());

      /* We're not going to display the protocol tree on this pass,
         so it's not going to be "visible". */
      edt = epan_dissect_new(cf->epan, create_proto_tree, FALSE);
    }

    wtap_rec_init(&rec);
    ws_buffer_init(&buf, 1514);

    while (wtap_read(cf->provider.wth, &rec, &buf, &err, &err_info, &data_offset)) {
      if (process_packet(cf, edt, data_offset, &rec, &buf, nump)) {
        /* Stop reading if we have the maximum number of packets;
         * When the -c option has not been used, max_packet_count
         * starts at 0, which practically means, never stop reading.
         * (unless we roll over max_packet_count ?)
         */
        if ( (--max_packet_count == 0) || (max_byte_count != 0 && data_offset >= max_byte_count)) {
          err = 0; /* This is not an error */
          break;
        }
      }
      nump++;
    }

    if (edt) {
      epan_dissect_free(edt);
      edt = NULL;
    }

    wtap_rec_cleanup(&rec);
    ws_buffer_free(&buf);

    /* Close the sequential I/O side, to free up memory it requires. */
    wtap_sequential_close(cf->provider.wth);

    /* Allow the protocol dissectors to free up memory that they
     * don't need after the sequential run-through of the packets. */
    postseq_cleanup_all_protocols();

    cf->provider.prev_dis = NULL;
    cf->provider.prev_cap = NULL;
  }

  if (err != 0) {
    cfile_read_failure_message("sharkd", cf->filename, err, err_info);
  }

  return err;
}

cf_status_t
cf_open(capture_file *cf, const char *fname, unsigned int type, gboolean is_tempfile, int *err)
{
  wtap  *wth;
  gchar *err_info;

  wth = wtap_open_offline(fname, type, err, &err_info, TRUE);
  if (wth == NULL)
    goto fail;

  /* The open succeeded.  Fill in the information for this file. */

  cf->provider.wth = wth;
  cf->f_datalen = 0; /* not used, but set it anyway */

  /* Set the file name because we need it to set the follow stream filter.
     XXX - is that still true?  We need it for other reasons, though,
     in any case. */
  cf->filename = g_strdup(fname);

  /* Indicate whether it's a permanent or temporary file. */
  cf->is_tempfile = is_tempfile;

  /* No user changes yet. */
  cf->unsaved_changes = FALSE;

  cf->cd_t      = wtap_file_type_subtype(cf->provider.wth);
  cf->open_type = type;
  cf->count     = 0;
  cf->drops_known = FALSE;
  cf->drops     = 0;
  cf->snap      = wtap_snapshot_length(cf->provider.wth);
  nstime_set_zero(&cf->elapsed_time);
  cf->provider.ref = NULL;
  cf->provider.prev_dis = NULL;
  cf->provider.prev_cap = NULL;

  /* Create new epan session for dissection. */
  epan_free(cf->epan);
  cf->epan = sharkd_epan_new(cf);

  cf->state = FILE_READ_IN_PROGRESS;

  wtap_set_cb_new_ipv4(cf->provider.wth, add_ipv4_name);
  wtap_set_cb_new_ipv6(cf->provider.wth, (wtap_new_ipv6_callback_t) add_ipv6_name);
  wtap_set_cb_new_secrets(cf->provider.wth, secrets_wtap_callback);

  return CF_OK;

fail:
  cfile_open_failure_message("sharkd", fname, *err, err_info);
  return CF_ERROR;
}

/* capturing */ 
#ifdef HAVE_LIBPCAP
#include "ui/capture_ui_utils.h"
#endif

#include "capture_opts.h"

#include "caputils/capture-pcap-util.h"

#ifdef HAVE_LIBPCAP
#include "caputils/capture_ifinfo.h"
#ifdef _WIN32
#include "caputils/capture-wpcap.h"
#endif /* _WIN32 */
#include <capchild/capture_session.h>
#include <capchild/capture_sync.h>
#include <capture_info.h>
#endif /* HAVE_LIBPCAP */

#include <epan/tap.h>
#include <epan/stat_tap_ui.h>


#ifdef HAVE_LIBPCAP
/*
 * TRUE if we're to print packet counts to keep track of captured packets.
 */
static gboolean print_packet_counts;
static gboolean print_packet_info = TRUE; /* TRUE if we're to print packet information */
static capture_options global_capture_opts;
static capture_session global_capture_session;
static info_data_t global_info_data;
static gboolean really_quiet = FALSE;
static gboolean do_dissection;     /* TRUE if we have to dissect each packet */
static gboolean print_details = TRUE;     /* TRUE if we're to print packet details information */
static gboolean print_hex;         /* TRUE if we're to print hex/ascci information */
static gboolean dissect_color = FALSE;
static guint32 epan_auto_reset_count = 0;
static gboolean epan_auto_reset = FALSE;

#ifdef SIGINFO
static gboolean infodelay;      /* if TRUE, don't print capture info in SIGINFO handler */
static gboolean infoprint;      /* if TRUE, print capture info after clearing infodelay */
#endif /* SIGINFO */

static gboolean capture(void);
static void report_counts(void);
#ifdef _WIN32
static BOOL WINAPI capture_cleanup(DWORD);
#else /* _WIN32 */
static void capture_cleanup(int);
#ifdef SIGINFO
static void report_counts_siginfo(int);
#endif /* SIGINFO */
#endif /* _WIN32 */
#endif /* HAVE_LIBPCAP */



/* helper functions */
static const nstime_t *
tshark_get_frame_ts(struct packet_provider_data *prov, guint32 frame_num)
{
  if (prov->ref && prov->ref->num == frame_num)
    return &prov->ref->abs_ts;

  if (prov->prev_dis && prov->prev_dis->num == frame_num)
    return &prov->prev_dis->abs_ts;

  if (prov->prev_cap && prov->prev_cap->num == frame_num)
    return &prov->prev_cap->abs_ts;

  if (prov->frames) {
     frame_data *fd = frame_data_sequence_find(prov->frames, frame_num);

     return (fd) ? &fd->abs_ts : NULL;
  }

  return NULL;
}

static epan_t *
tshark_epan_new(capture_file *cf)
{
  static const struct packet_provider_funcs funcs = {
    tshark_get_frame_ts,
    cap_file_provider_get_interface_name,
    cap_file_provider_get_interface_description,
    NULL,
  };

  return epan_new(&cf->provider, &funcs);
}

static void reset_epan_mem(capture_file *cf, epan_dissect_t *edt, gboolean tree, gboolean visual);

static void reset_epan_mem(capture_file *cf,epan_dissect_t *edt, gboolean tree, gboolean visual)
{
  if (!epan_auto_reset || (cf->count < epan_auto_reset_count))
    return;

  fprintf(stderr, "resetting session.\n");

  epan_dissect_cleanup(edt);
  epan_free(cf->epan);

  cf->epan = tshark_epan_new(cf);
  epan_dissect_init(edt, cf->epan, tree, visual);
  cf->count = 0;
}

static gboolean
must_do_dissection(dfilter_t *rfcode, dfilter_t *dfcode,
                   gchar *volatile pdu_export_arg)
{

  /* We have to dissect each packet if:

        we're printing information about each packet;

        we're using a read filter on the packets;

        we're using a display filter on the packets;

        we're exporting PDUs;

        we're using any taps that need dissection. */
  return print_packet_info || rfcode || dfcode || pdu_export_arg ||
      tap_listeners_require_dissection() || dissect_color;
}

/*#define USE_BROKEN_G_MAIN_LOOP*/

#ifdef USE_BROKEN_G_MAIN_LOOP
  GMainLoop *loop;
#else
  gboolean loop_running = FALSE;
#endif
  guint32 packet_count = 0;


typedef struct pipe_input_tag {
  gint             source;
  gpointer         user_data;
  ws_process_id   *child_process;
  pipe_input_cb_t  input_cb;
  guint            pipe_input_id;
#ifdef _WIN32
  GMutex          *callback_running;
#endif
} pipe_input_t;

static pipe_input_t pipe_input;



void
pipe_input_set_handler(gint source, gpointer user_data, ws_process_id *child_process, pipe_input_cb_t input_cb)
{

  pipe_input.source         = source;
  pipe_input.child_process  = child_process;
  pipe_input.user_data      = user_data;
  pipe_input.input_cb       = input_cb;

#ifdef _WIN32
  pipe_input.callback_running = g_malloc(sizeof(GMutex));
  g_mutex_init(pipe_input.callback_running);
  /* Tricky to use pipes in win9x, as no concept of wait.  NT can
     do this but that doesn't cover all win32 platforms.  GTK can do
     this but doesn't seem to work over processes.  Attempt to do
     something similar here, start a timer and check for data on every
     timeout. */
  /*g_log(NULL, G_LOG_LEVEL_DEBUG, "pipe_input_set_handler: new");*/
  pipe_input.pipe_input_id = g_timeout_add(200, pipe_timer_cb, &pipe_input);
#endif
}

#ifdef HAVE_LIBPCAP
static gboolean
capture(void)
{
  volatile gboolean ret = TRUE;
  guint             i;
  GString          *str;
#ifdef USE_TSHARK_SELECT
  fd_set            readfds;
#endif
#ifndef _WIN32
  struct sigaction  action, oldaction;
#endif

  /* Create new dissection section. */
  epan_free(cfile.epan);
  cfile.epan = tshark_epan_new(&cfile);

#ifdef _WIN32
  /* Catch a CTRL+C event and, if we get it, clean up and exit. */
  SetConsoleCtrlHandler(capture_cleanup, TRUE);
#else /* _WIN32 */
  /* Catch SIGINT and SIGTERM and, if we get either of them,
     clean up and exit.  If SIGHUP isn't being ignored, catch
     it too and, if we get it, clean up and exit.

     We restart any read that was in progress, so that it doesn't
     disrupt reading from the sync pipe.  The signal handler tells
     the capture child to finish; it will report that it finished,
     or will exit abnormally, so  we'll stop reading from the sync
     pipe, pick up the exit status, and quit. */
  memset(&action, 0, sizeof(action));
  action.sa_handler = capture_cleanup;
  action.sa_flags = SA_RESTART;
  sigemptyset(&action.sa_mask);
  sigaction(SIGTERM, &action, NULL);
  sigaction(SIGINT, &action, NULL);
  sigaction(SIGHUP, NULL, &oldaction);
  if (oldaction.sa_handler == SIG_DFL)
    sigaction(SIGHUP, &action, NULL);

#ifdef SIGINFO
  /* Catch SIGINFO and, if we get it and we're capturing to a file in
     quiet mode, report the number of packets we've captured.

     Again, restart any read that was in progress, so that it doesn't
     disrupt reading from the sync pipe. */
  action.sa_handler = report_counts_siginfo;
  action.sa_flags = SA_RESTART;
  sigemptyset(&action.sa_mask);
  sigaction(SIGINFO, &action, NULL);
#endif /* SIGINFO */
#endif /* _WIN32 */

  global_capture_session.state = CAPTURE_PREPARING;

  /* Let the user know which interfaces were chosen. */
  for (i = 0; i < global_capture_opts.ifaces->len; i++) {
    interface_options *interface_opts;

    interface_opts = &g_array_index(global_capture_opts.ifaces, interface_options, i);
    g_free(interface_opts->descr);
    interface_opts->descr = get_interface_descriptive_name(interface_opts->name);
  }
  str = get_iface_list_string(&global_capture_opts, IFLIST_QUOTE_IF_DESCRIPTION);
  if (really_quiet == FALSE)
    fprintf(stderr, "Capturing on %s\n", str->str);
  fflush(stderr);
  g_string_free(str, TRUE);

  ret = sync_pipe_start(&global_capture_opts, &global_capture_session, &global_info_data, NULL);

  if (!ret)
    return FALSE;

  /*
   * Force synchronous resolution of IP addresses; we're doing only
   * one pass, so we can't do it in the background and fix up past
   * dissections.
   */
  set_resolution_synchrony(TRUE);

  /* the actual capture loop
   *
   * XXX - glib doesn't seem to provide any event based loop handling.
   *
   * XXX - for whatever reason,
   * calling g_main_loop_new() ends up in 100% cpu load.
   *
   * But that doesn't matter: in UNIX we can use select() to find an input
   * source with something to do.
   *
   * But that doesn't matter because we're in a CLI (that doesn't need to
   * update a GUI or something at the same time) so it's OK if we block
   * trying to read from the pipe.
   *
   * So all the stuff in USE_TSHARK_SELECT could be removed unless I'm
   * wrong (but I leave it there in case I am...).
   */

#ifdef USE_TSHARK_SELECT
  FD_ZERO(&readfds);
  FD_SET(pipe_input.source, &readfds);
#endif

  loop_running = TRUE;

  TRY
  {
    while (loop_running)
    {
#ifdef USE_TSHARK_SELECT
      ret = select(pipe_input.source+1, &readfds, NULL, NULL, NULL);

      if (ret == -1)
      {
        fprintf(stderr, "%s: %s\n", "select()", g_strerror(errno));
        ret = TRUE;
        loop_running = FALSE;
      } else if (ret == 1) {
#endif
        /* Call the real handler */
        if (!pipe_input.input_cb(pipe_input.source, pipe_input.user_data)) {
          g_log(NULL, G_LOG_LEVEL_DEBUG, "input pipe closed");
          ret = FALSE;
          loop_running = FALSE;
        }
#ifdef USE_TSHARK_SELECT
      }
#endif
    }
  }
  CATCH(OutOfMemoryError) {
    fprintf(stderr,
            "Out Of Memory.\n"
            "\n"
            "Sorry, but TShark has to terminate now.\n"
            "\n"
            "More information and workarounds can be found at\n"
            "https://wiki.wireshark.org/KnownBugs/OutOfMemory\n");
    abort();
  }
  ENDTRY;
  return ret;
}

/* capture child detected an error */
void
capture_input_error_message(capture_session *cap_session _U_, char *error_msg, char *secondary_error_msg)
{
  cmdarg_err("%s", error_msg);
  cmdarg_err_cont("%s", secondary_error_msg);
}


/* capture child detected an capture filter related error */
void
capture_input_cfilter_error_message(capture_session *cap_session, guint i, const char *error_message)
{
  capture_options *capture_opts = cap_session->capture_opts;
  dfilter_t         *rfcode = NULL;
  interface_options *interface_opts;

  g_assert(i < capture_opts->ifaces->len);
  interface_opts = &g_array_index(capture_opts->ifaces, interface_options, i);

  if (dfilter_compile(interface_opts->cfilter, &rfcode, NULL) && rfcode != NULL) {
    cmdarg_err(
      "Invalid capture filter \"%s\" for interface '%s'.\n"
      "\n"
      "That string looks like a valid display filter; however, it isn't a valid\n"
      "capture filter (%s).\n"
      "\n"
      "Note that display filters and capture filters don't have the same syntax,\n"
      "so you can't use most display filter expressions as capture filters.\n"
      "\n"
      "See the User's Guide for a description of the capture filter syntax.",
      interface_opts->cfilter, interface_opts->descr, error_message);
    dfilter_free(rfcode);
  } else {
    cmdarg_err(
      "Invalid capture filter \"%s\" for interface '%s'.\n"
      "\n"
      "That string isn't a valid capture filter (%s).\n"
      "See the User's Guide for a description of the capture filter syntax.",
      interface_opts->cfilter, interface_opts->descr, error_message);
  }
}


/* capture child tells us we have a new (or the first) capture file */
gboolean
capture_input_new_file(capture_session *cap_session, gchar *new_file)
{
  capture_options *capture_opts = cap_session->capture_opts;
  capture_file *cf = cap_session->cf;
  gboolean is_tempfile;
  int      err;

  if (cap_session->state == CAPTURE_PREPARING) {
    g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "Capture started.");
  }
  g_log(LOG_DOMAIN_CAPTURE, G_LOG_LEVEL_MESSAGE, "File: \"%s\"", new_file);

  g_assert(cap_session->state == CAPTURE_PREPARING || cap_session->state == CAPTURE_RUNNING);

  /* free the old filename */
  if (capture_opts->save_file != NULL) {

    /* we start a new capture file, close the old one (if we had one before) */
    if (cf->state != FILE_CLOSED) {
      if (cf->provider.wth != NULL) {
        wtap_close(cf->provider.wth);
        cf->provider.wth = NULL;
      }
      cf->state = FILE_CLOSED;
    }

    g_free(capture_opts->save_file);
    is_tempfile = FALSE;

    epan_free(cf->epan);
    cf->epan = tshark_epan_new(cf);
  } else {
    /* we didn't had a save_file before, must be a tempfile */
    is_tempfile = TRUE;
  }

  /* save the new filename */
  capture_opts->save_file = g_strdup(new_file);

  /* if we are in real-time mode, open the new file now */
  if (do_dissection) {
    /* this is probably unecessary, but better safe than sorry */
    cap_session->cf->open_type = WTAP_TYPE_AUTO;
    /* Attempt to open the capture file and set up to read from it. */
    switch(cf_open(cap_session->cf, capture_opts->save_file, WTAP_TYPE_AUTO, is_tempfile, &err)) {
    case CF_OK:
      break;
    case CF_ERROR:
      /* Don't unlink (delete) the save file - leave it around,
         for debugging purposes. */
      g_free(capture_opts->save_file);
      capture_opts->save_file = NULL;
      return FALSE;
    }
  }

  cap_session->state = CAPTURE_RUNNING;

  return TRUE;
}


/* capture child tells us we have new packets to read */
void
capture_input_new_packets(capture_session *cap_session, int to_read)
{
  gboolean      ret;
  int           err;
  gchar        *err_info;
  gint64        data_offset;
  capture_file *cf = cap_session->cf;
  gboolean      filtering_tap_listeners;
  guint         tap_flags;
  gint64        nump = 0;

#ifdef SIGINFO
  /*
   * Prevent a SIGINFO handler from writing to the standard error while
   * we're doing so or writing to the standard output; instead, have it
   * just set a flag telling us to print that information when we're done.
   */
  infodelay = TRUE;
#endif /* SIGINFO */

  /* Do we have any tap listeners with filters? */
  filtering_tap_listeners = have_filtering_tap_listeners();

  /* Get the union of the flags for all tap listeners. */
  tap_flags = union_of_tap_listener_flags();

  if (do_dissection) {
    gboolean create_proto_tree;
    epan_dissect_t *edt;
    wtap_rec rec;
    Buffer buf;

    /*
     * Determine whether we need to create a protocol tree.
     * We do if:
     *
     *    we're going to apply a read filter;
     *
     *    we're going to apply a display filter;
     *
     *    we're going to print the protocol tree;
     *
     *    one of the tap listeners is going to apply a filter;
     *
     *    one of the tap listeners requires a protocol tree;
     *
     *    a postdissector wants field values or protocols
     *    on the first pass;
     *
     *    we have custom columns (which require field values, which
     *    currently requires that we build a protocol tree).
     */
    create_proto_tree =
      (cf->rfcode || cf->dfcode || print_details || filtering_tap_listeners ||
        (tap_flags & TL_REQUIRES_PROTO_TREE) || postdissectors_want_hfids() ||
        have_custom_cols(&cf->cinfo) || dissect_color);

    /* The protocol tree will be "visible", i.e., printed, only if we're
       printing packet details, which is true if we're printing stuff
       ("print_packet_info" is true) and we're in verbose mode
       ("packet_details" is true). */
    edt = epan_dissect_new(cf->epan, create_proto_tree, print_packet_info && print_details);

    wtap_rec_init(&rec);
    ws_buffer_init(&buf, 1514);

    while (to_read-- && cf->provider.wth) {
      wtap_cleareof(cf->provider.wth);
      ret = wtap_read(cf->provider.wth, &rec, &buf, &err, &err_info, &data_offset);
      reset_epan_mem(cf, edt, create_proto_tree, print_packet_info && print_details);
      if (ret == FALSE) {
        /* read from file failed, tell the capture child to stop */
        sync_pipe_stop(cap_session);
        wtap_close(cf->provider.wth);
        cf->provider.wth = NULL;
      } else {

        // TODO Not sure if this is the right point to put this
        /* Allocate a frame_data_sequence for all the frames. */
        cf->provider.frames = new_frame_data_sequence();

        ret = process_packet(cf, edt, data_offset, &rec, &buf,
                                         nump);
      }
      if (ret != FALSE) {
        /* packet successfully read and gone through the "Read Filter" */
        packet_count++;
      }
    }

    epan_dissect_free(edt);

    wtap_rec_cleanup(&rec);
    ws_buffer_free(&buf);

  } else {
    /*
     * Dumpcap's doing all the work; we're not doing any dissection.
     * Count all the packets it wrote.
     */
    packet_count += to_read;
  }

  if (print_packet_counts) {
      /* We're printing packet counts. */
      if (packet_count != 0) {
        fprintf(stderr, "\r%u ", packet_count);
        /* stderr could be line buffered */
        fflush(stderr);
      }
  }

#ifdef SIGINFO
  /*
   * Allow SIGINFO handlers to write.
   */
  infodelay = FALSE;

  /*
   * If a SIGINFO handler asked us to write out capture counts, do so.
   */
  if (infoprint)
    report_counts();
#endif /* SIGINFO */
}

static void
report_counts(void)
{
  if ((print_packet_counts == FALSE) && (really_quiet == FALSE)) {
    /* Report the count only if we aren't printing a packet count
       as packets arrive. */
      fprintf(stderr, "%u packet%s captured\n", packet_count,
            plurality(packet_count, "", "s"));
  }
#ifdef SIGINFO
  infoprint = FALSE; /* we just reported it */
#endif /* SIGINFO */
}

#ifdef SIGINFO
static void
report_counts_siginfo(int signum _U_)
{
  int sav_errno = errno;
  /* If we've been told to delay printing, just set a flag asking
     that we print counts (if we're supposed to), otherwise print
     the count of packets captured (if we're supposed to). */
  if (infodelay)
    infoprint = TRUE;
  else
    report_counts();
  errno = sav_errno;
}
#endif /* SIGINFO */


/* capture child detected any packet drops? */
void
capture_input_drops(capture_session *cap_session _U_, guint32 dropped, const char* interface_name)
{
  if (print_packet_counts) {
    /* We're printing packet counts to stderr.
       Send a newline so that we move to the line after the packet count. */
    fprintf(stderr, "\n");
  }

  if (dropped != 0) {
    /* We're printing packet counts to stderr.
       Send a newline so that we move to the line after the packet count. */
    if (interface_name != NULL) {
      fprintf(stderr, "%u packet%s dropped from %s\n", dropped, plurality(dropped, "", "s"), interface_name);
    } else {
      fprintf(stderr, "%u packet%s dropped\n", dropped, plurality(dropped, "", "s"));
    }
  }
}


/*
 * Capture child closed its side of the pipe, report any error and
 * do the required cleanup.
 */
void
capture_input_closed(capture_session *cap_session, gchar *msg)
{
  capture_file *cf = cap_session->cf;

  if (msg != NULL)
    fprintf(stderr, "tshark: %s\n", msg);

  report_counts();

  if (cf != NULL && cf->provider.wth != NULL) {
    wtap_close(cf->provider.wth);
    if (cf->is_tempfile) {
      ws_unlink(cf->filename);
    }
  }
#ifdef USE_BROKEN_G_MAIN_LOOP
  /*g_main_loop_quit(loop);*/
  g_main_loop_quit(loop);
#else
  loop_running = FALSE;
#endif
}

#ifdef _WIN32
static BOOL WINAPI
capture_cleanup(DWORD ctrltype _U_)
{
  /* CTRL_C_EVENT is sort of like SIGINT, CTRL_BREAK_EVENT is unique to
     Windows, CTRL_CLOSE_EVENT is sort of like SIGHUP, CTRL_LOGOFF_EVENT
     is also sort of like SIGHUP, and CTRL_SHUTDOWN_EVENT is sort of
     like SIGTERM at least when the machine's shutting down.

     For now, we handle them all as indications that we should clean up
     and quit, just as we handle SIGINT, SIGHUP, and SIGTERM in that
     way on UNIX.

     We must return TRUE so that no other handler - such as one that would
     terminate the process - gets called.

     XXX - for some reason, typing ^C to TShark, if you run this in
     a Cygwin console window in at least some versions of Cygwin,
     causes TShark to terminate immediately; this routine gets
     called, but the main loop doesn't get a chance to run and
     exit cleanly, at least if this is compiled with Microsoft Visual
     C++ (i.e., it's a property of the Cygwin console window or Bash;
     it happens if TShark is not built with Cygwin - for all I know,
     building it with Cygwin may make the problem go away). */

  /* tell the capture child to stop */
  sync_pipe_stop(&global_capture_session);

  /* don't stop our own loop already here, otherwise status messages and
   * cleanup wouldn't be done properly. The child will indicate the stop of
   * everything by calling capture_input_closed() later */

  return TRUE;
}
#else
static void
capture_cleanup(int signum _U_)
{
  /* tell the capture child to stop */
  sync_pipe_stop(&global_capture_session);

  /* don't stop our own loop already here, otherwise status messages and
   * cleanup wouldn't be done properly. The child will indicate the stop of
   * everything by calling capture_input_closed() later */
}
#endif /* _WIN32 */
#endif /* HAVE_LIBPCAP */

int
capture_start(const char *capture_device)
{
  e_prefs *prefs_p;
  volatile int exit_status = EXIT_SUCCESS;

  gchar *volatile pdu_export_arg = NULL;
  volatile gboolean draw_taps = FALSE;
  // static capture_options global_capture_opts;
  // static capture_session global_capture_session;

  dfilter_t *rfcode = NULL;
  dfilter_t *dfcode = NULL;


#ifdef HAVE_LIBPCAP
  capture_opts_init(&global_capture_opts);
  capture_session_init(&global_capture_session, &cfile);
#endif

  // TODO set capture opts

  int caps_queries = 0;
  // already loaded in main but just lead again in case of capture
  prefs_p = epan_load_settings();
  prefs_p->capture_device = capture_device;


  /* No capture file specified, so we're supposed to do a live capture
      or get a list of link-layer types for a live capture device;
      do we have support for live captures? */
#ifdef HAVE_LIBPCAP
#ifdef _WIN32
  /* Warn the user if npf.sys isn't loaded. */
  if (!npf_sys_is_running()) {
    fprintf(stderr, "The NPF driver isn't running.  You may have trouble "
        "capturing or\nlisting interfaces.\n");
  }
#endif /* _WIN32 */

  /* if no interface was specified, pick a default */
  exit_status = capture_opts_default_iface_if_necessary(&global_capture_opts,
      ((prefs_p->capture_device) && (*prefs_p->capture_device != '\0')) ? get_if_name(prefs_p->capture_device) : NULL);
  if (exit_status != 0) {
    return NULL;
    // goto clean_exit;
  }


  print_packet_counts = FALSE;

  // TODO skip preamble for now
  // if (print_packet_info) {
  //   if (!write_preamble(&cfile)) {
  //     show_print_file_io_error(errno);
  //     exit_status = INVALID_FILE;
  //     goto clean_exit;
  //   }
  // }

  /* Start statistics taps; we should only do so after the capture
      started successfully, so we know we have something to compute
      stats, but we currently don't check for that - see below.

      We do so after registering all dissectors, so that MATE will
      have registered its field array so we can have a tap filter
      with one of MATE's late-registered fields as part of the
      filter. */
  start_requested_stats();

  /* Do we need to do dissection of packets?  That depends on, among
      other things, what taps are listening, so determine that after
      starting the statistics taps. */
  do_dissection = must_do_dissection(rfcode, dfcode, pdu_export_arg);

  /*
    * XXX - this returns FALSE if an error occurred, but it also
    * returns FALSE if the capture stops because a time limit
    * was reached (and possibly other limits), so we can't assume
    * it means an error.
    *
    * The capture code is a bit twisty, so it doesn't appear to
    * be an easy fix.  We just ignore the return value for now.
    * Instead, pass on the exit status from the capture child.
    */
  capture();
  exit_status = global_capture_session.fork_child_status;

  // TODO skip for now
  // if (print_packet_info) {
  //   if (!write_finale()) {
  //     show_print_file_io_error(errno);
  //   }
  // }

  /*
    * If we never got a capture file, don't draw the taps; we not only
    * didn't capture any packets, we never even did any capturing.
    */
  if (cfile.filename != NULL)
    draw_taps = TRUE;
#else
  /* No - complain. */
  cmdarg_err("This version of TShark was not built with support for capturing packets.");
  exit_status = INVALID_CAPTURE;
  goto clean_exit;
#endif
  return 0;
}

/*
 * General errors and warnings are reported with an console message
 * in sharkd.
 */
static void
failure_warning_message(const char *msg_format, va_list ap)
{
  fprintf(stderr, "sharkd: ");
  vfprintf(stderr, msg_format, ap);
  fprintf(stderr, "\n");
}

/*
 * Open/create errors are reported with an console message in sharkd.
 */
static void
open_failure_message(const char *filename, int err, gboolean for_writing)
{
  fprintf(stderr, "sharkd: ");
  fprintf(stderr, file_open_error_message(err, for_writing), filename);
  fprintf(stderr, "\n");
}

/*
 * Read errors are reported with an console message in sharkd.
 */
static void
read_failure_message(const char *filename, int err)
{
  cmdarg_err("An error occurred while reading from the file \"%s\": %s.",
          filename, g_strerror(err));
}

/*
 * Write errors are reported with an console message in sharkd.
 */
static void
write_failure_message(const char *filename, int err)
{
  cmdarg_err("An error occurred while writing to the file \"%s\": %s.",
          filename, g_strerror(err));
}

/*
 * Report additional information for an error in command-line arguments.
 */
static void
failure_message_cont(const char *msg_format, va_list ap)
{
  vfprintf(stderr, msg_format, ap);
  fprintf(stderr, "\n");
}

cf_status_t
sharkd_cf_open(const char *fname, unsigned int type, gboolean is_tempfile, int *err)
{
  return cf_open(&cfile, fname, type, is_tempfile, err);
}

int
sharkd_capture_start(const char *capture_device)
{
  return capture_start(capture_device);
}

int
sharkd_load_cap_file(void)
{
  return load_cap_file(&cfile, 0, 0);
}

frame_data *
sharkd_get_frame(guint32 framenum)
{
  return frame_data_sequence_find(cfile.provider.frames, framenum);
}

int
sharkd_dissect_request(guint32 framenum, guint32 frame_ref_num, guint32 prev_dis_num, sharkd_dissect_func_t cb, guint32 dissect_flags, void *data)
{
  frame_data *fdata;
  column_info *cinfo = (dissect_flags & SHARKD_DISSECT_FLAG_COLUMNS) ? &cfile.cinfo : NULL;
  epan_dissect_t edt;
  gboolean create_proto_tree;
  wtap_rec rec; /* Record metadata */
  Buffer buf;   /* Record data */

  int err;
  char *err_info = NULL;

  fdata = sharkd_get_frame(framenum);
  if (fdata == NULL)
    return -1;

  wtap_rec_init(&rec);
  ws_buffer_init(&buf, 1514);

  if (!wtap_seek_read(cfile.provider.wth, fdata->file_off, &rec, &buf, &err, &err_info)) {
    wtap_rec_cleanup(&rec);
    ws_buffer_free(&buf);
    return -1; /* error reading the record */
  }

  create_proto_tree = ((dissect_flags & SHARKD_DISSECT_FLAG_PROTO_TREE) ||
                      ((dissect_flags & SHARKD_DISSECT_FLAG_COLOR) && color_filters_used()) ||
                      (cinfo && have_custom_cols(cinfo)));
  epan_dissect_init(&edt, cfile.epan, create_proto_tree, (dissect_flags & SHARKD_DISSECT_FLAG_PROTO_TREE));

  if (dissect_flags & SHARKD_DISSECT_FLAG_COLOR) {
    color_filters_prime_edt(&edt);
    fdata->need_colorize = 1;
  }

  if (cinfo)
    col_custom_prime_edt(&edt, cinfo);

  /*
   * XXX - need to catch an OutOfMemoryError exception and
   * attempt to recover from it.
   */
  fdata->ref_time = (framenum == frame_ref_num);
  fdata->frame_ref_num = frame_ref_num;
  fdata->prev_dis_num = prev_dis_num;
  epan_dissect_run(&edt, cfile.cd_t, &rec,
                   frame_tvbuff_new_buffer(&cfile.provider, fdata, &buf),
                   fdata, cinfo);

  if (cinfo) {
    /* "Stringify" non frame_data vals */
    epan_dissect_fill_in_columns(&edt, FALSE, TRUE/* fill_fd_columns */);
  }

  cb(&edt, (dissect_flags & SHARKD_DISSECT_FLAG_PROTO_TREE) ? edt.tree : NULL,
     cinfo, (dissect_flags & SHARKD_DISSECT_FLAG_BYTES) ? edt.pi.data_src : NULL,
     data);

  epan_dissect_cleanup(&edt);
  wtap_rec_cleanup(&rec);
  ws_buffer_free(&buf);
  return 0;
}

/* based on packet_list_dissect_and_cache_record */
int
sharkd_dissect_columns(frame_data *fdata, guint32 frame_ref_num, guint32 prev_dis_num, column_info *cinfo, gboolean dissect_color)
{
  epan_dissect_t edt;
  gboolean create_proto_tree;
  wtap_rec rec; /* Record metadata */
  Buffer buf;   /* Record data */

  int err;
  char *err_info = NULL;

  wtap_rec_init(&rec);
  ws_buffer_init(&buf, 1514);

  if (!wtap_seek_read(cfile.provider.wth, fdata->file_off, &rec, &buf, &err, &err_info)) {
    col_fill_in_error(cinfo, fdata, FALSE, FALSE /* fill_fd_columns */);
    wtap_rec_cleanup(&rec);
    ws_buffer_free(&buf);
    return -1; /* error reading the record */
  }

  create_proto_tree = (dissect_color && color_filters_used()) || (cinfo && have_custom_cols(cinfo));

  epan_dissect_init(&edt, cfile.epan, create_proto_tree, FALSE /* proto_tree_visible */);

  if (dissect_color) {
    color_filters_prime_edt(&edt);
    fdata->need_colorize = 1;
  }

  if (cinfo)
    col_custom_prime_edt(&edt, cinfo);

  /*
   * XXX - need to catch an OutOfMemoryError exception and
   * attempt to recover from it.
   */
  fdata->ref_time = (fdata->num == frame_ref_num);
  fdata->frame_ref_num = frame_ref_num;
  fdata->prev_dis_num = prev_dis_num;
  epan_dissect_run(&edt, cfile.cd_t, &rec,
                   frame_tvbuff_new_buffer(&cfile.provider, fdata, &buf),
                   fdata, cinfo);

  if (cinfo) {
    /* "Stringify" non frame_data vals */
    epan_dissect_fill_in_columns(&edt, FALSE, TRUE/* fill_fd_columns */);
  }

  epan_dissect_cleanup(&edt);
  wtap_rec_cleanup(&rec);
  ws_buffer_free(&buf);
  return 0;
}

int
sharkd_retap(void)
{
  guint32          framenum;
  frame_data      *fdata;
  Buffer           buf;
  wtap_rec         rec;
  int err;
  char *err_info = NULL;

  guint         tap_flags;
  gboolean      create_proto_tree;
  epan_dissect_t edt;
  column_info   *cinfo;

  /* Get the union of the flags for all tap listeners. */
  tap_flags = union_of_tap_listener_flags();

  /* If any tap listeners require the columns, construct them. */
  cinfo = (tap_flags & TL_REQUIRES_COLUMNS) ? &cfile.cinfo : NULL;

  /*
   * Determine whether we need to create a protocol tree.
   * We do if:
   *
   *    one of the tap listeners is going to apply a filter;
   *
   *    one of the tap listeners requires a protocol tree.
   */
  create_proto_tree =
    (have_filtering_tap_listeners() || (tap_flags & TL_REQUIRES_PROTO_TREE));

  wtap_rec_init(&rec);
  ws_buffer_init(&buf, 1514);
  epan_dissect_init(&edt, cfile.epan, create_proto_tree, FALSE);

  reset_tap_listeners();

  for (framenum = 1; framenum <= cfile.count; framenum++) {
    fdata = sharkd_get_frame(framenum);

    if (!wtap_seek_read(cfile.provider.wth, fdata->file_off, &rec, &buf, &err, &err_info))
      break;

    fdata->ref_time = FALSE;
    fdata->frame_ref_num = (framenum != 1) ? 1 : 0;
    fdata->prev_dis_num = framenum - 1;
    epan_dissect_run_with_taps(&edt, cfile.cd_t, &rec,
                               frame_tvbuff_new_buffer(&cfile.provider, fdata, &buf),
                               fdata, cinfo);
    epan_dissect_reset(&edt);
  }

  wtap_rec_cleanup(&rec);
  ws_buffer_free(&buf);
  epan_dissect_cleanup(&edt);

  draw_tap_listeners(TRUE);

  return 0;
}

int
sharkd_filter(const char *dftext, guint8 **result)
{
  dfilter_t  *dfcode = NULL;

  guint32 framenum, prev_dis_num = 0;
  guint32 frames_count;
  Buffer buf;
  wtap_rec rec;
  int err;
  char *err_info = NULL;

  guint8 *result_bits;
  guint8  passed_bits;

  epan_dissect_t edt;

  if (!dfilter_compile(dftext, &dfcode, &err_info)) {
    g_free(err_info);
    return -1;
  }

  /* if dfilter_compile() success, but (dfcode == NULL) all frames are matching */
  if (dfcode == NULL) {
    *result = NULL;
    return 0;
  }

  frames_count = cfile.count;

  wtap_rec_init(&rec);
  ws_buffer_init(&buf, 1514);
  epan_dissect_init(&edt, cfile.epan, TRUE, FALSE);

  passed_bits = 0;
  result_bits = (guint8 *) g_malloc(2 + (frames_count / 8));

  for (framenum = 1; framenum <= frames_count; framenum++) {
    frame_data *fdata = sharkd_get_frame(framenum);

    if ((framenum & 7) == 0) {
      result_bits[(framenum / 8) - 1] = passed_bits;
      passed_bits = 0;
    }

    if (!wtap_seek_read(cfile.provider.wth, fdata->file_off, &rec, &buf, &err, &err_info))
      break;

    /* frame_data_set_before_dissect */
    epan_dissect_prime_with_dfilter(&edt, dfcode);

    fdata->ref_time = FALSE;
    fdata->frame_ref_num = (framenum != 1) ? 1 : 0;
    fdata->prev_dis_num = prev_dis_num;
    epan_dissect_run(&edt, cfile.cd_t, &rec,
                     frame_tvbuff_new_buffer(&cfile.provider, fdata, &buf),
                     fdata, NULL);

    if (dfilter_apply_edt(dfcode, &edt)) {
      passed_bits |= (1 << (framenum % 8));
      prev_dis_num = framenum;
    }

    /* if passed or ref -> frame_data_set_after_dissect */

    epan_dissect_reset(&edt);
  }

  if ((framenum & 7) == 0)
      framenum--;
  result_bits[framenum / 8] = passed_bits;

  wtap_rec_cleanup(&rec);
  ws_buffer_free(&buf);
  epan_dissect_cleanup(&edt);

  dfilter_free(dfcode);

  *result = result_bits;

  return framenum;
}

const char *
sharkd_get_user_comment(const frame_data *fd)
{
  return cap_file_provider_get_user_comment(&cfile.provider, fd);
}

int
sharkd_set_user_comment(frame_data *fd, const gchar *new_comment)
{
  cap_file_provider_set_user_comment(&cfile.provider, fd, new_comment);
  return 0;
}

#include "version.h"
const char *sharkd_version(void)
{
  /* based on get_ws_vcs_version_info(), but shorter */
#ifdef VCSVERSION
  return VCSVERSION;
#else
  return VERSION;
#endif
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
