#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <locale.h>
#include <limits.h>

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#include <errno.h>

#ifdef _WIN32
# include <winsock2.h>
#endif

#ifndef _WIN32
#include <signal.h>
#endif

#ifdef HAVE_LIBCAP
# include <sys/capability.h>
#endif

#ifndef HAVE_GETOPT_LONG
#include "wsutil/wsgetopt.h"
#endif

#include <glib.h>

#include <epan/exceptions.h>
#include <epan/epan.h>

#include <ui/clopts_common.h>
#include <ui/cmdarg_err.h>
#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/socket.h>
#include <wsutil/privileges.h>
#include <wsutil/report_message.h>
#include <wsutil/please_report_bug.h>
#include <cli_main.h>
#include <version_info.h>
#include <wiretap/wtap_opttypes.h>
#include <wiretap/pcapng.h>

#include "globals.h"
#include <epan/timestamp.h>
#include <epan/packet.h>
#ifdef HAVE_LUA
#include <epan/wslua/init_wslua.h>
#endif
#include "frame_tvbuff.h"
#include <epan/disabled_protos.h>
#include <epan/prefs.h>
#include <epan/column.h>
#include <epan/decode_as.h>
#include <epan/print.h>
#include <epan/addr_resolv.h>
#ifdef HAVE_LIBPCAP
#include "ui/capture_ui_utils.h"
#endif
#include "ui/taps.h"
#include "ui/util.h"
#include "ui/ws_ui_util.h"
#include "ui/decode_as_utils.h"
#include "ui/filter_files.h"
#include "ui/cli/tshark-tap.h"
#include "ui/cli/tap-exportobject.h"
#include "ui/tap_export_pdu.h"
#include "ui/dissect_opts.h"
#include "ui/failure_message.h"
#if defined(HAVE_LIBSMI)
#include "epan/oids.h"
#endif
#include "epan/maxmind_db.h"
#include <epan/epan_dissect.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include <epan/conversation_table.h>
#include <epan/srt_table.h>
#include <epan/rtd_table.h>
#include <epan/ex-opt.h>
#include <epan/exported_pdu.h>
#include <epan/secrets.h>

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
#include "log.h"
#include <epan/funnel.h>

#include <wsutil/str_util.h>
#include <wsutil/utf8_entities.h>
#include <wsutil/json_dumper.h>

#include "extcap.h"

#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif

#include "sharkd.h"
#include "sharkd_session.h"


/* tshark.c is used as a template for this code
 * however the tshark code is so entangled that we almost ended up copying over everything
 * related to capturing
 * /

/* Exit codes */
#define INVALID_OPTION 1
#define INVALID_INTERFACE 2
#define INVALID_FILE 2
#define INVALID_FILTER 2
#define INVALID_EXPORT 2
#define INVALID_CAPABILITY 2
#define INVALID_TAP 2
#define INVALID_DATA_LINK 2
#define INVALID_TIMESTAMP_TYPE 2
#define INVALID_CAPTURE 2
#define INIT_FAILED 2


static capture_options global_capture_opts;
static capture_session global_capture_session;
static info_data_t global_info_data;
static gboolean print_hex;
static gboolean print_packet_counts;
static gboolean print_packet_info = TRUE; /* TRUE if we're to print packet information */
static gboolean do_dissection = TRUE;     /* TRUE if we have to dissect each packet */
static gboolean really_quiet = FALSE;
static gboolean print_details = TRUE;     /* TRUE if we're to print packet details information */
static gboolean dissect_color = TRUE;
static gboolean print_summary;     /* TRUE if we're to print packet summary information */
static gboolean line_buffered;
static guint32 epan_auto_reset_count = 0;
static gboolean epan_auto_reset = FALSE;
static guint32 cum_bytes;

static output_fields_t* output_fields  = NULL;
static gchar **protocolfilter = NULL;
static pf_flags protocolfilter_flags = PF_NONE;

static gboolean no_duplicate_keys = FALSE;
static proto_node_children_grouper_func node_children_grouper = proto_node_group_children_by_unique;

//static json_dumper jdumper;


static frame_data ref_frame;
static frame_data prev_dis_frame;
static frame_data prev_cap_frame;

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

static void reset_epan_mem(capture_file *cf,epan_dissect_t *edt, gboolean tree, gboolean visual)
{
  if (!epan_auto_reset || (cf->count < epan_auto_reset_count))
    return;

  fprintf(stderr, "resetting session.\n");

  epan_dissect_cleanup(edt);
  epan_free(cf->epan);

  cf->epan = sharkd_epan_new(cf);
  epan_dissect_init(edt, cf->epan, tree, visual);
  cf->count = 0;
}

static void
capture_cleanup(int signum _U_)
{
  /* tell the capture child to stop */
  sync_pipe_stop(&global_capture_session);

  /* don't stop our own loop already here, otherwise status messages and
   * cleanup wouldn't be done properly. The child will indicate the stop of
   * everything by calling capture_input_closed() later */
}

static gboolean write_preamble(capture_file *cf)
{
    return TRUE; // TODO: write json
}

static gboolean
write_finale(void)
{
  return TRUE;
}

static void
show_print_file_io_error(int err)
{
  switch (err) {

  case ENOSPC:
    cmdarg_err("Not all the packets could be printed because there is "
"no space left on the file system.");
    break;

#ifdef EDQUOT
  case EDQUOT:
    cmdarg_err("Not all the packets could be printed because you are "
"too close to, or over your disk quota.");
  break;
#endif

  default:
    cmdarg_err("An error occurred while printing packets: %s.",
      g_strerror(err));
    break;
  }
}


void
sharkd_capture_init(void)
{
#ifdef HAVE_LIBPCAP
    capture_opts_init(&global_capture_opts);
    capture_session_init(&global_capture_session, &cfile);
    output_fields = output_fields_new();

    // TODO read from req packet and do not hardcode
    output_fields_add(output_fields, "frame.number");
    output_fields_add(output_fields, "frame.time_relative");
    output_fields_add(output_fields, "9");
    output_fields_add(output_fields, "39");
    output_fields_add(output_fields, "ip.src");
    output_fields_add(output_fields, "ip.dst");
    output_fields_add(output_fields, "tcp.srcport");
    output_fields_add(output_fields, "tcp.dstport");
    output_fields_add(output_fields, "frame.len");

    //'frame.number', 'frame.time_relative', '9', '39', '14', 'frame.len', '28', 'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport'

    print_packet_info = TRUE;
#endif
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
    cf->epan = sharkd_epan_new(cf);
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

static gboolean
print_packet(capture_file *cf, epan_dissect_t *edt)
{
  if (print_summary || output_fields_has_cols(output_fields))
    /* Just fill in the columns. */
    epan_dissect_fill_in_columns(edt, FALSE, TRUE);

  if (print_details) {

    //sharkd_print_packet(&cf->cinfo)

    write_sharkd_proto_tree(output_fields, print_summary, print_hex, protocolfilter,
                        protocolfilter_flags, edt, &cf->cinfo, stdout);

    // TODO: maybe implement at least a little bit of buffering
    fflush(stdout);

    // write_json_proto_tree(output_fields, print_dissections_expanded,
    //                       print_hex, protocolfilter, protocolfilter_flags,
    //                       edt, &cf->cinfo, node_children_grouper, &dumper);
    return !ferror(stdout);
  }


  // case WRITE_EK:
  //   write_ek_proto_tree(output_fields, print_summary, print_hex, protocolfilter,
  //                       protocolfilter_flags, edt, &cf->cinfo, stdout);
  //   return !ferror(stdout);
  return TRUE;
}

static gboolean
process_packet_single_pass(capture_file *cf, epan_dissect_t *edt, gint64 offset,
                           wtap_rec *rec, Buffer *buf, guint tap_flags, guint64 nump)
{
  frame_data      fdata;
  column_info    *cinfo;
  gboolean        passed;
  
  /* Count this packet. */
  cf->count++;

  /* If we're not running a display filter and we're not printing any
     packet information, we don't need to do a dissection. This means
     that all packets can be marked as 'passed'. */
  passed = TRUE;

  frame_data_init(&fdata, cf->count, rec, offset, cum_bytes);

  /* If we're going to print packet information, or we're going to
     run a read filter, or we're going to process taps, set up to
     do a dissection and do so.  (This is the one and only pass
     over the packets, so, if we'll be printing packet information
     or running taps, we'll be doing it here.) */
  if (edt) {
    /* If we're running a filter, prime the epan_dissect_t with that
       filter. */
    if (cf->dfcode)
      epan_dissect_prime_with_dfilter(edt, cf->dfcode);

    /* This is the first and only pass, so prime the epan_dissect_t
       with the hfids postdissectors want on the first pass. */
    prime_epan_dissect_with_postdissector_wanted_hfids(edt);

    col_custom_prime_edt(edt, &cf->cinfo);

    /* We only need the columns if either
         1) some tap needs the columns
       or
         2) we're printing packet info but we're *not* verbose; in verbose
            mode, we print the protocol tree, not the protocol summary.
       or
         3) there is a column mapped as an individual field */
    if ((tap_flags & TL_REQUIRES_COLUMNS) || (print_packet_info && print_summary) || output_fields_has_cols(output_fields))
      cinfo = &cf->cinfo;
    else
      cinfo = NULL;

    frame_data_set_before_dissect(&fdata, &cf->elapsed_time,
                                  &cf->provider.ref, cf->provider.prev_dis);
    if (cf->provider.ref == &fdata) {
      ref_frame = fdata;
      cf->provider.ref = &ref_frame;
    }

    if (dissect_color) {
      color_filters_prime_edt(edt);
      fdata.need_colorize = 1;
    }

    epan_dissect_run_with_taps(edt, cf->cd_t, rec,
                               frame_tvbuff_new_buffer(&cf->provider, &fdata, buf),
                               &fdata, cinfo);


    if (cinfo) {
      /* "Stringify" non frame_data vals */
      epan_dissect_fill_in_columns(&edt, FALSE, TRUE/* fill_fd_columns */);
    }

    /* Run the filter if we have it. */
    if (cf->dfcode)
      passed = dfilter_apply_edt(cf->dfcode, edt);
  }

  if (passed) {
    frame_data_set_after_dissect(&fdata, &cum_bytes);

    /* Process this packet. */
    if (print_packet_info) {
      /* We're printing packet information; print the information for
         this packet. */
      g_assert(edt);
      
      //TODO: does this work?
      //sharkd_print_packet(&cf->cinfo);
      print_packet(cf, edt);

      /* If we're doing "line-buffering", flush the standard output
         after every packet.  See the comment above, for the "-l"
         option, for an explanation of why we do that. */
      if (line_buffered)
        fflush(stdout);

      if (ferror(stdout)) {
        show_print_file_io_error(errno);
        exit(2);
      }
    }

    /* this must be set after print_packet() [bug #8160] */
    prev_dis_frame = fdata;
    cf->provider.prev_dis = &prev_dis_frame;
  }

  prev_cap_frame = fdata;
  cf->provider.prev_cap = &prev_cap_frame;

  if (edt) {
    epan_dissect_reset(edt);
    frame_data_destroy(&fdata);
  }
  return passed;
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
        ret = process_packet_single_pass(cf, edt, data_offset, &rec, &buf,
                                         tap_flags, nump);
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
  cfile.epan = sharkd_epan_new(&cfile);

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


int
sharkd_list_linklayer_types(int caps_queries)
{
    gchar *err_str;
    volatile int exit_status = EXIT_SUCCESS;

    /* if requested, list the link layer types and exit */
    if (caps_queries) {
        guint i;

        /* Get the list of link-layer types for the capture devices. */
        for (i = 0; i < global_capture_opts.ifaces->len; i++) {
          interface_options *interface_opts;
          if_capabilities_t *caps;
          char *auth_str = NULL;
          int if_caps_queries = caps_queries;

          interface_opts = &g_array_index(global_capture_opts.ifaces, interface_options, i);

          caps = capture_get_if_capabilities(interface_opts->name, interface_opts->monitor_mode, auth_str, &err_str, NULL);
          g_free(auth_str);
          if (caps == NULL) {
            cmdarg_err("%s", err_str);
            g_free(err_str);
            exit_status = INVALID_CAPABILITY;
            return exit_status;
          }
          if ((if_caps_queries & CAPS_QUERY_LINK_TYPES) && caps->data_link_types == NULL) {
            cmdarg_err("The capture device \"%s\" has no data link types.", interface_opts->name);
            exit_status = INVALID_DATA_LINK;
            return exit_status;
          }
          if ((if_caps_queries & CAPS_QUERY_TIMESTAMP_TYPES) && caps->timestamp_types == NULL) {
            cmdarg_err("The capture device \"%s\" has no timestamp types.", interface_opts->name);
            exit_status = INVALID_TIMESTAMP_TYPE;
            return exit_status;
          }
          if (interface_opts->monitor_mode)
                if_caps_queries |= CAPS_MONITOR_MODE;
          capture_opts_print_if_capabilities(caps, interface_opts->name, if_caps_queries);
          free_if_capabilities(caps);
        }
        exit_status = EXIT_SUCCESS;
        return exit_status;
    }
    return exit_status;
}

int
sharkd_capture_stop(void)
{
  loop_running = FALSE;
  capture_cleanup(NULL);
}

int
sharkd_capture_start(e_prefs *prefs_p)
{
    volatile int exit_status = EXIT_SUCCESS;
    volatile gboolean draw_taps = FALSE;

    /* if no interface was specified, pick a default */
    exit_status = capture_opts_default_iface_if_necessary(&global_capture_opts,
        ((prefs_p->capture_device) && (*prefs_p->capture_device != '\0')) ? get_if_name(prefs_p->capture_device) : NULL);
    if (exit_status != 0) {
      return exit_status;
    }

    print_packet_counts = TRUE;

    if (print_packet_info) {
      if (!write_preamble(&cfile)) {
        show_print_file_io_error(errno);
        exit_status = INVALID_FILE;
        return exit_status;
      }
    }

    //tshark_debug("tshark: performing live capture");
    start_requested_stats();
    do_dissection = TRUE;

    capture();
    exit_status = global_capture_session.fork_child_status;

    if (print_packet_info) {
      if (!write_finale()) {
        show_print_file_io_error(errno);
      }
    }

    /*
     * If we never got a capture file, don't draw the taps; we not only
     * didn't capture any packets, we never even did any capturing.
     */
    if (cfile.filename != NULL)
      draw_taps = TRUE;

    if (draw_taps)
      draw_tap_listeners(TRUE);

    return exit_status;
}


int sharkd_capture_start_with_if(const char *capture_device)
{
  e_prefs *prefs_p;

  prefs_p = epan_load_settings();
  prefs_p->capture_device = (char *)capture_device;

  sharkd_capture_init();

  sharkd_capture_start(prefs_p);
  return 1;
}