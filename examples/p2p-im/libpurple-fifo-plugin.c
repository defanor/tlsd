/*
  libpurple-fifo-plugin, an example plugin that interacts with FIFOs
  created with std2fifo or similar programs.

  In this whole example, there is plenty to improve, but it should
  work for basic message transmission.

  This is free and unencumbered software released into the public
  domain.
*/

#include <glib.h>

#include "prpl.h"
#include "version.h"
#include "debug.h"
#include "cmds.h"
#include "accountopt.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <sys/inotify.h>
#include <time.h>


#define PLUGIN_ID          "prpl-defanor-fifo"
#define PLUGIN_NAME        "FIFOs-based IM"
#define PLUGIN_VERSION     "0.1-dev"
#define PLUGIN_SUMMARY     "Reads from and writes into FIFOs"
#define PLUGIN_DESCRIPTION "This is an example for the TLSd manual"

#define MAX_PEERS          64
#define MAX_DIRNAME_LEN    256
#define MAX_BUF_SIZE       4096
#define FIFO_OUT_MODE      S_IRWXU | S_IRWXG | S_IWGRP


typedef struct {
  int fd;
  int wd;
  guint handle;
} watch;

typedef struct {
  int input;
  int output;
  char dirname[MAX_DIRNAME_LEN];
  char *path;
  size_t path_len;
  guint handle;
  PurpleConnection *gc;
} peer;

typedef struct {
  watch w;
  peer p[MAX_PEERS];
} conn_state;


static void new_dir (gpointer data, gint source, PurpleInputCondition cond);
static void incoming_msg (gpointer data, gint source, PurpleInputCondition cond);
static void fifo_close(PurpleConnection *gc);

void peer_reset (peer *cp)
{
  cp->output = -1;
  cp->input = -1;
  cp->path = NULL;
  cp->path_len = 0;
  cp->handle = 0;
}

void peer_terminate (peer *cp)
{
  if (cp->path == NULL)
    return;
  purple_debug_misc(PLUGIN_ID, "Terminating %s\n", cp->dirname);
  purple_prpl_got_user_status(cp->gc->account, cp->dirname, "offline", NULL);
  if (cp->handle)
    purple_input_remove (cp->handle);
  if (cp->path != NULL)
    free (cp->path);
  if (cp->output != -1)
    close (cp->output);
  if (cp->input != -1)
    close (cp->input);
  peer_reset(cp);
}

static int peer_suspend (peer *cp)
{
  purple_debug_misc(PLUGIN_ID, "Suspending %s\n", cp->dirname);
  purple_prpl_got_user_status(cp->gc->account, cp->dirname, "offline", NULL);
  if (cp->handle)
    purple_input_remove (cp->handle);
  if (cp->output != -1)
    close (cp->output);
  if (cp->input != -1) {
    close (cp->input);
    cp->input = -1;
  }
  strcpy(cp->path + cp->path_len - 4, "out");
  cp->output = open(cp->path, O_RDONLY | O_NONBLOCK);
  if (cp->output == -1) {
    purple_debug_error(PLUGIN_ID, "Failed to open %s: %s\n",
                       cp->path, strerror(errno));
    peer_terminate(cp);
    return -1;
  }
  cp->handle = purple_input_add(cp->output, PURPLE_INPUT_READ,
                                incoming_msg, cp);
  return 0;
}


static void incoming_msg (gpointer data,
                          gint source,
                          PurpleInputCondition cond)
{
  peer *cp = data;
  ssize_t len;
  static char buf[MAX_BUF_SIZE + 1];
  len = read(cp->output, buf, MAX_BUF_SIZE);
  if (len < 0) {
    /* Error */
    purple_debug_error(PLUGIN_ID, "Failed to read from %s: %s\n",
                       cp->dirname, strerror(errno));
    peer_terminate(cp);
    return;
  } else if (len == 0) {
    /* EOF */
    purple_debug_misc(PLUGIN_ID, "EOF from %s\n", cp->dirname);
    peer_suspend(cp);
    return;
  }
  purple_prpl_got_user_status(cp->gc->account, cp->dirname, "available", NULL);
  buf[len] = 0;
  /* Messages would normally end with newline, but IM clients add
     newlines on output as well, so we'll have to get rid of that. */
  if (buf[len - 1] == '\n') {
    if (len == 1)
      /* Could be an automatically added newline, ignore that. */
      return;
    buf[len -1] = 0;
  }
  serv_got_im(purple_account_get_connection(cp->gc->account),
              cp->dirname, buf, 0, time(NULL));
}

static int add_peer (PurpleConnection *gc,
                     const char *dname)
{
  conn_state *cs = gc->proto_data;
  unsigned int i;
  purple_debug_misc(PLUGIN_ID, "Adding peer %s\n", dname);
  for (i = 0; (i < MAX_PEERS) && (cs->p[i].path != NULL); i++);
  if (i == MAX_PEERS) {
    purple_debug_error(PLUGIN_ID, "Too many peers (%d)\n", i);
    return -1;
  }
  cs->p[i].gc = gc;
  strncpy(cs->p[i].dirname, dname, MAX_DIRNAME_LEN - 1);
  cs->p[i].path_len =
    /* root, slash, sha256, slash, {in,out}, zero */
    strlen(gc->account->username) + 1 + strlen(dname) + 1 + 3 + 1;
  cs->p[i].path = malloc(cs->p[i].path_len);
  if (cs->p[i].path == NULL) {
    purple_debug_error(PLUGIN_ID, "Failed to allocate %d bytes of memory\n",
                       (int) cs->p[i].path_len);
    peer_terminate(&cs->p[i]);
    return -1;
  }
  snprintf(cs->p[i].path, cs->p[i].path_len,
           "%s/%s/out", gc->account->username, dname);
  /* Create a FIFO if it doesn't exist yet. Might be nicer to just set
     a watch and wait, but that'd be more cumbersome, so this will do
     for now. */
  if (mkfifo(cs->p[i].path, FIFO_OUT_MODE) && errno != EEXIST) {
    purple_debug_error(PLUGIN_ID, "Failed to create a FIFO at %s: %s\n",
                       cs->p[i].path, strerror(errno));
    peer_terminate(&cs->p[i]);
    return -1;
  }
  cs->p[i].output = open(cs->p[i].path, O_RDONLY | O_NONBLOCK);
  if (cs->p[i].output == -1) {
    purple_debug_error(PLUGIN_ID, "Failed to open %s: %s\n",
                       cs->p[i].path, strerror(errno));
    peer_terminate(&cs->p[i]);
    return -1;
  }
  strcpy(cs->p[i].path + cs->p[i].path_len - 4, "in");
  cs->p[i].input = open(cs->p[i].path, O_WRONLY | O_NONBLOCK);
  purple_prpl_got_user_status(gc->account, cs->p[i].dirname,
                              (cs->p[i].input == -1) ? "offline" : "available",
                              NULL);
  /* Set a callback */
  cs->p[i].handle = purple_input_add(cs->p[i].output, PURPLE_INPUT_READ,
                               incoming_msg, &cs->p[i]);
  return i;
}

static void new_dir (gpointer data,
                     gint source,
                     PurpleInputCondition cond)
{
  static char buf[sizeof(struct inotify_event) + NAME_MAX + 1];
  struct inotify_event *ie;
  ssize_t len;
  PurpleConnection *gc = data;
  conn_state *cs = gc->proto_data;
  purple_debug_misc(PLUGIN_ID, "A 'new dir' watch for %s has fired\n",
                    gc->account->username);
  len = read (cs->w.fd, buf, sizeof(struct inotify_event) + NAME_MAX + 1);
  if (len == 0)
    return;
  else if (len < 0) {
    /* error */
    purple_debug_error(PLUGIN_ID, "A watch failure\n");
    fifo_close (gc);
    return;
  }
  ie = (struct inotify_event *) &buf;
  purple_debug_misc(PLUGIN_ID, "A watch for %s has fired: %s, read %d bytes\n",
                    gc->account->username, ie->name, (int) len);
  add_peer (gc, ie->name);
}


static int load_peers (PurpleConnection *gc)
{
  DIR *dp;
  struct dirent *ep;

  dp = opendir(gc->account->username);
  if (dp == NULL)
    return -1;
  while ((ep = readdir(dp))) {
    if ((ep->d_name[0] == '.') || (ep->d_type != DT_DIR))
      continue;
    purple_debug_misc(PLUGIN_ID, "Loading %s\n", ep->d_name);
    add_peer (gc, ep->d_name);
  }
  closedir(dp);
  return 0;
}


static int fifo_send_im(PurpleConnection *gc,
                        const char *who,
                        const char *message,
                        PurpleMessageFlags flags)
{
  size_t written = 0, total = strlen(message), ret;
  unsigned int i;
  conn_state *cs = gc->proto_data;
  /* Find peer */
  for (i = 0; i < MAX_PEERS; i++) {
    if (! strncmp(who, cs->p[i].dirname, MAX_DIRNAME_LEN))
      break;
  }
  if (i == MAX_PEERS)
    return -ENOTCONN;
  /* Write */
  if (cs->p[i].input == -1) {
    strcpy(cs->p[i].path + cs->p[i].path_len - 4, "in");
    cs->p[i].input = open(cs->p[i].path, O_WRONLY | O_NONBLOCK);
    if (cs->p[i].input == -1) {
      purple_debug_misc(PLUGIN_ID, "Not connected to %s\n", cs->p[i].dirname);
      peer_suspend(&cs->p[i]);
      return -ENOTCONN;
    }
  }
  while (written < total) {
    ret = write(cs->p[i].input, message + written, total - written);
    if (ret <= 0) {
      purple_debug_misc(PLUGIN_ID, "Failed writing to %s\n", cs->p[i].dirname);
      peer_suspend(&cs->p[i]);
      return -ENOTCONN;
    } else {
      written += ret;
    }
  }
  write(cs->p[i].input, "\n", 1);
  purple_prpl_got_user_status(gc->account, cs->p[i].dirname, "available", NULL);
  return 1;
}


/* Login: take dir name from username, get subdirs, set add input
   handlers from "out", watch directory with inotify and add an input
   handler for that too. */
static void fifo_login(PurpleAccount *acct)
{
  PurpleConnection *gc = purple_account_get_connection(acct);
  conn_state *cs;
  unsigned int i;
  purple_debug_misc(PLUGIN_ID, "Login: %s\n", acct->username);
  purple_connection_update_progress(gc, "Connecting", 0, 2);
  /* Allocate and prepare connection state */
  cs = malloc(sizeof(conn_state));
  gc->proto_data = cs;
  for (i = 0; i < MAX_PEERS; i++)
    peer_reset(&cs->p[i]);
  /* Add a watch */
  /* TODO: checks, error handling */
  cs->w.fd = inotify_init();
  cs->w.wd = inotify_add_watch(cs->w.fd, acct->username, IN_CREATE);
  cs->w.handle = purple_input_add(cs->w.fd, PURPLE_INPUT_READ,
                                  new_dir, gc);
  /* Load peers */
  purple_debug_misc(PLUGIN_ID, "Loading peers\n");
  load_peers (gc);
  purple_connection_update_progress(gc, "Connected", 1, 2);
  purple_connection_set_state(gc, PURPLE_CONNECTED);
}

static void fifo_close(PurpleConnection *gc)
{
  unsigned int i;
  conn_state *cs = gc->proto_data;
  /* Terminate the watch */
  purple_debug_misc(PLUGIN_ID, "Removing the watch\n");
  if (cs->w.handle)
    purple_input_remove (cs->w.handle);
  if (cs->w.fd != -1 && cs->w.wd != -1)
    inotify_rm_watch (cs->w.fd, cs->w.wd);
  if (cs->w.fd != -1)
    close (cs->w.fd);
  /* Terminate the peers */
  purple_debug_misc(PLUGIN_ID, "Terminating peers\n");
  for (i = 0; i < MAX_PEERS; i++)
    peer_terminate(&cs->p[i]);
  /* Free */
  free (gc->proto_data);
  purple_debug_misc(PLUGIN_ID, "Closed: %s\n", gc->account->username);
}


static void fifo_init(PurplePlugin *plugin)
{
  purple_debug_misc(PLUGIN_ID, "Initializing\n");
}

static void fifo_destroy(PurplePlugin *plugin)
{
  purple_debug_misc(PLUGIN_ID, "Shutting down\n");
}

static const char *fifo_list_icon(PurpleAccount *acct,
                                  PurpleBuddy *buddy)
{
  /* TODO: do something about it. Maybe draw an icon. */
  return "irc";
}

static GList *fifo_status_types(PurpleAccount *acct)
{
  GList *types = NULL;
  types = g_list_prepend(types, purple_status_type_new(PURPLE_STATUS_AVAILABLE,
                                                       NULL, NULL, TRUE));
  types = g_list_prepend(types, purple_status_type_new(PURPLE_STATUS_OFFLINE,
                                                       NULL, NULL, TRUE));
  return types;
}

static PurplePluginProtocolInfo fifo_info =
  {
    .options = OPT_PROTO_NO_PASSWORD,
    .icon_spec = NO_BUDDY_ICONS,
    .list_icon = fifo_list_icon,
    .status_types = fifo_status_types,
    .login = fifo_login,
    .close = fifo_close,
    .send_im = fifo_send_im,
    .struct_size = sizeof(PurplePluginProtocolInfo)
  };

static PurplePluginInfo info =
  {
    .magic = PURPLE_PLUGIN_MAGIC,
    .major_version = PURPLE_MAJOR_VERSION,
    .minor_version = PURPLE_MINOR_VERSION,
    .type = PURPLE_PLUGIN_PROTOCOL,
    .priority = PURPLE_PRIORITY_DEFAULT,
    .id = PLUGIN_ID,
    .name = PLUGIN_NAME,
    .version = PLUGIN_VERSION,
    .summary = PLUGIN_SUMMARY,
    .description = PLUGIN_DESCRIPTION,
    .destroy = fifo_destroy,
    .extra_info = &fifo_info
  };

PURPLE_INIT_PLUGIN(fifo, fifo_init, info)
