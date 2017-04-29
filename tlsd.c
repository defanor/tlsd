/*
  TLSd, a TLS daemon.

  This is free and unencumbered software released into the public
  domain.
*/

#include <config.h>

#include <fcntl.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <netdb.h>
#include <syslog.h>
#include <gnutls/gnutls.h>

#define MAX_BUF_SIZE              4096
#define MAX_PEERS                 64
#define MAX_FINGERPRINT_BITS      256
#define MAX_FINGERPRINT_NIBBLES   MAX_FINGERPRINT_BITS / 4
#define MAX_FINGERPRINT_BYTES     MAX_FINGERPRINT_BITS / 8
#define FINGERPRINT_HASH          "SHA256"
#define DEFAULT_PORT              "0"
#define DEFAULT_HOST              "0.0.0.0"
#define DEFAULT_KEYFILE           "/etc/tls/key.pem"
#define DEFAULT_CERTFILE          "/etc/tls/cert.pem"

#define max(x,y) ((x) > (y) ? (x) : (y))
#define cc c[ci]
#define ATLS(x) assert(x == GNUTLS_E_SUCCESS)


/* Program options */
typedef struct {
  char *port;
  char *host;
  char *keyfile;
  char *certfile;
  char **args;
  int child_kill_signo;
  gnutls_certificate_request_t cert_req;
  char *peer_cert_path;
  size_t peer_cert_dir_len;
} options;

/* Child process information */
typedef struct {
  int input;
  int output;
  pid_t pid;
} child_proc;

/* Connection slot */
typedef struct {
  /* TODO: consider adding an "active" flag. */
  int tcp_socket;
  gnutls_session_t tls_session;
  child_proc child;
  int side;
} conn;

static gnutls_dh_params_t dh_params;
static int reload;

/* Print an error message, along with errno. */
void err_msg (int p,
              const char *str)
{
  syslog(p, "%s: %s (errno=%d)", str, strerror(errno), errno);
}

static int generate_dh_params (void)
{
  unsigned int bits =
    gnutls_sec_param_to_pk_bits(GNUTLS_PK_DH, GNUTLS_SEC_PARAM_HIGH);
  if (bits == 0)
    return -1;
  ATLS(gnutls_dh_params_init(&dh_params));
  ATLS(gnutls_dh_params_generate2(dh_params, bits));
  return 0;
}

/* Get the fingerprint, print it into a string, and write the
   certificate into a file if needed. */
int read_peer_cert (gnutls_session_t session,
                    char *str,
                    size_t *str_len,
                    char *cert_path,
                    size_t cert_dir_len)
{
  const gnutls_datum_t *peers_cert;
  size_t raw_len = MAX_FINGERPRINT_BYTES;
  static unsigned char raw[MAX_FINGERPRINT_BYTES];
  unsigned int list_size = 0;
  size_t i;
  int ret;
  FILE *fs;
  size_t written;

  peers_cert = gnutls_certificate_get_peers(session, &list_size);
  if (peers_cert == NULL)
    return -1;
  ret = gnutls_fingerprint(gnutls_digest_get_id(FINGERPRINT_HASH),
                           peers_cert,
                           raw,
                           &raw_len);
  if (ret < 0)
    return ret;
  for (i = 0; i < raw_len; i++)
    snprintf(str + i * 2, 3, "%02x", raw[i]);
  *str_len = raw_len * 2;

  if (cert_path) {
    strncpy(cert_path + cert_dir_len, str, MAX_FINGERPRINT_NIBBLES);
    fs = fopen(cert_path, "wx");
    if (!fs) {
      if (errno == EEXIST)
        return 0;
      syslog(LOG_ERR, "Can't open %s for writing: %s (errno=%d)",
             cert_path, strerror(errno), errno);
      return -1;
    }
    cert_path[cert_dir_len + MAX_FINGERPRINT_NIBBLES] = 0;
    written = fwrite(peers_cert->data, 1, peers_cert->size, fs);
    if (written != peers_cert->size)
      syslog(LOG_ERR, "Failed to write a peer certificate into %s",
             cert_path);
    if (fclose(fs))
      syslog(LOG_ERR, "Failed to close %s: %s (errno=%d)",
             cert_path, strerror(errno), errno);
  }
  return 0;
}

/* Run a child process, make its stdin and stdout available via
   child.{input,output}. */
int run_child (conn *c,
               options opt)
{
  pid_t pid;
  int to_child[2], from_child[2];
  size_t fingerprint_len = MAX_FINGERPRINT_NIBBLES;
  static char fingerprint_str[MAX_FINGERPRINT_NIBBLES + 1];

  /* Set the side in environment */
  if (setenv("SIDE", c->side == GNUTLS_CLIENT ? "CLIENT" : "SERVER", 1)) {
    err_msg(LOG_ERR, "Failed to set the SIDE environment variable");
    return -1;
  }
  if (unsetenv(FINGERPRINT_HASH)) {
    err_msg(LOG_ERR, "Failed to unset the fingerprint environment variable");
    return -1;
  }

  /* Read peer's certificate */
  if (read_peer_cert(c->tls_session, fingerprint_str, &fingerprint_len,
                     opt.peer_cert_path, opt.peer_cert_dir_len) < 0)
    {
      /* No fingerprint, but it may be fine */
      syslog(LOG_WARNING, "Unable to get a fingreprint string");
      if (opt.cert_req == GNUTLS_CERT_REQUIRE) {
        syslog(LOG_ERR, "Peer certificate is required");
        return -1;
      }
    }
  else {
    /* Got a fingerprint; set it in environment */
    fingerprint_str[MAX_FINGERPRINT_NIBBLES] = 0;
    syslog(LOG_DEBUG, "Peer's fingerprint: %s", fingerprint_str);
    if (setenv(FINGERPRINT_HASH, fingerprint_str, 1)) {
      err_msg(LOG_ERR, "Failed to set the fingerprint environment variable");
      return -1;
    }
  }

  /* Create pipes */
  if (pipe2(to_child, O_CLOEXEC) || pipe2(from_child, O_CLOEXEC)) {
    syslog(LOG_ERR, "Failed to create pipes");
    return -1;
  }

  /* Fork */
  pid = fork();
  if (pid < 0) {
    /* Error */
    err_msg(LOG_ERR, "Failed to fork");
    return -1;
  } else if (pid == 0) {
    /* Child */
    if (dup2(to_child[0], STDIN_FILENO) < 0
        || dup2(from_child[1], STDOUT_FILENO) < 0)
      {
        syslog(LOG_ERR, "Failed to set standard I/O in child");
        exit(1);
      }
    execvp(opt.args[0], opt.args);
    syslog(LOG_ERR, "Failed to execute %s: %s (errno=%d)",
           opt.args[0], strerror(errno), errno);
    exit(1);
  } else {
    /* Parent */
    if (close(to_child[0]) == -1
        || close(from_child[1]))
      err_msg(LOG_ERR, "Failed to close pipes in parent");
    c->child.input = to_child[1];
    c->child.output = from_child[0];
    c->child.pid = pid;
    return 0;
  }
}

/* Initialize a TLS connection */
int tls_conn_init (gnutls_certificate_credentials_t x509_cred,
                   gnutls_certificate_request_t cert_req,
                   unsigned int side,
                   int sd,
                   conn *c)
{
  gnutls_session_t session;
  int ret;

  /* Initialize structures */
  ATLS(gnutls_init(&session, side));
  ATLS(gnutls_set_default_priority(session));
  ATLS(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred));
  gnutls_certificate_server_set_request(session, cert_req);
  gnutls_heartbeat_enable(session, GNUTLS_HB_PEER_ALLOWED_TO_SEND);
  gnutls_transport_set_int(session, sd);

  /* Perform handshake */
  do {
    ret = gnutls_handshake(session);
  } while (ret < 0 && ! gnutls_error_is_fatal(ret));

  if (ret < 0) {
    syslog(LOG_WARNING, "TLS handshake has failed: %s (err=%d)",
           gnutls_strerror(ret), ret);
    if (shutdown(sd, SHUT_RDWR))
      err_msg(LOG_WARNING, "Failed to shutdown a TCP socket");
    if (close(sd))
      err_msg(LOG_WARNING, "Failed to close a TCP socket");
    gnutls_deinit(session);
    return -1;
  }

  /* Update the conn structure */
  c->tls_session = session;
  c->tcp_socket = sd;
  c->side = side;
  return 0;
}

/* Accept a new TLS connection. */
int tls_accept (conn *c,
                int listener,
                gnutls_certificate_credentials_t x509_cred,
                gnutls_certificate_request_t cert_req)
{
  static struct sockaddr sa;
  socklen_t sa_len = sizeof(sa);
  int sd;
  int ret;
  static char nhost[NI_MAXHOST], nserv[NI_MAXSERV];

  /* Accept a TCP connection */
  sd = accept(listener, &sa, &sa_len);
  if (sd == -1) {
    err_msg(LOG_WARNING, "Failed to accept a TCP connection");
    return -1;
  }
  ret = getnameinfo(&sa, sa_len, nhost, sizeof(nhost), nserv, sizeof(nserv),
                    NI_NUMERICHOST | NI_NUMERICSERV);
  if (ret) {
    syslog(LOG_WARNING, "Accepted, but failed to get name info: %s (err=%d)",
           gai_strerror(ret), ret);
    if (close(sd))
      err_msg(LOG_WARNING, "Failed to close a TCP socket");
    return -1;
  }
  syslog(LOG_INFO, "Accepted a TCP connection from %s, port %s",
         nhost, nserv);
  return tls_conn_init(x509_cred, cert_req, GNUTLS_SERVER, sd, c);
}

/* Initiate a new TCP connection */
int tcp_connect (const char *host,
                 const char *service)
{
  int sd;
  static struct addrinfo hints;
  struct addrinfo *addr, *addrp;
  int ret;
  static char nhost[NI_MAXHOST], nserv[NI_MAXSERV];

  /* Look up the address */
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  syslog(LOG_DEBUG, "Resolving %s:%s", host, service);
  ret = getaddrinfo(host, service, &hints, &addr);
  if (ret) {
    syslog(LOG_ERR, "Failed to get address information: %s (err=%d)",
           gai_strerror(ret), ret);
    return -1;
  }

  /* Try each resolved address in order */
  for (addrp = addr; addrp != NULL; addrp = addrp->ai_next) {
    /* Translate host and service into numeric names */
    ret = getnameinfo(addrp->ai_addr, addrp->ai_addrlen,
                      nhost, sizeof(nhost), nserv, sizeof(nserv),
                      NI_NUMERICHOST | NI_NUMERICSERV);
    if (ret) {
      syslog(LOG_WARNING, "Failed to get name information: %s (err=%d)",
             gai_strerror(ret), ret);
      continue;
    }
    /* Create a socket */
    sd = socket(addrp->ai_family, addrp->ai_socktype, addrp->ai_protocol);
    if (sd == -1) {
      err_msg(LOG_ERR, "Unable to create a socket");
      freeaddrinfo(addr);
      return -1;
    }
    /* Attempt to connect */
    syslog(LOG_DEBUG, "Connecting to %s, port %s", nhost, nserv);
    if (connect(sd, addrp->ai_addr, addrp->ai_addrlen)) {
      err_msg(LOG_WARNING, "Connection failure");
    } else {
      syslog(LOG_INFO, "Connected to %s, port %s", nhost, nserv);
      freeaddrinfo(addr);
      return sd;
    }
    /* Close the socket if we've got this far */
    if (close(sd))
      err_msg(LOG_WARNING, "Unable to close a socket");
  }
  /* Give up: cleanup and report an error */
  syslog(LOG_ERR, "Unable to connect");
  freeaddrinfo(addr);
  return -1;
}

/* Initiate a new TLS connection */
int tls_connect (conn *c,
                 gnutls_certificate_credentials_t x509_cred,
                 const char *host,
                 const char *service)
{
  int sd = tcp_connect(host, service);
  if (sd < 0)
    return -1;
  return tls_conn_init(x509_cred, GNUTLS_CERT_REQUIRE, GNUTLS_CLIENT, sd, c);
}

/* Create a socket, bind, listen, return it. */
int tcp_listen (const char *host,
                const char *service)
{
  int sd;
  int optval = 1;
  static struct addrinfo hints;
  struct addrinfo *addr, *addrp;
  int ret;
  static char nhost[NI_MAXHOST], nserv[NI_MAXSERV];
  struct sockaddr sa;
  socklen_t sa_len = sizeof(sa);

  /* Look up the address */
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  ret = getaddrinfo(host, service, &hints, &addr);
  if (ret) {
    syslog(LOG_ERR, "Failed to get address information: %s (err=%d)",
           gai_strerror(ret), ret);
    return -1;
  }
  /* Try each resolved address in order */
  for (addrp = addr; addrp != NULL; addrp = addrp->ai_next) {
    /* Translate host and service into numeric names */
    ret = getnameinfo(addrp->ai_addr, addrp->ai_addrlen,
                      nhost, sizeof(nhost), nserv, sizeof(nserv),
                      NI_NUMERICHOST | NI_NUMERICSERV);
    if (ret) {
      syslog(LOG_WARNING, "Failed to get name information: %s (err=%d)",
             gai_strerror(ret), ret);
      continue;
    }
    /* Create a socket */
    sd = socket(addrp->ai_family, addrp->ai_socktype, addrp->ai_protocol);
    if (sd == -1) {
      err_msg(LOG_ERR, "Unable to create a socket");
      freeaddrinfo(addr);
      return -1;
    }
    /* Attempt to bind */
    syslog(LOG_DEBUG, "Attempting to bind: %s, port %s", nhost, nserv);
    if (setsockopt (sd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int))
        || bind(sd, addrp->ai_addr, addrp->ai_addrlen)
        || listen(sd, MAX_PEERS)
        || getsockname(sd, &sa, &sa_len))
      {
        err_msg(LOG_WARNING, "Failed to bind and listen");
      }
    else
      {
        /* Bound, find out where */
        ret = getnameinfo(&sa, sa_len,
                          nhost, sizeof(nhost), nserv, sizeof(nserv),
                          NI_NUMERICHOST | NI_NUMERICSERV);
        if (ret) {
          syslog(LOG_WARNING,
                 "Bound, but failed to get name information: %s (err=%d)",
                 gai_strerror(ret), ret);
          continue;
        }
        /* Report, cleanup, return */
        syslog(LOG_INFO, "Listening on %s, port %s", nhost, nserv);
        freeaddrinfo(addr);
        return sd;
      }
    if (close(sd))
      err_msg(LOG_WARNING, "Unable to close a socket");
  }

  syslog(LOG_ERR, "Failed to bind");
  freeaddrinfo(addr);
  return -1;
}

/* Set conn's fds to -1. */
void conn_reset (conn *c)
{
  c->tcp_socket = -1;
  c->child.input = -1;
  c->child.output = -1;
}

/* Terminate a connection: close, disconnect, cleanup, etc. */
int conn_terminate (conn *c,
                    int tls_close,
                    int child_kill_signo)
{
  int status;
  /* TODO: maybe keep better track of what should be closed, and then
     add warnings for when close() fails unexpectedly. */
  if (c->child.input >= 0 && close(c->child.input) < 0)
    err_msg(LOG_ERR, "Failed to close child's stdin");
  if (c->child.output >= 0 && close(c->child.output) < 0)
    err_msg(LOG_ERR, "Failed to close child's stdout");
  if (tls_close)
    gnutls_bye(c->tls_session, GNUTLS_SHUT_WR);
  gnutls_deinit(c->tls_session);
  shutdown(c->tcp_socket, SHUT_RDWR);
  if (c->tcp_socket >= 0 && close(c->tcp_socket) < 0)
    err_msg(LOG_ERR, "Failed to close TCP socket");
  if (c->child.pid) {
    if (kill(c->child.pid, child_kill_signo))
      err_msg (LOG_ERR, "Failed to send signal to a child");
    syslog(LOG_INFO, "Waiting for process %d to exit", c->child.pid);
    if (waitpid(c->child.pid, &status, 0) < 1)
      err_msg(LOG_ERR, "Error while waiting for a child to exit");
    else if (WIFEXITED(status))
      syslog(LOG_INFO, "Process %d has exited with status %d",
             c->child.pid, WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
      syslog(LOG_NOTICE, "Process %d was terminated by signal %d",
             c->child.pid, WTERMSIG(status));
    else
      syslog(LOG_WARNING, "Process %d was terminated abnormally", c->child.pid);
  }
  conn_reset(c);
  return 0;
}

void on_signal (int signo)
{
  syslog(LOG_INFO, "Received signal %d", signo);
  if (signo == SIGHUP)
    reload = 1;
}

/* Block some signals, but fill oldset in order to use them for
   pselect later. Also set a dummy handler. */
int set_signals (sigset_t *oldset)
{
  struct sigaction sigact;
  sigset_t sigset;

  /* Block signals */
  if (sigemptyset(&sigset)
      || sigaddset(&sigset, SIGTERM)
      || sigaddset(&sigset, SIGINT)
      || sigaddset(&sigset, SIGHUP)
      || sigprocmask(SIG_BLOCK, &sigset, oldset))
    {
      err_msg(LOG_ERR, "Unable to block signals");
      return -1;
    }

  /* Handle signals */
  sigact.sa_handler = on_signal;
  sigact.sa_flags = 0;
  if (sigemptyset(&sigact.sa_mask)
      || sigaction(SIGTERM, &sigact, NULL)
      || sigaction(SIGINT, &sigact, NULL)
      || sigaction(SIGHUP, &sigact, NULL)
      || sigaction(SIGPIPE, &sigact, NULL))
    {
      err_msg(LOG_ERR, "Unable to handle signals");
      return -1;
    }
  return 0;
}

int cred_load (gnutls_certificate_credentials_t *x509_cred,
               options opt)
{
  int ret;
  ret = gnutls_certificate_allocate_credentials(x509_cred);
  if (ret < 0)
    syslog(LOG_ERR, "Failed to allocate credentials: %s (err=%d)",
           gnutls_strerror(ret), ret);
  ret = gnutls_certificate_set_x509_key_file(*x509_cred, opt.certfile,
                                             opt.keyfile, GNUTLS_X509_FMT_PEM);
  if (ret < 0)
    syslog(LOG_ERR, "Failed to load key or certificate: %s (err=%d)",
           gnutls_strerror(ret), ret);
  gnutls_certificate_set_dh_params(*x509_cred, dh_params);
  return ret;
}

/* Run the server */
/* TODO: consider splitting this function into a few smaller ones. */
int serve (options opt)
{
  int listener;
  int ret;
  static gnutls_certificate_credentials_t x509_cred;
  static char buffer[MAX_BUF_SIZE + 1];
  fd_set rfds;              /* for pselect() */
  int select_val;           /* pselect() return value */
  int max_fd;               /* for pselect() */
  static conn c[MAX_PEERS]; /* peers */
  unsigned int ci, nci;     /* peer index, next unused peer index */
  sigset_t sigmask;         /* to use in pselect() */
  int sent, received;
  /* A fixed-size r_format is not great, but perhaps better than
     dynamic allocation. 64 bytes should be enough for everyone. */
  static char r_host[NI_MAXHOST], r_service[NI_MAXSERV], r_format[64];
  int stdin_eof = 0;

  /* Initialization */
  syslog(LOG_DEBUG, "Initializing");
  snprintf(r_format, sizeof(r_format), "%%%ds %%%ds", NI_MAXHOST, NI_MAXSERV);
  ATLS(gnutls_global_init());
  assert(generate_dh_params() == 0);
  if (cred_load(&x509_cred, opt))
    return -1;
  for (ci = 0; ci < MAX_PEERS; ci++)
    conn_reset(&cc);
  if (set_signals(&sigmask) < 0)
    return -1;
  listener = tcp_listen(opt.host, opt.port);
  if (listener < 0)
    return -1;

  /* Event loop */
  for (;;) {
    /* Point nci to the first unused peer slot */
    for (nci = 0; nci < MAX_PEERS && c[nci].tcp_socket >= 0; nci++);

    /* Select */
    FD_ZERO(&rfds);
    if (nci < MAX_PEERS) {
      /* Only accept or create new connections when there are free
         slots */
      FD_SET(listener, &rfds);
      if (! stdin_eof)
        FD_SET(STDIN_FILENO, &rfds);
    }

    for (max_fd = listener, ci = 0; ci < MAX_PEERS; ci++) {
      if (cc.tcp_socket >= 0) {
        FD_SET(cc.tcp_socket, &rfds);
        max_fd = max(max_fd, cc.tcp_socket);
      }
      if (cc.child.output >= 0) {
        FD_SET(cc.child.output, &rfds);
        max_fd = max(max_fd, cc.child.output);
      }
    }

    select_val = pselect(max_fd + 1, &rfds, NULL, NULL, NULL, &sigmask);

    if (select_val == -1) {
      /* Select error */
      if (errno == EINTR) {
        if (reload) {
          reload = 0;
          syslog(LOG_INFO, "Reloading key and certificate");
          gnutls_certificate_free_credentials(x509_cred);
          if (cred_load(&x509_cred, opt))
            break;
        } else {
          syslog(LOG_INFO, "Terminating gracefully");
          break;
        }
      } else {
        err_msg(LOG_ERR, "pselect() failure");
        break;
      }
    } else if (select_val) {
      /* New connection request */
      if (nci < MAX_PEERS && FD_ISSET(STDIN_FILENO, &rfds)) {
        ret = scanf(r_format, r_host, r_service);
        if (ret == 2) {
          if (! tls_connect(&c[nci], x509_cred, r_host, r_service)) {
            if (run_child(&c[nci], opt) < 0) {
              syslog(LOG_ERR, "Failed to run a child process");
              conn_terminate(&c[nci], 1, opt.child_kill_signo);
            } else {
              /* Update nci */
              for (; nci < MAX_PEERS && c[nci].tcp_socket >= 0; nci++);
            }
          }
        } else if (ret == EOF) {
          syslog(LOG_INFO, "stdin is closed");
          stdin_eof = 1;
        } else {
          syslog(LOG_ERR, "Failed to scan host and port from stdin");
          stdin_eof = 1;
        }
        select_val--;
      }

      /* New incoming connection */
      if (nci < MAX_PEERS && FD_ISSET(listener, &rfds)) {
        if (! tls_accept(&c[nci], listener, x509_cred, opt.cert_req)) {
          if (run_child(&c[nci], opt) < 0) {
            syslog(LOG_ERR, "Failed to run a child process");
            conn_terminate(&c[nci], 1, opt.child_kill_signo);
          } else {
            /* Update nci */
            for (; nci < MAX_PEERS && c[nci].tcp_socket >= 0; nci++);
          }
        }
        select_val--;
      }

      /* Pass messages */
      for (ci = 0; ci < MAX_PEERS; ci++) {
        /* TLS peer to child process */
        if (cc.tcp_socket >= 0 && FD_ISSET(cc.tcp_socket, &rfds)) {
          do {
            received = gnutls_record_recv(cc.tls_session, buffer, MAX_BUF_SIZE);
            if (! received) {
              syslog(LOG_DEBUG, "EOF from the TLS end");
              conn_terminate(&cc, 0, opt.child_kill_signo);
            } else if (received < 0) {
              syslog(LOG_WARNING, "Failed to receive: %s (err=%d)",
                     gnutls_strerror(received), received);
              conn_terminate(&cc, 0, opt.child_kill_signo);
            } else
              for (sent = 0; sent < received; sent += ret) {
                ret = write(cc.child.input, buffer + sent, received - sent);
                if (! ret) {
                  syslog(LOG_ERR, "write() has returned 0");
                  conn_terminate(&cc, 1, opt.child_kill_signo);
                  break;
                } else if (ret < 0) {
                  err_msg(LOG_ERR, "Failed to write");
                  conn_terminate(&cc, 1, opt.child_kill_signo);
                  break;
                }
              }
          } while (cc.tcp_socket >= 0
                   && gnutls_record_check_pending(cc.tls_session));
          select_val--;
        }
        /* Child process to TLS peer */
        if (cc.child.output >= 0 && FD_ISSET(cc.child.output, &rfds)) {
          received = read(cc.child.output, buffer, MAX_BUF_SIZE);
          if (! received) {
            syslog(LOG_DEBUG, "EOF from the child process");
            conn_terminate(&cc, 1, opt.child_kill_signo);
          } else if (received < 0) {
            err_msg(LOG_WARNING, "Failed to read");
            conn_terminate(&cc, 1, opt.child_kill_signo);
          } else
            for (sent = 0; sent < received; sent += ret) {
              ret = gnutls_record_send(cc.tls_session,
                                       buffer + sent,
                                       received - sent);
              if (! ret) {
                syslog(LOG_ERR, "gnutls_record_send() has returned 0");
                conn_terminate(&cc, 1, opt.child_kill_signo);
                break;
              } else if (ret < 0) {
                syslog(LOG_ERR, "Failed to send: %s (err=%d)",
                       gnutls_strerror(ret), ret);
                conn_terminate(&cc, 1, opt.child_kill_signo);
                break;
              }
            }
          select_val--;
        }
      }
      if (select_val)
        syslog(LOG_WARNING, "Not all the events are processed");
      /* TODO: maybe analyze the situation. */
    }
  }

  /* Cleanup and close */
  for (ci = 0; ci < MAX_PEERS; ci++) {
    if (cc.tcp_socket >= 0)
      conn_terminate(&cc, 1, opt.child_kill_signo);
  }
  close(listener);
  gnutls_certificate_free_credentials(x509_cred);
  gnutls_dh_params_deinit(dh_params);
  gnutls_global_deinit();
  syslog(LOG_INFO, "Shutting down");
  return 0;
}

void print_help (const char *name)
{
  puts(PACKAGE_STRING);
  printf("Usage: %s [option ...] [--] <command> [argument ...]\n",
         name);
  puts("Options:");
  puts(" -k <keyfile>   private key file to use");
  puts(" -c <certfile>  certificate file to use");
  puts(" -p <port>      port to listen on");
  puts(" -b <host>      bind address");
  puts(" -s <signo>     a signal to send to a child on termination");
  puts(" -n             do not require a peer certificate");
  puts(" -d <directory> write peer certificates into a directory");
  puts(" -i <ident>     syslog ident to use");
  puts(" -e             print messages into stderr, in addition to syslog");
  puts(" -h             print this help message and exit");
}

/* Read options, run the serve function */
int main (int argc,
          char **argv)
{
  int c;
  int ret;
  int syslog_options = 0;
  char *ident = "tlsd";
  char *peer_cert_dir = NULL;
  options opt = { DEFAULT_PORT, DEFAULT_HOST,
                  DEFAULT_KEYFILE, DEFAULT_CERTFILE,
                  NULL, 0, GNUTLS_CERT_REQUIRE, NULL, 0 };

  /* Parse the arguments */
  while ((c = getopt (argc, argv, "k:c:p:b:s:nd:i:eh")) != -1)
    switch (c)
      {
      case 'k': opt.keyfile = optarg;                 break;
      case 'c': opt.certfile = optarg;                break;
      case 'p': opt.port = optarg;                    break;
      case 'b': opt.host = optarg;                    break;
      case 's': opt.child_kill_signo = atoi(optarg);  break;
      case 'n': opt.cert_req = GNUTLS_CERT_REQUEST;   break;
      case 'd': peer_cert_dir = optarg;               break;
      case 'i': ident = optarg;                       break;
      case 'e': syslog_options |= LOG_PERROR;         break;
      case 'h': print_help(argv[0]);                  return 0;
      default:  print_help(argv[0]);                  return 1;
      }

  if (argc <= optind) {
    print_help(argv[0]);
    return 1;
  }
  opt.args = &argv[optind];

  openlog(ident, syslog_options, LOG_USER);
  if (peer_cert_dir) {
    opt.peer_cert_dir_len = strlen(peer_cert_dir);
    /* TODO: consider using chdir or open/openat instead */
    opt.peer_cert_path = malloc(opt.peer_cert_dir_len +
                                MAX_FINGERPRINT_NIBBLES + 1);
    if (! opt.peer_cert_path) {
      syslog(LOG_ERR, "Failed to allocate memory");
      closelog();
      return 1;
    }
    strncpy(opt.peer_cert_path, peer_cert_dir, opt.peer_cert_dir_len);
  }

  /* Run the server */
  ret = serve(opt);

  /* Cleanup and exit */
  if (opt.peer_cert_path)
    free(opt.peer_cert_path);
  closelog();
  return ret;
}
