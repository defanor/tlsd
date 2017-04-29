/*
  std2fifo, a std{in,out} <-> <dir>/<env var>/{in,out} proxy

  This is free and unencumbered software released into the public
  domain.
*/

#include <config.h>

#include <syslog.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>

#define MAX_BUF_SIZE              4096
#define DIR_MODE                  S_IRWXU | S_IRWXG | S_IWGRP | S_IRGRP
#define FIFO_IN_MODE              S_IRUSR | S_IWUSR | S_IWGRP
#define FIFO_OUT_MODE             S_IRUSR | S_IWUSR | S_IRGRP

#define max(x,y) ((x) > (y) ? (x) : (y))


int chdir_err (const char *dir)
{
  if (chdir(dir)) {
    syslog(LOG_ERR, "Can't change directory to %s: %s", dir, strerror(errno));
    return -1;
  }
  return 0;
}

int fifo_open (const char *path,
               mode_t mode,
               int flag)
{
  if (mkfifo(path, mode) && errno != EEXIST) {
    syslog(LOG_ERR, "Failed to create FIFO %s: %s", path, strerror(errno));
    return -1;
  }
  return open(path, flag);
}

int write_all (int fd,
               const char *buffer,
               ssize_t count,
               const char *err)
{
  ssize_t written, ret;
  for (written = 0; written < count; written += ret) {
    ret = write (fd, buffer + written, count - written);
    if (! ret) {
      syslog(LOG_ERR, "write() has returned 0");
      return -1;
    } else if (ret < 0) {
      if (err != NULL)
        syslog(LOG_WARNING, "Failed to write to %s: %s", err, strerror(errno));
      return -1;
    }
  }
  return 0;
}

int run (const char *dir,
         const char *val,
         int continuous)
{
  int in = -1, out = -1;
  fd_set rfds;
  int select_val, max_fd;
  ssize_t len;
  static char buffer[MAX_BUF_SIZE + 1];

  if (chdir_err(dir))
    return -1;

  /* Create the directory if it doesn't exist */
  if (mkdir(val, DIR_MODE) && errno != EEXIST) {
    syslog(LOG_ERR, "Failed to create directory %s: %s", val, strerror(errno));
    return -1;
  }

  if (chdir_err(val))
    return -1;

  in = fifo_open("in", FIFO_IN_MODE, O_RDONLY | O_NONBLOCK);
  if (in == -1)
    return -1;

  for (;;) {
    FD_ZERO(&rfds);
    FD_SET(in, &rfds);
    FD_SET(STDIN_FILENO, &rfds);
    max_fd = max(STDIN_FILENO, in);

    select_val = select(max_fd + 1, &rfds, NULL, NULL, NULL);
    if (select_val == -1) {
      /* error */
      syslog(LOG_ERR, "select() failure: %s", strerror(errno));
      break;
    } else {
      /* stdin to FIFO */
      if (FD_ISSET(STDIN_FILENO, &rfds)) {
        len = read(STDIN_FILENO, buffer, MAX_BUF_SIZE);
        if (len < 0) {
          /* Error: quit */
          syslog(LOG_ERR, "Failed to read from stdin: %s", strerror(errno));
          break;
        } else if (len == 0) {
          /* EOF: quit, but without error */
          close(in);
          return 0;
        }
        /* Open, write, close */
        /* Only open once in the continuous streams mode */
        if ((continuous && out == -1) || ! continuous) {
          out = fifo_open("out", FIFO_OUT_MODE, O_WRONLY);
          if (out == -1) {
            syslog(LOG_ERR, "Failed to open 'out': %s", strerror(errno));
            break;
          }
        }
        if (write_all(out, buffer, len, "FIFO"))
          break;
        /* Do not close in the continuous streams mode */
        if (! continuous)
          close(out);
      }
      /* FIFO to stdout */
      if (FD_ISSET(in, &rfds)) {
        len = read(in, buffer, MAX_BUF_SIZE);
        if (len < 0) {
          /* Error: quit */
          syslog(LOG_ERR, "Failed to read from FIFO: %s", strerror(errno));
          break;
        } else if (len == 0) {
          /* EOF: reopen or quit, unless in continuous streams mode */
          close(in);
          if (continuous)
            break;
          in = fifo_open("in", FIFO_IN_MODE, O_RDONLY | O_NONBLOCK);
          if (in == -1) {
            syslog(LOG_ERR, "Failed to reopen 'in': %s", strerror(errno));
            break;
          }
        } else if (write_all(STDOUT_FILENO, buffer, len, "stdout"))
          break;
      }
    }
  }

  /* It's an error if we've got here */
  if (in >= 0)
    close(in);
  if (out >= 0)
    close(out);
  return -1;
}

void print_help (const char *name)
{
  printf("Usage: %s [option ...] <dir>\n", name);
  puts("Options:");
  puts(" -v <var>      an environment variable name");
  puts(" -c            continuous streams");
  puts(" -i <ident>    syslog ident to use");
  puts(" -e            print messages into stderr, in addition to syslog");
  puts(" -h            print this help message and exit");
}

int main (int argc,
          char **argv)
{
  int c;
  char *ident = "std2fifo";
  int syslog_options = 0, continuous = 0;
  char *var = "SHA256", *val, *dir;
  int ret;
  struct sigaction sigact;

  while ((c = getopt (argc, argv, "v:ci:eh")) != -1)
    switch (c)
      {
      case 'v': var = optarg;                  break;
      case 'c': continuous = 1;                break;
      case 'i': ident = optarg;                break;
      case 'e': syslog_options |= LOG_PERROR;  break;
      case 'h': print_help(argv[0]);           return 0;
      default:  print_help(argv[0]);           return 1;
      }

  if (argc <= optind) {
    print_help(argv[0]);
    return 1;
  }
  dir = argv[optind];
  val = getenv(var);
  if (! val) {
    print_help(argv[0]);
    return 1;
  }

  /* Prepare */
  openlog(ident, syslog_options, LOG_USER);

  /* Ignore SIGPIPE */
  sigact.sa_handler = SIG_IGN;
  sigact.sa_flags = 0;
  sigaction(SIGPIPE, &sigact, NULL);

  /* Run */
  ret = run(dir, val, continuous);

  /* Done */
  closelog();
  return ret;
}
