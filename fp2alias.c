/*
  fp2alias, a basic authentication and authorization helper

  This is free and unencumbered software released into the public
  domain.
*/

#include <config.h>

#include <syslog.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

/* This value is used in format strings as well */
#define MAX_ALIAS_LEN 32

#define DEFAULT_ALIAS_FILE "/etc/tls/aliases"

/* Get an alias from a file, or from a user */
int get_alias (const char *filename,
               const char *fingerprint,
               char *alias,
               int add_new)
{
  FILE * fd;
  char hash[65];
  char login[MAX_ALIAS_LEN + 1];
  int l;

  /* Try to find the fingerprint */
  fd = fopen(filename, "r");
  if (!fd) {
    syslog(LOG_ERR, "Can't open %s for reading: %s (errno=%d)",
           filename, strerror(errno), errno);
    return -1;
  }
  do {
    l = fscanf(fd, "%64[a-f0-9] %32[a-z0-9]\n", hash, login);
    if (! strncmp(hash, fingerprint, 64)) {
      fclose(fd);
      strncpy(alias, login, MAX_ALIAS_LEN + 1);
      return 0;
    }
  } while (l != EOF);

  /* In read-only mode, that's all */
  if (! add_new) {
    fclose(fd);
    puts("I don't recognize you.");
    return -1;
  }

  /* Ask for an alias to add */
  puts("Enter your alias, please.");
  fflush(stdout);
  l = scanf("%32[a-z0-9]", alias);
  if (l == EOF || strlen(alias) < 2) {
    fclose(fd);
    return -1;
  }

  /* Check that the alias is not taken */
  fd = freopen(filename, "a+", fd);
  if (!fd) {
    syslog(LOG_ERR, "Can't reopen %s for writing: %s (errno=%d)",
           filename, strerror(errno), errno);
    return -1;
  }
  do {
    l = fscanf(fd, "%64[a-f0-9] %32[a-z0-9]\n", hash, login);
    if (! strncmp(alias, login, MAX_ALIAS_LEN)) {
      fclose(fd);
      printf("The '%s' alias is taken already.", alias);
      return -1;
    }
  } while (l != EOF);

  /* Everything appears to be fine; add it */
  fprintf(fd, "%s %s\n", fingerprint, alias);
  fclose(fd);
  return 0;
}

void print_help (const char *name)
{
  printf("Usage: %s [option ...] [--] [<command> [argument ...]]\n", name);
  puts("Options:");
  puts(" -f <file>     a file with \"<fingerprint> <alias>\" entries");
  puts(" -a            add new aliases");
  puts(" -i <ident>    syslog ident to use");
  puts(" -e            print messages into stderr, in addition to syslog");
  puts(" -h            print this help message and exit");
}

int main (int argc,
          char **argv)
{
  int c;
  int syslog_options = 0;
  char *ident = "fp2alias";
  char *alias_file = DEFAULT_ALIAS_FILE;
  char *sha256;
  char alias[MAX_ALIAS_LEN + 1];
  int add_new = 0;

  ident = argv[0];

  while ((c = getopt (argc, argv, "f:ai:eh")) != -1)
    switch (c)
      {
      case 'f': alias_file = optarg;           break;
      case 'a': add_new = 1;                   break;
      case 'i': ident = optarg;                break;
      case 'e': syslog_options |= LOG_PERROR;  break;
      case 'h': print_help(argv[0]);           return 0;
      default:  print_help(argv[0]);           return 1;
      }

  openlog(ident, syslog_options, LOG_USER);

  sha256 = getenv("SHA256");
  if (! sha256) {
    syslog(LOG_ERR, "The SHA256 environment variable is not defined");
    closelog();
    return 1;
  }

  if (get_alias(alias_file, sha256, alias, add_new) < 0) {
    closelog();
    return 1;
  }
  syslog(LOG_INFO, "Identified %s as %s", sha256, alias);
  closelog();

  /* Run a program if one is specified */
  if (argc > optind) {
    setenv("ALIAS", alias, 1);
    return execvp(argv[optind], &argv[optind]);
  }
  return 0;
}
