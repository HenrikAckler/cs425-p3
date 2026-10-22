#include "lab.h"

#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#ifdef TEST
#define main main_exclude
#endif

static void usage(FILE *out) {
  (void)fprintf(out,
      "Usage: myapp info <address>/<prefix>\n"
      "       myapp split <network>/<prefix> <count>\n"
      "       myapp lookup <table-file> <address>...\n");
}

static bool parse_count(const char *text, uint32_t *count) {
  uint32_t value = 0;
  const unsigned char *p = (const unsigned char *)text;
  if (*p == '\0') return false;
  while (*p != '\0') {
    uint32_t digit;
    if (*p < '0' || *p > '9') return false;
    digit = (uint32_t)(*p - '0');
    if (value > (UINT32_MAX - digit) / 10U) return false;
    value = value * 10U + digit;
    ++p;
  }
  if (value == 0) return false;
  *count = value;
  return true;
}

static int run_info(const char *arg) {
  cidr_t block;
  char address[IP_STR_LEN];
  char mask[IP_STR_LEN];
  char network[IP_STR_LEN];
  char broadcast[IP_STR_LEN];
  char first[IP_STR_LEN];
  char last[IP_STR_LEN];
  if (!cidr_parse(arg, &block)) {
    (void)fprintf(stderr, "myapp: '%s': not a valid CIDR block\n", arg);
    return 1;
  }
  ip_format(block.addr, address);
  ip_format(cidr_mask(block.prefix), mask);
  ip_format(cidr_network(block), network);
  ip_format(cidr_broadcast(block), broadcast);
  ip_format(cidr_first_host(block), first);
  ip_format(cidr_last_host(block), last);
  (void)printf("address    %s\n", address);
  (void)printf("prefix     /%u\n", (unsigned int)(block.prefix > 32 ? 32 : block.prefix));
  (void)printf("netmask    %s\n", mask);
  (void)printf("network    %s\n", network);
  (void)printf("broadcast  %s\n", broadcast);
  (void)printf("first host %s\n", first);
  (void)printf("last host  %s\n", last);
  (void)printf("hosts      %" PRIu64 "\n", cidr_host_count(block));
  return 0;
}

static int run_split(const char *network_arg, const char *count_arg) {
  cidr_t network;
  cidr_t subnet;
  uint32_t count;
  if (!cidr_parse(network_arg, &network)) {
    (void)fprintf(stderr, "myapp: '%s': not a valid CIDR block\n", network_arg);
    return 1;
  }
  if (!cidr_is_network(network)) {
    (void)fprintf(stderr, "myapp: '%s': block has host bits set\n", network_arg);
    return 1;
  }
  if (!parse_count(count_arg, &count)) {
    (void)fprintf(stderr, "myapp: '%s': count must be a positive integer\n", count_arg);
    return 1;
  }
  if ((count & (count - 1U)) != 0) {
    (void)fprintf(stderr, "myapp: '%s': count must be a power of two\n", count_arg);
    return 1;
  }
  for (uint32_t i = 0; i < count; ++i) {
    char formatted[CIDR_STR_LEN];
    if (!cidr_subnet(network, count, i, &subnet)) {
      (void)fprintf(stderr, "myapp: cannot split %s into %" PRIu32 " subnets\n",
                    network_arg, count);
      return 1;
    }
    cidr_format(subnet, formatted);
    (void)puts(formatted);
  }
  return 0;
}

static int run_lookup(int argc, char **argv) {
  FILE *in = fopen(argv[2], "r");
  fwd_table_t *table;
  size_t bad_line;
  int saw_bad_address = 0;
  int saw_unmatched = 0;
  if (in == NULL) {
    (void)fprintf(stderr, "myapp: %s: %s\n", argv[2], strerror(errno));
    return 2;
  }
  table = table_create();
  if (table == NULL) {
    (void)fclose(in);
    (void)fprintf(stderr, "myapp: could not allocate forwarding table\n");
    return 2;
  }
  if (!table_load(table, in, &bad_line)) {
    (void)fclose(in);
    if (bad_line == 0) {
      (void)fprintf(stderr, "myapp: %s: could not read forwarding table\n", argv[2]);
    } else {
      (void)fprintf(stderr, "myapp: %s:%zu: not a valid route\n", argv[2], bad_line);
    }
    table_destroy(table);
    return 2;
  }
  (void)fclose(in);
  for (int i = 3; i < argc; ++i) {
    uint32_t dest;
    char formatted[IP_STR_LEN];
    if (!ip_parse(argv[i], &dest)) {
      (void)fprintf(stderr, "myapp: '%s': not a valid address\n", argv[i]);
      saw_bad_address = 1;
      continue;
    }
    ip_format(dest, formatted);
    const route_t *route = table_lookup(table, dest);
    if (route == NULL) {
      (void)printf("%s unreachable\n", formatted);
      saw_unmatched = 1;
    } else if (route->gateway == 0) {
      (void)printf("%s dev %s\n", formatted, route->dev);
    } else {
      char gateway[IP_STR_LEN];
      ip_format(route->gateway, gateway);
      (void)printf("%s via %s dev %s\n", formatted, gateway, route->dev);
    }
  }
  table_destroy(table);
  if (saw_bad_address) return 1;
  return saw_unmatched ? 3 : 0;
}

int main(int argc, char **argv) {
  if (argc == 1) {
    usage(stdout);
    return 0;
  }
  if (strcmp(argv[1], "info") == 0 && argc == 3) return run_info(argv[2]);
  if (strcmp(argv[1], "split") == 0 && argc == 4)
    return run_split(argv[2], argv[3]);
  if (strcmp(argv[1], "lookup") == 0 && argc >= 4)
    return run_lookup(argc, argv);
  usage(stderr);
  return 1;
}
