#define _POSIX_C_SOURCE 200809L
#include "lab.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

struct fwd_table {
  route_t *routes;
  size_t count;
  size_t capacity;
};

static bool parse_decimal(const char **cursor, unsigned int max,
                          unsigned int *value) {
  const char *p = *cursor;
  unsigned int parsed = 0;
  size_t digits = 0;
  if (*p < '0' || *p > '9') return false;
  while (*p >= '0' && *p <= '9') {
    unsigned int digit = (unsigned int)(*p - '0');
    if (parsed > (max - digit) / 10U) return false;
    parsed = parsed * 10U + digit;
    ++digits;
    ++p;
  }
  if (digits > 1 && **cursor == '0') return false;
  *cursor = p;
  *value = parsed;
  return true;
}

bool ip_parse(const char *text, uint32_t *addr) {
  uint32_t parsed = 0;
  const char *p = text;
  if (text == NULL || addr == NULL) return false;
  for (unsigned int octet_index = 0; octet_index < 4; ++octet_index) {
    unsigned int octet;
    if (!parse_decimal(&p, 255U, &octet)) return false;
    parsed = (parsed << 8) | (uint32_t)octet;
    if (octet_index < 3) {
      if (*p != '.') return false;
      ++p;
    } else if (*p != '\0') {
      return false;
    }
  }
  *addr = parsed;
  return true;
}

void ip_format(uint32_t addr, char out[IP_STR_LEN]) {
  (void)snprintf(out, IP_STR_LEN, "%u.%u.%u.%u",
                 (unsigned int)((addr >> 24) & 255U),
                 (unsigned int)((addr >> 16) & 255U),
                 (unsigned int)((addr >> 8) & 255U),
                 (unsigned int)(addr & 255U));
}

bool cidr_parse(const char *text, cidr_t *block) {
  cidr_t parsed;
  const char *slash;
  char address[IP_STR_LEN];
  size_t address_len;
  const char *prefix_text;
  unsigned int prefix;
  if (text == NULL || block == NULL) return false;
  slash = strchr(text, '/');
  if (slash == NULL || strchr(slash + 1, '/') != NULL) return false;
  address_len = (size_t)(slash - text);
  if (address_len == 0 || address_len >= sizeof(address)) return false;
  memcpy(address, text, address_len);
  address[address_len] = '\0';
  if (!ip_parse(address, &parsed.addr)) return false;
  prefix_text = slash + 1;
  if (!parse_decimal(&prefix_text, 32U, &prefix) || *prefix_text != '\0')
    return false;
  parsed.prefix = (uint8_t)prefix;
  *block = parsed;
  return true;
}

void cidr_format(cidr_t block, char out[CIDR_STR_LEN]) {
  char address[IP_STR_LEN];
  ip_format(block.addr, address);
  (void)snprintf(out, CIDR_STR_LEN, "%s/%u", address,
                 (unsigned int)(block.prefix > 32 ? 32 : block.prefix));
}

uint32_t cidr_mask(uint8_t prefix) {
  if (prefix == 0) return 0;
  if (prefix >= 32) return UINT32_MAX;
  return UINT32_MAX << (32U - prefix);
}

uint32_t cidr_network(cidr_t block) {
  return block.addr & cidr_mask(block.prefix);
}

uint32_t cidr_broadcast(cidr_t block) {
  return block.addr | ~cidr_mask(block.prefix);
}

uint32_t cidr_first_host(cidr_t block) {
  uint32_t network = cidr_network(block);
  return block.prefix >= 31 ? network : network + 1U;
}

uint32_t cidr_last_host(cidr_t block) {
  uint32_t broadcast = cidr_broadcast(block);
  return block.prefix >= 31 ? broadcast : broadcast - 1U;
}

uint64_t cidr_host_count(cidr_t block) {
  if (block.prefix >= 32) return 1;
  if (block.prefix == 31) return 2;
  return (UINT64_C(1) << (32U - block.prefix)) - 2U;
}

bool cidr_contains(cidr_t block, uint32_t addr) {
  uint32_t mask = cidr_mask(block.prefix);
  return (addr & mask) == (block.addr & mask);
}

bool cidr_is_network(cidr_t block) {
  return cidr_network(block) == block.addr;
}

bool cidr_subnet(cidr_t block, uint32_t n, uint32_t i, cidr_t *out) {
  uint32_t bits = 0;
  uint32_t remaining;
  uint8_t prefix;
  uint64_t size;
  cidr_t subnet;
  if (out == NULL || n == 0 || !cidr_is_network(block) || block.prefix > 32)
    return false;
  if ((n & (n - 1U)) != 0 || i >= n) return false;
  remaining = n;
  while (remaining > 1U) {
    ++bits;
    remaining >>= 1;
  }
  if ((uint32_t)block.prefix + bits > 32U) return false;
  prefix = (uint8_t)((uint32_t)block.prefix + bits);
  size = UINT64_C(1) << (32U - prefix);
  subnet.addr = (uint32_t)((uint64_t)block.addr + (uint64_t)i * size);
  subnet.prefix = prefix;
  *out = subnet;
  return true;
}

bool route_parse(const char *line, route_t *route) {
  route_t parsed;
  char *copy;
  char *p;
  char *fields[4];
  size_t count = 0;
  size_t dev_len;
  cidr_t dest;
  if (line == NULL || route == NULL) return false;
  copy = malloc(strlen(line) + 1U);
  if (copy == NULL) return false; // GCOVR_EXCL_BR_LINE: malloc failure cannot be forced reliably.
  (void)strcpy(copy, line);
  p = copy;
  while (isspace((unsigned char)*p)) ++p;
  while (*p != '\0') {
    if (count == 4) {
      free(copy);
      return false;
    }
    fields[count++] = p;
    while (*p != '\0' && !isspace((unsigned char)*p)) ++p;
    if (*p == '\0') break;
    *p++ = '\0';
    while (isspace((unsigned char)*p)) ++p;
  }
  if (count != 3) {
    free(copy);
    return false;
  }
  if (strcmp(fields[0], "default") == 0) {
    dest.addr = 0;
    dest.prefix = 0;
  } else if (!cidr_parse(fields[0], &dest) || !cidr_is_network(dest)) {
    free(copy);
    return false;
  }
  if (strcmp(fields[1], "direct") == 0) {
    parsed.gateway = 0;
  } else if (!ip_parse(fields[1], &parsed.gateway)) {
    free(copy);
    return false;
  }
  dev_len = strlen(fields[2]);
  if (dev_len >= DEV_NAME_LEN) {
    free(copy);
    return false;
  }
  parsed.dest = dest;
  (void)strcpy(parsed.dev, fields[2]);
  free(copy);
  *route = parsed;
  return true;
}

fwd_table_t *table_create(void) {
  return calloc(1, sizeof(fwd_table_t));
}

void table_destroy(fwd_table_t *table) {
  if (table == NULL) return;
  free(table->routes);
  free(table);
}

size_t table_count(const fwd_table_t *table) {
  return table == NULL ? 0 : table->count;
}

bool table_add(fwd_table_t *table, const route_t *route) {
  size_t capacity;
  route_t *routes;
  if (table == NULL || route == NULL || !cidr_is_network(route->dest))
    return false;
  for (size_t i = 0; i < table->count; ++i) {
    if (table->routes[i].dest.addr == route->dest.addr &&
        table->routes[i].dest.prefix == route->dest.prefix)
      return false;
  }
  if (table->count == table->capacity) {
    capacity = table->capacity == 0 ? 4 : table->capacity * 2;
    routes = realloc(table->routes, capacity * sizeof(route_t));
    if (routes == NULL) return false; // GCOVR_EXCL_BR_LINE: realloc failure cannot be forced reliably.
    table->routes = routes;
    table->capacity = capacity;
  }
  table->routes[table->count++] = *route;
  return true;
}

bool table_load(fwd_table_t *table, FILE *in, size_t *bad_line) {
  char *line = NULL;
  size_t capacity = 0;
  size_t line_number = 0;
  ssize_t length;
  bool result = true;
  if (bad_line != NULL) *bad_line = 0;
  if (table == NULL || in == NULL) return false;
  while ((length = getline(&line, &capacity, in)) >= 0) {
    char *comment;
    char *p;
    route_t route;
    (void)length;
    ++line_number;
    comment = strchr(line, '#');
    if (comment != NULL) *comment = '\0';
    p = line;
    while (isspace((unsigned char)*p)) ++p;
    if (*p == '\0') continue;
    if (!route_parse(p, &route) || !table_add(table, &route)) {
      if (bad_line != NULL) *bad_line = line_number;
      result = false;
      break;
    }
  }
  if (ferror(in)) {
    if (bad_line != NULL) *bad_line = 0;
    result = false;
  }
  free(line);
  return result;
}

const route_t *table_lookup(const fwd_table_t *table, uint32_t dest) {
  const route_t *best = NULL;
  if (table == NULL) return NULL;
  for (size_t i = 0; i < table->count; ++i) {
    const route_t *candidate = &table->routes[i];
    if (cidr_contains(candidate->dest, dest) &&
        (best == NULL || candidate->dest.prefix > best->dest.prefix))
      best = candidate;
  }
  return best;
}
