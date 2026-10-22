#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include "harness/unity.h"
#include "../src/lab.h"

static route_t parse_route(const char *line) {
  route_t route;
  TEST_ASSERT_TRUE(route_parse(line, &route));
  return route;
}

void setUp(void) {}
void tearDown(void) {}

static void test_ip_parse_and_format(void) {
  uint32_t addr = 77;
  char text[IP_STR_LEN];
  TEST_ASSERT_TRUE(ip_parse("192.168.1.10", &addr));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0A8010A), addr);
  ip_format(addr, text);
  TEST_ASSERT_EQUAL_STRING("192.168.1.10", text);
  TEST_ASSERT_TRUE(ip_parse("0.0.0.0", &addr));
  TEST_ASSERT_EQUAL_UINT32(0, addr);
  TEST_ASSERT_TRUE(ip_parse("255.255.255.255", &addr));
  TEST_ASSERT_EQUAL_HEX32(UINT32_MAX, addr);
  ip_format(addr, text);
  TEST_ASSERT_EQUAL_STRING("255.255.255.255", text);
  TEST_ASSERT_FALSE(ip_parse(NULL, &addr));
  TEST_ASSERT_FALSE(ip_parse("1.2.3.4", NULL));
  const char *bad[] = {"", "1.2.3", "1.2.3.4.5", "1..2.3", "256.1.1.1",
                       "010.0.0.1", "1.2.3.4x", "+1.2.3.4", "1.2.3.-1",
                       " 1.2.3.4", "1.2.3.4 ", "1.2.3.999999999999999999999"};
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
    addr = 77;
    TEST_ASSERT_FALSE(ip_parse(bad[i], &addr));
    TEST_ASSERT_EQUAL_UINT32(77, addr);
  }
}

static void test_cidr_parse_and_format(void) {
  cidr_t block = {123, 9};
  char text[CIDR_STR_LEN];
  TEST_ASSERT_TRUE(cidr_parse("132.178.227.11/25", &block));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84B2E30B), block.addr);
  TEST_ASSERT_EQUAL_UINT32(25, block.prefix);
  cidr_format(block, text);
  TEST_ASSERT_EQUAL_STRING("132.178.227.11/25", text);
  block.prefix = 33;
  cidr_format(block, text);
  TEST_ASSERT_EQUAL_STRING("132.178.227.11/32", text);
  TEST_ASSERT_FALSE(cidr_parse(NULL, &block));
  TEST_ASSERT_FALSE(cidr_parse("1.2.3.4/24", NULL));
  const char *bad[] = {"1.2.3.4", "1.2.3.4/", "1.2.3.4/33", "1.2.3.4/024",
                       "1.2.3/24", "1.2.3.4/-1", "1.2.3.4/1x",
                       "1.2.3.4/24/1", "/24", "123456789012345/24"};
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
    block.addr = 123;
    block.prefix = 9;
    TEST_ASSERT_FALSE(cidr_parse(bad[i], &block));
    TEST_ASSERT_EQUAL_UINT32(123, block.addr);
    TEST_ASSERT_EQUAL_UINT32(9, block.prefix);
  }
}

static void test_subnet_arithmetic(void) {
  cidr_t b = {UINT32_C(0x84B2E30B), 25};
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x00000000), cidr_mask(0));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xFFFFFF80), cidr_mask(25));
  TEST_ASSERT_EQUAL_HEX32(UINT32_MAX, cidr_mask(32));
  TEST_ASSERT_EQUAL_HEX32(UINT32_MAX, cidr_mask(33));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84B2E300), cidr_network(b));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84B2E37F), cidr_broadcast(b));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84B2E301), cidr_first_host(b));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84B2E37E), cidr_last_host(b));
  TEST_ASSERT_EQUAL_UINT64(126, cidr_host_count(b));
  TEST_ASSERT_TRUE(cidr_contains(b, UINT32_C(0x84B2E350)));
  TEST_ASSERT_FALSE(cidr_contains(b, UINT32_C(0x84B2E3C8)));
  TEST_ASSERT_FALSE(cidr_is_network(b));
  b.addr = UINT32_C(0x84B2E300);
  TEST_ASSERT_TRUE(cidr_is_network(b));

  b.addr = UINT32_C(0xFFFFFFFF);
  b.prefix = 0;
  TEST_ASSERT_EQUAL_UINT32(0, cidr_network(b));
  TEST_ASSERT_EQUAL_HEX32(UINT32_MAX, cidr_broadcast(b));
  TEST_ASSERT_EQUAL_UINT32(1, cidr_first_host(b));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xFFFFFFFE), cidr_last_host(b));
  TEST_ASSERT_EQUAL_UINT64(UINT64_C(4294967294), cidr_host_count(b));
  TEST_ASSERT_TRUE(cidr_contains(b, 0));
  b.addr = UINT32_C(0x0A010203);
  b.prefix = 31;
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x0A010202), cidr_network(b));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x0A010203), cidr_broadcast(b));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x0A010202), cidr_first_host(b));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x0A010203), cidr_last_host(b));
  TEST_ASSERT_EQUAL_UINT64(2, cidr_host_count(b));
  b.addr = UINT32_MAX;
  b.prefix = 32;
  TEST_ASSERT_EQUAL_HEX32(UINT32_MAX, cidr_first_host(b));
  TEST_ASSERT_EQUAL_HEX32(UINT32_MAX, cidr_last_host(b));
  TEST_ASSERT_EQUAL_UINT64(1, cidr_host_count(b));
}

static void test_cidr_subnet(void) {
  cidr_t block = {UINT32_C(0xC0A80100), 24};
  cidr_t out = {55, 7};
  TEST_ASSERT_TRUE(cidr_subnet(block, 4, 0, &out));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0A80100), out.addr);
  TEST_ASSERT_EQUAL_UINT32(26, out.prefix);
  TEST_ASSERT_TRUE(cidr_subnet(block, 4, 3, &out));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xC0A801C0), out.addr);
  TEST_ASSERT_FALSE(cidr_subnet(block, 4, 4, &out));
  TEST_ASSERT_FALSE(cidr_subnet(block, 0, 0, &out));
  TEST_ASSERT_FALSE(cidr_subnet(block, 3, 0, &out));
  TEST_ASSERT_FALSE(cidr_subnet(block, 512, 0, &out));
  TEST_ASSERT_FALSE(cidr_subnet(block, 4, 0, NULL));
  block.addr++;
  TEST_ASSERT_FALSE(cidr_subnet(block, 1, 0, &out));
  block.addr = 0;
  block.prefix = 33;
  TEST_ASSERT_FALSE(cidr_subnet(block, 1, 0, &out));
  block.prefix = 0;
  TEST_ASSERT_TRUE(cidr_subnet(block, UINT32_C(0x80000000),
                               UINT32_C(0x7FFFFFFF), &out));
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0xFFFFFFFE), out.addr);
  TEST_ASSERT_EQUAL_UINT32(31, out.prefix);
}

static void test_route_parse(void) {
  route_t route = parse_route("  default\t132.178.227.1  eno1 \n");
  TEST_ASSERT_EQUAL_UINT32(0, route.dest.addr);
  TEST_ASSERT_EQUAL_UINT32(0, route.dest.prefix);
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x84B2E301), route.gateway);
  TEST_ASSERT_EQUAL_STRING("eno1", route.dev);
  route = parse_route("10.1.2.0/24 direct eth2");
  TEST_ASSERT_EQUAL_UINT32(0, route.gateway);
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x0A010200), route.dest.addr);
  TEST_ASSERT_FALSE(route_parse(NULL, &route));
  TEST_ASSERT_FALSE(route_parse("default direct eno1", NULL));
  const char *bad[] = {"", "default direct", "default direct eno1 extra",
      "10.1.2.3/24 direct eth0", "10.1.2.0/24 nope eth0",
      "default direct", "default direct ", "default direct 1234567890123456",
      "Default direct eth0", "default direct eth0 x y"};
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
    route.dest.addr = 99;
    TEST_ASSERT_FALSE(route_parse(bad[i], &route));
    TEST_ASSERT_EQUAL_UINT32(99, route.dest.addr);
  }
}

static void test_table_add_and_lookup(void) {
  fwd_table_t *table = table_create();
  route_t broad = parse_route("10.0.0.0/8 10.1.0.1 eth1");
  route_t middle = parse_route("10.1.0.0/16 direct eth1");
  route_t narrow = parse_route("10.1.2.0/24 direct eth2");
  route_t most = parse_route("10.1.2.128/25 10.1.2.1 eth2");
  route_t fifth = parse_route("192.168.0.0/16 10.1.0.1 eth1");
  TEST_ASSERT_NOT_NULL(table);
  TEST_ASSERT_EQUAL_UINT32(0, (uint32_t)table_count(table));
  TEST_ASSERT_FALSE(table_add(NULL, &broad));
  TEST_ASSERT_FALSE(table_add(table, NULL));
  TEST_ASSERT_TRUE(table_add(table, &narrow));
  TEST_ASSERT_TRUE(table_add(table, &broad));
  TEST_ASSERT_TRUE(table_add(table, &most));
  TEST_ASSERT_TRUE(table_add(table, &middle));
  TEST_ASSERT_TRUE(table_add(table, &fifth));
  TEST_ASSERT_EQUAL_UINT32(5, (uint32_t)table_count(table));
  TEST_ASSERT_FALSE(table_add(table, &narrow));
  route_t invalid = broad;
  invalid.dest.addr++;
  TEST_ASSERT_FALSE(table_add(table, &invalid));
  TEST_ASSERT_NULL(table_lookup(NULL, UINT32_C(0x0A010205)));
  TEST_ASSERT_EQUAL_STRING("eth2", table_lookup(table, UINT32_C(0x0A010205))->dev);
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x0A010201),
                          table_lookup(table, UINT32_C(0x0A0102C8))->gateway);
  table_destroy(table);
  table_destroy(NULL);

  table = table_create();
  TEST_ASSERT_NOT_NULL(table);
  TEST_ASSERT_TRUE(table_add(table, &broad));
  TEST_ASSERT_TRUE(table_add(table, &middle));
  TEST_ASSERT_TRUE(table_add(table, &narrow));
  TEST_ASSERT_TRUE(table_add(table, &most));
  TEST_ASSERT_EQUAL_STRING("eth2", table_lookup(table, UINT32_C(0x0A010205))->dev);
  TEST_ASSERT_EQUAL_HEX32(UINT32_C(0x0A010201),
                          table_lookup(table, UINT32_C(0x0A0102C8))->gateway);
  TEST_ASSERT_NULL(table_lookup(table, UINT32_C(0xC0A80001)));
  table_destroy(table);
  TEST_ASSERT_EQUAL_UINT32(0, (uint32_t)table_count(NULL));
}

static void test_table_load(void) {
  fwd_table_t *table = table_create();
  FILE *file = tmpfile();
  size_t bad_line = 99;
  TEST_ASSERT_NOT_NULL(table);
  TEST_ASSERT_NOT_NULL(file);
  TEST_ASSERT_NOT_EQUAL(EOF, fputs("# comment\n \t\n default 1.2.3.4 eth0 # default\n10.0.0.0/8 direct eth1\n", file));
  rewind(file);
  TEST_ASSERT_TRUE(table_load(table, file, NULL));
  TEST_ASSERT_EQUAL_UINT32(2, (uint32_t)table_count(table));
  TEST_ASSERT_EQUAL_INT(0, fclose(file));
  table_destroy(table);
  table = table_create();
  TEST_ASSERT_NOT_NULL(table);

  file = tmpfile();
  TEST_ASSERT_NOT_NULL(file);
  TEST_ASSERT_NOT_EQUAL(EOF, fputs("default direct eth0\n10.0.0.0/8 direct eth1\n10.1.0.0/16 direct eth2\n10.1.2.3/24 direct eth3\n", file));
  rewind(file);
  TEST_ASSERT_FALSE(table_load(table, file, &bad_line));
  TEST_ASSERT_EQUAL_UINT32(4, (uint32_t)bad_line);
  TEST_ASSERT_EQUAL_UINT32(3, (uint32_t)table_count(table));
  TEST_ASSERT_EQUAL_INT(0, fclose(file));
  TEST_ASSERT_FALSE(table_load(NULL, NULL, &bad_line));
  TEST_ASSERT_FALSE(table_load(table, NULL, &bad_line));
  TEST_ASSERT_EQUAL_UINT32(0, (uint32_t)bad_line);
  table_destroy(table);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_ip_parse_and_format);
  RUN_TEST(test_cidr_parse_and_format);
  RUN_TEST(test_subnet_arithmetic);
  RUN_TEST(test_cidr_subnet);
  RUN_TEST(test_route_parse);
  RUN_TEST(test_table_add_and_lookup);
  RUN_TEST(test_table_load);
  return UNITY_END();
}
