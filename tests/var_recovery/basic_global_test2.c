/*
 * basic_global_test2.c
 *
 *  Created on: Aug 15, 2017
 *      Author: akkumar
 */


#include <stdio.h>

void ap_hook_get_monitor(void) {
  printf("%s:%d\n", __FUNCTION__, __LINE__);
}

void ap_hook_get_child_status(void) {
  printf("%s:%d\n", __FUNCTION__, __LINE__);
}

void ap_hook_get_end_generation(void) {
  printf("%s:%d\n", __FUNCTION__, __LINE__);
}

void ap_hook_get_error_log(void) {
  printf("%s:%d\n", __FUNCTION__, __LINE__);
}

void ap_hook_get_mpm_query(void) {
  printf("%s:%d\n", __FUNCTION__, __LINE__);
}

void ap_hook_get_mpm_get_name(void) {
  printf("%s:%d\n", __FUNCTION__, __LINE__);
}

void ap_hook_get_mpm_register_timed_callback(void) {
  printf("%s:%d\n", __FUNCTION__, __LINE__);
}

void ap_hook_get_expr_lookup(void) {
  printf("%s:%d\n", __FUNCTION__, __LINE__);
}

void ap_hook_get_get_mgmt_items(void) {
  printf("%s:%d\n", __FUNCTION__, __LINE__);
}


typedef void (*hook_get_t)(void);

typedef struct
{
    const char *name;
    hook_get_t get;
} hook_lookup_t;


static hook_lookup_t other_hooks[] = {
    {"Monitor", ap_hook_get_monitor},
    {"Child Status", ap_hook_get_child_status},
    {"End Generation", ap_hook_get_end_generation},
    {"Error Logging", ap_hook_get_error_log},
    {"Query MPM Attributes", ap_hook_get_mpm_query},
    {"Query MPM Name", ap_hook_get_mpm_get_name},
    {"Register Timed Callback", ap_hook_get_mpm_register_timed_callback},
    {"Extend Expression Parser", ap_hook_get_expr_lookup},
    {"Set Management Items", ap_hook_get_get_mgmt_items},
    {NULL},
};

static int dump_a_hook(hook_get_t hook_get)
{
  hook_get();
  return 0;
}


void main(int argc, char *argv[]) {

  int i = 0;
  for (i = 0; other_hooks[i].name; i++) {
    printf("<dt><strong>%s:</strong>\n <br /><tt>\n", other_hooks[i].name);
    dump_a_hook(other_hooks[i].get);
  }
  return;
}
