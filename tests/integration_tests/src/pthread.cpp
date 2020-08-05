/* TAGS: min cpp */
/* LIFT_OPTS: explicit +--explicit_args +--explicit_args_count 8 */
/* LIFT_OPTS: default */
/* LD_OPTS: -lpthread */
/*
 * Copyright (c) 2017 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

static pthread_cond_t gCond;
static pthread_mutex_t gLock;
static int gFlag = 0;

__thread int tls_data1;
__thread int tls_data2;

typedef struct {
  int data1;
  int data2;
} thread_parm_t;

void bar() {
  printf("bar(), tls data=%d %d\n", tls_data1, tls_data2);
  return;
}

void foo() {
  printf("foo(), tls data=%d %d\n", tls_data1, tls_data2);
  bar();
}

void *theThread(void *parm) {
  thread_parm_t *gData;

  pthread_mutex_lock(&gLock);
  pthread_cond_wait(&gCond, &gLock);

  gFlag += 1;

  gData = (thread_parm_t *) parm;
  tls_data1 = gData->data1;
  tls_data2 = gData->data2;
  foo();

  pthread_mutex_unlock(&gLock);
  return NULL;
}

int main(int argc, char **argv) {
  int rc = 0, i;
  pthread_t thread[2];
  thread_parm_t gData[2];

  printf("Create threads\n");
  pthread_mutex_init(&gLock, NULL);
  pthread_cond_init(&gCond, NULL);
  for (i = 0; i < 2; i++) {
    gData[i].data1 = i;
    gData[i].data2 = (i + 1) * 2;
    rc = pthread_create(&thread[i], NULL, theThread, &gData[i]);
    if (rc) {
      printf("Failed with %d at pthread_create()", rc);
      exit(1);
    }
  }

  // synchronize output. this gets printed before threads print
  printf("Wait for the threads to complete, and release their resources\n");
  fflush(stdout);
  while (gFlag < 2) {
    pthread_cond_signal(&gCond);
  }
  for (i = 0; i < 2; i++) {
    rc = pthread_join(thread[i], NULL);
    if (rc) {
      printf("Failed with %d at pthread_join()", rc);
      exit(1);
    }
  }

  printf("Main completed\n");
  return 0;
}
