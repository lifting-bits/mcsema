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

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

__thread int tls_data1;
__thread int tls_data2;

typedef struct {
  int   data1;
  int   data2;
} thread_parm_t;

void bar() {
  printf("bar(), tls data=%d %d\n", tls_data1, tls_data2);
  return;
}

void foo() {
  printf("foo(), tls data=%d %d\n", tls_data1, tls_data2);
  bar();
}

void *theThread(void *parm)
{
  int  rc;
  thread_parm_t  *gData;
  gData = (thread_parm_t*)parm;
  tls_data1 = gData->data1;
  tls_data2 = gData->data2;
  foo();
  return NULL;
}

int main(int argc, char **argv) {
  int rc=0, i;
  pthread_t thread[2];
  thread_parm_t gData[2];

  printf("Create threads\n");
  for (i=0; i < 2; i++) {
    gData[i].data1 = i;
    gData[i].data2 = (i+1)*2;
    rc = pthread_create(&thread[i], NULL, theThread, &gData[i]);
    if (rc) {
      printf("Failed with %d at pthread_create()", rc);
      exit(1);
    }
  }

  printf("Wait for the threads to complete, and release their resources\n");
  for (i=0; i < 2; i++) {
    rc = pthread_join(thread[i], NULL);
    if (rc) {
      printf("Failed with %d at pthread_join()", rc);
      exit(1);
    }
  }

  printf("Main completed\n");
  return 0;
}
