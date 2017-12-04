
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

class Buffer
{
 public:
  Buffer(void);
  ~Buffer();

  void put(bool x) {
    pthread_mutex_lock(&mtx);

    while (is_full) {
      pthread_cond_wait(&empty, &mtx);
    }

    value = x;
    is_full = true;
    pthread_cond_signal(&full);
    pthread_mutex_unlock(&mtx);
  }

  void get(bool &x) {
    pthread_mutex_lock(&mtx);

    while (not is_full) {
      pthread_cond_wait(&full, &mtx);
    }

    x = value;
    is_full = false;
    pthread_cond_signal(&empty);
    pthread_mutex_unlock(&mtx);
  }

 private:
  bool value;
  bool is_full;
  pthread_mutex_t mtx;
  pthread_cond_t full;
  pthread_cond_t empty;
};

Buffer::Buffer(void) {
  pthread_mutex_init(&mtx, NULL);
  pthread_cond_init(&full, NULL);
  pthread_cond_init(&empty, NULL);
  value = false;
  is_full = false;
}

Buffer::~Buffer() {
  pthread_mutex_destroy(&mtx);
  pthread_cond_destroy(&full);
  pthread_cond_destroy(&empty);
}

Buffer buff;

void *producer(void *arg) {
  int i = 0;
  unsigned long iter_counter = reinterpret_cast<unsigned long>(arg);

  for (i = 0; i != iter_counter - 1; ++i) {
    buff.put(false);
  }
  buff.put(true);
  return arg;
}

void *consumer(void *arg) {
  int count = 0;
  bool x;
  while (true) {
    buff.get(x);
    ++count;
    if (x) {
      break;
    }
  }
  printf("Executed %d iterations\n", count);
  return arg;
}

int main(int argc, char * argv[]) {
  (void)argc;
  int iter_counter = atoi(argv[1]);

  pthread_t pro_th;
  pthread_t cons_th;
  pthread_create(&pro_th, NULL, producer, iter_counter);
  pthread_create(&cons_th, NULL, consumer, NULL);
  pthread_join(pro_th, NULL);
  pthread_join(cons_th, NULL);
}
