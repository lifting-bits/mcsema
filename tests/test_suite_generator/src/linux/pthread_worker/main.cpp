
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

class Buffer
{
 public:
  Buffer(void);
  ~Buffer();

  void put(bool x) {
    pthread_mutex_lock(&mtx_);

    while (is_full_) {
      pthread_cond_wait(&empty_, &mtx_);
    }

    value_ = x;
    is_full_ = true;
    pthread_cond_signal(&full_);
    pthread_mutex_unlock(&mtx_);
  }

  void get(bool &x) {
    pthread_mutex_lock(&mtx_);

    while (not is_full_) {
      pthread_cond_wait(&full_, &mtx_);
    }

    x = value_;
    is_full_ = false;
    pthread_cond_signal(&empty_);
    pthread_mutex_unlock(&mtx_);
  }

 private:
  bool value_;
  bool is_full_;
  pthread_mutex_t mtx_;
  pthread_cond_t full_;
  pthread_cond_t empty_;
};

Buffer::Buffer(void) {
  pthread_mutex_init(&mtx_, NULL);
  pthread_cond_init(&full_, NULL);
  pthread_cond_init(&empty_, NULL);
  value_ = false;
  is_full_ = false;
}

Buffer::~Buffer() {
  pthread_mutex_destroy(&mtx_);
  pthread_cond_destroy(&full_);
  pthread_cond_destroy(&empty_);
}

Buffer buff;
int iterations;

void *producer(void *arg) {
  int i = 0;
  for (i = 0; i != iterations - 1; ++i) {
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

int main(int argc, char * argv[])
{
  iterations = atoi(argv[1]);

  pthread_t pro_th;
  pthread_t cons_th;
  pthread_create(&pro_th, NULL, producer, NULL);
  pthread_create(&cons_th, NULL, consumer, NULL);
  pthread_join(pro_th, NULL);
  pthread_join(cons_th, NULL);
}
