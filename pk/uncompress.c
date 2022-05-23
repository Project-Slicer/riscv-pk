// See LICENSE for license details.

#include "uncompress.h"
#include "ksyscall.h"
#include <stddef.h>

#define COMPRESS_QUEUE_LEN 255
static uint8_t compress_queue[COMPRESS_QUEUE_LEN];

#define FILE_BUFFER_LEN 255
static uint8_t file_buffer[FILE_BUFFER_LEN];

typedef struct {
  uint8_t *buf;
  size_t max_len;
  size_t begin;
  size_t len;
} queue_t;

static void queue_init(queue_t *queue, uint8_t *buf, size_t max_len)
{
  queue->buf = buf;
  queue->max_len = max_len;
  queue->begin = 0;
  queue->len = 0;
}

static uint8_t queue_get(const queue_t *queue, size_t index)
{
  return queue->buf[(queue->begin + index) % queue->max_len];
}

// returns non-zero if the beginning of the queue is updated
static int queue_push(queue_t *queue, uint8_t c)
{
  queue->buf[(queue->begin + queue->len) % queue->max_len] = c;
  if (queue->len < queue->max_len) {
    queue->len++;
    return 0;
  } else {
    queue->begin = (queue->begin + 1) % queue->max_len;
    return 1;
  }
}

int uncompress(int kfd, uncompress_callback_t write_byte)
{
  queue_t queue;
  queue_init(&queue, compress_queue, COMPRESS_QUEUE_LEN);

  ssize_t ret;
  while ((ret = sys_read(kfd, file_buffer, FILE_BUFFER_LEN)) > 0) {
    if (ret % 3 != 0) return -1;
    for (size_t i = 0; i < ret; i += 3) {
      size_t offset = file_buffer[i], length = file_buffer[i + 1];
      uint8_t data = file_buffer[i + 2];
      if (!offset) {
        write_byte(data);
        queue_push(&queue, data);
      } else {
        size_t j = 0, k = queue.len - offset;
        while (j < length) {
          uint8_t cur = queue_get(&queue, k + j);
          write_byte(cur);
          if (queue_push(&queue, cur)) k--;
          j++;
        }
      }
    }
  }

  return ret < 0 ? ret : 0;
}
