#ifndef _QUEUE_H
#define _QUEUE_H

#define QUEUE_SIZE 100

typedef struct {
  int head, tail, size;
  char **values;
} queue_t;

queue_t *alloc_queue(void) {
  queue_t *result = kmalloc(sizeof(queue_t), GFP_KERNEL);
  result->values = kmalloc(QUEUE_SIZE * sizeof(char *), GFP_KERNEL);
  int i;
  for (i = 0; i < QUEUE_SIZE; i++)
    result->values[i] = NULL;
  result->head = result->tail = 0;
  result->size = QUEUE_SIZE;
  return result;
}

void queue_enqueue(queue_t *queue, char *value) {
  if (queue->head >= queue->size)
    queue->head = 0;
  queue->values[queue->head++] = value;
}

char *queue_dequeue(queue_t *queue) {
  if (queue->tail >= queue->size)
    queue->tail = 0;
  char *result = queue->values[queue->tail];
  queue->values[queue->tail] = NULL;
  if (result != NULL) queue->tail++;
  return result;
}

#endif
