#ifndef _HASHTAB_H
#define _HASHTAB_H

#define HASHTAB_SIZE 1000

typedef struct hashtab_entry_t {
  char *key;
  char *value;
  struct hashtab_entry_t *next;
} hashtab_entry_t;

unsigned long hash(char *str) {
  unsigned long hash = 5381;
  int c;

  while (c = *str++)
    hash = ((hash << 5) + hash) + c;

  return hash;
}

hashtab_entry_t **alloc_hashtab(void) {
  hashtab_entry_t **result = kmalloc(sizeof(hashtab_entry_t *) * HASHTAB_SIZE, GFP_KERNEL);
  int i;
  for (i = 0; i < HASHTAB_SIZE; i++)
    result[i] = NULL;
  return result;
}

void hashtab_put(hashtab_entry_t **hashtab, char *key, char *value) {
  hashtab_entry_t *entry = kmalloc(sizeof(hashtab_entry_t *), GFP_KERNEL);
  entry->key = key;
  entry->value = value;
  entry->next = NULL;

  unsigned long bucket = hash(key) % HASHTAB_SIZE;

  if (hashtab[bucket] == NULL)
    hashtab[bucket] = entry;
  else {
    hashtab_entry_t *p = hashtab[bucket];
    while (p->next != NULL)
      p = p->next;
    p->next = entry;
  }
}

hashtab_entry_t *hashtab_get(hashtab_entry_t **hashtab, char *key) {
  unsigned long bucket = hash(key) % HASHTAB_SIZE;

  if (hashtab[bucket] == NULL)
    return NULL;

  hashtab_entry_t *p = hashtab[bucket];

  while (strcmp(p->key, key))
    if (p->next == NULL)
      return NULL;
    else
      p = p->next;

  return p;
}

#endif
