#ifndef HASHMAP_H
#define HASHMAP_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define TABLE_SIZE 10000
#define EMPTY_KEY -1

// Define structure for hash table entries
typedef struct {
    int key;
    int value;
    bool occupied;
} Entry;

// Define structure for hash table
typedef struct {
    Entry table[TABLE_SIZE];
} HashMap;

// Function prototypes
void initHashMap(HashMap *map);
void insert_key(HashMap *map, int key, int value);
int search_key(HashMap *map, int key, int *value);
void delete_key(HashMap *map, int key);
unsigned int myhash(int key);

#endif // HASHMAP_H
