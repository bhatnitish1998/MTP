// hashmap.c
#include "hashmap.h"

// Hash function (FNV-1a hash)
unsigned int myhash(int key) {
    return key % TABLE_SIZE;
}

// Initialize the hash table
void initHashMap(HashMap *map) {
    for (int i = 0; i < TABLE_SIZE; i++) {
        map->table[i].occupied = false;
        map->table[i].key = EMPTY_KEY;
    }
}

// Insert key-value pair into the hash table using linear probing
void insert_key(HashMap *map, int key, int value) {
    unsigned int index = myhash(key);
    while (map->table[index].occupied) {
        if (map->table[index].key == key) {
            map->table[index].value = value; // Update existing key
            return;
        }
        index = (index + 1) % TABLE_SIZE; // Linear probing
    }
    map->table[index].key = key;
    map->table[index].value = value;
    map->table[index].occupied = true;
}

// Search for a key in the hash table
int search_key(HashMap *map, int key, int *value) {
    unsigned int index = myhash(key);
    while (map->table[index].occupied) {
        if (map->table[index].key == key) {
            *value = map->table[index].value;
            return 1;
        }
        index = (index + 1) % TABLE_SIZE; // Linear probing
    }
    return 0;
}

// Delete a key from the hash table
void delete_key(HashMap *map, int key) {
    unsigned int index = myhash(key);
    while (map->table[index].occupied) {
        if (map->table[index].key == key) {
            map->table[index].occupied = false;
            map->table[index].key = EMPTY_KEY;
            return;
        }
        index = (index + 1) % TABLE_SIZE; // Linear probing
    }
}
