// index.c — Staging area implementation

#include "index.h"
#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

// Forward declarations for functions in object.c
extern int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);
extern int hex_to_hash(const char *hex, ObjectID *id_out);
extern void hash_to_hex(const ObjectID *id, char *hex_out);

// ─── PROVIDED ────────────────────────────────────────────────────────────────

// Find an index entry by path (linear scan).
IndexEntry* index_find(Index *index, const char *path) {
    for (int i = 0; i < index->count; i++) {
        if (strcmp(index->entries[i].path, path) == 0)
            return &index->entries[i];
    }
    return NULL;
}

// Remove a file from the index.
int index_remove(Index *index, const char *path) {
    for (int i = 0; i < index->count; i++) {
        if (strcmp(index->entries[i].path, path) == 0) {
            int remaining = index->count - i - 1;
            if (remaining > 0)
                memmove(&index->entries[i], &index->entries[i + 1],
                        remaining * sizeof(IndexEntry));
            index->count--;
            return index_save(index);
        }
    }
    fprintf(stderr, "error: '%s' is not in the index\n", path);
    return -1;
}

// Print the status of the working directory.
int index_status(const Index *index) {
    printf("Staged changes:\n");
    int staged_count = 0;
    for (int i = 0; i < index->count; i++) {
        printf("  staged:     %s\n", index->entries[i].path);
        staged_count++;
    }
    if (staged_count == 0) printf("  (nothing to show)\n");
    printf("\n");

    printf("Unstaged changes:\n");
    int unstaged_count = 0;
    for (int i = 0; i < index->count; i++) {
        struct stat st;
        if (stat(index->entries[i].path, &st) != 0) {
            printf("  deleted:    %s\n", index->entries[i].path);
            unstaged_count++;
        } else {
            if (st.st_mtime != (time_t)index->entries[i].mtime_sec || st.st_size != (off_t)index->entries[i].size) {
                printf("  modified:   %s\n", index->entries[i].path);
                unstaged_count++;
            }
        }
    }
    if (unstaged_count == 0) printf("  (nothing to show)\n");
    printf("\n");

    printf("Untracked files:\n");
    int untracked_count = 0;
    DIR *dir = opendir(".");
    if (dir) {
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
            if (strcmp(ent->d_name, ".pes") == 0) continue;
            if (strcmp(ent->d_name, "pes") == 0) continue;
            if (strstr(ent->d_name, ".o") != NULL) continue;

            int is_tracked = 0;
            for (int i = 0; i < index->count; i++) {
                if (strcmp(index->entries[i].path, ent->d_name) == 0) {
                    is_tracked = 1; 
                    break;
                }
            }
            
            if (!is_tracked) {
                struct stat st;
                stat(ent->d_name, &st);
                if (S_ISREG(st.st_mode)) {
                    printf("  untracked:  %s\n", ent->d_name);
                    untracked_count++;
                }
            }
        }
        closedir(dir);
    }
    if (untracked_count == 0) printf("  (nothing to show)\n");
    printf("\n");

    return 0;
}

// ─── IMPLEMENTED ─────────────────────────────────────────────────────────────

int index_load(Index *index) {
    index->count = 0;
    FILE *f = fopen(INDEX_FILE, "r");
    if (!f) return 0; // Empty/missing index is normal initially
    
    char line[1024];
    while (fgets(line, sizeof(line), f) && index->count < MAX_INDEX_ENTRIES) {
        IndexEntry *ent = &index->entries[index->count];
        char hex[65];
        
        // Fixed: Swapped %u to %lu for mtime_sec
        if (sscanf(line, "%o %64s %lu %u %[^\n]", 
                   &ent->mode, hex, &ent->mtime_sec, &ent->size, ent->path) == 5) {
            hex_to_hash(hex, &ent->hash);
            index->count++;
        }
    }
    fclose(f);
    return 0;
}

// Helper for qsort to alphabetize index by path
static int compare_index_entries(const void *a, const void *b) {
    return strcmp(((const IndexEntry *)a)->path, ((const IndexEntry *)b)->path);
}

int index_save(const Index *index) {
    // Fixed: Use malloc to prevent Stack Overflow from a massive struct
    Index *sorted_index = malloc(sizeof(Index));
    if (!sorted_index) return -1;
    
    *sorted_index = *index;
    qsort(sorted_index->entries, sorted_index->count, sizeof(IndexEntry), compare_index_entries);
    
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", INDEX_FILE);
    
    FILE *f = fopen(tmp_path, "w");
    if (!f) {
        free(sorted_index);
        return -1;
    }
    
    for (int i = 0; i < sorted_index->count; i++) {
        const IndexEntry *ent = &sorted_index->entries[i];
        char hex[65];
        hash_to_hex(&ent->hash, hex);
        // Fixed: Swapped %u to %lu for mtime_sec
        fprintf(f, "%o %s %lu %u %s\n", ent->mode, hex, ent->mtime_sec, ent->size, ent->path);
    }
    
    fflush(f);
    fsync(fileno(f));
    fclose(f);
    free(sorted_index); // Clean up heap memory
    
    return rename(tmp_path, INDEX_FILE);
}

int index_add(Index *index, const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) {
        fprintf(stderr, "error: could not stat '%s'\n", path);
        return -1;
    }
    
    // Read file contents
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    
    uint8_t *data = malloc(st.st_size);
    if (st.st_size > 0 && data) {
        if (fread(data, 1, st.st_size, f) != (size_t)st.st_size) {
            free(data);
            fclose(f);
            return -1;
        }
    }
    fclose(f);
    
    // Create blob in object store
    ObjectID blob_id;
    if (object_write(OBJ_BLOB, data, st.st_size, &blob_id) != 0) {
        free(data);
        return -1;
    }
    free(data);
    
    // Create or update index entry
    IndexEntry *ent = index_find(index, path);
    if (!ent) {
        if (index->count >= MAX_INDEX_ENTRIES) return -1;
        ent = &index->entries[index->count++];
        strncpy(ent->path, path, sizeof(ent->path) - 1);
        ent->path[sizeof(ent->path) - 1] = '\0';
    }
    
    ent->mode = S_ISDIR(st.st_mode) ? 0040000 : (st.st_mode & S_IXUSR ? 0100755 : 0100644);
    ent->hash = blob_id;
    ent->mtime_sec = st.st_mtime;
    ent->size = st.st_size;
    
    return index_save(index);
}
