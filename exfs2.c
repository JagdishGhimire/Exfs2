#include "exfs2.h"

// --- Global Variables ---
// These track the highest index segment files that *might* exist.
// They should be updated when new segments are created.
// A more robust approach might scan for existing segments on startup.
int next_inode_segment_idx = 0;
int next_data_segment_idx = 0;

// --- Helper Functions ---

// Generate segment filename
void get_segment_filename(const char* prefix, int index, char* buffer, size_t buffer_size) {
    snprintf(buffer, buffer_size, "%s%d%s", prefix, index, SEGMENT_SUFFIX);
}

// Open/Create a segment file
FILE* open_segment(const char* prefix, int index, const char* mode) {
    char filename[100];
    get_segment_filename(prefix, index, filename, sizeof(filename));
    FILE *fp = fopen(filename, mode);
    if (!fp && (mode[0] == 'r' && mode[1] == 'b' && mode[2] == '+')) { // If fopen with "rb+" fails, try creating it
         fp = fopen(filename, "wb+"); // Try creating
         if (fp) {
            // Initialize if newly created (specific initialization in create_*)
            if (ftruncate(fileno(fp), SEGMENT_SIZE) != 0) {
                 perror("Failed to set segment size");
                 fclose(fp);
                 return NULL;
            }
            rewind(fp);
         }
    }
     if (!fp) {
         fprintf(stderr, "Error opening/creating segment %s: %s\n", filename, strerror(errno));
     }
    return fp;
}

// Create and initialize a new inode segment
int create_inode_segment(int index) {
    FILE *fp = open_segment(INODE_SEGMENT_PREFIX, index, "wb+"); // Create or overwrite
    if (!fp) return -1;

    // Write initial empty bitmap (all zeros = free)
    uint8_t bitmap[INODE_BITMAP_SIZE] = {0};
    if (fwrite(bitmap, 1, INODE_BITMAP_SIZE, fp) != INODE_BITMAP_SIZE) {
        perror("Failed to write inode bitmap");
        fclose(fp);
        return -1;
    }

    // The rest of the file is implicitly zeroed by ftruncate in open_segment

    printf("Created inode segment %d\n", index);
    fclose(fp);
    if (index >= next_inode_segment_idx) {
        next_inode_segment_idx = index + 1;
    }
    return 0;
}

// Create and initialize a new data segment
int create_data_segment(int index) {
    FILE *fp = open_segment(DATA_SEGMENT_PREFIX, index, "wb+"); // Create or overwrite
    if (!fp) return -1;

    // Write initial empty bitmap (all zeros = free)
    uint8_t bitmap[DATA_BITMAP_SIZE] = {0};
    if (fwrite(bitmap, 1, DATA_BITMAP_SIZE, fp) != DATA_BITMAP_SIZE) {
        perror("Failed to write data bitmap");
        fclose(fp);
        return -1;
    }

    // The rest implicitly zeroed
    printf("Created data segment %d\n", index);
    fclose(fp);
     if (index >= next_data_segment_idx) {
        next_data_segment_idx = index + 1;
    }
    return 0;
}

// --- Bitmap Operations ---
int get_bit(const uint8_t *bitmap, uint32_t index) {
    return (bitmap[index / 8] >> (index % 8)) & 1;
}

void set_bit(uint8_t *bitmap, uint32_t index) {
    bitmap[index / 8] |= (1 << (index % 8));
}

void clear_bit(uint8_t *bitmap, uint32_t index) {
    bitmap[index / 8] &= ~(1 << (index % 8));
}


// --- Inode Operations ---

uint32_t find_free_inode() {
    for (int seg_idx = 0; seg_idx < next_inode_segment_idx; ++seg_idx) {
        FILE *fp = open_segment(INODE_SEGMENT_PREFIX, seg_idx, "rb+");
        if (!fp) continue; // Try next segment

        uint8_t bitmap[INODE_BITMAP_SIZE];
        if (fread(bitmap, 1, INODE_BITMAP_SIZE, fp) != INODE_BITMAP_SIZE) {
            perror("Failed to read inode bitmap");
            fclose(fp);
            continue;
        }

        for (uint32_t local_idx = 0; local_idx < MAX_INODES_PER_SEGMENT; ++local_idx) {
            if (!get_bit(bitmap, local_idx)) {
                set_bit(bitmap, local_idx);
                // Write bitmap back
                rewind(fp);
                if (fwrite(bitmap, 1, INODE_BITMAP_SIZE, fp) != INODE_BITMAP_SIZE) {
                    perror("Failed to write updated inode bitmap");
                    // Rollback? Error out? For now, just report error
                    clear_bit(bitmap, local_idx); // Attempt rollback of in-memory bitmap
                    fclose(fp);
                    return UINT32_MAX; // Indicate error
                }
                fclose(fp);
                return (uint32_t)seg_idx * MAX_INODES_PER_SEGMENT + local_idx;
            }
        }
        fclose(fp);
    }

    // No free inode found in existing segments, create a new one
    if (create_inode_segment(next_inode_segment_idx) == 0) {
        // The first inode (index 0) in the new segment is free
         FILE *fp = open_segment(INODE_SEGMENT_PREFIX, next_inode_segment_idx -1 , "rb+"); // Open the newly created one
         if (!fp) return UINT32_MAX;

         uint8_t bitmap[INODE_BITMAP_SIZE];
         fread(bitmap, 1, INODE_BITMAP_SIZE, fp); // Read the bitmap (should be zeroed)
         set_bit(bitmap, 0); // Set first bit
         rewind(fp);
         fwrite(bitmap, 1, INODE_BITMAP_SIZE, fp); // Write back
         fclose(fp);

         return (uint32_t)(next_inode_segment_idx - 1) * MAX_INODES_PER_SEGMENT + 0;

    } else {
        fprintf(stderr, "Failed to create new inode segment.\n");
        return UINT32_MAX; // Indicate error
    }
}


int read_inode(uint32_t inode_num, Inode *inode_buffer) {
    uint32_t seg_idx = inode_num / MAX_INODES_PER_SEGMENT;
    uint32_t local_idx = inode_num % MAX_INODES_PER_SEGMENT;
    long offset = (long)INODE_BITMAP_SIZE + (long)local_idx * INODE_SIZE;

    FILE *fp = open_segment(INODE_SEGMENT_PREFIX, seg_idx, "rb");
    if (!fp) return -1;

    if (fseek(fp, offset, SEEK_SET) != 0) {
        perror("Failed to seek to inode");
        fclose(fp);
        return -1;
    }

    if (fread(inode_buffer, sizeof(Inode), 1, fp) != 1) {
        // Check for EOF specifically, might just be an uninitialized part
        if(feof(fp)) {
             fprintf(stderr, "Warning: Read inode %u reached EOF (possibly uninitialized).\n", inode_num);
             memset(inode_buffer, 0, sizeof(Inode)); // Return zeroed inode
        } else {
            perror("Failed to read inode");
            fclose(fp);
            return -1;
        }
    }

    fclose(fp);
    return 0;
}

int write_inode(uint32_t inode_num, const Inode *inode_buffer) {
    uint32_t seg_idx = inode_num / MAX_INODES_PER_SEGMENT;
    uint32_t local_idx = inode_num % MAX_INODES_PER_SEGMENT;
    long offset = (long)INODE_BITMAP_SIZE + (long)local_idx * INODE_SIZE;

    FILE *fp = open_segment(INODE_SEGMENT_PREFIX, seg_idx, "rb+"); // Need write access
    if (!fp) return -1;

    if (fseek(fp, offset, SEEK_SET) != 0) {
        perror("Failed to seek to inode location for writing");
        fclose(fp);
        return -1;
    }

    if (fwrite(inode_buffer, sizeof(Inode), 1, fp) != 1) {
        perror("Failed to write inode");
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

void free_inode(uint32_t inode_num) {
    uint32_t seg_idx = inode_num / MAX_INODES_PER_SEGMENT;
    uint32_t local_idx = inode_num % MAX_INODES_PER_SEGMENT;

    FILE *fp = open_segment(INODE_SEGMENT_PREFIX, seg_idx, "rb+");
    if (!fp) {
        fprintf(stderr, "Error opening inode segment %d to free inode %u\n", seg_idx, inode_num);
        return;
    }

    uint8_t bitmap[INODE_BITMAP_SIZE];
     if (fread(bitmap, 1, INODE_BITMAP_SIZE, fp) != INODE_BITMAP_SIZE) {
        perror("Failed to read inode bitmap for freeing");
        fclose(fp);
        return;
     }

     if (get_bit(bitmap, local_idx)) {
        clear_bit(bitmap, local_idx);
        rewind(fp);
        if (fwrite(bitmap, 1, INODE_BITMAP_SIZE, fp) != INODE_BITMAP_SIZE) {
            perror("Failed to write updated inode bitmap after freeing");
            // Decide how to handle this error - the inode might be logically free
            // but the bitmap update failed.
        } else {
            printf("Freed inode %u\n", inode_num);
        }
     } else {
         fprintf(stderr, "Warning: Attempted to free already free inode %u\n", inode_num);
     }

    fclose(fp);
    // Note: This function only frees the inode number. The caller is responsible
    // for freeing the data blocks associated with the inode *before* calling this.
}


// --- Data Block Operations ---

uint32_t find_free_data_block() {
    for (int seg_idx = 0; seg_idx < next_data_segment_idx; ++seg_idx) {
        FILE *fp = open_segment(DATA_SEGMENT_PREFIX, seg_idx, "rb+");
        if (!fp) continue;

        uint8_t bitmap[DATA_BITMAP_SIZE];
        if (fread(bitmap, 1, DATA_BITMAP_SIZE, fp) != DATA_BITMAP_SIZE) {
             perror("Failed to read data bitmap");
             fclose(fp);
             continue;
        }

        for (uint32_t local_idx = 0; local_idx < MAX_BLOCKS_PER_DATA_SEGMENT; ++local_idx) {
            if (!get_bit(bitmap, local_idx)) {
                set_bit(bitmap, local_idx);
                rewind(fp);
                if (fwrite(bitmap, 1, DATA_BITMAP_SIZE, fp) != DATA_BITMAP_SIZE) {
                    perror("Failed to write updated data bitmap");
                    clear_bit(bitmap, local_idx); // Rollback in-memory
                    fclose(fp);
                    return UINT32_MAX; // Error
                }
                fclose(fp);
                return (uint32_t)seg_idx * MAX_BLOCKS_PER_DATA_SEGMENT + local_idx;
            }
        }
        fclose(fp);
    }

    // No free block found, create a new data segment
    if (create_data_segment(next_data_segment_idx) == 0) {
         FILE *fp = open_segment(DATA_SEGMENT_PREFIX, next_data_segment_idx - 1, "rb+");
         if (!fp) return UINT32_MAX;

         uint8_t bitmap[DATA_BITMAP_SIZE];
         fread(bitmap, 1, DATA_BITMAP_SIZE, fp);
         set_bit(bitmap, 0); // Allocate first block
         rewind(fp);
         fwrite(bitmap, 1, DATA_BITMAP_SIZE, fp);
         fclose(fp);

         return (uint32_t)(next_data_segment_idx - 1) * MAX_BLOCKS_PER_DATA_SEGMENT + 0;

    } else {
        fprintf(stderr, "Failed to create new data segment.\n");
        return UINT32_MAX; // Error
    }
}

int read_data_block(uint32_t block_num, char *buffer) {
    uint32_t seg_idx = block_num / MAX_BLOCKS_PER_DATA_SEGMENT;
    uint32_t local_idx = block_num % MAX_BLOCKS_PER_DATA_SEGMENT;
    long offset = (long)DATA_AREA_OFFSET + (long)local_idx * BLOCK_SIZE;

    FILE *fp = open_segment(DATA_SEGMENT_PREFIX, seg_idx, "rb");
    if (!fp) return -1;

     if (fseek(fp, offset, SEEK_SET) != 0) {
        perror("Failed to seek to data block");
        fclose(fp);
        return -1;
    }

    if (fread(buffer, 1, BLOCK_SIZE, fp) != BLOCK_SIZE) {
         if(feof(fp)) {
            // This might happen if reading past the allocated part of the last segment
            // Or reading an uninitialized block. Treat as zeros for safety.
            fprintf(stderr, "Warning: Read data block %u reached EOF or short read.\n", block_num);
            memset(buffer, 0, BLOCK_SIZE);
         } else {
            perror("Failed to read data block");
            fclose(fp);
            return -1;
         }
    }

    fclose(fp);
    return 0;
}

int write_data_block(uint32_t block_num, const char *buffer) {
    uint32_t seg_idx = block_num / MAX_BLOCKS_PER_DATA_SEGMENT;
    uint32_t local_idx = block_num % MAX_BLOCKS_PER_DATA_SEGMENT;
    long offset = (long)DATA_AREA_OFFSET + (long)local_idx * BLOCK_SIZE;

    FILE *fp = open_segment(DATA_SEGMENT_PREFIX, seg_idx, "rb+");
    if (!fp) return -1;

    if (fseek(fp, offset, SEEK_SET) != 0) {
        perror("Failed to seek to data block location for writing");
        fclose(fp);
        return -1;
    }

    if (fwrite(buffer, 1, BLOCK_SIZE, fp) != BLOCK_SIZE) {
        perror("Failed to write data block");
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

void free_data_block(uint32_t block_num) {
     if (block_num == UINT32_MAX || block_num == 0) { // Block 0 often special (e.g., root dir) - double check logic if freeing root block is needed/allowed
         fprintf(stderr, "Warning: Attempt to free invalid block number %u\n", block_num);
         return;
     }

    uint32_t seg_idx = block_num / MAX_BLOCKS_PER_DATA_SEGMENT;
    uint32_t local_idx = block_num % MAX_BLOCKS_PER_DATA_SEGMENT;

    FILE *fp = open_segment(DATA_SEGMENT_PREFIX, seg_idx, "rb+");
    if (!fp) {
         fprintf(stderr, "Error opening data segment %d to free block %u\n", seg_idx, block_num);
         return;
     }

    uint8_t bitmap[DATA_BITMAP_SIZE];
     if (fread(bitmap, 1, DATA_BITMAP_SIZE, fp) != DATA_BITMAP_SIZE) {
         perror("Failed to read data bitmap for freeing");
         fclose(fp);
         return;
     }

     if (get_bit(bitmap, local_idx)) {
         clear_bit(bitmap, local_idx);
         rewind(fp);
         if (fwrite(bitmap, 1, DATA_BITMAP_SIZE, fp) != DATA_BITMAP_SIZE) {
             perror("Failed to write updated data bitmap after freeing block");
             // Handle error - block might be logically free but bitmap update failed
         } else {
              // Optional: Can add debug printf("Freed data block %u\n", block_num);
         }
     } else {
         fprintf(stderr, "Warning: Attempted to free already free data block %u\n", block_num);
     }

    fclose(fp);
}

// Recursive helper to free indirect blocks
void free_indirect_blocks(uint32_t block_num, int level) {
    if (block_num == 0 || level < 0) {
        return;
    }

    uint32_t pointers[POINTERS_PER_BLOCK];
    char block_buffer[BLOCK_SIZE];

    if (read_data_block(block_num, block_buffer) != 0) {
        fprintf(stderr, "Error reading indirect block %u for freeing\n", block_num);
        return; // Cannot proceed
    }
    memcpy(pointers, block_buffer, BLOCK_SIZE); // Copy buffer content to pointer array

    for (int i = 0; i < POINTERS_PER_BLOCK; ++i) {
        if (pointers[i] != 0) {
            if (level == 0) { // These are direct data blocks
                free_data_block(pointers[i]);
            } else { // These are further indirect blocks
                free_indirect_blocks(pointers[i], level - 1);
            }
        }
    }
    // After freeing all pointed-to blocks, free this indirect block itself
    free_data_block(block_num);
}


// --- Path and Directory Operations ---

// Parses path like "/a/b/c", finds inode for 'c', returns parent ('b') inode_num.
// Sets *target_inode_num to the inode of the final component if found.
// Sets *target_name to the final component name (e.g., "c").
// Returns 0 on success, -1 on error (e.g., path component not found).
int parse_path(const char *path, uint32_t *parent_inode_num, uint32_t *target_inode_num, char *target_name) {
    if (path == NULL || path[0] != '/') {
        fprintf(stderr, "Invalid path format. Must start with '/'.\n");
        return -1;
    }

    uint32_t current_inode_num = 0; // Start at root (inode 0)
    *parent_inode_num = 0; // Default parent is root
    *target_inode_num = UINT32_MAX; // Not found yet

    char path_copy[PATH_MAX]; // Use PATH_MAX or similar limit
    strncpy(path_copy, path, PATH_MAX - 1);
    path_copy[PATH_MAX - 1] = '\0';

    char *token;
    char *rest = path_copy;
    char *last_token = NULL;

    // Skip leading '/'
    if (rest[0] == '/') rest++;
    if (strlen(rest) == 0) { // Path is just "/"
        *target_inode_num = 0;
        target_name[0] = '/'; // Special case representation
        target_name[1] = '\0';
        *parent_inode_num = 0; // Root's parent is itself conceptually for this function
        return 0;
    }


    while ((token = strtok_r(rest, "/", &rest))) {
        if (last_token) { // We have processed at least one component before this one
             uint32_t found_inode;
             if (find_entry_in_dir(current_inode_num, last_token, &found_inode) != 0) {
                 fprintf(stderr, "Path component '%s' not found in directory inode %u\n", last_token, current_inode_num);
                 return -1; // Component not found
             }
             Inode temp_inode;
             if (read_inode(found_inode, &temp_inode) != 0) {
                 fprintf(stderr, "Failed to read inode %u for path component '%s'\n", found_inode, last_token);
                 return -1;
             }
             if (!temp_inode.is_directory) {
                 fprintf(stderr, "Path component '%s' is not a directory.\n", last_token);
                 return -1;
             }
             *parent_inode_num = current_inode_num; // Update parent
             current_inode_num = found_inode; // Move to the found directory
        }
         last_token = token; // Current token becomes last_token for the next iteration (or the final target)
    }


    if (last_token) {
        strncpy(target_name, last_token, MAX_FILENAME_LEN);
        target_name[MAX_FILENAME_LEN] = '\0'; // Ensure null termination

        // Check if the final component exists in the final directory (current_inode_num)
        uint32_t final_inode;
        if (find_entry_in_dir(current_inode_num, target_name, &final_inode) == 0) {
            *target_inode_num = final_inode; // Found it
        } else {
            *target_inode_num = UINT32_MAX; // Not found
             // It's okay if it's not found during 'add' operation, but indicates error for 'remove', 'list', 'extract'
        }
        *parent_inode_num = current_inode_num; // The directory where target_name should reside (or does reside)
        return 0; // Success in parsing, target_inode_num indicates if it exists
    } else {
        // This case should technically be handled by the "/" check earlier
        fprintf(stderr, "Error parsing path.\n");
        return -1;
    }
}


// Searches directory data blocks for an entry. Returns 0 and sets entry_inode_num if found.
int find_entry_in_dir(uint32_t dir_inode_num, const char *name, uint32_t *entry_inode_num) {
    Inode dir_inode;
    if (read_inode(dir_inode_num, &dir_inode) != 0 || !dir_inode.is_directory) {
        fprintf(stderr, "Cannot search: Inode %u is not a valid directory.\n", dir_inode_num);
        return -1;
    }

    char block_buffer[BLOCK_SIZE];
    DirectoryEntry *entries = (DirectoryEntry *)block_buffer;
    size_t entries_searched = 0;
    size_t total_entries = dir_inode.size; // Inode size for dir stores number of entries

    // TODO: Iterate through direct, single, double, triple blocks of the directory inode
    // This simplified version only checks direct blocks for brevity.
    // A full implementation needs get_block_for_offset logic here.

    for (int i = 0; i < MAX_DIRECT_POINTERS && entries_searched < total_entries; ++i) {
        uint32_t block_num = dir_inode.direct_blocks[i];
        if (block_num == 0) continue; // Skip unused pointers

        if (read_data_block(block_num, block_buffer) != 0) {
            fprintf(stderr, "Error reading directory data block %u\n", block_num);
            continue; // Skip this block
        }

        for (int j = 0; j < DIRENTRIES_PER_BLOCK && entries_searched < total_entries; ++j) {
             entries_searched++;
             if (entries[j].inode_num != 0 && // Check if entry is valid
                 strncmp(entries[j].name, name, MAX_FILENAME_LEN) == 0)
             {
                 *entry_inode_num = entries[j].inode_num;
                 return 0; // Found
             }
        }
    }
    // If not found in direct blocks, continue search into single, double, triple indirect blocks...
    // ... (Implementation needed) ...

    return -1; // Not found
}

// Adds a directory entry. May need to allocate new data block for the directory.
int add_entry_to_dir(uint32_t dir_inode_num, const char *name, uint32_t entry_inode_num) {
    Inode dir_inode;
    if (read_inode(dir_inode_num, &dir_inode) != 0 || !dir_inode.is_directory) {
        fprintf(stderr, "Cannot add entry: Inode %u is not a valid directory.\n", dir_inode_num);
        return -1;
    }

     if (strlen(name) > MAX_FILENAME_LEN) {
         fprintf(stderr, "Error: Filename '%s' is too long (max %d chars).\n", name, MAX_FILENAME_LEN);
         return -1;
     }

    char block_buffer[BLOCK_SIZE];
    DirectoryEntry *entries = (DirectoryEntry *)block_buffer;
    size_t entries_searched = 0;
    size_t total_entries = dir_inode.size;
    int found_slot = 0;
    uint32_t target_block_num = 0;
    int target_entry_index = -1;

    // --- Phase 1: Find an empty slot in existing blocks ---
    // TODO: Iterate through direct, single, double, triple blocks
    // Simplified: check direct blocks only
    for (int i = 0; i < MAX_DIRECT_POINTERS; ++i) {
        uint32_t block_num = dir_inode.direct_blocks[i];
        if (block_num == 0) { // Potential block to allocate if needed later
             if (target_block_num == 0) target_block_num = i; // Mark potential direct pointer index
             continue;
        }

        if (read_data_block(block_num, block_buffer) != 0) continue;

        for (int j = 0; j < DIRENTRIES_PER_BLOCK; ++j) {
             if (entries_searched < total_entries) {
                 entries_searched++; // Count existing valid entries
             }
             if (entries[j].inode_num == 0) { // Found an empty slot
                 target_block_num = block_num;
                 target_entry_index = j;
                 found_slot = 1;
                 goto slot_found; // Exit loops
             }
        }
        if (found_slot) break; // Should be caught by goto, but for safety
    }
     // ... Add logic for indirect blocks search here ...


slot_found:
    // --- Phase 2: Handle slot finding result ---
    if (found_slot) {
        // Read the target block again (it might not be the last one read)
        if (read_data_block(target_block_num, block_buffer) != 0) {
            fprintf(stderr, "Error re-reading block %u to add entry.\n", target_block_num);
            return -1;
        }
        // Write the new entry
        strncpy(entries[target_entry_index].name, name, MAX_FILENAME_LEN);
        entries[target_entry_index].name[MAX_FILENAME_LEN] = '\0';
        entries[target_entry_index].inode_num = entry_inode_num;

        if (write_data_block(target_block_num, block_buffer) != 0) {
            fprintf(stderr, "Error writing updated directory block %u.\n", target_block_num);
            // Attempt to revert entry? Complicated.
            return -1;
        }
        // If the slot was previously unused (beyond total_entries), increment size
         if ((size_t)((target_block_num / BLOCK_SIZE) * DIRENTRIES_PER_BLOCK + target_entry_index) >= total_entries) {
             dir_inode.size++;
             if (write_inode(dir_inode_num, &dir_inode) != 0) {
                 fprintf(stderr, "Error updating directory inode %u size after adding entry.\n", dir_inode_num);
                 // Inconsistency!
             }
         }
        printf("Added entry '%s' -> %u in dir inode %u (used existing slot)\n", name, entry_inode_num, dir_inode_num);
        return 0; // Success

    } else {
        // --- Phase 3: Allocate a new block if no slot found ---
        printf("No free slot found in directory %u, allocating new block.\n", dir_inode_num);
        uint32_t new_block = find_free_data_block();
        if (new_block == UINT32_MAX) {
            fprintf(stderr, "Failed to allocate new data block for directory %u.\n", dir_inode_num);
            return -1;
        }

        // Find where to store the pointer to the new block
        // TODO: Check direct pointers first, then single indirect, etc.
        // Simplified: Check direct pointers
        int pointer_stored = 0;
        for (int i = 0; i < MAX_DIRECT_POINTERS; ++i) {
             if (dir_inode.direct_blocks[i] == 0) {
                 dir_inode.direct_blocks[i] = new_block;
                 pointer_stored = 1;
                 break;
             }
        }
        // ... Add logic to store in indirect blocks if direct are full ...

        if (!pointer_stored) {
            fprintf(stderr, "Directory inode %u is full (no place to store new block pointer).\n", dir_inode_num);
            free_data_block(new_block); // Free the allocated block
            return -1;
        }

        // Initialize the new block (all entries except the first are empty)
        memset(block_buffer, 0, BLOCK_SIZE);
        strncpy(entries[0].name, name, MAX_FILENAME_LEN);
        entries[0].name[MAX_FILENAME_LEN] = '\0';
        entries[0].inode_num = entry_inode_num;

        if (write_data_block(new_block, block_buffer) != 0) {
            fprintf(stderr, "Error writing newly allocated directory block %u.\n", new_block);
            // Revert inode pointer? Free block?
             free_data_block(new_block);
            // Find and clear the pointer in dir_inode (tricky if indirect was used)
            // For simplicity here, we might leave a dangling pointer in the inode on error.
            return -1;
        }

        // Update directory inode size and write it back
        dir_inode.size++;
        if (write_inode(dir_inode_num, &dir_inode) != 0) {
            fprintf(stderr, "Error updating directory inode %u after allocating new block.\n", dir_inode_num);
            // Inconsistency!
            return -1;
        }

        printf("Added entry '%s' -> %u in dir inode %u (allocated new block %u)\n", name, entry_inode_num, dir_inode_num, new_block);
        return 0; // Success
    }
}


// Removes entry by setting its inode number to 0. Does not compact directory file.
int remove_entry_from_dir(uint32_t dir_inode_num, const char *name) {
    Inode dir_inode;
    if (read_inode(dir_inode_num, &dir_inode) != 0 || !dir_inode.is_directory) {
        fprintf(stderr, "Cannot remove entry: Inode %u is not a valid directory.\n", dir_inode_num);
        return -1;
    }

    char block_buffer[BLOCK_SIZE];
    DirectoryEntry *entries = (DirectoryEntry *)block_buffer;
    size_t entries_searched = 0;
    size_t total_entries = dir_inode.size;
    int found = 0;

    // TODO: Iterate through direct, single, double, triple blocks
    // Simplified: Check direct blocks only
    for (int i = 0; i < MAX_DIRECT_POINTERS && entries_searched < total_entries; ++i) {
        uint32_t block_num = dir_inode.direct_blocks[i];
        if (block_num == 0) continue;

        if (read_data_block(block_num, block_buffer) != 0) continue;

        for (int j = 0; j < DIRENTRIES_PER_BLOCK && entries_searched < total_entries; ++j) {
            entries_searched++;
            if (entries[j].inode_num != 0 && strncmp(entries[j].name, name, MAX_FILENAME_LEN) == 0) {
                // Found the entry, mark as invalid
                entries[j].inode_num = 0; // Mark as free/invalid
                memset(entries[j].name, 0, MAX_FILENAME_LEN + 1); // Clear name

                if (write_data_block(block_num, block_buffer) != 0) {
                    fprintf(stderr, "Error writing directory block %u after removing entry '%s'.\n", block_num, name);
                    // Entry might still appear if read before this failed write is fixed.
                    return -1; // Indicate error
                }

                // Optional: Could decrement dir_inode.size, but simple removal doesn't require it.
                // Compacting the directory or freeing empty blocks is more complex.
                printf("Removed entry '%s' from directory inode %u (marked slot as free).\n", name, dir_inode_num);
                found = 1;
                goto entry_removed; // Exit loops
            }
        }
        if (found) break;
    }
    // ... Add logic for indirect blocks search here ...

entry_removed:
    if (!found) {
        fprintf(stderr, "Entry '%s' not found in directory inode %u.\n", name, dir_inode_num);
        return -1; // Not found
    }

    // Optional: Check if the directory block is now empty and potentially free it
    // Requires reading the block again and checking all entries.
    // Also requires removing the block pointer from the inode (direct or indirect)
    // This adds significant complexity.

    return 0; // Success
}


// Creates a new directory with "." and ".." entries
uint32_t create_directory(uint32_t parent_inode_num, const char *name) {
     // 1. Allocate inode for the new directory
     uint32_t new_dir_inode_num = find_free_inode();
     if (new_dir_inode_num == UINT32_MAX) {
         fprintf(stderr, "Failed to allocate inode for new directory '%s'\n", name);
         return UINT32_MAX;
     }

     // 2. Allocate a data block for the new directory's entries
     uint32_t new_dir_data_block = find_free_data_block();
     if (new_dir_data_block == UINT32_MAX) {
         fprintf(stderr, "Failed to allocate data block for new directory '%s'\n", name);
         free_inode(new_dir_inode_num); // Rollback inode allocation
         return UINT32_MAX;
     }

     // 3. Initialize the new directory's inode
     Inode new_dir_inode;
     memset(&new_dir_inode, 0, sizeof(Inode));
     new_dir_inode.is_directory = 1;
     new_dir_inode.size = 2; // Starts with "." and ".." entries
     new_dir_inode.direct_blocks[0] = new_dir_data_block;
     // Initialize other fields (mode, etc.) if necessary
     // new_dir_inode.mode = S_IFDIR | 0755; // Example

     // 4. Initialize the new directory's data block with "." and ".."
     char block_buffer[BLOCK_SIZE];
     DirectoryEntry *entries = (DirectoryEntry *)block_buffer;
     memset(block_buffer, 0, BLOCK_SIZE);

     // Entry for "."
     strncpy(entries[0].name, ".", MAX_FILENAME_LEN);
     entries[0].inode_num = new_dir_inode_num; // Points to itself

     // Entry for ".."
     strncpy(entries[1].name, "..", MAX_FILENAME_LEN);
     entries[1].inode_num = parent_inode_num; // Points to parent

     // 5. Write the new inode and data block
     if (write_inode(new_dir_inode_num, &new_dir_inode) != 0) {
         fprintf(stderr, "Failed to write inode for new directory '%s'\n", name);
         free_data_block(new_dir_data_block);
         free_inode(new_dir_inode_num);
         return UINT32_MAX;
     }
     if (write_data_block(new_dir_data_block, block_buffer) != 0) {
         fprintf(stderr, "Failed to write data block for new directory '%s'\n", name);
         // Ideally, should attempt to clear the partially written inode, but tricky
         free_inode(new_dir_inode_num); // Free inode, block is already potentially corrupt
         return UINT32_MAX;
     }

     // 6. Add the entry for the new directory to its parent directory
     if (add_entry_to_dir(parent_inode_num, name, new_dir_inode_num) != 0) {
         fprintf(stderr, "Failed to add entry for new directory '%s' to parent inode %u\n", name, parent_inode_num);
         // Rollback: Remove the created directory (inode and data block)
         // This requires recursive freeing logic if the directory had contents (though it shouldn't yet)
         free_data_block(new_dir_data_block); // Free data block
         free_inode(new_dir_inode_num);       // Free inode
         return UINT32_MAX;
     }

     printf("Created directory '%s' (inode %u)\n", name, new_dir_inode_num);
     return new_dir_inode_num; // Success
}


// Helper to get the actual data block number for a given file offset
// Handles direct, single, double, triple indirect blocks.
// If allocate=1, allocates necessary blocks if they don't exist.
// Returns block number or UINT32_MAX on error/if block not allocated and allocate=0.
uint32_t get_block_for_offset(uint32_t inode_num, size_t offset, int allocate) {
    Inode inode;
    if (read_inode(inode_num, &inode) != 0) {
        fprintf(stderr, "get_block_for_offset: Failed to read inode %u\n", inode_num);
        return UINT32_MAX;
    }

    uint32_t block_index = offset / BLOCK_SIZE; // Which block in the file sequence (0, 1, 2...)

    // 1. Direct Blocks
    if (block_index < MAX_DIRECT_POINTERS) {
        if (inode.direct_blocks[block_index] == 0) {
            if (allocate) {
                uint32_t new_block = find_free_data_block();
                if (new_block == UINT32_MAX) return UINT32_MAX;
                inode.direct_blocks[block_index] = new_block;
                if (write_inode(inode_num, &inode) != 0) {
                     fprintf(stderr, "get_block_for_offset: Failed to write inode after allocating direct block\n");
                     free_data_block(new_block); // Try to rollback
                     return UINT32_MAX;
                }
                 return new_block;
            } else {
                return UINT32_MAX; // Not allocated
            }
        }
        return inode.direct_blocks[block_index];
    }

    // 2. Single Indirect
    block_index -= MAX_DIRECT_POINTERS;
    if (block_index < POINTERS_PER_BLOCK) {
        uint32_t single_indirect_block_num = inode.single_indirect;
        if (single_indirect_block_num == 0) {
            if (allocate) {
                 single_indirect_block_num = find_free_data_block();
                 if (single_indirect_block_num == UINT32_MAX) return UINT32_MAX;
                 // Zero out the new indirect block
                 char zero_buffer[BLOCK_SIZE] = {0};
                 if (write_data_block(single_indirect_block_num, zero_buffer) != 0) {
                     free_data_block(single_indirect_block_num);
                     return UINT32_MAX;
                 }
                 inode.single_indirect = single_indirect_block_num;
                 if (write_inode(inode_num, &inode) != 0) {
                     fprintf(stderr, "get_block_for_offset: Failed to write inode after allocating single indirect block\n");
                     free_data_block(single_indirect_block_num);
                     return UINT32_MAX;
                 }
            } else {
                return UINT32_MAX; // Not allocated
            }
        }

        // Read the single indirect block
        uint32_t pointers[POINTERS_PER_BLOCK];
        char indirect_block_buffer[BLOCK_SIZE];
        if(read_data_block(single_indirect_block_num, indirect_block_buffer) != 0) return UINT32_MAX;
        memcpy(pointers, indirect_block_buffer, BLOCK_SIZE);

        if (pointers[block_index] == 0) {
            if (allocate) {
                uint32_t new_block = find_free_data_block();
                if (new_block == UINT32_MAX) return UINT32_MAX;
                pointers[block_index] = new_block;
                 // Write the updated single indirect block back
                 memcpy(indirect_block_buffer, pointers, BLOCK_SIZE);
                 if (write_data_block(single_indirect_block_num, indirect_block_buffer) != 0) {
                     fprintf(stderr, "get_block_for_offset: Failed to write single indirect block after allocating data block\n");
                     free_data_block(new_block);
                     return UINT32_MAX;
                 }
                 return new_block;
            } else {
                return UINT32_MAX; // Not allocated
            }
        }
        return pointers[block_index];
    }

    // 3. Double Indirect
    block_index -= POINTERS_PER_BLOCK;
    if (block_index < POINTERS_PER_BLOCK * POINTERS_PER_BLOCK) {
        // --- Implementation similar to single indirect, but with two levels ---
        // a. Check/Allocate Double Indirect Block (pointed by inode.double_indirect)
        // b. Read Double Indirect Block
        // c. Calculate index into Double Indirect Block (block_index / POINTERS_PER_BLOCK)
        // d. Check/Allocate Single Indirect Block (pointed by entry in Double Indirect Block)
        // e. Read Single Indirect Block
        // f. Calculate index into Single Indirect Block (block_index % POINTERS_PER_BLOCK)
        // g. Check/Allocate Data Block (pointed by entry in Single Indirect Block)
        // h. Return Data Block number
        fprintf(stderr, "Double indirect blocks not fully implemented in get_block_for_offset.\n");
        return UINT32_MAX; // Placeholder
    }

    // 4. Triple Indirect
     block_index -= POINTERS_PER_BLOCK * POINTERS_PER_BLOCK;
     // Check if block_index is within the range of triple indirect block
     // --- Implementation similar to double indirect, but with three levels ---
     fprintf(stderr, "Triple indirect blocks not implemented in get_block_for_offset.\n");
     return UINT32_MAX; // Placeholder

    // Offset is beyond the maximum file size supported
    fprintf(stderr, "Offset %zu is beyond the maximum file size.\n", offset);
    return UINT32_MAX;
}


// --- Core File System Operations ---

// Recursive helper for listing
void list_recursive(uint32_t dir_inode_num, int depth, int debug_mode) {
    Inode dir_inode;
    if (read_inode(dir_inode_num, &dir_inode) != 0 || !dir_inode.is_directory) {
        return; // Should not happen if called correctly
    }

    char block_buffer[BLOCK_SIZE];
    DirectoryEntry *entries = (DirectoryEntry *)block_buffer;
    size_t entries_processed = 0;
    size_t total_entries = dir_inode.size; // Number of valid entries

    // Indentation
    for (int i = 0; i < depth; ++i) printf("  "); // 2 spaces per depth level

    // Print current directory being listed (requires getting its name from parent, complex)
    // Or just indicate inode number if debugging
    if (debug_mode) {
         printf("dir (inode %u, size %zu):\n", dir_inode_num, total_entries);
    } else {
         // How to get the name? Need to pass it down or look up in parent.
         // Simplified: just print based on depth
         printf("/\n"); // Placeholder name for root, need proper name handling
    }


    // TODO: Iterate through direct, single, double, triple blocks of the directory
    // Simplified: Direct blocks only
    for (int i = 0; i < MAX_DIRECT_POINTERS && entries_processed < total_entries; ++i) {
        uint32_t block_num = dir_inode.direct_blocks[i];
        if (block_num == 0) continue;

        if (read_data_block(block_num, block_buffer) != 0) continue;

        for (int j = 0; j < DIRENTRIES_PER_BLOCK && entries_processed < total_entries; ++j) {
            if (entries[j].inode_num != 0) { // If valid entry
                 entries_processed++;

                 // Indentation for entry
                 for (int k = 0; k < depth + 1; ++k) printf("  ");

                 if (debug_mode) {
                     printf("'%s' -> %u\n", entries[j].name, entries[j].inode_num);
                 } else {
                      printf("%s\n", entries[j].name);
                 }


                 // Recurse if it's a directory (and not "." or "..")
                 if (strcmp(entries[j].name, ".") != 0 && strcmp(entries[j].name, "..") != 0) {
                    Inode entry_inode;
                    if (read_inode(entries[j].inode_num, &entry_inode) == 0) {
                        if (entry_inode.is_directory) {
                            list_recursive(entries[j].inode_num, depth + 1, debug_mode);
                        } else if (debug_mode) {
                             // Optionally print file details in debug mode
                             for (int k = 0; k < depth + 2; ++k) printf("  ");
                             printf("(file, size %zu)\n", entry_inode.size);
                        }
                    }
                 }
            }
        }
    }
    // ... Add logic for indirect blocks here ...
}

void list_fs(const char *path, int debug_mode) {
    // For now, ignoring path and always listing from root.
    // A full implementation would parse path and start listing from there.
    if (strcmp(path, "/") != 0) {
        fprintf(stderr, "Warning: Listing currently only supported from root '/'. Ignoring path '%s'.\n", path);
    }
    printf("Listing filesystem contents%s:\n", debug_mode ? " (Debug Mode)" : "");
    list_recursive(0, 0, debug_mode); // Start recursion from root inode (0), depth 0
}

// Adds a local file to the ExFS2 path
void add_file_to_fs(const char *exfs_path, const char *local_path) {
    printf("Adding local file '%s' to exfs path '%s'\n", local_path, exfs_path);

    // 1. Open local file for reading
    FILE *local_fp = fopen(local_path, "rb");
    if (!local_fp) {
        perror("Failed to open local file for reading");
        return;
    }

    // 2. Parse ExFS path, create directories if they don't exist
    uint32_t parent_inode_num = 0; // Start search from root
    uint32_t target_inode_num = UINT32_MAX;
    char target_name[MAX_FILENAME_LEN + 1];
    char current_path[PATH_MAX] = ""; // Keep track of created path
    uint32_t current_dir_inode = 0; // Root

    char exfs_path_copy[PATH_MAX];
    strncpy(exfs_path_copy, exfs_path, PATH_MAX - 1);
    exfs_path_copy[PATH_MAX - 1] = '\0';

    char *token;
    char *rest = exfs_path_copy;
    if (rest[0] == '/') rest++;

    char *next_token = strtok_r(rest, "/", &rest);
    while (next_token != NULL) {
        char *current_token = next_token;
        next_token = strtok_r(rest, "/", &rest); // Peek ahead

        strncat(current_path, "/", PATH_MAX - strlen(current_path) -1);
        strncat(current_path, current_token, PATH_MAX - strlen(current_path) -1);


        uint32_t found_inode;
        if (find_entry_in_dir(current_dir_inode, current_token, &found_inode) != 0) {
            // Not found
            if (next_token != NULL) { // It's an intermediate directory that needs creation
                 printf("Directory '%s' not found, creating...\n", current_token);
                 uint32_t new_dir = create_directory(current_dir_inode, current_token);
                 if (new_dir == UINT32_MAX) {
                     fprintf(stderr, "Failed to create intermediate directory '%s'\n", current_token);
                     fclose(local_fp);
                     return;
                 }
                 current_dir_inode = new_dir; // Move into the new directory
            } else { // It's the final component (the file to be created)
                strncpy(target_name, current_token, MAX_FILENAME_LEN);
                target_name[MAX_FILENAME_LEN]='\0';
                parent_inode_num = current_dir_inode;
                target_inode_num = UINT32_MAX; // Mark as not existing yet
            }
        } else {
            // Found
             Inode temp_inode;
             if(read_inode(found_inode, &temp_inode) != 0) {
                 fprintf(stderr, "Error reading inode %u for '%s'\n", found_inode, current_token);
                 fclose(local_fp);
                 return;
             }

            if (next_token != NULL) { // Intermediate component must be a directory
                 if (!temp_inode.is_directory) {
                     fprintf(stderr, "Error: '%s' in path '%s' exists but is not a directory.\n", current_token, exfs_path);
                     fclose(local_fp);
                     return;
                 }
                 current_dir_inode = found_inode; // Move into existing directory
            } else { // Final component
                strncpy(target_name, current_token, MAX_FILENAME_LEN);
                 target_name[MAX_FILENAME_LEN]='\0';
                parent_inode_num = current_dir_inode;
                 target_inode_num = found_inode; // File/Dir already exists
                 fprintf(stderr, "Error: '%s' already exists at path '%s'. Remove it first.\n", target_name, exfs_path);
                 // Or implement overwrite logic if desired
                 fclose(local_fp);
                 return;
            }
        }
    } // End path parsing loop

     if (target_inode_num != UINT32_MAX) {
          fprintf(stderr, "Error: Target '%s' already exists.\n", exfs_path);
          fclose(local_fp);
          return;
     }


    // 3. Allocate inode for the new file
    uint32_t new_file_inode_num = find_free_inode();
    if (new_file_inode_num == UINT32_MAX) {
        fprintf(stderr, "Failed to allocate inode for file '%s'\n", target_name);
        fclose(local_fp);
        return;
    }

    // 4. Initialize file inode (size starts at 0)
    Inode new_file_inode;
    memset(&new_file_inode, 0, sizeof(Inode));
    new_file_inode.is_directory = 0;
    new_file_inode.size = 0;
    // new_file_inode.mode = S_IFREG | 0644; // Example permissions

    // 5. Read local file and write data to ExFS blocks
    char buffer[BLOCK_SIZE];
    size_t bytes_read;
    size_t total_bytes_written = 0;
    int error_occurred = 0;

    while ((bytes_read = fread(buffer, 1, BLOCK_SIZE, local_fp)) > 0) {
        uint32_t target_block = get_block_for_offset(new_file_inode_num, total_bytes_written, 1); // Allocate=1
        if (target_block == UINT32_MAX) {
            fprintf(stderr, "Failed to allocate/get data block for file '%s' at offset %zu\n", target_name, total_bytes_written);
            error_occurred = 1;
            break;
        }

        // If bytes_read < BLOCK_SIZE, zero out the rest of the buffer
        if (bytes_read < BLOCK_SIZE) {
            memset(buffer + bytes_read, 0, BLOCK_SIZE - bytes_read);
        }

        if (write_data_block(target_block, buffer) != 0) {
             fprintf(stderr, "Failed to write data block %u for file '%s'\n", target_block, target_name);
             error_occurred = 1;
             break;
        }
        total_bytes_written += bytes_read;
    } // End read/write loop

    fclose(local_fp); // Close local file regardless of ExFS write success

    // 6. Update file inode with final size and write it
    if (!error_occurred) {
        new_file_inode.size = total_bytes_written;
        if (write_inode(new_file_inode_num, &new_file_inode) != 0) {
            fprintf(stderr, "Failed to write final inode %u for file '%s'\n", new_file_inode_num, target_name);
            error_occurred = 1;
            // Data blocks are written, but inode is wrong/missing! Critical error.
        }
    }

    // 7. Add entry to parent directory
    if (!error_occurred) {
        if (add_entry_to_dir(parent_inode_num, target_name, new_file_inode_num) != 0) {
             fprintf(stderr, "Failed to add entry for file '%s' to parent directory %u\n", target_name, parent_inode_num);
             error_occurred = 1;
             // File data exists, inode exists, but not linked in directory! Orphaned.
        }
    }

    // 8. Cleanup on error
    if (error_occurred) {
        fprintf(stderr, "An error occurred during add operation. Attempting cleanup...\n");
        // Need to free allocated blocks and the inode. This requires iterating
        // through the potentially partially written inode's block pointers (direct/indirect)
        // and calling free_data_block / free_indirect_blocks.
        Inode cleanup_inode;
         if (read_inode(new_file_inode_num, &cleanup_inode) == 0) { // Read potentially partial inode
            // Free data blocks
            for(int i=0; i<MAX_DIRECT_POINTERS; ++i) free_data_block(cleanup_inode.direct_blocks[i]);
            free_indirect_blocks(cleanup_inode.single_indirect, 0);
            free_indirect_blocks(cleanup_inode.double_indirect, 1);
            free_indirect_blocks(cleanup_inode.triple_indirect, 2);
         }
        free_inode(new_file_inode_num); // Free the inode itself
        // We don't remove the entry from the parent dir here, as it likely wasn't added on error.
        fprintf(stderr, "Cleanup attempted for failed add of '%s'. Filesystem might be inconsistent.\n", exfs_path);
    } else {
        printf("Successfully added '%s' (inode %u, size %zu bytes)\n", exfs_path, new_file_inode_num, total_bytes_written);
    }
}


// Recursive remove helper
void remove_recursive(uint32_t inode_num, uint32_t parent_inode_num, const char* name) {
     Inode current_inode;
     if (read_inode(inode_num, &current_inode) != 0) {
         fprintf(stderr, "remove_recursive: Failed to read inode %u for '%s'\n", inode_num, name);
         return;
     }

     if (current_inode.is_directory) {
         printf("Removing directory '%s' (inode %u)\n", name, inode_num);
         char block_buffer[BLOCK_SIZE];
         DirectoryEntry *entries = (DirectoryEntry *)block_buffer;
         size_t entries_processed = 0;
         size_t total_entries = current_inode.size;

         // TODO: Iterate through ALL directory blocks (direct, indirect)
         // Simplified: Direct blocks only
         for (int i = 0; i < MAX_DIRECT_POINTERS && entries_processed < total_entries; ++i) {
             uint32_t block_num = current_inode.direct_blocks[i];
             if (block_num == 0) continue;

             if (read_data_block(block_num, block_buffer) != 0) continue;

             for (int j = 0; j < DIRENTRIES_PER_BLOCK && entries_processed < total_entries; ++j) {
                 if (entries[j].inode_num != 0) {
                     entries_processed++;
                     // Skip . and .. for recursion, handle them later
                     if (strcmp(entries[j].name, ".") != 0 && strcmp(entries[j].name, "..") != 0) {
                         remove_recursive(entries[j].inode_num, inode_num, entries[j].name); // Recurse
                     }
                 }
             }
         }
         // ... Add logic for indirect blocks iteration ...

          // After removing contents, free the directory's data blocks
          printf("Freeing data blocks for directory inode %u\n", inode_num);
          for(int i=0; i<MAX_DIRECT_POINTERS; ++i) free_data_block(current_inode.direct_blocks[i]);
          free_indirect_blocks(current_inode.single_indirect, 0);
          free_indirect_blocks(current_inode.double_indirect, 1);
          free_indirect_blocks(current_inode.triple_indirect, 2);

     } else {
          // It's a regular file
          printf("Removing file '%s' (inode %u)\n", name, inode_num);
          // Free the file's data blocks
           printf("Freeing data blocks for file inode %u\n", inode_num);
          for(int i=0; i<MAX_DIRECT_POINTERS; ++i) free_data_block(current_inode.direct_blocks[i]);
          free_indirect_blocks(current_inode.single_indirect, 0);
          free_indirect_blocks(current_inode.double_indirect, 1);
          free_indirect_blocks(current_inode.triple_indirect, 2);
     }

     // Remove entry from parent directory
     if (parent_inode_num != UINT32_MAX) { // Don't remove root from root
          printf("Removing entry '%s' from parent directory inode %u\n", name, parent_inode_num);
         if(remove_entry_from_dir(parent_inode_num, name) != 0){
             fprintf(stderr, "Warning: Failed to remove entry '%s' from parent %u during cleanup.\n", name, parent_inode_num);
         }
     }

     // Free the inode itself
     printf("Freeing inode %u\n", inode_num);
     free_inode(inode_num);
}


// Removes a file or directory (recursively)
void remove_from_fs(const char *exfs_path) {
    printf("Removing '%s'\n", exfs_path);

    uint32_t parent_inode_num = UINT32_MAX;
    uint32_t target_inode_num = UINT32_MAX;
    char target_name[MAX_FILENAME_LEN + 1];

    if (strcmp(exfs_path, "/") == 0) {
        fprintf(stderr, "Error: Cannot remove root directory '/'.\n");
        return;
    }

    if (parse_path(exfs_path, &parent_inode_num, &target_inode_num, target_name) != 0) {
        // Error message already printed by parse_path if path is invalid
        return;
    }

    if (target_inode_num == UINT32_MAX) {
        fprintf(stderr, "Error: '%s' not found.\n", exfs_path);
        return;
    }

    // Start recursive removal
    remove_recursive(target_inode_num, parent_inode_num, target_name);

    printf("Removal process for '%s' complete.\n", exfs_path);
}

// Extracts a file's content to stdout
void extract_file_from_fs(const char *exfs_path) {
    printf("Extracting '%s' to stdout\n", exfs_path);

    uint32_t parent_inode_num = UINT32_MAX;
    uint32_t target_inode_num = UINT32_MAX;
    char target_name[MAX_FILENAME_LEN + 1];

    if (parse_path(exfs_path, &parent_inode_num, &target_inode_num, target_name) != 0) {
        return; // Error in path
    }

    if (target_inode_num == UINT32_MAX) {
        fprintf(stderr, "Error: File '%s' not found.\n", exfs_path);
        return;
    }

    Inode file_inode;
    if (read_inode(target_inode_num, &file_inode) != 0) {
        fprintf(stderr, "Error reading inode %u for extraction.\n", target_inode_num);
        return;
    }

    if (file_inode.is_directory) {
        fprintf(stderr, "Error: '%s' is a directory. Please specify a regular file for extraction.\n", exfs_path);
        return;
    }

    // Read data blocks and write to stdout
    char buffer[BLOCK_SIZE];
    size_t bytes_remaining = file_inode.size;
    size_t current_offset = 0;

    while (bytes_remaining > 0) {
        uint32_t block_num = get_block_for_offset(target_inode_num, current_offset, 0); // Allocate=0
        if (block_num == UINT32_MAX) {
            fprintf(stderr, "Error: Could not find data block for file '%s' at offset %zu. File possibly corrupt.\n", exfs_path, current_offset);
            return;
        }

        if (read_data_block(block_num, buffer) != 0) {
             fprintf(stderr, "Error reading data block %u for file '%s'.\n", block_num, exfs_path);
             return;
        }

        size_t bytes_to_write = (bytes_remaining < BLOCK_SIZE) ? bytes_remaining : BLOCK_SIZE;
        if (fwrite(buffer, 1, bytes_to_write, stdout) != bytes_to_write) {
             perror("Error writing file content to stdout");
             // Check ferror(stdout)
             return;
        }

        bytes_remaining -= bytes_to_write;
        current_offset += bytes_to_write;
    }
    // Ensure stdout is flushed if needed (often buffered)
    fflush(stdout);
}


// --- Initialization ---
void init_exfs2() {
     // Scan for existing segments to set next_*_segment_idx accurately
     // For simplicity, we assume they start from 0 if they exist.
     // A robust implementation would check file existence in a loop.
     FILE *fp_i = fopen("inode_segment_0.exfs", "rb");
     FILE *fp_d = fopen("data_segment_0.exfs", "rb");

     if (fp_i && fp_d) {
         printf("Found existing ExFS2 segments. (Basic Check)\n");
         // TODO: Scan for highest numbered segment files to set next_*_idx correctly
         next_inode_segment_idx = 1; // Assume at least 0 exists if check passes
         next_data_segment_idx = 1;  // Assume at least 0 exists if check passes
          fclose(fp_i);
          fclose(fp_d);
         // Here you could also read some superblock info if you implement one.
     } else {
         printf("Initializing new ExFS2 filesystem...\n");
         if (fp_i) fclose(fp_i);
         if (fp_d) fclose(fp_d);

         // Create Segment 0 for inodes
         if (create_inode_segment(0) != 0) {
             fprintf(stderr, "Fatal: Could not create initial inode segment.\n");
             exit(EXIT_FAILURE);
         }
         // Create Segment 0 for data
         if (create_data_segment(0) != 0) {
             fprintf(stderr, "Fatal: Could not create initial data segment.\n");
             // Attempt cleanup? Remove inode_segment_0?
             exit(EXIT_FAILURE);
         }

         // Allocate and initialize root directory (inode 0)
         uint32_t root_inode_num = find_free_inode(); // Should be 0
         if (root_inode_num != 0) {
              fprintf(stderr, "Fatal: First allocated inode is not 0! (%u)\n", root_inode_num);
              exit(EXIT_FAILURE);
         }
         uint32_t root_data_block = find_free_data_block(); // Should be 0
         if (root_data_block != 0) {
              fprintf(stderr, "Fatal: First allocated data block is not 0! (%u)\n", root_data_block);
              exit(EXIT_FAILURE);
         }

         // Write root inode
         Inode root_inode;
         memset(&root_inode, 0, sizeof(Inode));
         root_inode.is_directory = 1;
         root_inode.size = 2; // For "." and ".."
         root_inode.direct_blocks[0] = root_data_block;
         // root_inode.mode = S_IFDIR | 0755;
         if (write_inode(root_inode_num, &root_inode) != 0) {
             fprintf(stderr, "Fatal: Failed to write root inode.\n");
             exit(EXIT_FAILURE);
         }

         // Write root data block (".", "..")
         char root_block_buffer[BLOCK_SIZE];
         DirectoryEntry *entries = (DirectoryEntry *)root_block_buffer;
         memset(root_block_buffer, 0, BLOCK_SIZE);
         strncpy(entries[0].name, ".", MAX_FILENAME_LEN);
         entries[0].inode_num = root_inode_num; // Root "." points to itself
         strncpy(entries[1].name, "..", MAX_FILENAME_LEN);
         entries[1].inode_num = root_inode_num; // Root ".." points to itself
         if (write_data_block(root_data_block, root_block_buffer) != 0) {
              fprintf(stderr, "Fatal: Failed to write root data block.\n");
              exit(EXIT_FAILURE);
         }

         printf("Filesystem initialized successfully.\n");
     }
}


// --- Main Function ---

int main(int argc, char *argv[]) {
    int opt;
    char *operation = NULL;
    char *exfs_path = NULL;
    char *local_path = NULL;
    int debug_mode = 0;

    // Option parsing
    while ((opt = getopt(argc, argv, "la:r:e:D:f:")) != -1) {
        switch (opt) {
            case 'l':
                if (operation) { fprintf(stderr, "Error: Multiple operations specified.\n"); return EXIT_FAILURE; }
                operation = "list";
                // Optional: Check for extra arguments after -l? Assume path is '/' if not given via -D
                exfs_path = "/"; // Default for list if no path given by -D
                break;
            case 'a':
                 if (operation) { fprintf(stderr, "Error: Multiple operations specified.\n"); return EXIT_FAILURE; }
                 operation = "add";
                 exfs_path = optarg;
                 break;
            case 'r':
                 if (operation) { fprintf(stderr, "Error: Multiple operations specified.\n"); return EXIT_FAILURE; }
                 operation = "remove";
                 exfs_path = optarg;
                 break;
            case 'e':
                 if (operation) { fprintf(stderr, "Error: Multiple operations specified.\n"); return EXIT_FAILURE; }
                 operation = "extract";
                 exfs_path = optarg;
                 break;
             case 'D':
                 // Debug can be combined with other ops potentially, or standalone list
                 debug_mode = 1;
                 exfs_path = optarg; // Path to debug/list
                 if (!operation) operation = "list"; // Default to list if only -D /path is given
                 break;
            case 'f': // Required argument for '-a'
                 local_path = optarg;
                 break;
            case '?':
                fprintf(stderr, "Usage: %s [-l | -a /exfs/path -f /local/path | -r /exfs/path | -e /exfs/path | -D /exfs/path]\n", argv[0]);
                return EXIT_FAILURE;
            default:
                abort(); // Should not happen
        }
    }

    // Validate arguments based on operation
    if (!operation) {
         fprintf(stderr, "No operation specified.\nUsage: %s [-l | -a /exfs/path -f /local/path | -r /exfs/path | -e /exfs/path | -D /exfs/path]\n", argv[0]);
         return EXIT_FAILURE;
    }
     if (strcmp(operation, "add") == 0 && (!exfs_path || !local_path)) {
         fprintf(stderr, "Error: -a operation requires both an exfs path (-a) and a local file path (-f).\n");
         return EXIT_FAILURE;
     }
     if ((strcmp(operation, "remove") == 0 || strcmp(operation, "extract") == 0) && !exfs_path) {
          fprintf(stderr, "Error: -%c operation requires an exfs path.\n", operation[0]);
          return EXIT_FAILURE;
     }
     // For list (-l or -D), exfs_path should have been set (defaulted to "/" or from -D)


    // Initialize the filesystem (check existence or create)
    init_exfs2();

    // Execute the requested operation
    if (strcmp(operation, "list") == 0) {
        list_fs(exfs_path ? exfs_path : "/", debug_mode); // Use default "/" if path somehow null
    } else if (strcmp(operation, "add") == 0) {
        add_file_to_fs(exfs_path, local_path);
    } else if (strcmp(operation, "remove") == 0) {
        remove_from_fs(exfs_path);
    } else if (strcmp(operation, "extract") == 0) {
        extract_file_from_fs(exfs_path);
    } else {
        fprintf(stderr, "Internal error: Unknown operation '%s'\n", operation);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}