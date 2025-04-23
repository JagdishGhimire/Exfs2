# Compiler and flags
CC = gcc
# Use C11 standard to support static_assert
# -Wall -Wextra: Enable common and extra warnings
# -g: Include debug symbols
CFLAGS = -Wall -Wextra -std=c11 -g
# Linker flags (add libraries here if needed, -lm for math library)
LDFLAGS = -lm

# Target executable name
TARGET = exfs2

# Source files
SOURCES = exfs2.c

# Object files (derived from source files)
OBJECTS = $(SOURCES:.c=.o)

# Default target: Build the executable
all: $(TARGET)

# Rule to link the executable from object files
$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

# Rule to compile source files into object files
# The dependency on exfs2.h ensures object files are rebuilt if the header changes
%.o: %.c exfs2.h
	$(CC) $(CFLAGS) -c $< -o $@

# Phony targets (targets that don't represent files)
.PHONY: all clean run_list run_add run_extract run_remove create_test_file run_list_debug

# Target to clean up build artifacts and test files
# Added test_file.txt to the clean list
clean:
	rm -f $(TARGET) $(OBJECTS) inode_segment_*.exfs data_segment_*.exfs test_output.txt test_file.bin test_file.txt extracted_large.bin

# Target to create dummy files for testing add/extract
create_test_file:
	echo "This is a test file for ExFS2." > test_file.txt
	# Create a ~5MB binary test file (adjust size if needed)
	# Using 1024k for clarity, equivalent to 1M for dd if supported
	dd if=/dev/urandom of=test_file.bin bs=1024k count=5

# --- Example Usage Targets ---
# Modify paths and commands as needed for your testing workflow

# Run the list command
run_list: $(TARGET)
	@echo "--- Running List Operation ---"
	./$(TARGET) -l

# Run the list command with debug output
run_list_debug: $(TARGET)
	@echo "--- Running List Operation (Debug) ---"
	./$(TARGET) -D /

# Add test files to the filesystem
run_add: $(TARGET) create_test_file
	@echo "--- Running Add Operations ---"
	./$(TARGET) -a /test_dir/test_file.txt -f test_file.txt
	./$(TARGET) -a /large_file.bin -f test_file.bin

# Extract test files and compare with originals
run_extract: $(TARGET)
	@echo "--- Running Extract and Diff Operations ---"
	./$(TARGET) -e /test_dir/test_file.txt > test_output.txt
	@echo "Comparing test_file.txt and extracted test_output.txt:"
	diff test_file.txt test_output.txt || echo "Files differ!"
	# Optional: Extract large file (might take time) and compare
	# @echo "Extracting large file (may take time)..."
	# ./$(TARGET) -e /large_file.bin > extracted_large.bin
	# @echo "Comparing test_file.bin and extracted_large.bin:"
	# diff test_file.bin extracted_large.bin || echo "Large files differ!"

# Remove test files/directories from the filesystem
run_remove: $(TARGET)
	@echo "--- Running Remove Operations ---"
	./$(TARGET) -r /test_dir/test_file.txt
	# Attempt to remove the directory (should work if file removal succeeded)
	./$(TARGET) -r /test_dir
	# Remove the large file
	./$(TARGET) -r /large_file.bin
	@echo "--- Listing after removals ---"
	./$(TARGET) -l

