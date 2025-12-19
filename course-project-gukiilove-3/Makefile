# Makefile for LangOS Distributed File System
# Author: LangOS Team
# Date: November 2025

CC = gcc
CFLAGS = -Wall -Wextra -pthread -g -mcmodel=medium
LIBS = -lpthread -lz

# Object files
COMMON_OBJS = common.o
NM_OBJS = $(COMMON_OBJS) name_server.o
SS_OBJS = $(COMMON_OBJS) storage_server.o
CLIENT_OBJS = $(COMMON_OBJS) client.o

# Target executables
TARGETS = name_server storage_server client

# Default target - build everything

all: directories $(TARGETS)
	@echo ""
	@echo "Build successful!"
	@echo ""
	@echo "To run the system:" 
	@echo "  Option A (single command): use the run targets or run components manually"
	@echo "  Option B (manual):"
	@echo "    Terminal 1: ./name_server"
	@echo "    Terminal 2: ./storage_server"
	@echo "    Terminal 3: ./client"
	@echo ""

# Create necessary directories
directories:
	@mkdir -p logs
	@mkdir -p storage/files

# Name Server executable
name_server: $(NM_OBJS)
	@echo " Linking name_server..."
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# Storage Server executable
storage_server: $(SS_OBJS)
	@echo " Linking storage_server..."
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# AddressSanitizer build for storage_server (useful if valgrind is not available)
.PHONY: asan
asan: CFLAGS += -fsanitize=address -fno-omit-frame-pointer
asan: clean storage_server

# Explicit ASAN-instrumented storage server binary
storage_server_asan: $(SS_OBJS)
	@echo " Linking storage_server_asan with AddressSanitizer..."
	$(CC) $(CFLAGS) -fsanitize=address -fno-omit-frame-pointer -g -o $@ $^ $(LIBS)

# Client executable
client: $(CLIENT_OBJS)
	@echo " Linking client..."
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)


# Compile object files
%.o: %.c
	@echo " Compiling $<..."
	$(CC) $(CFLAGS) -c -o $@ $<

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -f name_server storage_server *.o
	@rm -f client 2>/dev/null || true
	@echo "Clean complete!"

# Deep clean - remove everything including logs and storage
deepclean: clean
	@echo "Deep cleaning (removing logs and storage)..."
	rm -rf logs/
	rm -rf storage/
	@echo "Deep clean complete!"

# Clean only logs
clean-logs:
	@echo "Cleaning logs..."
	rm -rf logs/*.log
	@echo "Logs cleaned!"

# Clean only storage
clean-storage:
	@echo "Cleaning storage..."
	rm -rf storage/files/*
	@echo "Storage cleaned!"

# Rebuild everything from scratch
rebuild: clean all

# Run Name Server
run-nm: name_server directories
	@echo " Starting Name Server..."
	./name_server

# Run Storage Server
run-ss: storage_server directories
	@echo " Starting Storage Server..."
	./storage_server

# Run Client
run-client: client
	@echo " Starting Client..."
	./client

# Run all tests (requires tmux)
test: all
	@echo "Running tests..."
	@if command -v tmux >/dev/null 2>&1; then \
		./run_system.sh; \
	else \
			echo "tmux not installed. Please run components manually:"; \
				echo "   Option A: use the run targets or run components manually"; \
		echo "   Option B:"; \
		echo "     Terminal 1: make run-nm"; \
		echo "     Terminal 2: make run-ss"; \
		echo "     Terminal 3: make run-client"; \
	fi

# Check if system is running
status:
	@echo " Checking system status..."
	@echo ""
	@echo "Name Server (port 8000):"
	@lsof -i :8000 2>/dev/null || echo "   Not running"
	@echo ""
	@echo "Storage Server (port 9100):"
	@lsof -i :9100 2>/dev/null || echo "   Not running"
	@echo ""
	@echo "Processes:"
	@ps aux | grep -E "name_server|storage_server|client" | grep -v grep || echo "   No processes found"

# Stop all running processes
stop:
	@echo " Stopping all LangOS processes..."
	@killall name_server 2>/dev/null || true
	@killall storage_server 2>/dev/null || true
	@killall client 2>/dev/null || true
	@echo " All processes stopped!"

# View logs
logs-nm:
	@tail -f logs/nm.log

logs-ss:
	@tail -f logs/ss.log

logs-all:
	@tail -f logs/*.log

# Show file statistics
stats:
	@echo " LangOS Statistics"
	@echo "===================="
	@echo ""
	@echo "Files in storage: $$(ls -1 storage/files/ 2>/dev/null | wc -l)"
	@echo "Total storage size: $$(du -sh storage/files/ 2>/dev/null | cut -f1)"
	@echo ""
	@echo "Log files:"
	@ls -lh logs/*.log 2>/dev/null || echo "  No logs found"
	@echo ""
	@echo "Recent operations (last 5):"
	@tail -5 logs/nm.log 2>/dev/null || echo "  No operations yet"

# Help target
help:
	@echo "LangOS Makefile Commands"
	@echo "========================"
	@echo ""
	@echo "Building:"
	@echo "  make              - Build all components"
	@echo "  make all          - Build all components"
	@echo "  make rebuild      - Clean and rebuild"
	@echo ""
	@echo "Cleaning:"
	@echo "  make clean        - Remove executables and object files"
	@echo "  make deepclean    - Remove everything including logs/storage"
	@echo "  make clean-logs   - Remove only log files"
	@echo "  make clean-storage - Remove only storage files"
	@echo ""
	@echo "Running:"
	@echo "  make run-nm       - Start Name Server"
	@echo "  make run-ss       - Start Storage Server"
	@echo "  make run-client   - Start Client"
	@echo "  (No final_run.sh available) Use make run-nm/run-ss or run components manually"
	@echo "  make test         - Run automated tests (requires tmux)"
	@echo ""
	@echo "Monitoring:"
	@echo "  make status       - Check system status"
	@echo "  make logs-nm      - Tail Name Server logs"
	@echo "  make logs-ss      - Tail Storage Server logs"
	@echo "  make logs-all     - Tail all logs"
	@echo "  make stats        - Show statistics"
	@echo ""
	@echo "Control:"
	@echo "  make stop         - Stop all running processes"
	@echo ""
	@echo "Documentation:"
	@echo "  make help         - Show this help message"
	@echo ""
	@echo "Quick Start:"
	@echo "  Option A:"
	@echo "    1. make           - Build everything"
	@echo "    2. make run-nm    - Terminal 1"
	@echo "    3. make run-client - Terminal 3"
	@echo "  Option B:"
	@echo "    1. make           - Build everything"
	@echo "    2. make run-nm    - Terminal 1"
	@echo "    3. make run-ss    - Terminal 2"
	@echo "    4. make run-client - Terminal 3"

# Declare phony targets
.PHONY: all clean deepclean clean-logs clean-storage rebuild directories \
        run-nm run-ss run-client test status stop \
        logs-nm logs-ss logs-all stats help

# Dependencies
common.o: common.c common.h
name_server.o: name_server.c common.h
storage_server.o: storage_server.c common.h
client.o: client.c common.h
