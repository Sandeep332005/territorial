#!/usr/bin/env bash
# Recreates the two-commit git history for the network_protocol_parser demo
# target (the "Target B" used for the real Immune Transfer experiment).
# Not committed to this repo's own history — same reason as
# setup_demo_target.sh: its .git would be tracked as a broken embedded-repo
# gitlink. Run this once after cloning, or any time you want to reset it.
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET_DIR="vulnerable_targets/network_protocol_parser"

if [ -d "$TARGET_DIR/.git" ]; then
    echo "Target B already initialized at $TARGET_DIR — nothing to do."
    exit 0
fi

rm -rf "$TARGET_DIR"
mkdir -p "$TARGET_DIR"
cd "$TARGET_DIR"
git init -q
git config user.email "abhimanyux@local"
git config user.name "ABHIMANYU X Demo"

cat > frame.c << 'EOF'
/*
 * network_protocol_parser — second demo target for ABHIMANYU X.
 * Educational, intentionally-controlled vulnerability for hackathon demo.
 */
#include <string.h>

#define MAX_FRAME 512

typedef struct {
    char data[MAX_FRAME];
    int len;
} Frame;

#define ERROR_INVALID_LENGTH -1

int ingest_frame(Frame *f, const char *raw, int raw_len) {
    if (raw_len <= 0 || raw_len > MAX_FRAME) {
        return ERROR_INVALID_LENGTH;
    }
    memcpy(f->data, raw, raw_len);
    f->len = raw_len;
    return 0;
}
EOF

cat > CMakeLists.txt << 'EOF'
cmake_minimum_required(VERSION 3.10)
project(network_protocol_parser C)
add_library(frame STATIC frame.c)
EOF

cat > fuzz_harness.c << 'EOF'
/*
 * fuzz_harness — AFL++ entry point for network_protocol_parser.
 */
#include <stdio.h>
#include <stdlib.h>
#include "frame.c"

int main(int argc, char **argv) {
    if (argc < 2) return 0;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 0;
    static unsigned char input[65536];
    size_t n = fread(input, 1, sizeof(input), f);
    fclose(f);

    Frame frame;
    ingest_frame(&frame, (const char *)input, (int)n);
    return 0;
}
EOF

git add -A
git commit -q -m "Initial network_protocol_parser with bounds-checked frame ingestion"

cat > frame.c << 'EOF'
/*
 * network_protocol_parser — second demo target for ABHIMANYU X.
 * Educational, intentionally-controlled vulnerability for hackathon demo.
 */
#include <string.h>

#define MAX_FRAME 512

typedef struct {
    char data[MAX_FRAME];
    int len;
} Frame;

#define ERROR_INVALID_LENGTH -1

int ingest_frame(Frame *f, const char *raw, int raw_len) {
    memcpy(f->data, raw, raw_len);
    f->len = raw_len;
    return 0;
}
EOF

git add -A
git commit -q -m "refactor: simplify frame ingestion hot path"

mkdir -p corpus findings/crashes
python3 -c "open('corpus/seed_small','wb').write(b'CCCC')"
python3 -c "open('corpus/seed_boundary','wb').write(b'D'*600)"
python3 -c "open('findings/crashes/crash-frame-01.bin','wb').write(b'D'*600)"

echo "Target B initialized at $TARGET_DIR (2 commits, seed corpus, crash input)."
