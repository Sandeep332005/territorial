#!/usr/bin/env bash
# Recreates the two-commit git history for the secure_packet_parser demo
# target that REWIND's commit-diff analysis runs against. Not committed to
# this repo's own history (that .git lives inside vulnerable_targets/ and
# would otherwise be tracked as a broken embedded-repo gitlink) — run this
# once after cloning, or any time you want to reset the demo target.
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET_DIR="vulnerable_targets/secure_packet_parser"

if [ -d "$TARGET_DIR/.git" ]; then
    echo "Demo target already initialized at $TARGET_DIR — nothing to do."
    exit 0
fi

rm -rf "$TARGET_DIR"
mkdir -p "$TARGET_DIR"
cd "$TARGET_DIR"
git init -q
git config user.email "sentinel@local"
git config user.name "SENTINEL-X Demo"

cat > parser.c << 'EOF'
/*
 * secure_packet_parser — demo target for SENTINEL-X CORE
 * Educational, intentionally-controlled vulnerability for hackathon demo.
 */
#include <string.h>
#include <stdio.h>

#define BUFFER_SIZE 256

typedef struct {
    unsigned char buffer[BUFFER_SIZE];
    int length;
} Packet;

#define ERROR_INVALID_LENGTH -1

int parse_packet(Packet *pkt, const unsigned char *input, int packet_length) {
    if (packet_length <= 0 || packet_length > BUFFER_SIZE) {
        return ERROR_INVALID_LENGTH;
    }
    memcpy(pkt->buffer, input, packet_length);
    pkt->length = packet_length;
    return 0;
}
EOF

cat > CMakeLists.txt << 'EOF'
cmake_minimum_required(VERSION 3.10)
project(secure_packet_parser C)
add_library(parser STATIC parser.c)
EOF

cat > fuzz_harness.c << 'EOF'
/*
 * fuzz_harness — AFL++ entry point for secure_packet_parser.
 * Reads a file (argv[1]) as raw packet bytes and feeds it straight into
 * parse_packet() with its own length, exactly modeling an attacker-controlled
 * packet_length argument.
 */
#include <stdio.h>
#include <stdlib.h>
#include "parser.c"

int main(int argc, char **argv) {
    if (argc < 2) return 0;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 0;
    static unsigned char input[65536];
    size_t n = fread(input, 1, sizeof(input), f);
    fclose(f);

    Packet pkt;
    parse_packet(&pkt, input, (int)n);
    return 0;
}
EOF

git add -A
git commit -q -m "Initial secure packet parser with bounds-checked length validation"

# Introduce the vulnerability as a second commit — this is what REWIND analyzes.
cat > parser.c << 'EOF'
/*
 * secure_packet_parser — demo target for SENTINEL-X CORE
 * Educational, intentionally-controlled vulnerability for hackathon demo.
 */
#include <string.h>
#include <stdio.h>

#define BUFFER_SIZE 256

typedef struct {
    unsigned char buffer[BUFFER_SIZE];
    int length;
} Packet;

#define ERROR_INVALID_LENGTH -1

int parse_packet(Packet *pkt, const unsigned char *input, int packet_length) {
    memcpy(pkt->buffer, input, packet_length);
    pkt->length = packet_length;
    return 0;
}
EOF

git add -A
git commit -q -m "perf: streamline packet ingestion path"

mkdir -p corpus
python3 -c "open('corpus/seed_small','wb').write(b'AAAA')"
python3 -c "open('corpus/seed_boundary','wb').write(b'B'*300)"
mkdir -p findings/crashes
python3 -c "open('findings/crashes/crash-00017.bin','wb').write(b'B'*300)"

echo "Demo target initialized at $TARGET_DIR (2 commits, seed corpus, crash input)."
