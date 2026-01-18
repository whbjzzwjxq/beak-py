#!/bin/bash

# Configuration for parallel fuzzing
WORKERS=4
IMAGE_NAME="openvm-fuzzer"
ZKVM_PATH="$(pwd)/openvm-src"
RESULT_BASE="$(pwd)/fuzz_results"

echo "=== Starting $WORKERS Beak Fuzzer Workers ==="

# Create base result directory
mkdir -p "$RESULT_BASE"

for i in $(seq 1 $WORKERS); do
    # Generate unique seed and directory for each worker
    SEED=$((RANDOM + i * 1000))
    WORKER_DIR="$RESULT_BASE/worker_$i"
    mkdir -p "$WORKER_DIR"
    
    echo "Launching Worker $i (Seed: $SEED)..."
    
    # Start background container
    docker run -d \
        --name "beak_worker_$i" \
        -v "$ZKVM_PATH:/app/openvm-src" \
        -v "$WORKER_DIR:/app/output" \
        --env PYTHONUNBUFFERED=1 \
        $IMAGE_NAME \
        run --seed $SEED --zkvm /app/openvm-src --out /app/output
done

echo "=== All workers launched. Use 'docker ps' to monitor. ==="
echo "Logs for worker 1: docker logs -f beak_worker_1"
