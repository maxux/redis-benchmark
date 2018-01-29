# redis-benchmark
Simple redis SET and GET benchmark writing keys and random values.

Keys are sha-256 of the value, after writing everything, each keys are re-read and hash re-computed to ensure the backend is stable.
