# redis-benchmark
Simple redis SET and GET benchmark writing keys and random values.

Keys are sha-256 of the value, after writing everything, each keys are re-read and hash re-computed to ensure the backend is stable.

**WARNING**: this benchmark doesn't use default redis behavior, when doing a SET, the result is used as `key`.
This benchmark is mainly used to test `zero-os/0-db` project which can generate keys during SET.
