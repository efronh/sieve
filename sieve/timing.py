# Milliseconds each stage of a check took: a result's timings, and timings_ms in the SIEM event.
import time


def since(start):
    return (time.perf_counter() - start) * 1000


# Adds to a stage, for one that runs several times (a layer on each part of a document).
def add(timings, stage, start):
    timings[stage] = timings.get(stage, 0.0) + since(start)
