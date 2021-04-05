# allocbench

This is a set of tools to benchmark memory allocators realistically using techniques from Android.

Currently, the only program available is `replay`, which replays Android's real-world memory traces. It is written in C++ with no dependencies other than the STL, so it's much more portable than Android's memory_replay and trace_benchmark tools.

Traces can be obtained from the [Android Open Source Project](https://android.googlesource.com/platform/system/extras/+/refs/heads/master/memory_replay/traces/). Each trace must be unzipped before it can be used with replay.cpp.
