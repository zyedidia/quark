# QUark Assembly Rewriting Kit

This is a tool for static instrumentation of ARM64 programs. It works on
relocatable object files (before the linker has run, but after the compiler).

The tool is currently in-progress and currently does not have a nice API for
writing instrumentation tools (a Lua-based API is planned for the future).

There is an example in the `example` folder that instruments a fibonacci
program to record how many times it executes a `ret` instruction.
