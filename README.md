# COMP7402_Assignment4

# template
A template for assignments and projects.
## Setup
```
mkdir cmake-build-debug
```

## Source Code Additions
Add your source files to the CMakeLists.txt:

```
set(HEADER_LIST [files])
set(SOURCE_LIST [files])
```

```
cmake -S . -B cmake-build-debug
```

## Build 
Examples:
```
cmake --build cmake-build-debug
cmake --build cmake-build-debug --clean-first
```
