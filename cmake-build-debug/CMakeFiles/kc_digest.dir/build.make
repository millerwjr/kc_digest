# CMAKE generated file: DO NOT EDIT!
# Generated by "MinGW Makefiles" Generator, CMake Version 3.6

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

SHELL = cmd.exe

# The CMake executable.
CMAKE_COMMAND = "C:\Program Files (x86)\JetBrains\CLion 2016.3.2\bin\cmake\bin\cmake.exe"

# The command to remove a file.
RM = "C:\Program Files (x86)\JetBrains\CLion 2016.3.2\bin\cmake\bin\cmake.exe" -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = "D:\Google Drive\Projects\Programs\GitHub\kc_digest"

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = "D:\Google Drive\Projects\Programs\GitHub\kc_digest\cmake-build-debug"

# Include any dependencies generated for this target.
include CMakeFiles/kc_digest.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/kc_digest.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/kc_digest.dir/flags.make

CMakeFiles/kc_digest.dir/main.cpp.obj: CMakeFiles/kc_digest.dir/flags.make
CMakeFiles/kc_digest.dir/main.cpp.obj: ../main.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="D:\Google Drive\Projects\Programs\GitHub\kc_digest\cmake-build-debug\CMakeFiles" --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/kc_digest.dir/main.cpp.obj"
	C:\MinGW\bin\g++.exe   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles\kc_digest.dir\main.cpp.obj -c "D:\Google Drive\Projects\Programs\GitHub\kc_digest\main.cpp"

CMakeFiles/kc_digest.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/kc_digest.dir/main.cpp.i"
	C:\MinGW\bin\g++.exe  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E "D:\Google Drive\Projects\Programs\GitHub\kc_digest\main.cpp" > CMakeFiles\kc_digest.dir\main.cpp.i

CMakeFiles/kc_digest.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/kc_digest.dir/main.cpp.s"
	C:\MinGW\bin\g++.exe  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S "D:\Google Drive\Projects\Programs\GitHub\kc_digest\main.cpp" -o CMakeFiles\kc_digest.dir\main.cpp.s

CMakeFiles/kc_digest.dir/main.cpp.obj.requires:

.PHONY : CMakeFiles/kc_digest.dir/main.cpp.obj.requires

CMakeFiles/kc_digest.dir/main.cpp.obj.provides: CMakeFiles/kc_digest.dir/main.cpp.obj.requires
	$(MAKE) -f CMakeFiles\kc_digest.dir\build.make CMakeFiles/kc_digest.dir/main.cpp.obj.provides.build
.PHONY : CMakeFiles/kc_digest.dir/main.cpp.obj.provides

CMakeFiles/kc_digest.dir/main.cpp.obj.provides.build: CMakeFiles/kc_digest.dir/main.cpp.obj


CMakeFiles/kc_digest.dir/kc_digest.cpp.obj: CMakeFiles/kc_digest.dir/flags.make
CMakeFiles/kc_digest.dir/kc_digest.cpp.obj: ../kc_digest.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir="D:\Google Drive\Projects\Programs\GitHub\kc_digest\cmake-build-debug\CMakeFiles" --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/kc_digest.dir/kc_digest.cpp.obj"
	C:\MinGW\bin\g++.exe   $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles\kc_digest.dir\kc_digest.cpp.obj -c "D:\Google Drive\Projects\Programs\GitHub\kc_digest\kc_digest.cpp"

CMakeFiles/kc_digest.dir/kc_digest.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/kc_digest.dir/kc_digest.cpp.i"
	C:\MinGW\bin\g++.exe  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E "D:\Google Drive\Projects\Programs\GitHub\kc_digest\kc_digest.cpp" > CMakeFiles\kc_digest.dir\kc_digest.cpp.i

CMakeFiles/kc_digest.dir/kc_digest.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/kc_digest.dir/kc_digest.cpp.s"
	C:\MinGW\bin\g++.exe  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S "D:\Google Drive\Projects\Programs\GitHub\kc_digest\kc_digest.cpp" -o CMakeFiles\kc_digest.dir\kc_digest.cpp.s

CMakeFiles/kc_digest.dir/kc_digest.cpp.obj.requires:

.PHONY : CMakeFiles/kc_digest.dir/kc_digest.cpp.obj.requires

CMakeFiles/kc_digest.dir/kc_digest.cpp.obj.provides: CMakeFiles/kc_digest.dir/kc_digest.cpp.obj.requires
	$(MAKE) -f CMakeFiles\kc_digest.dir\build.make CMakeFiles/kc_digest.dir/kc_digest.cpp.obj.provides.build
.PHONY : CMakeFiles/kc_digest.dir/kc_digest.cpp.obj.provides

CMakeFiles/kc_digest.dir/kc_digest.cpp.obj.provides.build: CMakeFiles/kc_digest.dir/kc_digest.cpp.obj


# Object files for target kc_digest
kc_digest_OBJECTS = \
"CMakeFiles/kc_digest.dir/main.cpp.obj" \
"CMakeFiles/kc_digest.dir/kc_digest.cpp.obj"

# External object files for target kc_digest
kc_digest_EXTERNAL_OBJECTS =

kc_digest.exe: CMakeFiles/kc_digest.dir/main.cpp.obj
kc_digest.exe: CMakeFiles/kc_digest.dir/kc_digest.cpp.obj
kc_digest.exe: CMakeFiles/kc_digest.dir/build.make
kc_digest.exe: CMakeFiles/kc_digest.dir/linklibs.rsp
kc_digest.exe: CMakeFiles/kc_digest.dir/objects1.rsp
kc_digest.exe: CMakeFiles/kc_digest.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir="D:\Google Drive\Projects\Programs\GitHub\kc_digest\cmake-build-debug\CMakeFiles" --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX executable kc_digest.exe"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles\kc_digest.dir\link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/kc_digest.dir/build: kc_digest.exe

.PHONY : CMakeFiles/kc_digest.dir/build

CMakeFiles/kc_digest.dir/requires: CMakeFiles/kc_digest.dir/main.cpp.obj.requires
CMakeFiles/kc_digest.dir/requires: CMakeFiles/kc_digest.dir/kc_digest.cpp.obj.requires

.PHONY : CMakeFiles/kc_digest.dir/requires

CMakeFiles/kc_digest.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles\kc_digest.dir\cmake_clean.cmake
.PHONY : CMakeFiles/kc_digest.dir/clean

CMakeFiles/kc_digest.dir/depend:
	$(CMAKE_COMMAND) -E cmake_depends "MinGW Makefiles" "D:\Google Drive\Projects\Programs\GitHub\kc_digest" "D:\Google Drive\Projects\Programs\GitHub\kc_digest" "D:\Google Drive\Projects\Programs\GitHub\kc_digest\cmake-build-debug" "D:\Google Drive\Projects\Programs\GitHub\kc_digest\cmake-build-debug" "D:\Google Drive\Projects\Programs\GitHub\kc_digest\cmake-build-debug\CMakeFiles\kc_digest.dir\DependInfo.cmake" --color=$(COLOR)
.PHONY : CMakeFiles/kc_digest.dir/depend

