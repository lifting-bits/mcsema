//
// This does nothing, of course.  If a user has restricted us via
// BUILD_PROJECTS to no projects that contain libraries, this guy gets
// compiled as a dummy executable target so that cmake install(EXPORT
// ...)  doesn't fail with "unknown export Boost".
//
int main(int, char**) { }
