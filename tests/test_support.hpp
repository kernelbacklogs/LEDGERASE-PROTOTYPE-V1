#pragma once

// The exit code a test binary returns when it could not run a check because
// the environment does not support it, rather than because the code is wrong.
//
// CTest is told about this through the SKIP_RETURN_CODE test property in
// tests/CMakeLists.txt, so a suite that could not run reports "Skipped" and
// not "Passed". That distinction matters here: a skipped check is a gap in
// what was verified, and reading it as a pass would turn an honest gap into
// a false assurance.
//
// 77 is the exit code the GNU Autotools convention reserves for "skipped",
// and it is outside the 0-125 range a test would use to report a real
// failure.
//
// A suite that has a genuine failure returns its failure code regardless: a
// broken assertion is reported as a failure even when another check in the
// same suite had to be skipped.

constexpr int kSkipExitCode = 77;
