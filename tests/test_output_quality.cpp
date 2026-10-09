// Tests for the progress display and the limitation registry.
//
// The progress formatter is a pure function of its arguments, so it is tested
// by feeding it scripted values. The rate limiting is tested by driving a real
// reporter through a callback sequence.

#include "ledgerase/operator.hpp"
#include "ledgerase/reporting.hpp"
#include "ledgerase/evidence.hpp"
#include "ledgerase/limitations.hpp"
#include "evidence/reports/progress_reporter.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

using namespace ledgerase;

namespace {

int g_failures = 0;

void check(bool condition, const std::string& what) {
    if (condition) {
        std::printf("  ok   %s\n", what.c_str());
        return;
    }
    std::printf("  FAIL %s\n", what.c_str());
    ++g_failures;
}

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

ProgressConfig wide(bool unicode = true) {
    ProgressConfig config;
    config.enabled = true;
    config.unicode = unicode;
    config.barCells = 20;
    config.terminalWidth = 200;
    return config;
}

constexpr uint64_t kGiB = 1024ull * 1024 * 1024;

// The three-cell UTF-8 glyphs, as strings. A char literal would be narrowed
// to a single execution character, which -Werror=overflow rejects.
const std::string kOpenMouth = "\u1597";
const std::string kClosedMouth = "\u25CF";
const std::string kDot = "\u00B7";

// Terminal columns occupied by a UTF-8 string. The bar's glyphs are three
// bytes each, so measuring with .size() would report roughly double the real
// width and a width-handling test would pass or fail for the wrong reason.
std::size_t displayWidth(const std::string& text) {
    std::size_t columns = 0;
    for (const unsigned char byte : text) {
        if ((byte & 0xC0) != 0x80) {   // not a continuation byte
            ++columns;
        }
    }
    return columns;
}

// The bar contents.
//
// The bar is unbracketed, so it is extracted by shape rather than by
// delimiters: it is the run of trail dashes, the mouth, the gap and the
// 'o-' chain, and it ends where the first space after the mouth's gap begins.
// Bracketing it would add two columns to every row for no information, and the
// earlier version bracketed a bar that was already a dense fill - where a
// bracket read as part of the bar and the reader could not tell where the bar
// stopped.
std::string barOf(const std::string& line) {
    // Start at the first run of two or more dashes that is not part of a bar
    // that begins at column 0 of the line: the bar always follows "Pass n" or
    // "Verify", so find the mouth and walk outwards.
    const std::size_t mouth = line.find_first_of("Cc");
    if (mouth == std::string::npos) {
        return "";
    }
    std::size_t start = mouth;
    while (start > 0 && line[start - 1] == '-') {
        --start;
    }
    std::size_t end = mouth + 1;
    while (end < line.size() && (line[end] == '-' || line[end] == 'o')) {
        ++end;
    }
    return line.substr(start, end - start);
}

std::size_t countOf(const std::string& haystack, const std::string& needle) {
    std::size_t total = 0;
    std::size_t at = haystack.find(needle);
    while (at != std::string::npos) {
        ++total;
        at = haystack.find(needle, at + needle.size());
    }
    return total;
}


// ---------------------------------------------------------------------------
// Progress formatting
// ---------------------------------------------------------------------------

void testProgressFields() {
    std::printf("the bar reports every field it is given\n");

    const std::string line =
        formatProgress(wide(), ProgressPhase::WRITE, 1, 1, kGiB / 2, kGiB,
                       5.0 * 1024 * 1024, 60, true);

    check(contains(line, "Pass 1"), "the pass number is shown");
    check(!contains(line, "Pass 1/1"), "a single pass is not shown as 1/1");
    check(contains(line, "50.0%"), "the percentage is shown to one decimal");
    check(contains(line, "512.0 MiB/1.0 GiB"),
          "bytes written and total are shown");
    check(contains(line, "5.0 MiB/s"), "the throughput is shown");
    check(contains(line, "ETA 1m 00s"), "the ETA is shown from the given rate");

    const std::string multi =
        formatProgress(wide(), ProgressPhase::WRITE, 2, 3, kGiB, 3 * kGiB,
                       10.0 * 1024 * 1024, 0, false);
    check(contains(multi, "Pass 2/3"), "a multi-pass run shows pass n of total");
    check(!contains(multi, "100.0%"), "a partial multi-pass is not 100%");
    check(contains(multi, "33.3%"), "the multi-pass percentage is correct");
    check(contains(multi, "ETA 0s"), "a zero ETA is shown as 0s, not blank");
}

// The geometry, which is the whole of what this renderer decides.
//
// Written against the reference shape rather than against the previous
// implementation:
//
//   ----C---o-o-o-o-o-o-o-o-o-
//
// trail, mouth, gap, then the unconsumed circles separated by dashes.
void testPacManGeometryFollowsThePercentage() {
    std::printf("pac-man's position and circle count are derived from progress\n");

    // 24 cells is the default width and the width the reference shape is drawn
    // at, where ten circles fit alongside a trail, a mouth and a gap. The
    // narrower geometry is covered separately below.
    ProgressConfig config = wide();
    config.barCells = 24;

    // At 0% every circle is present and the mouth is near the left.
    const std::string emptyBar = barOf(formatProgress(
        config, ProgressPhase::WRITE, 1, 1, 0, kGiB, 0, 0, true));
    check(countOf(emptyBar, "o") == 10,
          "at 0% all ten circle markers are present");
    check(countOf(emptyBar, "-") == static_cast<std::size_t>(emptyBar.size()) - 10 - 1,
          "at 0% every column other than the mouth and the circles is a dash");

    // The circle count falls with progress and reaches zero at 100%.
    const auto circlesAt = [&](uint64_t done) {
        return countOf(barOf(formatProgress(config, ProgressPhase::WRITE, 1, 1,
                                            done, kGiB, 0, 0, true)),
                       "o");
    };
    check(circlesAt(kGiB / 2) == 5, "at 50% half the circles remain");
    check(circlesAt(kGiB) == 0, "at 100% no circles remain");
    check(circlesAt(0) == 10,
          "at 0% on a 24-cell bar all ten circles fit");

    // The mouth advances, and the trail in front of it grows, as progress
    // increases. This is the property that makes the bar read as eating.
    const auto trailAt = [&](uint64_t done) {
        const std::string b = barOf(formatProgress(
            config, ProgressPhase::WRITE, 1, 1, done, kGiB, 0, 0, true));
        return b.find_first_of("Cc");
    };
    const std::size_t t0 = trailAt(0);
    const std::size_t t50 = trailAt(kGiB / 2);
    const std::size_t t100 = trailAt(kGiB);
    check(t0 < t50 && t50 < t100,
          "the mouth advances left to right as progress increases");
    check(t0 >= 1, "and there is always a trail in front of it");

    // The width is fixed, which is what stops the text after the bar moving.
    const auto widthAt = [&](uint64_t done) {
        return displayWidth(barOf(formatProgress(
            config, ProgressPhase::WRITE, 1, 1, done, kGiB, 0, 0, true)));
    };
    check(widthAt(0) == widthAt(kGiB / 2) && widthAt(kGiB / 2) == widthAt(kGiB),
          "the bar is the same width at 0%, 50% and 100%");
}

// A narrower bar drops circles rather than the trail or the gap. Ten circles
// need twenty columns, so a 20-cell bar that insisted on ten would have nothing
// left for a mouth or a trail and would render as a dense fill - which is the
// one shape the reference rules out.
void testANarrowBarDropsCirclesNotTheGaps() {
    std::printf("a narrow bar drops circles rather than the gaps\n");

    for (int cells : {10, 14, 20, 24, 40}) {
        ProgressConfig config = wide();
        config.barCells = cells;
        const std::string b = barOf(formatProgress(
            config, ProgressPhase::WRITE, 1, 1, 0, kGiB, 0, 0, true));
        const std::size_t mouth = b.find_first_of("Cc");
        check(mouth != std::string::npos, "a mouth is drawn at " +
                                               std::to_string(cells) + " cells");
        if (mouth == std::string::npos) {
            continue;
        }
        check(mouth >= 1, "a trail survives at " + std::to_string(cells) +
                             " cells");
        check(b[mouth + 1] == '-', "the gap survives at " +
                                       std::to_string(cells) + " cells");
        check(displayWidth(b) == static_cast<std::size_t>(cells),
              "the bar is exactly the requested width at " +
                  std::to_string(cells) + " cells");
    }
}

void testMouthCaseAlternatesOnly() {
    std::printf("the mouth alternates case, and only case, between redraws\n");

    const ProgressConfig config = wide();
    const std::string a = formatProgress(config, ProgressPhase::WRITE, 1, 1,
                                          kGiB / 2, kGiB, 0, 0, true);
    const std::string b = formatProgress(config, ProgressPhase::WRITE, 1, 1,
                                          kGiB / 2, kGiB, 0, 0, false);

    check(contains(a, "C"), "the first frame uses an upper-case mouth");
    check(contains(b, "c"), "the second frame uses a lower-case mouth");

    // The case is the *only* difference. If position were derived from the
    // animation frame rather than the percentage - which is what the renderer is
    // required not to do - the two would be at different columns.
    std::string aBar = barOf(a);
    std::string bBar = barOf(b);
    for (char& c : aBar) if (c == 'C') c = 'c';
    check(aBar == bBar,
          "position and circle count are identical on both frames, so the "
          "alternation is purely visual");
}

void testTheBarIsSparseAndKeepsItsGaps() {
    std::printf("the bar stays sparse and keeps gaps around the mouth\n");

    const ProgressConfig config = wide();
    for (uint64_t done : {uint64_t{0}, kGiB / 4, kGiB / 2,
                          (3 * kGiB) / 4, kGiB}) {
        const std::string b = barOf(
            formatProgress(config, ProgressPhase::WRITE, 1, 1, done, kGiB, 0, 0,
                           true));
        const std::size_t mouth = b.find_first_of("Cc");
        check(mouth != std::string::npos, "a mouth is drawn");
        if (mouth == std::string::npos) {
            continue;
        }
        // A gap after the mouth, so the mouth never runs into the first circle.
        check(b[mouth + 1] == '-', "there is a gap after the mouth");
        // And a trail before it.
        check(mouth >= 1, "there is a trail before the mouth");
        // The circles are separated, not a dense run.
        check(b.find("oo") == std::string::npos,
              "circles are separated by dashes, not a dense oooooo run");
    }
}

void testAsciiFallback() {
    std::printf("a terminal that cannot show UTF-8 gets ASCII\n");

    const std::string line =
        formatProgress(wide(false), ProgressPhase::WRITE, 1, 1, kGiB / 2, kGiB, 0,
                       0, true);
    check(contains(line, "C"), "pac-man is a C");
    check(contains(line, "o"), "remaining cells are spaced circles");
    check(contains(line, "-"), "the trail and the separators are dashes");
    check(!contains(line, kOpenMouth), "no open-mouth glyph appears in ASCII mode");
    check(!contains(line, kClosedMouth), "no closed glyph appears in ASCII mode");
    check(!contains(line, kDot), "no middle dot appears in ASCII mode");
}

void testVerifyPhase() {
    std::printf("verification is a labelled second phase counting sectors\n");

    const std::string line =
        formatProgress(wide(), ProgressPhase::VERIFY, 1, 1, 32, 64, 0, 0, true,
                       32, 64);
    check(contains(line, "Verify"), "the verify phase is labelled");
    check(contains(line, "32/64 sectors"), "the sampled sector count is shown");
    check(!contains(line, "Pass"), "the verify phase claims no pass number");
    check(!contains(line, "ETA"), "the verify phase shows no ETA");
}

void testNarrowTerminal() {
    std::printf("a narrow terminal loses the least important fields first\n");

    ProgressConfig narrow = wide();
    narrow.terminalWidth = 44;
    const std::string line =
        formatProgress(narrow, ProgressPhase::WRITE, 1, 1, kGiB / 2, kGiB,
                       5.0 * 1024 * 1024, 60, true);
    check(displayWidth(line) <= 44,
          "the line fits the terminal width in display columns");
    check(contains(line, "50.0%"),
          "the percentage is kept: it is the most important field");
    check(!contains(line, "ETA"), "the ETA is the first field dropped");
    check(!contains(line, "/s"), "throughput is dropped before the percentage");

    ProgressConfig tiny = wide();
    tiny.terminalWidth = 20;
    const std::string squeezed =
        formatProgress(tiny, ProgressPhase::WRITE, 1, 1, kGiB / 2, kGiB, 0, 0,
                       true);
    check(contains(squeezed, "Pass"), "the pass label survives a very narrow line");
    check(squeezed.find('[') != std::string::npos, "the bar is still drawn");
    check(displayWidth(barOf(squeezed)) >= 10,
          "the bar never shrinks below ten columns");
}

void testReporterCallbackSequence() {
    std::printf("a reporter fed by a callback sequence redraws on demand\n");

    ProgressConfig config;
    config.enabled = false;   // no terminal attached for this test
    config.unicode = true;
    config.barCells = 20;
    config.terminalWidth = 200;

    {
        ProgressReporter reporter(config);
        reporter.drawNow(ProgressPhase::WRITE, 0, kGiB, 1, 1);
        check(contains(reporter.lastLine(), "0.0%"),
              "an empty progress reports 0.0%");
        reporter.drawNow(ProgressPhase::WRITE, kGiB / 4, kGiB, 1, 1);
        check(contains(reporter.lastLine(), "25.0%"),
              "a quarter written reports 25.0%");
        reporter.drawNow(ProgressPhase::WRITE, kGiB, kGiB, 1, 1);
        check(contains(reporter.lastLine(), "100.0%"),
              "a finished progress reports 100.0%");
        reporter.finish();
    }

    // A disabled reporter writes nothing through onProgress, which is what
    // makes --no-progress, --json and a redirected stdout behave identically.
    {
        ProgressReporter reporter(config);
        reporter.onProgress(ProgressPhase::WRITE, kGiB / 2, kGiB);
        check(reporter.lastLine().empty(),
              "a disabled reporter writes no line at all");
    }

    // The process-wide hook is how the write loop reaches the reporter.
    check(activeProgressReporter() == nullptr,
          "no reporter is installed by default");
    {
        ProgressReporter reporter(config);
        setActiveProgressReporter(&reporter);
        check(activeProgressReporter() == &reporter,
              "installing a reporter makes it the active one");
        setActiveProgressReporter(nullptr);
        check(activeProgressReporter() == nullptr,
              "clearing the hook leaves no reporter installed");
    }
}

// Captures whatever the formatter writes to std::cout for the duration of a
// call. Used so the terminal view can be asserted on line by line without a
// pty.
class CapturedOutput {
public:
    CapturedOutput() : previous_(std::cout.rdbuf(buffer_.rdbuf())) {}
    ~CapturedOutput() { std::cout.rdbuf(previous_); }
    std::string text() const { return buffer_.str(); }

private:
    std::ostringstream buffer_;
    std::streambuf* previous_;
};

std::vector<std::string> nonEmptyLines(const std::string& text) {
    std::vector<std::string> lines;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        if (line.find_first_not_of(" \t\r") != std::string::npos) {
            lines.push_back(line);
        }
    }
    return lines;
}

void testSummaryStaysShort() {
    std::printf("the terminal limitation view is grouped and stays short\n");

    // The set a real USB host-overwrite run produces, including the four
    // "not recorded" entries that used to be four separate sentences.
    LimitationSet limitations;
    limitations.add(LimitationId::HOST_SCOPE_ONLY);
    limitations.add(LimitationId::SELF_VERIFIED);
    limitations.add(LimitationId::CLEAR_ONLY);
    limitations.add(LimitationId::USB_BRIDGE_OPAQUE);
    limitations.add(LimitationId::NO_AUTHORIZATION);
    limitations.add(LimitationId::COPIES_NOT_ATTESTED);
    limitations.add(LimitationId::NO_RETENTION_POLICY);
    limitations.add(LimitationId::NO_IDENTITY_CONFIRMATION);

    OutputFormatter formatter;
    {
        CapturedOutput capture;
        formatter.outputLimitations(limitations, "/var/lib/ledgerase/evidence/job.json");
    }

    std::string captured;
    {
        CapturedOutput capture;
        formatter.outputLimitations(limitations, "/var/lib/ledgerase/evidence/job.json");
        captured = capture.text();
    }

    const std::vector<std::string> lines = nonEmptyLines(captured);
    // The spec's cap is "roughly 8 lines". A wrapped group line counts once per
    // printed row, so the bound is set to cover the wrapping of four groups.
    check(lines.size() <= 12,
          "the grouped summary stays within the line budget");
    check(contains(captured, "Scope:"), "the Scope group is labelled");
    check(contains(captured, "Verification:"), "the Verification group is labelled");
    check(contains(captured, "Device:"), "the Device group is labelled");
    check(contains(captured, "Not recorded:"), "the Not recorded group is labelled");
    check(contains(captured, "8 recorded"),
          "the count of recorded limitations is shown");
    check(contains(captured, "/var/lib/ledgerase/evidence/job.json"),
          "the evidence path is given so the full list can be found");

    // Each limitation appears exactly once in the terminal view.
    //
    // The phrase checked here is the entry's short label, not its sentence. The
    // grouped view was changed to use short labels precisely because joining
    // whole sentences into four lines produced text that read as one claim when
    // it was two; the full sentence is still printed under --verbose, which
    // testVerbosePrintsTheFullListOnce covers. This test previously looked for
    // the sentence and was updated when that behaviour changed.
    std::size_t scopeMentions = 0;
    for (const std::string& line : lines) {
        if (contains(line, "host-visible address space only")) {
            ++scopeMentions;
        }
    }
    check(scopeMentions == 1,
          "a limitation that appears in several sources is printed once");

    // The grouped view must not also dump the ID-prefixed full list.
    check(!contains(captured, "HOST_SCOPE_ONLY:"),
          "the short view does not print the ID-prefixed form");
}

void testVerbosePrintsTheFullListOnce() {
    std::printf("--verbose prints the full list, and it is not printed again\n");

    LimitationSet limitations;
    limitations.add(LimitationId::HOST_SCOPE_ONLY);
    limitations.add(LimitationId::NO_AUTHORIZATION);
    limitations.add(LimitationId::COPIES_NOT_ATTESTED);

    OutputFormatter formatter;
    formatter.setVerbose(true);
    check(!formatter.fullLimitationListPrinted(),
          "nothing has been printed before the call");

    std::string captured;
    {
        CapturedOutput capture;
        formatter.outputLimitations(limitations, "/tmp/job.json");
        captured = capture.text();
    }

    check(contains(captured, "HOST_SCOPE_ONLY:"),
          "--verbose shows the ID of every limitation");
    check(contains(captured, "COPIES_NOT_ATTESTED:"),
          "--verbose shows IDs, not just sentences");
    check(formatter.fullLimitationListPrinted(),
          "the formatter records that the full list has been shown");

    // A second call must not reprint it.
    std::string second;
    {
        CapturedOutput capture;
        formatter.outputLimitations(limitations, "/tmp/job.json");
        second = capture.text();
    }
    check(!contains(second, "HOST_SCOPE_ONLY:"),
          "a later call does not print the list a second time");
}

// Pulls the string literals out of one source file. Comments are skipped, so
// this checks what a user could actually see and leaves the internal notes
// alone - the wording rules are about output, not about how the code is
// annotated.
std::vector<std::string> stringLiteralsIn(const std::string& path) {
    std::vector<std::string> literals;
    std::ifstream input(path);
    if (!input) {
        return literals;
    }
    std::string line;
    bool inBlockComment = false;
    while (std::getline(input, line)) {
        bool inLineComment = false;
        bool inString = false;
        bool escaped = false;
        std::string current;
        for (std::size_t i = 0; i < line.size(); ++i) {
            const char c = line[i];
            if (inLineComment) {
                break;
            }
            if (inBlockComment) {
                if (c == '*' && i + 1 < line.size() && line[i + 1] == '/') {
                    inBlockComment = false;
                    ++i;
                }
                continue;
            }
            if (!inString) {
                if (c == '/' && i + 1 < line.size() && line[i + 1] == '/') {
                    inLineComment = true;
                    continue;
                }
                if (c == '/' && i + 1 < line.size() && line[i + 1] == '*') {
                    inBlockComment = true;
                    ++i;
                    continue;
                }
                if (c == '"') {
                    inString = true;
                    escaped = false;
                    current.clear();
                }
                continue;
            }
            // Inside a literal.
            if (escaped) {
                current.push_back(c);
                escaped = false;
                continue;
            }
            if (c == '\\') {
                escaped = true;
                current.push_back(c);
                continue;
            }
            if (c == '"') {
                literals.push_back(current);
                inString = false;
                current.clear();
                continue;
            }
            current.push_back(c);
        }
    }
    return literals;
}

void collectSources(const std::string& root, std::vector<std::string>& out) {
    std::error_code ec;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(root, ec)) {
        if (ec) {
            return;
        }
        if (!entry.is_regular_file(ec)) {
            continue;
        }
        const std::string extension = entry.path().extension().string();
        if (extension == ".cpp" || extension == ".hpp") {
            out.push_back(entry.path().string());
        }
    }
}

void testNoBannedWordInUserFacingStrings() {
    std::printf("no user-facing string uses the banned phrasing\n");

    // The wording rules in update.md, applied to every string literal in the
    // source tree. Comments are excluded by stringLiteralsIn().
    static const char* kBanned[] = {
        "fail-closed",     "fail closed",  "honest",
        "honestly",        "overstate",    "rather than silently",
        "genuinely",       "robust",       "comprehensive",
        "designed with reference to",
    };

    const std::string sourceDir = LEDGERASE_SOURCE_DIR;
    std::vector<std::string> files;
    collectSources(sourceDir + "/src", files);
    collectSources(sourceDir + "/include", files);
    collectSources(sourceDir + "/cli", files);
    collectSources(sourceDir + "/gui", files);
    check(!files.empty(), "source files were found to scan");

    std::size_t literals = 0;
    std::size_t offenders = 0;
    for (const std::string& file : files) {
        for (const std::string& literal : stringLiteralsIn(file)) {
            ++literals;
            std::string lower = literal;
            std::transform(lower.begin(), lower.end(), lower.begin(),
                           [](unsigned char c) {
                               return static_cast<char>(std::tolower(c));
                           });
            for (const char* banned : kBanned) {
                if (lower.find(banned) != std::string::npos) {
                    std::printf("       %s: \"%s\"\n",
                                file.substr(file.rfind('/') + 1).c_str(),
                                literal.substr(0, 70).c_str());
                    ++offenders;
                }
            }
        }
    }

    std::printf("       scanned %zu string literals in %zu files\n", literals,
                files.size());
    check(literals > 500, "a substantial number of literals was scanned");
    check(offenders == 0, "no user-facing string contains a banned phrase");
}


// The operator identity is only useful if it survives sudo.
//
// A certificate that recorded "root" would name a machine account rather than
// the person who authorised destroying a disk. The test sets the sudo
// environment variables and checks that the invoking user is taken from
// SUDO_USER rather than from USER, which sudo overwrites.
void testOperatorIdentityUnderSudo() {
    std::printf("the invoking user and the effective user are recorded "
                "separately\n");

    // A clean environment first, so the ambient one cannot influence the result.
    ::unsetenv("SUDO_USER");
    ::unsetenv("SUDO_UID");
    const OperatorIdentity plain = currentOperatorIdentity();
    check(!plain.invokingUser.empty(),
          "an invoking user is always determined, even with no sudo");
    check(plain.invokingUid != 0,
          "the invoking user's uid is resolved from the passwd database");
    check(!plain.effectiveUser.empty(), "an effective user is always determined");
    if (plain.invokingUser == plain.effectiveUser) {
        check(!plain.elevated,
              "a run that did not elevate is not recorded as elevated");
    } else {
        check(plain.elevated,
              "a run whose effective user differs is recorded as elevated");
    }

    // Now the case that motivated the change.
    ::setenv("SUDO_USER", "analyst", 1);
    ::setenv("SUDO_UID", "0", 1);
    // sudo resets these to the target account, so they must NOT be what is
    // recorded as the operator.
    ::setenv("USER", "root", 1);
    ::setenv("LOGNAME", "root", 1);

    const OperatorIdentity elevated = currentOperatorIdentity();
    check(elevated.invokingUser == "analyst",
          "SUDO_USER is recorded as the operator, not USER or LOGNAME");
    check(elevated.invokingUid == 0, "SUDO_UID is recorded as the operator's uid");
    check(elevated.effectiveUser != "analyst",
          "the effective user is not the invoking user when elevating");
    check(elevated.elevated,
          "a sudo run is recorded as elevated rather than as plain root");

    // And the same bundle carries both, distinctly.
    EvidenceBundle bundle;
    bundle.operatorName = elevated.invokingUser;
    bundle.invokingUser = elevated.invokingUser;
    bundle.invokingUid = elevated.invokingUid;
    bundle.effectiveUser = elevated.effectiveUser;
    bundle.effectiveUid = elevated.effectiveUid;
    bundle.elevated = elevated.elevated;

    nlohmann::json document = bundle;
    check(document.contains("operator_invoking_user"),
          "the bundle records the invoking user");
    check(document.contains("operator_effective_user"),
          "the bundle records the effective user");
    check(document.at("operator_invoking_user").get<std::string>() == "analyst",
          "the recorded invoking user is the person, not root");

    EvidenceBundle readBack;
    document.get_to(readBack);
    check(readBack.invokingUser == "analyst",
          "the invoking user survives a JSON round trip");
    check(readBack.effectiveUser == elevated.effectiveUser,
          "the effective user survives a JSON round trip");
    check(readBack.elevated,
          "the elevated flag survives a JSON round trip");

    // A schema-1 bundle has only the single name, and must still read.
    nlohmann::json legacy = nlohmann::json::parse(
        "{\"schema\":\"sanitizer.evidence_bundle/1\",\"operator\":\"analyst\"}");
    EvidenceBundle old;
    legacy.get_to(old);
    check(old.invokingUser == "analyst",
          "a schema 1 bundle with one operator name still reads, and the "
          "invoking user falls back to it");

    ::unsetenv("SUDO_USER");
    ::unsetenv("SUDO_UID");
    ::unsetenv("USER");
    ::unsetenv("LOGNAME");
}

// ---------------------------------------------------------------------------
// Limitation registry
// ---------------------------------------------------------------------------

void testLimitationsAreUnique() {
    std::printf("the same limitation cannot be recorded twice\n");

    LimitationSet set;
    set.add(LimitationId::HOST_SCOPE_ONLY);
    set.add(LimitationId::HOST_SCOPE_ONLY);
    set.add(LimitationId::HOST_SCOPE_ONLY);
    check(set.size() == 1, "three identical adds produce one entry");

    // The fact that used to be recorded by four different modules collapses.
    LimitationSet fromPlan;
    fromPlan.add(LimitationId::SELF_VERIFIED);
    LimitationSet fromVerification;
    fromVerification.add(LimitationId::SELF_VERIFIED);
    fromVerification.add(LimitationId::HOST_SCOPE_ONLY);
    fromPlan.merge(fromVerification);
    check(fromPlan.size() == 2,
          "merging two sets does not duplicate a shared limitation");
    check(fromPlan.contains(LimitationId::SELF_VERIFIED),
          "the merged set still contains the shared limitation");
    check(fromPlan.contains(LimitationId::HOST_SCOPE_ONLY),
          "the merge brought in the other set's entry");

    // Detail makes an entry distinct: two probe failures with different errors
    // are two facts.
    LimitationSet probes;
    probes.add(LimitationId::PROBE_FAILED, "open failed");
    probes.add(LimitationId::PROBE_FAILED, "identify failed");
    probes.add(LimitationId::PROBE_FAILED, "open failed");
    check(probes.size() == 2,
          "the same ID with two different details is two entries");
    check(contains(probes.texts()[0], "open failed"),
          "the detail is carried into the rendered text");
    check(contains(probes.texts()[0], "PROBE_FAILED"),
          "the rendered text is prefixed with the ID");
}

void testEveryIdIsWellFormed() {
    std::printf("every registered limitation is complete and grouped\n");

    const std::vector<LimitationEntry>& table = knownLimitationEntries();
    check(!table.empty(), "the registry is not empty");

    std::set<std::string> ids;
    const std::vector<std::string>& groups = limitationGroups();
    check(groups.size() <= 4, "there are at most four group headings");

    bool allGrouped = true;
    bool allNamed = true;
    bool allSentences = true;
    std::set<std::string> observedGroups;
    for (const LimitationEntry& entry : table) {
        if (entry.idText.empty() || ids.count(entry.idText) != 0) {
            std::printf("       bad or duplicate ID: '%s'\n",
                        entry.idText.c_str());
            allNamed = false;
        }
        ids.insert(entry.idText);
        if (std::find(groups.begin(), groups.end(), entry.group) == groups.end()) {
            std::printf("       unknown group '%s' on %s\n", entry.group.c_str(),
                        entry.idText.c_str());
            allGrouped = false;
        }
        observedGroups.insert(entry.group);
        if (entry.text.empty() || entry.text.back() != '.' ||
            entry.text.size() < 20) {
            std::printf("       %s is not a full sentence\n",
                        entry.idText.c_str());
            allSentences = false;
        }
    }

    check(allNamed, "every entry has a unique non-empty ID");
    check(allGrouped, "every entry belongs to one of the declared groups");
    check(allSentences, "every entry is a full sentence ending in a full stop");
    check(observedGroups.size() <= 4, "no more than four groups are in use");
}

void testBannedPhrasing() {
    std::printf("no registered sentence uses the banned phrasing\n");

    // From update.md. These phrases are the ones whose absence cannot be left
    // to a later read-through.
    static const char* kBanned[] = {
        "fail-closed",     "fail closed",  "honest",
        "honestly",        "overstate",    "rather than silently",
        "genuinely",       "robust",       "comprehensive",
        "designed with reference to",
    };

    const std::vector<LimitationEntry>& table = knownLimitationEntries();
    bool clean = true;
    for (const LimitationEntry& entry : table) {
        std::string haystack = entry.idText + " " + entry.text;
        std::transform(haystack.begin(), haystack.end(), haystack.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        for (const char* banned : kBanned) {
            if (haystack.find(banned) != std::string::npos) {
                std::printf("       %s contains '%s'\n", entry.idText.c_str(),
                            banned);
                clean = false;
            }
        }
    }
    check(clean, "no limitation sentence contains a banned phrase");
}

void testRendering() {
    std::printf("a rendered limitation is ID, sentence, then detail\n");

    LimitationSet set;
    set.add(LimitationId::CLEAR_ONLY);
    check(set.texts().size() == 1, "one entry renders one line");
    check(contains(set.texts()[0], "CLEAR_ONLY"), "the line starts with the ID");

    LimitationSet withDetail;
    withDetail.add(LimitationId::PROBE_FAILED, "device busy");
    check(contains(withDetail.texts()[0], "PROBE_FAILED"),
          "a detailed entry still starts with the ID");
    check(contains(withDetail.texts()[0], "device busy"),
          "the detail appears in the line");
    check(withDetail.texts()[0].find('(') != std::string::npos,
          "the detail is bracketed so the sentence stays readable");
}

} // namespace

int main() {
    testProgressFields();
    testPacManGeometryFollowsThePercentage();
    testANarrowBarDropsCirclesNotTheGaps();
    testMouthCaseAlternatesOnly();
    testTheBarIsSparseAndKeepsItsGaps();
    testAsciiFallback();
    testVerifyPhase();
    testNarrowTerminal();
    testReporterCallbackSequence();
    testSummaryStaysShort();
    testVerbosePrintsTheFullListOnce();

    testOperatorIdentityUnderSudo();
    testLimitationsAreUnique();
    testEveryIdIsWellFormed();
    testBannedPhrasing();
    testNoBannedWordInUserFacingStrings();
    testRendering();

    if (g_failures == 0) {
        std::printf("\nAll progress and limitation checks passed.\n");
        return 0;
    }
    std::printf("\n%d check(s) failed.\n", g_failures);
    return 1;
}
