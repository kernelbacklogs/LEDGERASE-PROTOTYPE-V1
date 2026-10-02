// Terminal progress display for long-running writes.
//
// One class, one place that formats progress. The write loop calls
// onProgress(); nothing else prints a progress line. An earlier version of
// this code had two formatters and one of them printed "0%" for a device
// with no progress field, which is the failure this single-owner design
// exists to prevent.
//
// Cosmetic only. Nothing here reaches the evidence file, influences a
// decision, or is read back by another component.

#ifndef LEDGERASE_PROGRESS_REPORTER_HPP
#define LEDGERASE_PROGRESS_REPORTER_HPP

#include <chrono>
#include <cstdint>
#include <string>

namespace ledgerase {

enum class ProgressPhase {
    WRITE,     // host overwrite
    VERIFY,    // read-back sampling
};

struct ProgressConfig {
    // False when stdout is redirected or a TTY is not available, when
    // --quiet or --json was given, or for --no-progress.
    bool enabled = true;
    // ASCII glyphs for a terminal that cannot show UTF-8.
    bool unicode = true;
    // Cells the bar occupies before the other fields are added.
    int barCells = 24;
    int terminalWidth = 80;
};

// Formats one line. Public so the output can be asserted on without a TTY.
std::string formatProgress(const ProgressConfig& config,
                           ProgressPhase phase,
                           unsigned pass,
                           unsigned totalPasses,
                           uint64_t done,
                           uint64_t total,
                           double bytesPerSecond,
                           uint64_t etaSeconds,
                           bool chomping,
                           unsigned itemsDone = 0,
                           unsigned itemsTotal = 0);

class ProgressReporter {
public:
    explicit ProgressReporter(ProgressConfig config);

    ProgressReporter(const ProgressReporter&) = delete;
    ProgressReporter& operator=(const ProgressReporter&) = delete;
    ~ProgressReporter();

    // Fed by the write loop. Cheap to call: it decides whether to draw before
    // doing any work.
    // `itemsDone`/`itemsTotal` are only used by ProgressPhase::VERIFY, where
    // the unit is sampled sectors rather than bytes.
    void onProgress(ProgressPhase phase,
                    uint64_t done,
                    uint64_t total,
                    unsigned pass = 1,
                    unsigned totalPasses = 1,
                    unsigned itemsDone = 0,
                    unsigned itemsTotal = 0);

    // Replaces the bar with a single line and restores the cursor.
    void finish();
    // Draws the current state once, ignoring the rate limit. Used by tests.
    void drawNow(ProgressPhase phase,
                 uint64_t done,
                 uint64_t total,
                 unsigned pass = 1,
                 unsigned totalPasses = 1);
    // Exposed for tests: the last line this reporter would print.
    const std::string& lastLine() const { return lastLine_; }

    // Detects a usable terminal and UTF-8 support for stdout.
    static ProgressConfig detect(bool suppressed, bool unicodeCapable);

private:
    void draw(ProgressPhase phase,
              uint64_t done,
              uint64_t total,
              unsigned pass,
              unsigned totalPasses);
    void hideCursor();
    void showCursor();

    ProgressConfig config_;
    bool cursorHidden_ = false;
    bool finished_ = false;
    // Rate limit: at most 4 redraws a second, and at most one per 4 MB, so
    // drawing cannot slow the write.
    std::chrono::steady_clock::time_point lastDraw_{};
    uint64_t lastDrawnBytes_ = 0;
    std::string lastLine_;
    // Throughput is measured over a trailing window, not since start, so a
    // brief stall does not drag the average down for the rest of the run.
    std::chrono::steady_clock::time_point windowStart_{};
    uint64_t windowStartBytes_ = 0;
    std::chrono::steady_clock::time_point start_{};
    double rate_ = 0.0;
    // False until the first measurement lands, so a device written in under a
    // second still gets a rate instead of showing "--" for the whole run.
    bool haveRate_ = false;
    unsigned itemsDone_ = 0;
    unsigned itemsTotal_ = 0;
    // Alternates so the pac-man glyph reads as chewing.
    unsigned frame_ = 0;
};

// Process-wide hook.
//
// The sanitization layer has no dependency on the CLI and its methods are
// constructed in several places, including tests, so threading a reporter
// through every constructor would spread a display concern through the
// engine. The hook keeps the write loop free of any UI knowledge: it asks
// whether a reporter is installed and calls it if so.
void setActiveProgressReporter(ProgressReporter* reporter);
ProgressReporter* activeProgressReporter();

} // namespace ledgerase

#endif // LEDGERASE_PROGRESS_REPORTER_HPP
