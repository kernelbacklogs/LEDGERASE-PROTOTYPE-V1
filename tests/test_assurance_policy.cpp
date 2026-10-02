// Tests for the local assurance policy that derives a sanitization level.
//
// This is a judgement encoded as a function, so the tests are mostly about three
// things a table-driven rule is easy to get wrong:
//
//   1. Every input maps to a level, and the mapping is total and consistent.
//   2. A level is never derived from partial input. Half an answer is not an
//      answer, and guessing the rest would be indistinguishable in the record
//      from a real decision.
//   3. Nothing the function says, and nothing the record says about it, claims
//      that NIST SP 800-88 Rev. 2 requires the level. The level names are the
//      standard's; the choice between them is this project's policy. That
//      distinction is the whole reason this function is worded the way it is,
//      so a regression that reintroduces a NIST attribution is a failure here
//      even though nothing about the returned level would change.
//
// The provenance string is checked case-insensitively and on the word "local",
// because a test that only asserted an exact string would pass if the string
// were reworded into an attribution.

#include "ledgerase/types.hpp"

#include <cstdio>
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

std::string lower(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

// The provenance statement must never let a reader conclude that the standard
// chose the level. This is checked on the rationale as well as the provenance
// field, because the rationale is what the plan report prints next to the level.
void checkNotAttributedToNist(const AssurancePolicyDecision& d,
                              const std::string& what) {
    const std::string p = lower(d.provenance);
    check(p.find("local") != std::string::npos,
          what + ": provenance names it as local policy (" + p + ")");
    check(p.find("not a nist") != std::string::npos,
          what + ": provenance explicitly disclaims being a NIST requirement");
    check(d.rationale.find("Local policy") == 0,
          what + ": the rationale is prefixed 'Local policy', so it cannot be "
                 "read as a quotation of a requirement");
    check(lower(d.rationale).find("nist") == std::string::npos,
          what + ": the rationale does not mention NIST at all");
}

// --- the mapping, exhaustively -------------------------------------------

struct Case {
    SecurityCategorization cat;
    TriState reuse;
    TriState leaving;
    SanitizationCategory expect;
    const char* why;
};

const std::vector<Case>& cases() {
    static const std::vector<Case> v = {
        // Leaving organizational control outranks everything. The argument is
        // loss of control, not the content, so even Low is destroyed.
        {SecurityCategorization::HIGH,     TriState::YES, TriState::YES, SanitizationCategory::DESTROY, "high, leaving"},
        {SecurityCategorization::MODERATE, TriState::YES, TriState::YES, SanitizationCategory::DESTROY, "moderate, leaving"},
        {SecurityCategorization::LOW,      TriState::YES, TriState::YES, SanitizationCategory::DESTROY, "low, leaving"},
        {SecurityCategorization::LOW,      TriState::NO,  TriState::YES, SanitizationCategory::DESTROY, "low, not reused, leaving"},

        // High is destroyed on its own categorisation, reused or not.
        {SecurityCategorization::HIGH, TriState::YES, TriState::NO, SanitizationCategory::DESTROY, "high, reused"},
        {SecurityCategorization::HIGH, TriState::NO,  TriState::NO, SanitizationCategory::DESTROY, "high, not reused"},

        // Moderate is purged when the media stays with the organisation.
        {SecurityCategorization::MODERATE, TriState::YES, TriState::NO, SanitizationCategory::PURGE, "moderate, reused"},
        {SecurityCategorization::MODERATE, TriState::NO,  TriState::NO, SanitizationCategory::PURGE, "moderate, not reused"},

        // Low is the only row where reuse changes the answer, and it changes it
        // between CLEAR and PURGE - not up to DESTROY.
        {SecurityCategorization::LOW, TriState::YES, TriState::NO, SanitizationCategory::CLEAR, "low, reused"},
        {SecurityCategorization::LOW, TriState::NO,  TriState::NO, SanitizationCategory::PURGE, "low, not reused"},
    };
    return v;
}

void testTheMappingIsWhatThePolicySays() {
    std::printf("the policy maps every input to the level it documents\n");
    for (const Case& c : cases()) {
        const AssurancePolicyDecision d = deriveAssuranceTier(c.cat, c.reuse, c.leaving);
        const std::string label = std::string("policy test: ") + c.why;
        check(d.derived, label + ": a decision was derived from complete input");
        check(d.tier == c.expect,
              label + ": expected " + categoryToString(c.expect) + ", got " +
                  categoryToString(d.tier));
        check(d.categorization == c.cat && d.reuseMedia == c.reuse &&
                  d.leavingOrgControl == c.leaving,
              label + ": the decision records the inputs it was given");
        check(!d.rationale.empty(), label + ": the rule that fired is stated");
        checkNotAttributedToNist(d, label);
    }
}

void testEveryCombinationIsCovered() {
    std::printf("every combination of the three inputs is decided\n");
    // 3 categorizations x 3 reuse x 3 leaving = 27. Total coverage matters more
    // here than in most tables: an unhandled combination would leave the CLI
    // with no level, and the fallback is the default rather than an error.
    const SecurityCategorization cats[] = {
        SecurityCategorization::UNSET, SecurityCategorization::LOW,
        SecurityCategorization::MODERATE, SecurityCategorization::HIGH};
    const TriState states[] = {TriState::UNSET, TriState::YES, TriState::NO};
    int decided = 0;
    int total = 0;
    for (SecurityCategorization c : cats) {
        for (TriState r : states) {
            for (TriState l : states) {
                ++total;
                const AssurancePolicyDecision d = deriveAssuranceTier(c, r, l);
                const bool complete = c != SecurityCategorization::UNSET &&
                                      r != TriState::UNSET && l != TriState::UNSET;
                if (complete) {
                    ++decided;
                    check(d.derived, "complete input derives a decision");
                } else {
                    check(!d.derived, "incomplete input derives no decision");
                }
            }
        }
    }
    check(decided == 3 * 2 * 2,
          "all 12 complete combinations are decided (" +
              std::to_string(decided) + " of " + std::to_string(total) + ")");
}

void testPartialInputDecidesNothing() {
    std::printf("partial input derives nothing rather than guessing\n");
    // Each of the three inputs on its own, and each pair.
    const SecurityCategorization low = SecurityCategorization::LOW;
    const SecurityCategorization mod = SecurityCategorization::MODERATE;
    const TriState yes = TriState::YES;
    const TriState no = TriState::NO;

    const AssurancePolicyDecision onlyCat = deriveAssuranceTier(low, TriState::UNSET, TriState::UNSET);
    check(!onlyCat.derived, "categorization alone derives nothing");
    check(!onlyCat.rationale.empty(),
          "and says why, rather than returning an empty rationale");

    const AssurancePolicyDecision onlyReuse = deriveAssuranceTier(SecurityCategorization::UNSET, yes, TriState::UNSET);
    check(!onlyReuse.derived, "reuse alone derives nothing");

    const AssurancePolicyDecision onlyLeaving = deriveAssuranceTier(SecurityCategorization::UNSET, TriState::UNSET, no);
    check(!onlyLeaving.derived, "leaving-control alone derives nothing");

    const AssurancePolicyDecision catAndReuse = deriveAssuranceTier(mod, yes, TriState::UNSET);
    check(!catAndReuse.derived,
          "two of three inputs still derives nothing: the third is a genuine "
          "question, not a formality");

    const AssurancePolicyDecision reuseAndLeaving = deriveAssuranceTier(SecurityCategorization::UNSET, yes, no);
    check(!reuseAndLeaving.derived, "reuse plus leaving-control derives nothing");
}

void testTheInputsAreRecordedNotJustTheAnswer() {
    std::printf("the decision records its inputs, not only its answer\n");
    // A record that says CLEAR without saying why is not auditable: the reader
    // cannot tell a considered decision from a default that happened to match.
    for (const Case& c : cases()) {
        const AssurancePolicyDecision d = deriveAssuranceTier(c.cat, c.reuse, c.leaving);
        const std::string label = std::string("policy test: ") + c.why;
        const std::string cat = securityCategorizationToString(c.cat);
        check(d.rationale.find(cat) != std::string::npos,
              label + ": the rationale names the categorization (" + cat + ")");
        check(d.rationale.find("Local policy") == 0,
              label + ": the rationale is attributed to the local policy");
    }
}

void testDerivedDecisionAlwaysHasProvenance() {
    std::printf("a derived decision always carries its provenance\n");
    for (const Case& c : cases()) {
        const AssurancePolicyDecision d = deriveAssuranceTier(c.cat, c.reuse, c.leaving);
        check(!d.provenance.empty(),
              std::string("policy test: ") + c.why + ": provenance is present");
    }
    // And the default on an unset decision is also populated, so a struct that
    // was never filled in cannot be read as a silent standard mandate.
    const AssurancePolicyDecision none =
        deriveAssuranceTier(SecurityCategorization::UNSET, TriState::UNSET, TriState::UNSET);
    check(!none.provenance.empty(),
          "an undecided result still carries a provenance string");
    check(lower(none.provenance).find("not a nist") != std::string::npos,
          "and that string still disclaims being a NIST requirement");
}

void testEnumerationStringsRoundTrip() {
    std::printf("the input enumerations name themselves unambiguously\n");
    // Two inputs that rendered the same would make a record ambiguous, and the
    // record is the only place the inputs survive.
    const std::vector<std::string> catNames = {
        securityCategorizationToString(SecurityCategorization::UNSET),
        securityCategorizationToString(SecurityCategorization::LOW),
        securityCategorizationToString(SecurityCategorization::MODERATE),
        securityCategorizationToString(SecurityCategorization::HIGH)};
    for (std::size_t i = 0; i < catNames.size(); ++i) {
        for (std::size_t j = i + 1; j < catNames.size(); ++j) {
            check(catNames[i] != catNames[j],
                  "categorization names are distinct: " + catNames[i] + " / " +
                      catNames[j]);
        }
    }
    const std::string unset = triStateToString(TriState::UNSET);
    const std::string yes = triStateToString(TriState::YES);
    const std::string no = triStateToString(TriState::NO);
    check(unset != yes && unset != no && yes != no,
          "the three states are distinct, so 'no' and 'unset' stay tellable apart");
    // This is the distinction the CLI flag help leans on: omitting a flag means
    // the policy cannot decide, which is not the same as answering "no".
    check(unset != no, "'unset' is not rendered as 'no'");
}

void testTheLevelOrderIsRespected() {
    std::printf("the policy never escalates past what the inputs justify\n");
    // Destroy is the strongest level and must be reached only by the two
    // documented routes: leaving control, or high categorisation.
    for (const Case& c : cases()) {
        const AssurancePolicyDecision d = deriveAssuranceTier(c.cat, c.reuse, c.leaving);
        if (d.tier == SanitizationCategory::DESTROY) {
            const bool justified =
                c.leaving == TriState::YES ||
                c.cat == SecurityCategorization::HIGH;
            check(justified,
                  std::string("policy test: ") + c.why +
                      ": DESTROY is reached only by leaving control or high "
                      "categorization");
        }
    }
}

} // namespace

int main() {
    std::printf("assurance policy: the documented mapping, its totality, and its provenance\n");
    testTheMappingIsWhatThePolicySays();
    testEveryCombinationIsCovered();
    testPartialInputDecidesNothing();
    testTheInputsAreRecordedNotJustTheAnswer();
    testDerivedDecisionAlwaysHasProvenance();
    testEnumerationStringsRoundTrip();
    testTheLevelOrderIsRespected();

    if (g_failures == 0) {
        std::printf("\nAll assurance-policy checks passed.\n");
        return 0;
    }
    std::printf("\n%d assurance-policy check(s) FAILED.\n", g_failures);
    return 1;
}
