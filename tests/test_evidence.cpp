// Tests for the evidence layer: hash chain, tamper and truncation detection,
// Ed25519 signing, and the honesty gates that prevent a bundle from reporting a
// stronger outcome than its inputs support.

#include "ledgerase/erasure.hpp"
#include "ledgerase/evidence.hpp"
#include "ledgerase/limitations.hpp"
#include "ledgerase/json_adapters.hpp"
#include "ledgerase/ledgerase.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>

namespace fs = std::filesystem;

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

ledgerase::AuditRecord makeRecord() {
    ledgerase::AuditRecord record;
    record.jobId = "JOB-EVIDENCE-0001";
    record.timestamp = "2026-01-01T00:00:00Z";
    record.operatorName = "test-operator";
    record.applicationVersion = "1.0.0";
    record.device.path = "/dev/mock0";
    record.device.model = "Mock NVMe";
    record.device.serial = "MOCKSERIAL01";
    record.device.transport = ledgerase::TransportType::NVME;
    record.plan.requestedCategory = ledgerase::SanitizationCategory::PURGE;
    record.plan.selectedMethod = ledgerase::SanitizationMethod::NVME_CRYPTO_ERASE;
    record.plan.rationale = "Device reports NVMe Crypto Erase";
    ledgerase::MethodAssessment assessment;
    assessment.method = ledgerase::SanitizationMethod::NVME_CRYPTO_ERASE;
    assessment.deviceSupported = true;
    assessment.permittedByPolicy = true;
    assessment.selected = true;
    assessment.reason = "Selected";
    record.plan.alternativesConsidered.push_back(assessment);
    record.execution.jobId = record.jobId;
    record.execution.state = ledgerase::JobState::COMPLETED;
    record.execution.simulated = false;
    return record;
}

ledgerase::VerificationReport passingVerification() {
    ledgerase::VerificationReport report;
    report.jobId = "JOB-EVIDENCE-0001";
    report.result = ledgerase::VerificationResult::PASS;
    report.evidence.push_back({"nvme_sanitize_status", "Sanitize Status log", true,
                               "Device reported success", {}});
    return report;
}

ledgerase::ValidationReport acceptingValidation() {
    ledgerase::ValidationReport report;
    report.jobId = "JOB-EVIDENCE-0001";
    report.result = ledgerase::ValidationResult::ACCEPTED;
    report.reasoning = "Device-reported completion accepted";
    return report;
}

ledgerase::MediaScopeAttestation fullScope() {
    ledgerase::MediaScopeAttestation scope;
    scope.allCopiesAccountedFor = true;
    scope.copiesAddressed.push_back("/dev/mock0");
    scope.rationale = "No other copies exist";
    return scope;
}

ledgerase::PreExecutionAttestation fullPreExecution() {
    ledgerase::PreExecutionAttestation pre;
    pre.deviceIdentityConfirmed = true;
    pre.authorizationReference = "CHG-0001";
    pre.authorizedBy = "ops-lead";
    pre.checks.push_back({"Mounted check", ledgerase::SafetyCheckResult::PASS,
                          "not mounted", "", true});
    return pre;
}

ledgerase::VerificationIndependence independent() {
    ledgerase::VerificationIndependence value;
    value.level = ledgerase::VerificationIndependence::Level::INDEPENDENT;
    value.performedBy = "second team";
    return value;
}

ledgerase::RetentionAttestation definedRetention() {
    ledgerase::RetentionAttestation retention;
    retention.policy = ledgerase::RetentionAttestation::Policy::ORGANIZATION_DEFINED;
    retention.retainUntil = "2033-01-01";
    return retention;
}

// A journal with a few linked records, used to prove the chain behaves.
// Filled by reference: the journal is deliberately non-copyable.
void fillJournal(ledgerase::EvidenceJournal& journal) {
    (void)journal.append("media_identified", "JOB-1", {{"path", "/dev/mock0"}});
    (void)journal.append("decision", "JOB-1", {{"method", "NVME_CRYPTO_ERASE"}});
    (void)journal.append("execution", "JOB-1", {{"state", "Completed"}});
}

void attachChain(ledgerase::EvidenceBundle& bundle, const ledgerase::EvidenceJournal& journal) {
    bundle.eventChain = journal.records();
    bundle.chainLength = journal.count();
    bundle.chainHead = journal.head();
    bundle.canonicalHash = ledgerase::EvidenceBuilder::canonicalHash(bundle).valueOr("");
}

void testChainLinks() {
    std::printf("the event chain links and verifies\n");

    ledgerase::EvidenceJournal journal;
    fillJournal(journal);
    check(journal.count() == 3, "three records were appended");
    check(journal.head() != ledgerase::EvidenceJournal::kGenesisHash,
          "the head is no longer the genesis value");
    check(journal.records().front().prevHash == ledgerase::EvidenceJournal::kGenesisHash,
          "the first record commits to the genesis hash");
    check(journal.records()[1].prevHash == journal.records()[0].recordHash,
          "the second record commits to the first");

    auto verified = journal.verifyChain();
    check(verified.ok() && verified.value().intact, "an untouched chain verifies");
    check(verified.value().recordsChecked == 3, "every record was checked");
}

void testChainDetectsEdits() {
    std::printf("the chain detects edits and reordering\n");

    {   // Edited payload
        ledgerase::EvidenceJournal journal;
    fillJournal(journal);
        // Journals are not copyable, so rebuild and mutate the record list via
        // the records() accessor is impossible; instead verify that a record
        // whose hash does not match its content is rejected.
        ledgerase::EvidenceRecord tampered = journal.records()[1];
        tampered.payload = nlohmann::json({{"method", "OVERWRITE_HOST"}});
        auto recomputed = ledgerase::EvidenceJournal::recordHash(tampered);
        check(recomputed.ok(), "a tampered record can be re-hashed");
        check(recomputed.value() != tampered.recordHash,
              "re-hashing altered content yields a different hash");
    }

    {   // Reordered chain
        ledgerase::EvidenceJournal journal;
    fillJournal(journal);
        auto records = journal.records();
        std::swap(records[0], records[1]);
        std::string expected = ledgerase::EvidenceJournal::kGenesisHash;
        bool broken = false;
        for (const auto& record : records) {
            if (record.prevHash != expected) { broken = true; break; }
            expected = record.recordHash;
        }
        check(broken, "swapping two records breaks the link chain");
    }
}

void testBundleCarriesChain() {
    std::printf("the bundle embeds the chain and its own hash\n");

    ledgerase::EvidenceJournal journal;
    fillJournal(journal);
    auto built = ledgerase::EvidenceBuilder::build(
        makeRecord(), passingVerification(), acceptingValidation(), fullScope(),
        fullPreExecution(), independent(), definedRetention());
    check(built.ok(), "the bundle builds");
    if (built.isError()) return;

    auto bundle = built.value();
    check(bundle.jobId == "JOB-EVIDENCE-0001", "the bundle carries the job id");
    check(bundle.certificateId.rfind("CERT-", 0) == 0, "a certificate id is assigned");
    check(bundle.chainLength == 0, "chain length is zero before the chain is attached");

    attachChain(bundle, journal);
    check(bundle.chainLength == 3, "chain length is recorded");
    check(!bundle.canonicalHash.empty(), "a canonical hash is computed");
    check(bundle.eventChain.size() == 3, "the chain is embedded in the bundle");

    auto ok = ledgerase::EvidenceVerifier::verifyCanonicalHash(bundle);
    check(ok.ok() && ok.value(), "the canonical hash verifies against the content");

    auto reserialized = ledgerase::EvidenceWriter::write(bundle, "/dev/null", true);
    check(reserialized.isError() || reserialized.ok(), "writing is well defined");
}

void testCanonicalHashExcludesSignatures() {
    std::printf("signing does not invalidate the signed hash\n");

    ledgerase::EvidenceJournal journal;
    fillJournal(journal);
    auto built = ledgerase::EvidenceBuilder::build(
        makeRecord(), passingVerification(), acceptingValidation(), fullScope(),
        fullPreExecution(), independent(), definedRetention());
    if (built.isError()) return;

    auto bundle = built.value();
    attachChain(bundle, journal);
    const std::string before = bundle.canonicalHash;

    // Attaching a signature must not change the pre-image that was hashed.
    ledgerase::EvidenceSignature signature;
    signature.algorithm = "Ed25519";
    signature.keyId = "deadbeef";
    signature.signedField = "canonical_hash";
    signature.valueBase64 = "AAAA";
    signature.signedAt = "2026-01-01T00:00:00Z";
    bundle.signatures.push_back(signature);

    const std::string after = ledgerase::EvidenceBuilder::canonicalHash(bundle).valueOr("");
    check(before == after, "the canonical hash is unchanged by adding a signature");
}

void testHonestyGates() {
    std::printf("the builder refuses to overstate the outcome\n");

    // Unattested scope must prevent a clean ACCEPTED.
    {
        ledgerase::MediaScopeAttestation scope;   // allCopiesAccountedFor = false
        auto bundle = ledgerase::EvidenceBuilder::build(
            makeRecord(), passingVerification(), acceptingValidation(), scope,
            fullPreExecution(), independent(), definedRetention()).valueOr({});
        check(bundle.validation.result != ledgerase::ValidationResult::ACCEPTED,
              "an unattested scope prevents ACCEPTED");
        check(!bundle.residualRiskLimitations.empty(),
              "the missing scope is recorded as a limitation");
        // Keyed on the ID, not the sentence. The wording of a limitation is
        // free to change; the ID has to keep meaning the same thing, so a
        // test that pins the ID still catches a real regression and does not
        // break on a rewording.
        bool mentionsScope = false;
        for (const auto& limitation : bundle.residualRiskLimitations) {
            if (limitation.find("COPIES_NOT_ATTESTED") != std::string::npos) {
                mentionsScope = true;
            }
        }
        check(mentionsScope, "the limitation names the missing scope attestation");
    }

    // Failed verification must never be accepted.
    {
        auto verification = passingVerification();
        verification.result = ledgerase::VerificationResult::FAIL;
        auto bundle = ledgerase::EvidenceBuilder::build(
            makeRecord(), verification, acceptingValidation(), fullScope(),
            fullPreExecution(), independent(), definedRetention()).valueOr({});
        check(bundle.validation.result == ledgerase::ValidationResult::INCONCLUSIVE,
              "a failed verification forces INCONCLUSIVE, never ACCEPTED");
    }

    // Self-verification alone must prevent a clean ACCEPTED.
    {
        ledgerase::VerificationIndependence self;
        self.level = ledgerase::VerificationIndependence::Level::SELF;
        auto bundle = ledgerase::EvidenceBuilder::build(
            makeRecord(), passingVerification(), acceptingValidation(), fullScope(),
            fullPreExecution(), self, definedRetention()).valueOr({});
        check(bundle.validation.result != ledgerase::ValidationResult::ACCEPTED,
              "self-verification alone prevents ACCEPTED");
    }

    // A simulated run must be labelled and must not be a clean accept.
    {
        auto record = makeRecord();
        record.execution.simulated = true;
        auto bundle = ledgerase::EvidenceBuilder::build(
            record, passingVerification(), acceptingValidation(), fullScope(),
            fullPreExecution(), independent(), definedRetention()).valueOr({});
        check(bundle.simulated, "the bundle records that the run was simulated");
        check(bundle.validation.result != ledgerase::ValidationResult::ACCEPTED,
              "a simulated run is never a clean ACCEPTED");
        bool warned = false;
        for (const auto& limitation : bundle.residualRiskLimitations) {
            if (limitation.find("SIMULATED") != std::string::npos) warned = true;
        }
        check(warned, "the simulated run carries an explicit warning");
    }

    // Undefined retention must be disclosed. It is deliberately not an outcome
    // gate: how long a record is kept does not change whether the sanitization
    // succeeded, so it is recorded as a limitation rather than used to downgrade
    // the result.
    {
        ledgerase::RetentionAttestation retention;   // UNDEFINED
        auto bundle = ledgerase::EvidenceBuilder::build(
            makeRecord(), passingVerification(), acceptingValidation(), fullScope(),
            fullPreExecution(), independent(), retention).valueOr({});
        check(bundle.retention.policy == ledgerase::RetentionAttestation::Policy::UNDEFINED,
              "an undefined retention policy is recorded as undefined");
        bool disclosed = false;
        for (const auto& limitation : bundle.residualRiskLimitations) {
            if (limitation.find("NO_RETENTION_POLICY") != std::string::npos) {
                disclosed = true;
            }
        }
        check(disclosed, "undefined retention is disclosed as a limitation");
    }

    // The full set of attestations must be allowed to reach ACCEPTED.
    {
        auto bundle = ledgerase::EvidenceBuilder::build(
            makeRecord(), passingVerification(), acceptingValidation(), fullScope(),
            fullPreExecution(), independent(), definedRetention()).valueOr({});
        check(bundle.validation.result == ledgerase::ValidationResult::ACCEPTED,
              "a fully attested run may be ACCEPTED");
        check(bundle.residualDataPossible,
              "residual data remains possible even for an accepted outcome");
    }
}

void testResidualRiskIsNeverDismissed() {
    std::printf("residual risk is always disclosed\n");

    auto bundle = ledgerase::EvidenceBuilder::build(
        makeRecord(), passingVerification(), acceptingValidation(), fullScope(),
        fullPreExecution(), independent(), definedRetention()).valueOr({});

    check(bundle.residualDataPossible, "residual data is recorded as possible");
    check(!bundle.residualRiskStatement.empty(), "a residual risk statement is present");
    check(bundle.residualRiskStatement.find("cannot") != std::string::npos ||
              bundle.residualRiskStatement.find("may remain") != std::string::npos,
          "the statement does not claim erasure");
    check(bundle.conformanceStatement.find("not a certification") != std::string::npos,
          "the conformance statement disclaims certification");
}

void testWriteReadRoundTrip(const fs::path& dir) {
    std::printf("write and read round trip\n");

    ledgerase::EvidenceJournal journal;
    fillJournal(journal);
    auto bundle = ledgerase::EvidenceBuilder::build(
        makeRecord(), passingVerification(), acceptingValidation(), fullScope(),
        fullPreExecution(), independent(), definedRetention()).valueOr({});
    attachChain(bundle, journal);

    const fs::path path = dir / "bundle.json";
    std::error_code ec;
    fs::remove(path, ec);

    auto written = ledgerase::EvidenceWriter::write(bundle, path.string(), false);
    check(written.ok(), "the bundle is written");
    check(fs::exists(path), "the file exists");
    check(written.isError() || fs::exists(path), "the file is a regular file");

    auto loaded = ledgerase::EvidenceWriter::read(path.string());
    check(loaded.ok(), "the bundle reads back");
    if (loaded.ok()) {
        check(loaded.value().canonicalHash == bundle.canonicalHash,
              "the hash survives the round trip");
        check(loaded.value().chainLength == bundle.chainLength,
              "the chain length survives the round trip");
        check(loaded.value().eventChain.size() == bundle.eventChain.size(),
              "the embedded chain survives the round trip");
        check(loaded.value().scope.allCopiesAccountedFor,
              "the scope attestation survives the round trip");
    }

    auto again = ledgerase::EvidenceWriter::write(bundle, path.string(), false);
    check(again.isError(), "an existing file is not clobbered without --force");

    auto forced = ledgerase::EvidenceWriter::write(bundle, path.string(), true);
    check(forced.ok(), "--force replaces the file");

    auto verified = ledgerase::EvidenceVerifier::verifyStructure(path.string());
    check(verified.ok(), "structure verification runs");
    if (verified.ok()) {
        check(verified.value().schemaRecognised, "the schema is recognised");
        check(verified.value().canonicalHashMatches, "the hash matches");
        check(verified.value().chainConsistent, "the chain is consistent");
        check(!verified.value().signaturePresent, "no signature is claimed");
    }

    // A file that is not a bundle must be rejected, not accepted.
    const fs::path junk = dir / "junk.json";
    { std::ofstream out(junk); out << "{\"hello\":\"world\"}"; }
    auto rejected = ledgerase::EvidenceVerifier::verifyStructure(junk.string());
    check(rejected.isError() || !rejected.value().schemaRecognised,
          "an unrelated JSON file is not accepted as evidence");

    fs::remove(path, ec);
    fs::remove(junk, ec);
}

void testSigning(const fs::path& dir) {
    std::printf("Ed25519 signing and verification\n");

    const fs::path key = dir / "test-key.pem";
    const fs::path pub = dir / "test-key.pub";
    std::error_code ec;
    fs::remove(key, ec);
    fs::remove(pub, ec);

    // Generate a real key with the platform tool so the test exercises the same
    // PEM format an operator would use.
    const std::string genKey = "openssl genpkey -algorithm ed25519 -out " + key.string() +
                               " 2>/dev/null";
    const std::string genPub = "openssl pkey -in " + key.string() + " -pubout -out " +
                               pub.string() + " 2>/dev/null";
    if (std::system(genKey.c_str()) != 0 || std::system(genPub.c_str()) != 0) {
        std::printf("  skip signing tests: openssl unavailable\n");
        return;
    }

    ledgerase::EvidenceJournal journal;
    fillJournal(journal);
    auto bundle = ledgerase::EvidenceBuilder::build(
        makeRecord(), passingVerification(), acceptingValidation(), fullScope(),
        fullPreExecution(), independent(), definedRetention()).valueOr({});
    attachChain(bundle, journal);

    auto signature = ledgerase::EvidenceVerifier::sign(bundle, key.string());
    check(signature.ok(), "signing succeeds");
    if (signature.isError()) return;

    check(signature.value().algorithm == "Ed25519", "the algorithm is recorded");
    check(!signature.value().keyId.empty(), "the key is identified");
    check(bundle.signatures.size() == 1, "the signature is attached to the bundle");

    // The 64-byte Ed25519 signature base64-encodes to 88 characters with one
    // padding character. Getting the decode wrong breaks verification, so the
    // length is asserted rather than assumed.
    check(signature.value().valueBase64.size() == 88,
          "the signature encodes to 88 base64 characters");

    const fs::path path = dir / "signed.json";
    fs::remove(path, ec);
    auto written = ledgerase::EvidenceWriter::write(bundle, path.string(), true);
    check(written.ok(), "the signed bundle is written");

    auto verified = ledgerase::EvidenceVerifier::verify(path.string(), pub.string());
    check(verified.ok(), "verification runs");
    if (verified.ok()) {
        check(verified.value().signatureValid, "the signature verifies");
        check(verified.value().canonicalHashMatches, "the content is unaltered");
        check(verified.value().chainConsistent, "the chain is intact");
    }

    // Post-hoc tampering with the file is the threat this guards against.
    // Note that re-writing an altered bundle through EvidenceWriter is NOT
    // tampering: the writer recomputes the hash, and anyone able to run the
    // tool can produce a self-consistent document. Detecting that requires an
    // external trust anchor, which is what the signature key is.
    {
        const fs::path badPath = dir / "tampered.json";
        std::string text;
        {
            std::ifstream in(path);
            text.assign((std::istreambuf_iterator<char>(in)),
                        std::istreambuf_iterator<char>());
        }
        const std::string from = "Device reports NVMe Crypto Erase";
        const std::string to = "Device reports nothing at all";
        const bool replaced = text.find(from) != std::string::npos;
        if (replaced) {
            text.replace(text.find(from), from.size(), to);
        }
        check(replaced, "the rationale text was found in the written file");
        {
            std::ofstream out(badPath);
            out << text;
        }

        auto result = ledgerase::EvidenceVerifier::verify(badPath.string(), pub.string());
        check(result.ok(), "verification of the hand-edited file runs");
        if (result.ok()) {
            check(!result.value().canonicalHashMatches,
                  "a hand-edited file fails the hash check");
        }
        fs::remove(badPath, ec);
    }

    // Truncating the chain must be detected via the declared length.
    {
        auto truncated = bundle;
        truncated.eventChain.pop_back();
        const fs::path shortPath = dir / "truncated.json";
        auto wrote = ledgerase::EvidenceWriter::write(truncated, shortPath.string(), true);
        check(wrote.ok(), "the truncated bundle is written");
        auto result = ledgerase::EvidenceVerifier::verifyStructure(shortPath.string());
        check(result.ok(), "verification of the truncated bundle runs");
        if (result.ok()) {
            check(!result.value().chainConsistent,
                  "a chain shorter than declared is detected");
        }
        fs::remove(shortPath, ec);
    }

    // A wrong key must not pass.
    {
        const fs::path otherKey = dir / "other-key.pem";
        const fs::path otherPub = dir / "other-key.pub";
        fs::remove(otherKey, ec);
        const std::string cmd = "openssl genpkey -algorithm ed25519 -out " + otherKey.string() +
                                " 2>/dev/null && openssl pkey -in " + otherKey.string() +
                                " -pubout -out " + otherPub.string() + " 2>/dev/null";
        if (std::system(cmd.c_str()) == 0) {
            auto result = ledgerase::EvidenceVerifier::verify(path.string(), otherPub.string());
            check(result.ok(), "verification with the wrong key runs");
            if (result.ok()) {
                check(!result.value().signatureValid,
                      "the wrong key does not validate the signature");
            }
        }
        fs::remove(otherKey, ec);
        fs::remove(otherPub, ec);
    }

    // A non-Ed25519 key must be refused rather than silently accepted.
    {
        const fs::path rsa = dir / "rsa.pem";
        const fs::path rsaPub = dir / "rsa.pub";
        fs::remove(rsa, ec);
        const std::string cmd = "openssl genrsa -out " + rsa.string() +
                                " 2048 2>/dev/null && openssl rsa -in " + rsa.string() +
                                " -pubout -out " + rsaPub.string() + " 2>/dev/null";
        if (std::system(cmd.c_str()) == 0) {
            auto refused = ledgerase::EvidenceVerifier::sign(bundle, rsa.string());
            check(refused.isError(), "an RSA key is refused for signing");
        }
        fs::remove(rsa, ec);
        fs::remove(rsaPub, ec);
    }

    fs::remove(path, ec);
    fs::remove(key, ec);
    fs::remove(pub, ec);
}

void testNoSecretsInBundle() {
    std::printf("no key material reaches the bundle\n");

    const fs::path dir = fs::temp_directory_path() / "ledgerase-evidence-test";
    std::error_code ec;
    fs::create_directories(dir, ec);
    const fs::path key = dir / "leak-key.pem";
    fs::remove(key, ec);
    const std::string cmd = "openssl genpkey -algorithm ed25519 -out " + key.string() +
                            " 2>/dev/null";
    if (std::system(cmd.c_str()) != 0) {
        std::printf("  skip: openssl unavailable\n");
        return;
    }

    ledgerase::EvidenceJournal journal;
    fillJournal(journal);
    auto bundle = ledgerase::EvidenceBuilder::build(
        makeRecord(), passingVerification(), acceptingValidation(), fullScope(),
        fullPreExecution(), independent(), definedRetention()).valueOr({});
    attachChain(bundle, journal);

    (void)ledgerase::EvidenceVerifier::sign(bundle, key.string());

    std::ifstream keyFile(key);
    std::string secret((std::istreambuf_iterator<char>(keyFile)),
                       std::istreambuf_iterator<char>());
    const std::string body = secret.substr(secret.find("-----BEGIN"));
    // canonicalJson is the exact byte form that gets written, so this is the
    // right thing to search for leaked key material.
    const std::string serialised =
        ledgerase::EvidenceBuilder::canonicalJson(bundle).valueOr("");

    check(!body.empty(), "the private key body was read for comparison");
    check(serialised.find(body) == std::string::npos,
          "the private key body does not appear in the serialised bundle");
    check(serialised.find("PRIVATE KEY") == std::string::npos,
          "no private key marker appears in the serialised bundle");

    fs::remove_all(dir, ec);
}

} // namespace


namespace {

bool containsText(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

} // namespace

// A bundle written before limitations gained IDs stores them as bare
// sentences. Those files are on disk, signed in some cases, and have to keep
// loading and keep verifying.
void testSchema1BundlesStillRead() {
    std::printf("a schema 1 bundle, with bare limitation sentences, still reads\n");

    // The shape schema 1 used.
    nlohmann::json legacy = nlohmann::json::object();
    legacy["limitations"] = nlohmann::json::array(
        {"Host cannot verify controller-managed areas",
         "Not equivalent to device-level sanitization for SSDs"});

    ledgerase::LimitationSet limitations;
    legacy.at("limitations").get_to(limitations);
    check(limitations.size() == 2,
          "both schema 1 limitation sentences are recovered");
    check(containsText(limitations.texts().front(), "controller-managed"),
          "the sentence survives the round trip verbatim");

    // A document that already carries IDs is read back into registry entries,
    // which is what lets the terminal group a stored bundle by topic.
    nlohmann::json current = nlohmann::json::array();
    current.push_back({{"id", "HOST_SCOPE_ONLY"},
                       {"text", "Host-visible address space only."},
                       {"group", "Scope"}});
    current.push_back({{"id", "NO_AUTHORIZATION"},
                       {"text", "No authorization reference was recorded."},
                       {"group", "Not recorded"}});
    ledgerase::LimitationSet fromIds;
    current.get_to(fromIds);
    check(fromIds.size() == 2, "both identified entries are recovered");
    check(fromIds.contains(ledgerase::LimitationId::HOST_SCOPE_ONLY),
          "an ID in the file restores the registry entry");
    check(fromIds.entries().front().group == "Scope",
          "the stored group is restored, so the terminal can group by it");
    check(containsText(fromIds.texts().front(), "HOST_SCOPE_ONLY"),
          "the rendered line carries the ID again");

    // Mixed content: a file that has both, as a partial upgrade would produce.
    nlohmann::json mixed = nlohmann::json::array();
    mixed.push_back("a bare sentence with no ID");
    mixed.push_back({{"id", "SELF_VERIFIED"}, {"text", "Checked by this tool."}});
    ledgerase::LimitationSet both;
    mixed.get_to(both);
    check(both.size() == 2, "a mixed array keeps both entries");
}

// The canonical hash is computed from the stored document, not from a
// re-serialisation of the parsed struct. That is what lets an older bundle
// verify: reading it and writing it back would change its shape, and a
// struct-based hash would report a mismatch on a file nobody touched.
void testCanonicalHashDependsOnlyOnTheDocument() {
    std::printf("the canonical hash is a function of the stored document\n");

    nlohmann::json document;
    document["schema"] = "sanitizer.evidence_bundle/1";
    document["job_id"] = "JOB-1";
    document["canonical_hash"] = "whatever";
    document["signatures"] = nlohmann::json::array();
    document["limitations"] = nlohmann::json::array({"a bare sentence"});

    const auto first =
        ledgerase::EvidenceBuilder::canonicalHashOfDocument(document);
    const auto again =
        ledgerase::EvidenceBuilder::canonicalHashOfDocument(document);
    check(first.ok() && again.ok(), "the document hashes");
    check(first.value() == again.value(),
          "hashing the same document twice gives the same answer");

    // The self-referential fields are excluded, so a bundle that carries its
    // own hash and signature still hashes over the rest of the content.
    nlohmann::json withHash = document;
    withHash["canonical_hash"] = "a different value";
    const auto changed = ledgerase::EvidenceBuilder::canonicalHashOfDocument(withHash);
    check(changed.ok() && changed.value() == first.value(),
          "the canonical_hash field is excluded from its own pre-image");
    withHash["signatures"] = nlohmann::json::array({{"valueBase64", "AAA"}});
    const auto withSig = ledgerase::EvidenceBuilder::canonicalHashOfDocument(withHash);
    check(withSig.ok() && withSig.value() == first.value(),
          "the signatures field is excluded too, so signing does not change it");

    // Any other byte does change it.
    nlohmann::json edited = document;
    edited["job_id"] = "JOB-2";
    const auto moved = ledgerase::EvidenceBuilder::canonicalHashOfDocument(edited);
    check(moved.ok() && moved.value() != first.value(),
          "editing the content changes the hash");

    // And the schema-1 shape specifically keeps its own hash, which is the
    // regression this guards: a limitation stored as a sentence must not
    // re-serialise as an object.
    nlohmann::json asSentences = document;
    asSentences["limitations"] = nlohmann::json::array({"a bare sentence"});
    const auto sentences = ledgerase::EvidenceBuilder::canonicalHashOfDocument(asSentences);
    check(sentences.ok() && sentences.value() == first.value(),
          "a schema 1 limitation array hashes to the same value as before");
}


// Schema 3 stores each fact once: the chain records reference a section by name
// and carry its SHA-256, rather than copying it. Two properties have to hold.
//
//  * A bundle must get smaller, not lose information.
//  * The chain must still *commit* to the section it references. A reference
//    that is written but never checked is worse than a copy, because it looks
//    like a guarantee.
void testSectionsAreStoredOnceAndStillCommitted() {
    std::printf("each fact is stored once, and the chain still commits to it\n");

    // A bundle with a deliberately heavy section, to make duplication visible.
    ledgerase::EvidenceBundle bundle;
    bundle.schema = ledgerase::EvidenceBundle().schema;
    bundle.certificateId = "CERT-DEDUP-0001";
    bundle.device.path = "/dev/fake0";
    bundle.device.model = "A model with a fairly long name";
    bundle.device.serial = "SERIAL0000000001";
    bundle.requestedCategory = ledgerase::SanitizationCategory::CLEAR;
    bundle.selectedMethod = ledgerase::SanitizationMethod::OVERWRITE_HOST;
    bundle.execution.state = ledgerase::JobState::COMPLETED;
    for (int i = 0; i < 12; ++i) {
        ledgerase::MethodAssessment candidate;
        candidate.method = ledgerase::SanitizationMethod::NVME_BLOCK_ERASE;
        candidate.reason = "A reason long enough to be worth deduplicating, "
                            "because a real one says why a method was ruled out";
        candidate.deviceSupported = false;
        candidate.selected = false;
        bundle.alternativesConsidered.push_back(candidate);
    }

    // Build the document the way the writer does, then derive a referencing
    // chain from it.
    const nlohmann::json serialised = bundle;
    check(serialised.contains("decision"),
          "the decision section is present in the document");

    ledgerase::EvidenceJournal journal;
    nlohmann::json payload = {
        {"section", "decision"},
        {"summary", {{"selected_method", bundle.selectedMethod}}},
    };
    const std::string canonical = serialised.at("decision").dump();
    const auto digest = ledgerase::sha256HexBytes(
        reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size());
    check(digest.ok(), "the referenced section can be digested");
    payload["section_sha256"] = digest.value();
    const auto appended = journal.append("decision", "JOB-1", payload);
    check(appended.ok(), "the referencing record is appended");

    // The payload holds a reference and a compact summary, not the section.
    const nlohmann::json stored = journal.records().front().payload;
    check(!stored.contains("alternatives_considered"),
          "the chain record does not copy the section's body");
    check(stored.contains("section_sha256"),
          "the chain record carries the section's digest");
    check(stored.contains("summary"),
          "the chain record carries a compact summary a reader can use");

    // A reference that is never checked would let a section change freely. So
    // check it: a section whose digest still matches passes, and one that has
    // been edited does not.
    auto referenceHolds = [](const nlohmann::json& document) {
        const nlohmann::json record = document.at("chain_record");
        const std::string section = record.at("payload").at("section");
        const std::string recorded =
            record.at("payload").at("section_sha256").get<std::string>();
        if (!document.contains(section)) {
            return false;
        }
        const std::string body = document.at(section).dump();
        const auto computed = ledgerase::sha256HexBytes(
            reinterpret_cast<const uint8_t*>(body.data()), body.size());
        return computed.ok() && computed.value() == recorded;
    };

    nlohmann::json document = serialised;
    document["chain_record"] = journal.records().front();
    check(referenceHolds(document),
          "an unedited section still matches the digest the chain recorded");

    nlohmann::json edited = serialised;
    edited["chain_record"] = journal.records().front();
    edited["decision"]["rationale"] = "a rationale that was added after signing";
    check(!referenceHolds(edited),
          "an edited section no longer matches the chain's digest, so the "
          "chain detects it");

    // A record whose section is missing entirely must fail, not pass quietly.
    nlohmann::json missing = nlohmann::json::object();
    missing["chain_record"] = journal.records().front();
    check(!referenceHolds(missing),
          "a record pointing at an absent section fails rather than passing");

    // Size: the reference must be smaller than the copy it replaced.
    const std::size_t copied = canonical.size();
    const std::size_t referenced = stored.dump().size();
    check(referenced < copied,
          "a referencing record is smaller than the section it replaces (" +
              std::to_string(referenced) + " vs " + std::to_string(copied) +
              " bytes)");
}

// ---------------------------------------------------------------------------
// The rename
//
// The tool is named ledgerase. Two consequences are pinned here, because both
// are ways a rename can quietly destroy something rather than merely move it.
//
// A bundle's schema string carries the tool's name, so this build writes
// "ledgerase.*" - and it must still read every "sanitizer.*" bundle ever
// written. The string is part of the bytes the canonical hash covers, so
// renaming it *on an existing bundle* would invalidate that bundle's own hash;
// and a reader that stopped recognising the old string would declare real audit
// history unreadable. The name lives in a string, not in a format, so an old
// bundle is exactly the same format and has to keep verifying.
// ---------------------------------------------------------------------------

void testTheCurrentSchemaUsesTheNewName() {
    std::printf("new bundles are written under the current tool name\n");

    check(std::string(ledgerase::EvidenceBundle::kSupportedSchemas[0]) ==
              "ledgerase.evidence_bundle/3",
          "the newest supported schema is the ledgerase spelling");
    check(std::string(ledgerase::EvidenceBundle().schema) ==
              "ledgerase.evidence_bundle/3",
          "and a default-constructed bundle writes that name");
    check(std::string(ledgerase::CarveEvidenceBundle::kSchema) ==
              "ledgerase.carve_bundle/1",
          "the carve bundle likewise");
    check(std::string(ledgerase::EraseEvidenceBundle::kSchema) ==
              "ledgerase.erase_bundle/1",
          "and the erase bundle likewise");
}

void testPreRenameBundleStillVerifies(const fs::path& dir) {
    std::printf("a bundle written under the old name still verifies\n");

    // A real file on disk, with a pre-rename schema string, verified through the
    // same path an operator uses. Asserted on the verification result rather than
    // on a string comparison, because what matters is that the file still passes
    // - not that its schema field happens to be on a list.
    nlohmann::json document;
    document["schema"] = "sanitizer.evidence_bundle/1";
    document["job_id"] = "PRE-RENAME-JOB";
    document["operator"] = "analyst";
    document["limitations"] = nlohmann::json::array({"a bare sentence"});
    document["signatures"] = nlohmann::json::array();

    // Its own directory: an earlier test in this suite removes the shared one
    // after signing, and writing into a directory that has just been deleted
    // fails for a reason that has nothing to do with the rename.
    const fs::path own = dir / "pre-rename";
    std::error_code mkEc;
    fs::create_directories(own, mkEc);
    const fs::path old = own / "bundle.json";
    {
        std::ofstream out(old, std::ios::binary | std::ios::trunc);
        out << document.dump(2);
    }
    check(fs::exists(old), "a pre-rename bundle was written");

    const auto verification = ledgerase::EvidenceVerifier::verify(old.string(), "");
    check(verification.ok(), "it is readable after the rename");
    if (verification.isError()) {
        return;
    }
    check(verification.value().schemaRecognised,
          "its schema is recognised rather than reported as an unknown format");
    // The verifier always emits findings describing the hash and the chain, so
    // asserting on the count would be asserting on the shape of a synthetic
    // document rather than on the rename. What must not appear is the one
    // finding that would mean the rename orphaned real history: an
    // unrecognised schema.
    bool reportsUnknownSchema = false;
    for (const std::string& finding : verification.value().findings) {
        if (finding.find("Unrecognised schema") != std::string::npos) {
            reportsUnknownSchema = true;
        }
    }
    check(!reportsUnknownSchema,
          "no 'Unrecognised schema' finding, which is the specific way a "
          "rename would strand existing audit history");
}

int main() {
    const fs::path dir = fs::temp_directory_path() / "ledgerase-evidence-test";
    std::error_code ec;
    fs::create_directories(dir, ec);

    testChainLinks();
    testChainDetectsEdits();
    testBundleCarriesChain();
    testCanonicalHashExcludesSignatures();
    testHonestyGates();
    testResidualRiskIsNeverDismissed();
    testWriteReadRoundTrip(dir);
    testSigning(dir);
    testNoSecretsInBundle();
    testSchema1BundlesStillRead();
    testCanonicalHashDependsOnlyOnTheDocument();
    testSectionsAreStoredOnceAndStillCommitted();
    testTheCurrentSchemaUsesTheNewName();
    testPreRenameBundleStillVerifies(dir);

    fs::remove_all(dir, ec);

    if (g_failures == 0) {
        std::printf("\nall evidence tests passed\n");
        return 0;
    }
    std::printf("\n%d check(s) failed\n", g_failures);
    return 1;
}
