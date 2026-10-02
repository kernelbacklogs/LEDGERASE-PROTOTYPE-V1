#include "ledgerase/evidence.hpp"
#include "ledgerase/json_adapters.hpp"
#include "ledgerase/ledgerase.hpp"

#include "evidence_document.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <random>
#include <fstream>
#include <sstream>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ctime>
#include <iomanip>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

namespace ledgerase {
namespace {

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

std::string toHex(const unsigned char* data, std::size_t size) {
    static const char* kDigits = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i) {
        out.push_back(kDigits[(data[i] >> 4) & 0x0F]);
        out.push_back(kDigits[data[i] & 0x0F]);
    }
    return out;
}

Result<std::string> sha256Hex(const std::string& data) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int length = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        return Result<std::string>::err(ErrorCode::INTERNAL_ERROR,
                                        "Unable to allocate a digest context");
    }

    const bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
                    EVP_DigestUpdate(ctx, data.data(), data.size()) == 1 &&
                    EVP_DigestFinal_ex(ctx, digest, &length) == 1;

    EVP_MD_CTX_free(ctx);

    if (!ok) {
        return Result<std::string>::err(ErrorCode::INTERNAL_ERROR,
                                        "SHA-256 computation failed");
    }
    return toHex(digest, length);
}

std::string base64Encode(const unsigned char* data, std::size_t size) {
    if (size == 0) return std::string();
    std::string out(4 * ((size + 2) / 3), '\0');
    const int written = EVP_EncodeBlock(
        reinterpret_cast<unsigned char*>(out.data()), data, static_cast<int>(size));
    if (written < 0) return std::string();
    out.resize(static_cast<std::size_t>(written));
    return out;
}

Result<std::string> base64Decode(const std::string& encoded) {
    if (encoded.empty()) return std::string();

    std::string out(3 * (encoded.size() / 4) + 3, '\0');
    const int written = EVP_DecodeBlock(
        reinterpret_cast<unsigned char*>(out.data()),
        reinterpret_cast<const unsigned char*>(encoded.data()),
        static_cast<int>(encoded.size()));
    if (written < 0) {
        return Result<std::string>::err(ErrorCode::INVALID_ARGUMENT,
                                        "Signature is not valid base64");
    }

    // EVP_DecodeBlock reports the decoded length *including* the bytes implied
    // by '=' padding, so the padding has to be subtracted here. Getting this
    // wrong yields a signature one byte too long and every verification fails.
    std::size_t effective = encoded.size();
    std::size_t padding = 0;
    while (effective > 0 && encoded[effective - 1] == '=') {
        --effective;
        ++padding;
    }
    if (padding > 2) {
        return Result<std::string>::err(ErrorCode::INVALID_ARGUMENT,
                                        "Signature has invalid base64 padding");
    }

    std::size_t length = static_cast<std::size_t>(written);
    length = length > padding ? length - padding : 0;
    out.resize(length);
    return out;
}

// Reads a key file without following symlinks. The bytes are handed straight
// to OpenSSL and are never copied into a std::string that could be logged.
Result<std::string> readKeyFile(const std::string& path) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return Result<std::string>::err(
            ErrorCode::IO_ERROR,
            "Cannot open key file " + path + ": " + std::strerror(errno),
            "Check the path, the file permissions, and that it is not a symlink");
    }

    std::string bytes;
    char buffer[4096];
    while (true) {
        const ssize_t n = ::read(fd, buffer, sizeof(buffer));
        if (n < 0) {
            if (errno == EINTR) continue;
            const int saved = errno;
            ::close(fd);
            return Result<std::string>::err(
                ErrorCode::IO_ERROR,
                "Failed reading key file " + path + ": " + std::strerror(saved));
        }
        if (n == 0) break;
        bytes.append(buffer, static_cast<std::size_t>(n));
    }
    ::close(fd);
    return bytes;
}

Result<EVP_PKEY*> loadPrivateKey(const std::string& path) {
    auto bytes = readKeyFile(path);
    if (bytes.isError()) {
        return Result<EVP_PKEY*>::err(bytes.error());
    }
    BIO* bio = BIO_new_mem_buf(bytes.value().data(), static_cast<int>(bytes.value().size()));
    if (bio == nullptr) {
        return Result<EVP_PKEY*>::err(ErrorCode::INTERNAL_ERROR,
                                      "Cannot allocate a key buffer");
    }
    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (key == nullptr) {
        return Result<EVP_PKEY*>::err(ErrorCode::INVALID_ARGUMENT,
                                      "File is not a readable PEM private key: " + path,
                                      "Expected an unencrypted PEM key, e.g. "
                                      "-----BEGIN PRIVATE KEY-----");
    }
    if (EVP_PKEY_base_id(key) != EVP_PKEY_ED25519) {
        EVP_PKEY_free(key);
        return Result<EVP_PKEY*>::err(ErrorCode::UNSUPPORTED_OPERATION,
                                      "Key is not Ed25519",
                                      "Generate one with: "
                                      "openssl genpkey -algorithm ed25519 -out key.pem");
    }
    return key;
}

Result<EVP_PKEY*> loadPublicKey(const std::string& path) {
    auto bytes = readKeyFile(path);
    if (bytes.isError()) {
        return Result<EVP_PKEY*>::err(bytes.error());
    }
    BIO* bio = BIO_new_mem_buf(bytes.value().data(), static_cast<int>(bytes.value().size()));
    if (bio == nullptr) {
        return Result<EVP_PKEY*>::err(ErrorCode::INTERNAL_ERROR,
                                      "Cannot allocate a key buffer");
    }
    EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (key == nullptr) {
        return Result<EVP_PKEY*>::err(ErrorCode::INVALID_ARGUMENT,
                                      "File is not a readable PEM public key: " + path);
    }
    if (EVP_PKEY_base_id(key) != EVP_PKEY_ED25519) {
        EVP_PKEY_free(key);
        return Result<EVP_PKEY*>::err(ErrorCode::UNSUPPORTED_OPERATION,
                                      "Key is not Ed25519");
    }
    return key;
}

// Identifies a key by a hash of its public half, so a verifier can tell which
// key was meant without trusting a self-declared name.
Result<std::string> keyIdentifier(EVP_PKEY* key) {
    unsigned char* der = nullptr;
    const int length = i2d_PUBKEY(key, &der);
    if (length <= 0 || der == nullptr) {
        return Result<std::string>::err(ErrorCode::INTERNAL_ERROR,
                                        "Cannot encode the public key");
    }
    const std::string derText(reinterpret_cast<const char*>(der),
                              static_cast<std::size_t>(length));
    OPENSSL_free(der);

    auto digest = sha256Hex(derText);
    if (digest.isError()) return digest;
    return digest.value().substr(0, 32);
}

bool writeAll(int fd, const char* data, std::size_t size) {
    std::size_t written = 0;
    while (written < size) {
        const ssize_t n = ::write(fd, data + written, size - written);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        written += static_cast<std::size_t>(n);
    }
    return true;
}

std::string generateRandomSuffix() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 0xFFFFFF);
    std::ostringstream out;
    out << std::hex << dist(gen);
    return out.str();
}

std::string retentionPolicyToStringImpl(RetentionAttestation::Policy policy) {
    switch (policy) {
        case RetentionAttestation::Policy::ORGANIZATION_DEFINED: return "organization-defined";
        case RetentionAttestation::Policy::CONTRACTUAL: return "contractual";
        case RetentionAttestation::Policy::LEGAL_HOLD: return "legal-hold";
        case RetentionAttestation::Policy::UNDEFINED: break;
    }
    return "undefined";
}

} // namespace

std::string verificationIndependenceToString(VerificationIndependence::Level level) {
    switch (level) {
        case VerificationIndependence::Level::OBSERVED: return "observed";
        case VerificationIndependence::Level::INDEPENDENT: return "independent";
        case VerificationIndependence::Level::SELF: break;
        case VerificationIndependence::Level::NONE: break;
    }
    return level == VerificationIndependence::Level::SELF ? "self" : "none";
}

std::string retentionPolicyToString(RetentionAttestation::Policy policy) {
    return retentionPolicyToStringImpl(policy);
}

// ---------------------------------------------------------------------------
// JSON adapters for the new types
//
// These must sit in namespace ledgerase, not in an anonymous namespace, or
// argument-dependent lookup will not find them.
// ---------------------------------------------------------------------------

void to_json(nlohmann::json& j, const MediaScopeAttestation& s) {
    j = {
        {"all_copies_accounted_for", s.allCopiesAccountedFor},
        {"copies_addressed", s.copiesAddressed},
        {"copies_not_addressed", s.copiesNotAddressed},
        {"rationale", s.rationale},
        {"attested_by", s.attestedBy},
        {"attestation_type", "operator assertion; not verified by this tool"}
    };
}

void from_json(const nlohmann::json& j, MediaScopeAttestation& s) {
    if (j.contains("all_copies_accounted_for")) j.at("all_copies_accounted_for").get_to(s.allCopiesAccountedFor);
    if (j.contains("copies_addressed")) j.at("copies_addressed").get_to(s.copiesAddressed);
    if (j.contains("copies_not_addressed")) j.at("copies_not_addressed").get_to(s.copiesNotAddressed);
    if (j.contains("rationale")) j.at("rationale").get_to(s.rationale);
    if (j.contains("attested_by")) j.at("attested_by").get_to(s.attestedBy);
}

void to_json(nlohmann::json& j, const PreExecutionAttestation& p) {
    j = {
        {"checks", p.checks},
        {"device_identity_confirmed", p.deviceIdentityConfirmed},
        {"authorization_reference", p.authorizationReference},
        {"authorized_by", p.authorizedBy},
        {"authorization_basis", p.authorizationBasis}
    };
}

void from_json(const nlohmann::json& j, PreExecutionAttestation& p) {
    if (j.contains("checks")) j.at("checks").get_to(p.checks);
    if (j.contains("device_identity_confirmed")) j.at("device_identity_confirmed").get_to(p.deviceIdentityConfirmed);
    if (j.contains("authorization_reference")) j.at("authorization_reference").get_to(p.authorizationReference);
    if (j.contains("authorized_by")) j.at("authorized_by").get_to(p.authorizedBy);
    if (j.contains("authorization_basis")) j.at("authorization_basis").get_to(p.authorizationBasis);
}

void to_json(nlohmann::json& j, const VerificationIndependence& v) {
    j = {
        {"level", verificationIndependenceToString(v.level)},
        {"performed_by", v.performedBy},
        {"notes", v.notes}
    };
}

void from_json(const nlohmann::json& j, VerificationIndependence& v) {
    if (j.contains("performed_by")) j.at("performed_by").get_to(v.performedBy);
    if (j.contains("notes")) j.at("notes").get_to(v.notes);
    if (j.contains("level")) {
        const std::string value = j.at("level").get<std::string>();
        v.level = value == "independent" ? VerificationIndependence::Level::INDEPENDENT
                 : value == "observed" ? VerificationIndependence::Level::OBSERVED
                 : value == "self" ? VerificationIndependence::Level::SELF
                                    : VerificationIndependence::Level::NONE;
    }
}

void to_json(nlohmann::json& j, const RetentionAttestation& r) {
    j = {
        {"policy", retentionPolicyToString(r.policy)},
        {"retain_until", r.retainUntil}
    };
}

void from_json(const nlohmann::json& j, RetentionAttestation& r) {
    if (j.contains("retain_until")) j.at("retain_until").get_to(r.retainUntil);
    if (j.contains("policy")) {
        const std::string value = j.at("policy").get<std::string>();
        r.policy = value == "organization-defined" ? RetentionAttestation::Policy::ORGANIZATION_DEFINED
                 : value == "contractual" ? RetentionAttestation::Policy::CONTRACTUAL
                 : value == "legal-hold" ? RetentionAttestation::Policy::LEGAL_HOLD
                                          : RetentionAttestation::Policy::UNDEFINED;
    }
}

void to_json(nlohmann::json& j, const EvidenceRecord& r) {
    j = {
        {"sequence", r.sequence},
        {"timestamp", r.timestamp},
        {"type", r.type},
        {"job_id", r.jobId},
        {"payload", r.payload},
        {"prev_hash", r.prevHash},
        {"record_hash", r.recordHash}
    };
}

void from_json(const nlohmann::json& j, EvidenceRecord& r) {
    j.at("sequence").get_to(r.sequence);
    if (j.contains("timestamp")) j.at("timestamp").get_to(r.timestamp);
    if (j.contains("type")) j.at("type").get_to(r.type);
    if (j.contains("job_id")) j.at("job_id").get_to(r.jobId);
    if (j.contains("payload")) j.at("payload").get_to(r.payload);
    if (j.contains("prev_hash")) j.at("prev_hash").get_to(r.prevHash);
    if (j.contains("record_hash")) j.at("record_hash").get_to(r.recordHash);
}

void to_json(nlohmann::json& j, const EvidenceSignature& s) {
    j = {
        {"algorithm", s.algorithm},
        {"key_id", s.keyId},
        {"signed_field", s.signedField},
        {"value", s.valueBase64},
        {"signed_at", s.signedAt}
    };
}

void from_json(const nlohmann::json& j, EvidenceSignature& s) {
    j.at("algorithm").get_to(s.algorithm);
    if (j.contains("key_id")) j.at("key_id").get_to(s.keyId);
    if (j.contains("signed_field")) j.at("signed_field").get_to(s.signedField);
    if (j.contains("value")) j.at("value").get_to(s.valueBase64);
    if (j.contains("signed_at")) j.at("signed_at").get_to(s.signedAt);
}

// The assurance basis, as it appears in a bundle. Written by hand rather than
// through a macro because the struct is anonymous and local to the header: it
// exists only to give the evidence record a place to say where the level came
// from, and it deliberately has no operator== either.
inline void to_json(nlohmann::json& j, const decltype(EvidenceBundle::assuranceBasis)& b) {
    j = {{"source", b.source},
         {"categorization", b.categorization},
         {"reuse_media", b.reuseMedia},
         {"leaving_org_control", b.leavingOrgControl},
         {"provenance", b.provenance},
         {"rationale", b.rationale}};
}

void to_json(nlohmann::json& j, const EvidenceBundle& b) {
    j = {
        {"schema", b.schema},
        {"job_id", b.jobId},
        {"certificate_id", b.certificateId},
        {"generated_at", b.generatedAt},

        {"standard", {
            {"name", b.standardName},
            {"role", b.standardRole},
            {"conformance_statement", b.conformanceStatement},
            {"additional_references", b.additionalReferences}
        }},

        {"media", {
            {"device", b.device},
            {"scope", b.scope}
        }},

        {"decision", {
            {"requested_category", b.requestedCategory},
            // Where the level came from, recorded beside it. The level names are
            // the standard's, so a reader given only "PURGE" cannot tell whether
            // NIST SP 800-88 Rev. 2 required it or the organisation's local
            // policy derived it - and the two support different conclusions about
            // the program. provenance says which, and never attributes a derived
            // tier to NIST.
            {"assurance_basis", b.assuranceBasis},
            {"selected_method", b.selectedMethod},
            {"rationale", b.decisionRationale},
            {"alternatives_considered", b.alternativesConsidered},
            {"standard_references", b.standardReferences}
        }},

        {"pre_execution", b.preExecution},
        {"operator", b.operatorName},
        {"operator_invoking_user", b.invokingUser},
        {"operator_invoking_uid", b.invokingUid},
        {"operator_effective_user", b.effectiveUser},
        {"operator_effective_uid", b.effectiveUid},
        {"operator_elevated", b.elevated},
        {"application_version", b.applicationVersion},

        {"execution", {
            {"status", b.execution},
            {"simulated", b.simulated}
        }},

        {"verification", {
            {"report", b.verification},
            {"independence", b.verificationIndependence}
        }},

        {"validation", b.validation},

        {"residual_risk", {
            {"residual_data_possible", b.residualDataPossible},
            {"statement", b.residualRiskStatement},
            {"limitations", b.residualRiskLimitations}
        }},

        {"integrity", {
            {"hash_algorithm", b.hashAlgorithm},
            {"chain_length", b.chainLength},
            {"chain_head", b.chainHead},
            {"event_chain", b.eventChain}
        }},

        {"retention", b.retention},
        {"canonical_hash", b.canonicalHash},
        {"signatures", b.signatures}
    };
}

void from_json(const nlohmann::json& j, EvidenceBundle& b) {
    j.at("schema").get_to(b.schema);
    if (j.contains("job_id")) j.at("job_id").get_to(b.jobId);
    if (j.contains("certificate_id")) j.at("certificate_id").get_to(b.certificateId);
    if (j.contains("generated_at")) j.at("generated_at").get_to(b.generatedAt);

    if (j.contains("standard")) {
        const auto& s = j.at("standard");
        if (s.contains("name")) s.at("name").get_to(b.standardName);
        if (s.contains("role")) s.at("role").get_to(b.standardRole);
        if (s.contains("conformance_statement")) s.at("conformance_statement").get_to(b.conformanceStatement);
        if (s.contains("additional_references")) s.at("additional_references").get_to(b.additionalReferences);
    }

    if (j.contains("media")) {
        const auto& m = j.at("media");
        if (m.contains("device")) m.at("device").get_to(b.device);
        if (m.contains("scope")) m.at("scope").get_to(b.scope);
    }

    if (j.contains("decision")) {
        const auto& d = j.at("decision");
        if (d.contains("requested_category")) d.at("requested_category").get_to(b.requestedCategory);
        if (d.contains("assurance_basis")) {
            const auto& ab = d.at("assurance_basis");
            if (ab.contains("source")) ab.at("source").get_to(b.assuranceBasis.source);
            if (ab.contains("categorization")) ab.at("categorization").get_to(b.assuranceBasis.categorization);
            if (ab.contains("reuse_media")) ab.at("reuse_media").get_to(b.assuranceBasis.reuseMedia);
            if (ab.contains("leaving_org_control")) ab.at("leaving_org_control").get_to(b.assuranceBasis.leavingOrgControl);
            if (ab.contains("provenance")) ab.at("provenance").get_to(b.assuranceBasis.provenance);
            if (ab.contains("rationale")) ab.at("rationale").get_to(b.assuranceBasis.rationale);
        }
        if (d.contains("selected_method")) d.at("selected_method").get_to(b.selectedMethod);
        if (d.contains("rationale")) d.at("rationale").get_to(b.decisionRationale);
        if (d.contains("alternatives_considered")) d.at("alternatives_considered").get_to(b.alternativesConsidered);
        if (d.contains("standard_references")) d.at("standard_references").get_to(b.standardReferences);
    }

    if (j.contains("pre_execution")) j.at("pre_execution").get_to(b.preExecution);
    if (j.contains("operator")) j.at("operator").get_to(b.operatorName);
    // A schema-1 bundle has only the single operator name. Reading one must
    // still work, so the extra fields fall back to it.
    if (j.contains("operator_invoking_user")) {
        j.at("operator_invoking_user").get_to(b.invokingUser);
    } else {
        b.invokingUser = b.operatorName;
    }
    if (j.contains("operator_invoking_uid")) j.at("operator_invoking_uid").get_to(b.invokingUid);
    if (j.contains("operator_effective_user")) j.at("operator_effective_user").get_to(b.effectiveUser);
    if (j.contains("operator_effective_uid")) j.at("operator_effective_uid").get_to(b.effectiveUid);
    if (j.contains("operator_elevated")) j.at("operator_elevated").get_to(b.elevated);
    if (j.contains("application_version")) j.at("application_version").get_to(b.applicationVersion);

    if (j.contains("execution")) {
        const auto& e = j.at("execution");
        if (e.contains("status")) e.at("status").get_to(b.execution);
        if (e.contains("simulated")) e.at("simulated").get_to(b.simulated);
    }

    if (j.contains("verification")) {
        const auto& v = j.at("verification");
        if (v.contains("report")) v.at("report").get_to(b.verification);
        if (v.contains("independence")) v.at("independence").get_to(b.verificationIndependence);
    }

    if (j.contains("validation")) j.at("validation").get_to(b.validation);
    if (j.contains("retention")) j.at("retention").get_to(b.retention);
    if (j.contains("canonical_hash")) j.at("canonical_hash").get_to(b.canonicalHash);
    if (j.contains("signatures")) j.at("signatures").get_to(b.signatures);

    if (j.contains("integrity")) {
        const auto& i = j.at("integrity");
        if (i.contains("hash_algorithm")) i.at("hash_algorithm").get_to(b.hashAlgorithm);
        if (i.contains("chain_length")) i.at("chain_length").get_to(b.chainLength);
        if (i.contains("chain_head")) i.at("chain_head").get_to(b.chainHead);
        if (i.contains("event_chain")) i.at("event_chain").get_to(b.eventChain);
    }

    if (j.contains("residual_risk")) {
        const auto& r = j.at("residual_risk");
        if (r.contains("residual_data_possible")) r.at("residual_data_possible").get_to(b.residualDataPossible);
        if (r.contains("statement")) r.at("statement").get_to(b.residualRiskStatement);
        if (r.contains("limitations")) r.at("limitations").get_to(b.residualRiskLimitations);
    }
}

// ---------------------------------------------------------------------------
// EvidenceJournal
// ---------------------------------------------------------------------------

class EvidenceJournal::Impl {
public:
    std::vector<EvidenceRecord> records;
};

EvidenceJournal::EvidenceJournal() : pImpl_(std::make_unique<Impl>()) {}
EvidenceJournal::~EvidenceJournal() = default;

const std::vector<EvidenceRecord>& EvidenceJournal::records() const noexcept {
    return pImpl_->records;
}

uint64_t EvidenceJournal::count() const noexcept {
    return pImpl_->records.size();
}

std::string EvidenceJournal::head() const {
    if (pImpl_->records.empty()) return kGenesisHash;
    return pImpl_->records.back().recordHash;
}

void EvidenceJournal::clear() noexcept {
    pImpl_->records.clear();
}

Result<std::string> EvidenceJournal::canonicalRecordJson(const EvidenceRecord& record) {
    nlohmann::json j = {
        {"sequence", record.sequence},
        {"timestamp", record.timestamp},
        {"type", record.type},
        {"job_id", record.jobId},
        {"payload", record.payload},
        {"prev_hash", record.prevHash}
    };
    // nlohmann::json orders object keys, so dump() with no indent is a stable
    // byte sequence for a given record. That determinism is what makes the
    // chain hashes reproducible.
    return j.dump();
}

Result<std::string> EvidenceJournal::recordHash(const EvidenceRecord& record) {
    const auto canonical = canonicalRecordJson(record);
    if (canonical.isError()) {
        return Result<std::string>::err(canonical.error());
    }
    return sha256Hex(canonical.value());
}

Result<EvidenceRecord> EvidenceJournal::append(const std::string& type,
                                                const std::string& jobId,
                                                nlohmann::json payload) {
    EvidenceRecord record;
    record.sequence = pImpl_->records.size() + 1;
    record.timestamp = formatTimestamp(std::chrono::system_clock::now());
    record.type = type;
    record.jobId = jobId;
    record.payload = std::move(payload);
    record.prevHash = head();

    const auto hash = recordHash(record);
    if (hash.isError()) {
        return Result<EvidenceRecord>::err(hash.error());
    }
    record.recordHash = hash.value();

    pImpl_->records.push_back(record);
    return record;
}

Result<ChainVerification> EvidenceJournal::verifyChain() const {
    ChainVerification result;

    std::string expectedPrev = kGenesisHash;
    for (const auto& record : pImpl_->records) {
        const auto recomputed = recordHash(record);
        if (recomputed.isError()) {
            return Result<ChainVerification>::err(recomputed.error());
        }
        if (record.prevHash != expectedPrev) {
            result.intact = false;
            result.failureReason = "Broken link: record " +
                                   std::to_string(record.sequence) +
                                   " does not commit to the previous record";
            result.failureAtSequence = std::to_string(record.sequence);
            result.headHash = head();
            return result;
        }
        if (record.recordHash != recomputed.value()) {
            result.intact = false;
            result.failureReason = "Content mismatch: record " +
                                   std::to_string(record.sequence) +
                                   " has been altered since it was written";
            result.failureAtSequence = std::to_string(record.sequence);
            result.headHash = head();
            return result;
        }
        expectedPrev = record.recordHash;
        ++result.recordsChecked;
    }

    result.intact = true;
    result.headHash = head();
    return result;
}

// ---------------------------------------------------------------------------
// EvidenceBuilder
// ---------------------------------------------------------------------------

std::string EvidenceBuilder::generateCertificateId() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(100000, 999999);

    const std::time_t now = std::time(nullptr);
    std::tm tmValue{};
    gmtime_r(&now, &tmValue);

    std::ostringstream out;
    out << "CERT-" << std::put_time(&tmValue, "%Y%m%dT%H%M%SZ") << "-"
        << dist(gen);
    return out.str();
}

Result<EvidenceBundle> EvidenceBuilder::build(const AuditRecord& record,
                                              const VerificationReport& verification,
                                              const ValidationReport& validation,
                                              const MediaScopeAttestation& scope,
                                              const PreExecutionAttestation& preExecution,
                                              const VerificationIndependence& independence,
                                              const RetentionAttestation& retention) {

    EvidenceBundle bundle;
    bundle.jobId = record.jobId;
    bundle.certificateId = generateCertificateId();
    bundle.generatedAt = formatTimestamp(std::chrono::system_clock::now());
    bundle.conformanceStatement =
        "This record was produced by software that maps sanitization categories "
        "onto " +
        std::string(EvidenceBundle().standardName) +
        ". It is not a certification and does not by itself establish "
        "conformance. Conformance of a sanitization program is determined by an "
        "assessor against the standard and the applicable organizational policy. "
        "Clause-level mapping must be confirmed against the licensed copy of the "
        "standard.";
    bundle.additionalReferences = {
        "IEEE 2883-2022 (sanitization information security)",
        "NVMe Base Specification, Sanitize command and Sanitize Status log"
    };

    bundle.device = record.device;
    bundle.scope = scope;
    bundle.requestedCategory = record.plan.requestedCategory;
    // Copied field by field rather than assigning the plan's nested struct,
    // because the evidence record uses strings. The consequence is that a field
    // added to the plan's basis is not automatically recorded here - which is
    // deliberate, since a silently missing field in an audit record is worse
    // than a compile error.
    {
        const auto& pb = record.plan.assuranceBasis;
        auto& eb = bundle.assuranceBasis;
        eb.source = pb.source;
        eb.categorization = securityCategorizationToString(pb.categorization);
        eb.reuseMedia = triStateToString(pb.reuseMedia);
        eb.leavingOrgControl = triStateToString(pb.leavingOrgControl);
        eb.provenance = pb.provenance;
        eb.rationale = pb.rationale;
    }
    bundle.selectedMethod = record.plan.selectedMethod;
    bundle.decisionRationale = record.plan.rationale;
    bundle.alternativesConsidered = record.plan.alternativesConsidered;
    bundle.standardReferences = record.plan.standardReferences;
    bundle.preExecution = preExecution;
    bundle.operatorName = record.operatorName;
    bundle.invokingUser = record.invokingUser.empty() ? record.operatorName
                                                     : record.invokingUser;
    bundle.invokingUid = record.invokingUid;
    bundle.effectiveUser = record.effectiveUser.empty() ? record.operatorName
                                                       : record.effectiveUser;
    bundle.effectiveUid = record.effectiveUid;
    bundle.elevated = record.elevated;
    bundle.applicationVersion = record.applicationVersion;
    bundle.execution = record.execution;
    bundle.simulated = record.execution.simulated;
    bundle.verification = verification;
    bundle.verificationIndependence = independence;
    bundle.validation = validation;
    bundle.retention = retention;

    // -- Honesty gates -------------------------------------------------------
    // Each of these can only move the outcome downwards. Nothing here can turn
    // a weak result into a strong one.

    // One set, fed from all three sources. The old code appended three
    // vectors into a fourth, which is how the same sentence ended up in the
    // bundle four or five times. merge() is unique by (id, detail), so a fact
    // stated by the plan and again by verification is recorded once.
    LimitationSet limitations;
    limitations.merge(record.plan.limitations);
    limitations.merge(validation.limitations);
    limitations.merge(verification.limitations);
    limitations.merge(record.capabilities.limitations);

    if (!scope.allCopiesAccountedFor) {
        limitations.add(LimitationId::COPIES_NOT_ATTESTED);
    }
    if (preExecution.authorizationReference.empty()) {
        limitations.add(LimitationId::NO_AUTHORIZATION);
    }
    if (!preExecution.deviceIdentityConfirmed) {
        limitations.add(LimitationId::NO_IDENTITY_CONFIRMATION);
    }
    if (independence.level == VerificationIndependence::Level::NONE) {
        limitations.add(LimitationId::NO_VERIFICATION);
    } else if (independence.level == VerificationIndependence::Level::SELF) {
        limitations.add(LimitationId::SELF_VERIFIED);
    }
    if (retention.policy == RetentionAttestation::Policy::UNDEFINED) {
        limitations.add(LimitationId::NO_RETENTION_POLICY);
    }
    if (bundle.simulated) {
        limitations.add(LimitationId::SIMULATED_RUN);
    }

    // The outcome may not exceed the evidence. An unverified operation cannot be
    // accepted, whatever the validation engine reported.
    //
    // appendSentence() rather than `+=` because the engine's own reasoning
    // already ends in a space. Appending " Outcome..." to that produced a
    // double space in the middle of the sentence, which is the kind of thing
    // that reads as two thoughts jammed together and is not.
    const auto appendSentence = [&bundle](const std::string& sentence) {
        if (!bundle.validation.reasoning.empty() && bundle.validation.reasoning.back() == ' ') {
            bundle.validation.reasoning.pop_back();
        }
        if (!bundle.validation.reasoning.empty()) {
            bundle.validation.reasoning += " ";
        }
        bundle.validation.reasoning += sentence;
    };

    if (bundle.validation.result == ValidationResult::ACCEPTED) {
        if (verification.result != VerificationResult::PASS) {
            bundle.validation.result = ValidationResult::INCONCLUSIVE;
            appendSentence("Outcome downgraded to INCONCLUSIVE: verification did not pass.");
        } else if (bundle.simulated) {
            bundle.validation.result = ValidationResult::ACCEPTED_WITH_LIMITATIONS;
            appendSentence("Outcome downgraded: this is a simulated run.");
        } else if (!scope.allCopiesAccountedFor ||
                   preExecution.authorizationReference.empty() ||
                   !preExecution.deviceIdentityConfirmed) {
            bundle.validation.result = ValidationResult::ACCEPTED_WITH_LIMITATIONS;
            appendSentence(
                "Outcome downgraded: scope attestation, authorization reference "
                "or device identity confirmation is missing.");
        } else if (independence.level != VerificationIndependence::Level::INDEPENDENT &&
                   independence.level != VerificationIndependence::Level::OBSERVED) {
            bundle.validation.result = ValidationResult::ACCEPTED_WITH_LIMITATIONS;
            appendSentence(
                "Outcome downgraded: verification was not independently performed.");
        }
    }

    for (const std::string& limitation : limitations.texts()) {
        if (std::find(bundle.residualRiskLimitations.begin(),
                      bundle.residualRiskLimitations.end(),
                      limitation) == bundle.residualRiskLimitations.end()) {
            bundle.residualRiskLimitations.push_back(limitation);
        }
    }

    // Residual data is possible after every method this tool can perform. A
    // host overwrite does not reach controller-managed areas; crypto erase
    // leaves ciphertext; block erase leaves unallocated and retired blocks.
    // Only a physical disposition (DESTROY) removes the media itself, and this
    // tool does not perform that.
    bundle.residualDataPossible = true;
    bundle.residualRiskStatement =
        "Residual data may remain on the media. Host software cannot observe "
        "controller-managed areas such as NAND overprovisioning, wear-levelled "
        "and retired blocks, spare media, or areas serviced through a USB "
        "bridge. This record does not assert that data was physically erased, "
        "that recovery is impossible, or that every copy was sanitized.";

    auto canonical = canonicalJson(bundle);
    if (canonical.isError()) {
        return Result<EvidenceBundle>::err(canonical.error());
    }
    auto hash = sha256Hex(canonical.value());
    if (hash.isError()) {
        return Result<EvidenceBundle>::err(hash.error());
    }
    bundle.canonicalHash = hash.value();

    return bundle;
}

Result<std::string> EvidenceBuilder::canonicalJson(const EvidenceBundle& bundle) {
    nlohmann::json j = bundle;

    // Excluded so that attaching a signature does not change the bytes that
    // were signed. Everything else, including the whole event chain, is
    // covered.
    j.erase("canonical_hash");
    j.erase("signatures");

    return j.dump();
}

Result<std::string> EvidenceBuilder::canonicalHash(const EvidenceBundle& bundle) {
    const auto canonical = canonicalJson(bundle);
    if (canonical.isError()) {
        return Result<std::string>::err(canonical.error());
    }
    return sha256Hex(canonical.value());
}

Result<std::string> EvidenceBuilder::canonicalHashOfDocument(const nlohmann::json& document) {
    // Hash the stored document, not a re-serialisation of the parsed struct.
    //
    // Those two are the same for a bundle this build just wrote, and they
    // differ for any bundle written by a different build: reading a schema-1
    // bundle and writing it back out would render its limitations as objects
    // instead of sentences, and the hash would stop matching even though
    // nothing had been altered. Hashing the tree makes the check depend only
    // on the bytes on disk, so an old bundle keeps verifying, and adding a
    // field to a C++ struct can no longer silently invalidate every stored
    // hash.
    nlohmann::json copy = document;
    copy.erase("canonical_hash");
    copy.erase("signatures");
    return sha256Hex(copy.dump());
}

Sha256Stream::Sha256Stream() {
    auto* ctx = EVP_MD_CTX_new();
    if (ctx != nullptr && EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        ctx = nullptr;
    }
    context_ = ctx;
}

Sha256Stream::~Sha256Stream() {
    if (context_ != nullptr) {
        EVP_MD_CTX_free(static_cast<EVP_MD_CTX*>(context_));
    }
}

void Sha256Stream::update(const uint8_t* data, size_t length) {
    if (context_ == nullptr || finalised_ || length == 0) {
        return;
    }
    EVP_DigestUpdate(static_cast<EVP_MD_CTX*>(context_), data, length);
}

Result<std::string> Sha256Stream::finalHex() {
    if (context_ == nullptr) {
        return Result<std::string>::err(ErrorCode::INTERNAL_ERROR,
                                        "The digest context could not be created");
    }
    if (finalised_) {
        return Result<std::string>::err(ErrorCode::INVALID_ARGUMENT,
                                        "The digest has already been finalised");
    }
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLength = 0;
    if (EVP_DigestFinal_ex(static_cast<EVP_MD_CTX*>(context_), digest,
                            &digestLength) != 1) {
        return Result<std::string>::err(ErrorCode::INTERNAL_ERROR,
                                        "SHA-256 finalisation failed");
    }
    finalised_ = true;
    return Result<std::string>::ok(toHex(digest, digestLength));
}

Result<std::string> sha256HexBytes(const uint8_t* data, size_t length) {
    Sha256Stream stream;
    if (length > 0) {
        stream.update(data, length);
    }
    return stream.finalHex();
}

// ---------------------------------------------------------------------------
// Atomic document write
//
// Shared by both bundle writers. The discipline is the same for a sanitization
// certificate and for a recovery record, so it lives in one place: 0600
// temporary file in the destination directory, fsync, then link() or rename().
// link() fails when the destination exists, which makes "do not clobber"
// atomic rather than a check followed by a write that another process can race.
// ---------------------------------------------------------------------------

Result<void> detail::writeEvidenceDocument(const std::string& path,
                                          const std::string& payload,
                                          bool overwrite) {
    if (path.empty()) {
        return Result<void>::err(ErrorCode::INVALID_ARGUMENT,
                                 "An explicit output path is required");
    }
    if (path.find('\0') != std::string::npos) {
        return Result<void>::err(ErrorCode::INVALID_ARGUMENT,
                                 "Output path contains an embedded NUL byte");
    }

    const std::size_t slash = path.find_last_of('/');
    const std::string directory =
        slash == std::string::npos ? std::string(".") : path.substr(0, slash);
    const std::string base =
        slash == std::string::npos ? path : path.substr(slash + 1);

    if (base.empty() || base == "." || base == "..") {
        return Result<void>::err(ErrorCode::INVALID_ARGUMENT,
                                 "Output path does not name a file");
    }

    const std::string tempPath =
        directory + "/." + base + ".tmp-" + generateRandomSuffix();

    const int fd = ::open(tempPath.c_str(),
                          O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                          S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return Result<void>::err(ErrorCode::IO_ERROR,
                                 "Cannot create temporary file in " + directory + ": " +
                                     std::strerror(errno),
                                 "Check that the directory exists and is writable");
    }

    if (!writeAll(fd, payload.data(), payload.size())) {
        const int saved = errno;
        ::close(fd);
        ::unlink(tempPath.c_str());
        return Result<void>::err(ErrorCode::IO_ERROR,
                                 "Failed writing evidence file: " + std::string(std::strerror(saved)));
    }

    if (::fsync(fd) != 0) {
        const int saved = errno;
        ::close(fd);
        ::unlink(tempPath.c_str());
        return Result<void>::err(ErrorCode::IO_ERROR,
                                 "Failed flushing evidence file: " + std::string(std::strerror(saved)));
    }
    ::close(fd);

    if (overwrite) {
        if (::rename(tempPath.c_str(), path.c_str()) != 0) {
            const int saved = errno;
            ::unlink(tempPath.c_str());
            return Result<void>::err(ErrorCode::IO_ERROR,
                                     "Cannot replace " + path + ": " + std::strerror(saved));
        }
    } else {
        // link() fails if the destination exists, which makes creation atomic
        // and refuses to clobber without a check-then-write race.
        if (::link(tempPath.c_str(), path.c_str()) != 0) {
            const int saved = errno;
            ::unlink(tempPath.c_str());
            std::string action = "Choose a different path";
            if (saved == EEXIST) {
                action = "The file already exists. Re-run with --force to replace it";
            } else if (saved == ELOOP) {
                action = "Refusing to write through a symbolic link";
            }
            return Result<void>::err(ErrorCode::IO_ERROR,
                                     "Cannot create " + path + ": " + std::strerror(saved),
                                     action);
        }
        ::unlink(tempPath.c_str());
    }

    // Persist the directory entry so the file survives a crash.
    const int dirFd = ::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirFd >= 0) {
        (void)::fsync(dirFd);
        ::close(dirFd);
    }

    return Result<void>::success();
}

Result<nlohmann::json> detail::readEvidenceDocument(const std::string& path) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return Result<nlohmann::json>::err(
            ErrorCode::IO_ERROR,
            "Cannot open evidence file " + path + ": " + std::strerror(errno));
    }

    std::string text;
    char buffer[8192];
    while (true) {
        const ssize_t n = ::read(fd, buffer, sizeof(buffer));
        if (n < 0) {
            if (errno == EINTR) continue;
            const int saved = errno;
            ::close(fd);
            return Result<nlohmann::json>::err(
                ErrorCode::IO_ERROR,
                "Failed reading " + path + ": " + std::strerror(saved));
        }
        if (n == 0) break;
        text.append(buffer, static_cast<std::size_t>(n));
    }
    ::close(fd);

    nlohmann::json parsed = nlohmann::json::parse(text, nullptr, false);
    if (parsed.is_discarded() || !parsed.is_object()) {
        return Result<nlohmann::json>::err(
            ErrorCode::INVALID_ARGUMENT, "File is not a JSON object: " + path);
    }
    return Result<nlohmann::json>::ok(std::move(parsed));
}

// ---------------------------------------------------------------------------
// EvidenceWriter
// ---------------------------------------------------------------------------

Result<void> EvidenceWriter::write(const EvidenceBundle& bundle,
                                   const std::string& path,
                                   bool overwrite) {
    if (path.empty()) {
        return Result<void>::err(ErrorCode::INVALID_ARGUMENT,
                                 "An explicit output path is required",
                                 "Usage: ledgerase-cli evidence <job-id> --output <file.json>");
    }

    // The signed artefact must contain the hash it was signed over.
    auto document = bundle;
    auto hash = EvidenceBuilder::canonicalHash(document);
    if (hash.isError()) {
        return Result<void>::err(hash.error());
    }
    document.canonicalHash = hash.value();

    std::string payload = nlohmann::json(document).dump(2);
    payload.push_back('\n');
    return detail::writeEvidenceDocument(path, payload, overwrite);
}

Result<EvidenceBundle> EvidenceWriter::read(const std::string& path) {
    auto document = detail::readEvidenceDocument(path);
    if (document.isError()) {
        return Result<EvidenceBundle>::err(document.error());
    }

    EvidenceBundle bundle;
    try {
        document.value().get_to(bundle);
    } catch (const std::exception& e) {
        return Result<EvidenceBundle>::err(ErrorCode::INVALID_ARGUMENT,
                                           std::string("Evidence file is malformed: ") + e.what());
    }
    return bundle;
}

// ---------------------------------------------------------------------------
// EvidenceVerifier
// ---------------------------------------------------------------------------

Result<bool> EvidenceVerifier::verifyCanonicalHash(const EvidenceBundle& bundle) {
    const auto recomputed = EvidenceBuilder::canonicalHash(bundle);
    if (recomputed.isError()) {
        return Result<bool>::err(recomputed.error());
    }
    return recomputed.value() == bundle.canonicalHash;
}

Result<bool> EvidenceVerifier::verifyCanonicalHashOfDocument(
    const nlohmann::json& document, const std::string& storedHash) {
    const auto recomputed = EvidenceBuilder::canonicalHashOfDocument(document);
    if (recomputed.isError()) {
        return Result<bool>::err(recomputed.error());
    }
    return recomputed.value() == storedHash;
}

Result<EvidenceSignature> EvidenceVerifier::sign(EvidenceBundle& bundle,
                                                 const std::string& privateKeyPath) {
    auto key = loadPrivateKey(privateKeyPath);
    if (key.isError()) {
        return Result<EvidenceSignature>::err(key.error());
    }
    EVP_PKEY* pkey = key.value();

    // Sign the canonical hash, not the document, so verification needs only the
    // published hash.
    const auto hash = EvidenceBuilder::canonicalHash(bundle);
    if (hash.isError()) {
        EVP_PKEY_free(pkey);
        return Result<EvidenceSignature>::err(hash.error());
    }
    const std::string message = hash.value();

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        EVP_PKEY_free(pkey);
        return Result<EvidenceSignature>::err(ErrorCode::INTERNAL_ERROR,
                                             "Cannot allocate a signing context");
    }

    size_t signatureSize = 0;
    if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) != 1 ||
        EVP_DigestSign(ctx, nullptr, &signatureSize,
                       reinterpret_cast<const unsigned char*>(message.data()),
                       message.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return Result<EvidenceSignature>::err(ErrorCode::INTERNAL_ERROR,
                                             "Cannot initialise Ed25519 signing");
    }

    std::string signature(signatureSize, '\0');
    if (EVP_DigestSign(ctx, reinterpret_cast<unsigned char*>(signature.data()),
                       &signatureSize,
                       reinterpret_cast<const unsigned char*>(message.data()),
                       message.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return Result<EvidenceSignature>::err(ErrorCode::INTERNAL_ERROR,
                                             "Ed25519 signing failed");
    }
    signature.resize(signatureSize);

    EVP_MD_CTX_free(ctx);

    auto keyId = keyIdentifier(pkey);
    EVP_PKEY_free(pkey);
    if (keyId.isError()) {
        return Result<EvidenceSignature>::err(keyId.error());
    }

    EvidenceSignature result;
    result.algorithm = "Ed25519";
    result.keyId = keyId.value();
    result.signedField = "canonical_hash";
    result.valueBase64 = base64Encode(
        reinterpret_cast<const unsigned char*>(signature.data()), signature.size());
    result.signedAt = formatTimestamp(std::chrono::system_clock::now());

    bundle.canonicalHash = message;
    bundle.signatures.push_back(result);
    return result;
}

namespace {

// Walks the embedded chain and cross-checks it against the declared length and
// head, then checks the schema-3 section references.
//
// The section check is specific to the sanitization bundle: schema 3 records
// point at a top-level section and carry its digest, so the chain commits to
// content it does not copy. Carve records carry their own values, so the shared
// walk above is the whole of their chain check.
ChainVerification verifyEmbeddedChain(const EvidenceBundle& bundle) {
    detail::ChainCheck walked = detail::verifyChainRecords(
        bundle.eventChain, bundle.chainLength, bundle.chainHead);

    ChainVerification result;
    result.intact = walked.intact;
    result.recordsChecked = walked.recordsChecked;
    result.headHash = walked.headHash;
    result.failureReason = walked.failureReason;
    result.failureAtSequence = walked.failureAtSequence;
    if (!result.intact) {
        return result;
    }

    // Schema 3 records reference a section by name and carry its digest. The
    // reference is the thing that lets the chain commit to a section it does not
    // copy, so it has to be *checked*: recompute each referenced section's
    // digest and compare.
    //
    // Without this, editing a top-level section left the chain reporting
    // "intact" while its own recorded digest no longer described the file. The
    // canonical hash still caught the edit, but a chain that claims to commit to
    // a section and does not is worse than no claim at all.
    for (const EvidenceRecord& record : bundle.eventChain) {
        if (!record.payload.is_object()) {
            continue;
        }
        if (!record.payload.contains("section") ||
            !record.payload.contains("section_sha256")) {
            continue;   // a schema 1 or 2 record, which carries its own copy
        }
        const std::string section =
            record.payload.at("section").get<std::string>();
        const std::string recorded =
            record.payload.at("section_sha256").get<std::string>();
        const nlohmann::json document = bundle;
        if (!document.contains(section)) {
            result.intact = false;
            result.failureReason =
                "Broken reference: record " + std::to_string(record.sequence) +
                " points at section '" + section + "', which is not present";
            result.failureAtSequence = std::to_string(record.sequence);
            return result;
        }
        const std::string canonical = document.at(section).dump();
        const auto digest = sha256HexBytes(
            reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size());
        if (digest.isError()) {
            result.intact = false;
            result.failureReason =
                "Could not digest section '" + section + "'";
            result.failureAtSequence = std::to_string(record.sequence);
            return result;
        }
        if (digest.value() != recorded) {
            result.intact = false;
            result.failureReason =
                "Broken reference: record " + std::to_string(record.sequence) +
                " commits to section '" + section +
                "', and that section no longer matches the digest the chain "
                "recorded for it";
            result.failureAtSequence = std::to_string(record.sequence);
            return result;
        }
    }

    return result;
}

} // namespace

Result<EvidenceVerification> EvidenceVerifier::verifyStructureFromBundle(
    const EvidenceBundle& bundle, const nlohmann::json* document) {
    EvidenceVerification report;
    report.schemaRecognised = false;
    for (const char* supported : EvidenceBundle::kSupportedSchemas) {
        if (bundle.schema == supported) {
            report.schemaRecognised = true;
            break;
        }
    }
    if (!report.schemaRecognised) {
        report.findings.push_back("Unrecognised schema: " + bundle.schema);
        return report;
    }

    Result<bool> hashOk = (document != nullptr && document->contains("canonical_hash"))
                              ? verifyCanonicalHashOfDocument(
                                    *document,
                                    document->at("canonical_hash").get<std::string>())
                              : verifyCanonicalHash(bundle);
    if (hashOk.isError()) {
        return Result<EvidenceVerification>::err(hashOk.error());
    }
    report.canonicalHashMatches = hashOk.value();
    report.findings.push_back(report.canonicalHashMatches
                                  ? "Canonical hash matches: content is unaltered"
                                  : "Canonical hash MISMATCH: content was modified "
                                    "after it was produced");

    const ChainVerification chain = verifyEmbeddedChain(bundle);
    report.chainConsistent = chain.intact;
    report.chainLength = bundle.chainLength;
    report.findings.push_back(chain.intact
                                  ? "Event chain is intact (" +
                                        std::to_string(chain.recordsChecked) + " records)"
                                  : "Event chain FAILED: " + chain.failureReason);

    report.signaturePresent = !bundle.signatures.empty();
    if (!report.signaturePresent) {
        report.findings.push_back(
            "No signature present. Integrity here rests on the hash alone, which "
            "detects accidental change but proves nothing about origin.");
    }

    report.limitations.add(LimitationId::VERIFYLOG_SCOPE);
    return report;
}

Result<EvidenceVerification> EvidenceVerifier::verifyStructure(const std::string& path) {
    // The stored text is read as JSON before the bundle is parsed, so the
    // canonical hash can be checked against what is actually on disk.
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return Result<EvidenceVerification>::err(
            ErrorCode::INVALID_ARGUMENT,
            "Cannot open evidence file: " + path,
            "Check the path. The file reported when the job ran is the one to use.");
    }
    std::ostringstream buffer;
    buffer << input.rdbuf();

    nlohmann::json document;
    try {
        document = nlohmann::json::parse(buffer.str());
    } catch (const nlohmann::json::parse_error& error) {
        return Result<EvidenceVerification>::err(
            ErrorCode::INVALID_ARGUMENT,
            std::string("Evidence file is not valid JSON: ") + error.what(),
            "The file has been damaged or truncated. It cannot be verified.");
    }

    auto bundle = EvidenceWriter::read(path);
    if (bundle.isError()) {
        return Result<EvidenceVerification>::err(bundle.error());
    }
    return verifyStructureFromBundle(bundle.value(), &document);
}

Result<EvidenceVerification> EvidenceVerifier::verify(const std::string& path,
                                                      const std::string& publicKeyPath) {
    auto structure = verifyStructure(path);
    if (structure.isError()) {
        return structure;
    }
    EvidenceVerification report = structure.value();

    if (publicKeyPath.empty()) {
        report.limitations.add(LimitationId::SIGNATURE_UNCHECKED);
        return report;
    }

    auto bundle = EvidenceWriter::read(path);
    if (bundle.isError()) {
        return Result<EvidenceVerification>::err(bundle.error());
    }

    if (bundle.value().signatures.empty()) {
        report.findings.push_back("Nothing to verify: the document is unsigned.");
        return report;
    }

    auto key = loadPublicKey(publicKeyPath);
    if (key.isError()) {
        report.findings.push_back(std::string("Signature NOT verified: ") +
                                  key.error().what());
        return report;
    }
    EVP_PKEY* pkey = key.value();

    const auto keyId = keyIdentifier(pkey);
    const std::string message = bundle.value().canonicalHash;

    bool allValid = !message.empty();
    for (const auto& signature : bundle.value().signatures) {
        if (signature.algorithm != "Ed25519") {
            report.findings.push_back("Unsupported signature algorithm: " +
                                      signature.algorithm);
            allValid = false;
            continue;
        }
        if (keyId.ok() && !signature.keyId.empty() && signature.keyId != keyId.value()) {
            report.findings.push_back(
                "Signature was made with a different key (" + signature.keyId +
                ") than the one supplied (" + keyId.value() + ")");
            allValid = false;
            continue;
        }

        const auto decoded = base64Decode(signature.valueBase64);
        if (decoded.isError()) {
            report.findings.push_back(std::string("Signature is corrupt: ") +
                                      decoded.error().what());
            allValid = false;
            continue;
        }

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        const bool verified =
            ctx != nullptr &&
            EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1 &&
            EVP_DigestVerify(ctx,
                             reinterpret_cast<const unsigned char*>(decoded.value().data()),
                             decoded.value().size(),
                             reinterpret_cast<const unsigned char*>(message.data()),
                             message.size()) == 1;
        if (ctx != nullptr) EVP_MD_CTX_free(ctx);

        if (verified) {
            report.findings.push_back("Signature valid (Ed25519, key " +
                                      signature.keyId + ")");
        } else {
            report.findings.push_back(
                "Signature is INVALID for the supplied key. Either the document "
                "was altered or the key is wrong.");
            allValid = false;
        }
    }

    EVP_PKEY_free(pkey);
    report.signatureValid = allValid;
    return report;
}

} // namespace ledgerase
