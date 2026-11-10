contract ThreatRegistry {

    enum ReportStatus { Active, Disputed, Revised }

    struct Revision {
        bytes32 reportHash;
        string note;
        uint256 timestamp;
    }

    struct Report {
        uint256 id;
        bytes32 reportHash;
        bytes32 domainHash;
        uint8 category;
        string evidenceRef;
        address reporter;
        uint256 timestamp;
        uint256 revision;
        ReportStatus status;
        uint256 confirmations;
        uint256 disputes;
    }

    uint256 public reportCount;
    mapping(uint256 => Report) public reports;
    mapping(uint256 => Revision[]) private _revisionHistory;
    mapping(bytes32 => uint256) public hashToReportId;
    mapping(uint256 => mapping(address => bool)) public hasVoted;

    // Events
    event ReportSubmitted(
        uint256 indexed id,
        bytes32 indexed reportHash,
        bytes32 indexed domainHash,
        address reporter,
        uint8 category,
        string evidenceRef
    );

    event ReportRevised(
        uint256 indexed id,
        bytes32 oldHash,
        bytes32 indexed newHash,
        address indexed reporter,
        uint256 revision,
        string note
    );

    event ReportConfirmed(
        uint256 indexed id,
        address indexed voter,
        uint256 totalConfirmations
    );

    event ReportDisputed(
        uint256 indexed id,
        address indexed voter,
        bytes32 indexed reasonHash,
        uint256 totalDisputes
    );

    error ReportNotFound();
    error NotReporter();
    error AlreadyVoted();
    error HashAlreadyCommitted();
    error EmptyHash();
    error EmptyEvidenceReference();

    function submitReport(
        bytes32 reportHash,
        bytes32 domainHash,
        uint8 category,
        string calldata evidenceRef
    ) external returns (uint256 id) {
        if (reportHash == bytes32(0)) revert EmptyHash();
        if (hashToReportId[reportHash] != 0) revert HashAlreadyCommitted();
        if (bytes(evidenceRef).length == 0) revert EmptyEvidenceReference();

        reportCount++;
        id = reportCount;

        Report storage r = reports[id];
        r.id = id;
        r.reportHash = reportHash;
        r.domainHash = domainHash;
        r.category = category;
        r.evidenceRef = evidenceRef;
        r.reporter = msg.sender;
        r.timestamp = block.timestamp;
        r.revision = 0;
        r.status = ReportStatus.Active;
        r.confirmations = 1;
        r.disputes = 0;

        hashToReportId[reportHash] = id;
        hasVoted[id][msg.sender] = true;

        emit ReportSubmitted(id, reportHash, domainHash, msg.sender, category, evidenceRef);
        return id;
    }

    function reviseReport(
        uint256 id,
        bytes32 newHash,
        string calldata note
    ) external {
        if (id == 0 || id > reportCount) revert ReportNotFound();
        Report storage r = reports[id];
        if (msg.sender != r.reporter) revert NotReporter();
        if (newHash == bytes32(0)) revert EmptyHash();
        if (hashToReportId[newHash] != 0) revert HashAlreadyCommitted();

        bytes32 oldHash = r.reportHash;
        _revisionHistory[id].push(Revision({
            reportHash: oldHash,
            note: note,
            timestamp: block.timestamp
        }));

        r.revision++;
        r.reportHash = newHash;
        r.status = ReportStatus.Revised;
        delete hashToReportId[oldHash];
        hashToReportId[newHash] = id;

        emit ReportRevised(id, oldHash, newHash, msg.sender, r.revision, note);
    }

    function confirmReport(uint256 id) external {
        if (id == 0 || id > reportCount) revert ReportNotFound();
        if (hasVoted[id][msg.sender]) revert AlreadyVoted();

        Report storage r = reports[id];
        hasVoted[id][msg.sender] = true;
        r.confirmations++;

        emit ReportConfirmed(id, msg.sender, r.confirmations);
    }

    function disputeReport(uint256 id, bytes32 reasonHash) external {
        if (id == 0 || id > reportCount) revert ReportNotFound();
        if (hasVoted[id][msg.sender]) revert AlreadyVoted();

        Report storage r = reports[id];
        hasVoted[id][msg.sender] = true;
        r.disputes++;

        if (r.disputes > r.confirmations) {
            r.status = ReportStatus.Disputed;
        }

        emit ReportDisputed(id, msg.sender, reasonHash, r.disputes);
    }

    function getReport(uint256 id) external view returns (Report memory) {
        if (id == 0 || id > reportCount) revert ReportNotFound();
        return reports[id];
    }

    function getRevisionHistory(uint256 id) external view returns (Revision[] memory) {
        if (id == 0 || id > reportCount) revert ReportNotFound();
        return _revisionHistory[id];
    }

    function verifyHash(bytes32 reportHash) external view returns (
        bool exists,
        uint256 id,
        address reporter,
        uint256 timestamp,
        uint256 revision,
        ReportStatus status
    ) {
        id = hashToReportId[reportHash];
        if (id == 0) {
            return (false, 0, address(0), 0, 0, ReportStatus.Active);
        }
        Report storage r = reports[id];
        return (true, r.id, r.reporter, r.timestamp, r.revision, r.status);
    }
}
