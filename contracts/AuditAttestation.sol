// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Stores SHA-256 hashes of audit reports so anyone can prove a PDF is unchanged.
contract AuditAttestation {
    struct Attestation { address auditor; uint64 timestamp; string contractRef; }

    mapping(bytes32 => Attestation) private _att;

    event ReportAnchored(bytes32 indexed reportHash, address indexed auditor, string contractRef, uint64 timestamp);

    function anchor(bytes32 reportHash, string calldata contractRef) external {
        require(reportHash != bytes32(0), "empty hash");
        require(_att[reportHash].timestamp == 0, "already anchored");
        _att[reportHash] = Attestation(msg.sender, uint64(block.timestamp), contractRef);
        emit ReportAnchored(reportHash, msg.sender, contractRef, uint64(block.timestamp));
    }

    function verify(bytes32 reportHash) external view returns (bool exists, address auditor, uint64 timestamp, string memory contractRef) {
        Attestation storage a = _att[reportHash];
        return (a.timestamp != 0, a.auditor, a.timestamp, a.contractRef);
    }
}
