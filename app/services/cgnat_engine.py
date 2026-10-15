"""
WISPnet Deterministic CGNAT Mapping Engine & Validator
Supports MikroTik RouterOS v7 deterministic fixed port block CGNAT architecture.
"""
import ipaddress
import csv
import io
import uuid
from typing import List, Dict, Any, Optional, Tuple, Set
from datetime import datetime, timezone
from app.models.security_schemas import (
    CGNATConfig,
    CGNATMapping,
    CGNATValidationReport,
    CGNATValidationIssue
)

def parse_iso_datetime(dt_str: Optional[str]) -> Optional[datetime]:
    if not dt_str:
        return None
    try:
        clean = dt_str.replace("Z", "+00:00")
        return datetime.fromisoformat(clean)
    except Exception:
        return None

class CGNATEngine:
    """Authoritative deterministic CGNAT allocation generator, validator, and exporter"""

    @staticmethod
    def generate_deterministic_mappings(
        config: CGNATConfig,
        num_subscribers: Optional[int] = None,
        router_id: str = "core-router-ccr2116"
    ) -> List[CGNATMapping]:
        """
        Generates deterministic mappings based on configured pools, port block size,
        and eligible port ranges.
        """
        pub_start = ipaddress.IPv4Address(config.public_pool_start)
        pub_end = ipaddress.IPv4Address(config.public_pool_end)
        sub_start = ipaddress.IPv4Address(config.subscriber_pool_start)

        if int(pub_end) < int(pub_start):
            raise ValueError(f"Public pool end {pub_end} cannot be less than start {pub_start}")

        total_public_ips = int(pub_end) - int(pub_start) + 1
        port_span = config.last_eligible_port - config.first_eligible_port + 1
        if port_span <= 0:
            raise ValueError(f"Invalid port range: {config.first_eligible_port} to {config.last_eligible_port}")

        blocks_per_public_ip = port_span // config.port_block_size
        if blocks_per_public_ip <= 0:
            raise ValueError(
                f"Port block size {config.port_block_size} exceeds port span {port_span}"
            )

        max_capacity = total_public_ips * blocks_per_public_ip
        subscribers_to_allocate = num_subscribers if num_subscribers is not None else max_capacity
        subscribers_to_allocate = min(subscribers_to_allocate, max_capacity)

        mappings: List[CGNATMapping] = []
        current_sub_int = int(sub_start)

        for ip_offset in range(total_public_ips):
            current_pub_ip = str(pub_start + ip_offset)

            for b in range(blocks_per_public_ip):
                if len(mappings) >= subscribers_to_allocate:
                    break

                port_start = config.first_eligible_port + (b * config.port_block_size)
                port_end = port_start + config.port_block_size - 1

                subscriber_ip = str(ipaddress.IPv4Address(current_sub_int))
                current_sub_int += 1

                mapping_id = f"cgnat-{config.mapping_version}-{current_pub_ip}-{port_start}"

                mapping = CGNATMapping(
                    mapping_id=mapping_id,
                    mapping_version=config.mapping_version,
                    public_ip=current_pub_ip,
                    port_start=port_start,
                    port_end=port_end,
                    protocol_scope=config.protocol_scope.lower(),
                    subscriber_cgnat_ip=subscriber_ip,
                    pppoe_username=None,
                    router_id=router_id,
                    effective_from=config.effective_from,
                    effective_to=None,
                    source_of_truth="deterministic_algorithm",
                    validation_status="verified"
                )
                mappings.append(mapping)

            if len(mappings) >= subscribers_to_allocate:
                break

        return mappings

    @staticmethod
    def validate_mappings(
        mappings: List[CGNATMapping],
        first_eligible_port: int = 2048,
        last_eligible_port: int = 65535,
        expected_block_size: Optional[int] = 2048
    ) -> CGNATValidationReport:
        """
        Performs exhaustive mathematical and policy validation across all mappings:
        1. Valid IPv4 addresses
        2. Boundary conditions (first & last eligible ports)
        3. Block alignment and block size consistency
        4. Overlapping port blocks on the same public IP and protocol
        5. Duplicate subscriber allocations
        6. Historical conflict detection (overlapping time intervals for same resource)
        """
        issues: List[CGNATValidationIssue] = []
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        if not mappings:
            return CGNATValidationReport(
                valid=False,
                total_mappings_checked=0,
                unique_public_ips=0,
                unique_subscriber_ips=0,
                blocks_per_public_ip=0,
                issues=[CGNATValidationIssue(
                    severity="error",
                    code="EMPTY_TABLE",
                    message="Mapping table is empty; cannot perform attribution"
                )],
                timestamp=now_iso
            )

        unique_pub_ips: Set[str] = set()
        unique_sub_ips: Set[str] = set()
        pub_ip_block_counts: Dict[str, int] = {}

        # Tracking for overlap detection: (public_ip, protocol) -> list of (port_start, port_end, effective_from, effective_to, mapping_id)
        pub_allocations: Dict[Tuple[str, str], List[Tuple[int, int, Optional[datetime], Optional[datetime], str]]] = {}
        # Tracking for subscriber duplicate: (subscriber_ip, protocol) -> list of (effective_from, effective_to, mapping_id)
        sub_allocations: Dict[Tuple[str, str], List[Tuple[Optional[datetime], Optional[datetime], str]]] = {}

        for idx, m in enumerate(mappings):
            m_id = m.mapping_id or f"entry-{idx}"

            # 1. Validate Public IP
            try:
                pub_obj = ipaddress.IPv4Address(m.public_ip)
                if pub_obj.is_private or pub_obj.is_loopback or pub_obj.is_multicast or pub_obj.is_reserved:
                    issues.append(CGNATValidationIssue(
                        severity="warning",
                        code="NON_PUBLIC_IP",
                        message=f"Public IP {m.public_ip} in mapping {m_id} is private/reserved",
                        details={"mapping_id": m_id, "public_ip": m.public_ip}
                    ))
                unique_pub_ips.add(m.public_ip)
                pub_ip_block_counts[m.public_ip] = pub_ip_block_counts.get(m.public_ip, 0) + 1
            except Exception as e:
                issues.append(CGNATValidationIssue(
                    severity="error",
                    code="INVALID_PUBLIC_IP",
                    message=f"Malformed public IPv4 address '{m.public_ip}' in mapping {m_id}: {e}",
                    details={"mapping_id": m_id, "public_ip": m.public_ip}
                ))

            # 2. Validate Subscriber IP
            try:
                sub_obj = ipaddress.IPv4Address(m.subscriber_cgnat_ip)
                # CGNAT space is RFC 6598 (100.64.0.0/10)
                unique_sub_ips.add(m.subscriber_cgnat_ip)
            except Exception as e:
                issues.append(CGNATValidationIssue(
                    severity="error",
                    code="INVALID_SUBSCRIBER_IP",
                    message=f"Malformed subscriber IPv4 address '{m.subscriber_cgnat_ip}' in mapping {m_id}: {e}",
                    details={"mapping_id": m_id, "subscriber_ip": m.subscriber_cgnat_ip}
                ))

            # 3. Validate Port Range & Alignment
            if m.port_start < first_eligible_port:
                issues.append(CGNATValidationIssue(
                    severity="error",
                    code="PORT_BELOW_MINIMUM",
                    message=f"Port start {m.port_start} in {m_id} is below first eligible port {first_eligible_port}",
                    details={"mapping_id": m_id, "port_start": m.port_start}
                ))

            if m.port_end > last_eligible_port or m.port_end > 65535:
                issues.append(CGNATValidationIssue(
                    severity="error",
                    code="PORT_EXCEEDS_MAXIMUM",
                    message=f"Port end {m.port_end} in {m_id} exceeds last eligible port {last_eligible_port}",
                    details={"mapping_id": m_id, "port_end": m.port_end}
                ))

            if m.port_start > m.port_end:
                issues.append(CGNATValidationIssue(
                    severity="error",
                    code="INVERTED_PORT_RANGE",
                    message=f"Port start {m.port_start} is greater than port end {m.port_end} in {m_id}",
                    details={"mapping_id": m_id}
                ))

            size = m.port_end - m.port_start + 1
            if expected_block_size and size != expected_block_size:
                issues.append(CGNATValidationIssue(
                    severity="error",
                    code="INCORRECT_BLOCK_SIZE",
                    message=f"Block size {size} in {m_id} does not match expected {expected_block_size}",
                    details={"mapping_id": m_id, "size": size, "expected": expected_block_size}
                ))

            if expected_block_size and (m.port_start - first_eligible_port) % expected_block_size != 0:
                issues.append(CGNATValidationIssue(
                    severity="warning",
                    code="MISALIGNED_BLOCK",
                    message=f"Port block {m.port_start}-{m.port_end} in {m_id} is not aligned to {expected_block_size}-port boundary from port {first_eligible_port}",
                    details={"mapping_id": m_id, "port_start": m.port_start}
                ))

            # 4. Check Effective Timestamps
            dt_from = parse_iso_datetime(m.effective_from)
            dt_to = parse_iso_datetime(m.effective_to)

            if not dt_from:
                issues.append(CGNATValidationIssue(
                    severity="error",
                    code="INVALID_EFFECTIVE_FROM",
                    message=f"Mapping {m_id} has invalid or missing effective_from timestamp",
                    details={"mapping_id": m_id, "effective_from": m.effective_from}
                ))

            if dt_from and dt_to and dt_to <= dt_from:
                issues.append(CGNATValidationIssue(
                    severity="error",
                    code="INVALID_VALIDITY_INTERVAL",
                    message=f"Mapping {m_id} has effective_to ({m.effective_to}) <= effective_from ({m.effective_from})",
                    details={"mapping_id": m_id}
                ))

            # 5. Overlap detection on Public IP & Ports
            proto_key = m.protocol_scope.lower()
            pub_key = (m.public_ip, proto_key)
            if pub_key not in pub_allocations:
                pub_allocations[pub_key] = []

            for ex_start, ex_end, ex_from, ex_to, ex_id in pub_allocations[pub_key]:
                # Check port overlap
                if not (m.port_end < ex_start or m.port_start > ex_end):
                    # Check time overlap
                    time_overlap = True
                    if dt_from and ex_to and dt_from >= ex_to:
                        time_overlap = False
                    if dt_to and ex_from and dt_to <= ex_from:
                        time_overlap = False

                    if time_overlap:
                        issues.append(CGNATValidationIssue(
                            severity="error",
                            code="OVERLAPPING_PORT_BLOCK",
                            message=f"Public port block {m.port_start}-{m.port_end} on {m.public_ip} in {m_id} overlaps with {ex_id} ({ex_start}-{ex_end}) during active validity interval",
                            details={"mapping_id": m_id, "conflicting_with": ex_id, "public_ip": m.public_ip}
                        ))

            pub_allocations[pub_key].append((m.port_start, m.port_end, dt_from, dt_to, m_id))

            # 6. Check Duplicate Subscriber Allocation
            sub_key = (m.subscriber_cgnat_ip, proto_key)
            if sub_key not in sub_allocations:
                sub_allocations[sub_key] = []

            for ex_from, ex_to, ex_id in sub_allocations[sub_key]:
                time_overlap = True
                if dt_from and ex_to and dt_from >= ex_to:
                    time_overlap = False
                if dt_to and ex_from and dt_to <= ex_from:
                    time_overlap = False

                if time_overlap:
                    issues.append(CGNATValidationIssue(
                        severity="error",
                        code="DUPLICATE_SUBSCRIBER_ALLOCATION",
                        message=f"Subscriber {m.subscriber_cgnat_ip} in {m_id} is assigned multiple port blocks concurrently (conflicts with {ex_id})",
                        details={"mapping_id": m_id, "conflicting_with": ex_id, "subscriber_ip": m.subscriber_cgnat_ip}
                    ))

            sub_allocations[sub_key].append((dt_from, dt_to, m_id))

        has_errors = any(i.severity == "error" for i in issues)
        avg_blocks = (
            sum(pub_ip_block_counts.values()) // max(1, len(pub_ip_block_counts))
            if pub_ip_block_counts else 0
        )

        return CGNATValidationReport(
            valid=not has_errors,
            total_mappings_checked=len(mappings),
            unique_public_ips=len(unique_pub_ips),
            unique_subscriber_ips=len(unique_sub_ips),
            blocks_per_public_ip=avg_blocks,
            issues=issues,
            timestamp=now_iso
        )

    @staticmethod
    def export_routeros_v7_script(mappings: List[CGNATMapping]) -> str:
        """
        Exports production-grade MikroTik RouterOS v7 NAT rules.
        In RouterOS v7:
        /ip firewall nat add chain=srcnat action=src-nat to-addresses=X.X.X.X to-ports=A-B protocol=tcp src-address=Y.Y.Y.Y comment="..."
        """
        lines = [
            "# ===================================================================",
            "# WISPnet Deterministic CGNAT Firewall NAT Configuration",
            "# MikroTik RouterOS v7.x Architecture - CCR2116 Core Router",
            f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
            f"# Total Rules: {len(mappings)} entries",
            "# ===================================================================",
            "/ip firewall nat",
            "# Disable existing non-deterministic masquerade to prevent port clashing",
            "# /ip firewall nat disable [find chain=srcnat action=masquerade]",
            ""
        ]

        for m in mappings:
            comment = f"WISPnet-CGNAT {m.mapping_version} | Sub:{m.subscriber_cgnat_ip} -> {m.public_ip}:{m.port_start}-{m.port_end}"
            if m.protocol_scope in ("all", "tcp"):
                lines.append(
                    f"add chain=srcnat action=src-nat protocol=tcp src-address={m.subscriber_cgnat_ip} "
                    f"to-addresses={m.public_ip} to-ports={m.port_start}-{m.port_end} "
                    f"comment=\"{comment} (TCP)\""
                )
            if m.protocol_scope in ("all", "udp"):
                lines.append(
                    f"add chain=srcnat action=src-nat protocol=udp src-address={m.subscriber_cgnat_ip} "
                    f"to-addresses={m.public_ip} to-ports={m.port_start}-{m.port_end} "
                    f"comment=\"{comment} (UDP)\""
                )

        lines.append("")
        lines.append("# End of WISPnet RouterOS v7 CGNAT Rules")
        return "\n".join(lines)

    @staticmethod
    def export_csv(mappings: List[CGNATMapping]) -> str:
        """Exports mappings to standard CSV format"""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "mapping_id", "mapping_version", "public_ip", "port_start", "port_end",
            "protocol_scope", "subscriber_cgnat_ip", "pppoe_username", "router_id",
            "effective_from", "effective_to", "source_of_truth", "validation_status"
        ])
        for m in mappings:
            writer.writerow([
                m.mapping_id, m.mapping_version, m.public_ip, m.port_start, m.port_end,
                m.protocol_scope, m.subscriber_cgnat_ip, m.pppoe_username or "", m.router_id or "",
                m.effective_from, m.effective_to or "", m.source_of_truth, m.validation_status
            ])
        return output.getvalue()

    @staticmethod
    def import_csv(csv_content: str) -> List[CGNATMapping]:
        """Imports and parses mappings from CSV content"""
        f = io.StringIO(csv_content.strip())
        reader = csv.DictReader(f)
        mappings: List[CGNATMapping] = []

        for row in reader:
            m = CGNATMapping(
                mapping_id=row.get("mapping_id") or str(uuid.uuid4()),
                mapping_version=row.get("mapping_version", "v1.0"),
                public_ip=row["public_ip"].strip(),
                port_start=int(row["port_start"]),
                port_end=int(row["port_end"]),
                protocol_scope=row.get("protocol_scope", "all").strip().lower(),
                subscriber_cgnat_ip=row["subscriber_cgnat_ip"].strip(),
                pppoe_username=row.get("pppoe_username") or None,
                router_id=row.get("router_id") or "core-router-ccr2116",
                effective_from=row.get("effective_from") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                effective_to=row.get("effective_to") or None,
                source_of_truth=row.get("source_of_truth", "manual_import"),
                validation_status="verified"
            )
            mappings.append(m)
        return mappings
