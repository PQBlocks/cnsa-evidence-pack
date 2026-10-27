"""Parsers for pqblocks-cnsa-evidence: scan_parser() and lockfile_parser() for all 4 ecosystems."""

import hashlib
import json
import re
import warnings
from typing import Dict, List, Any, TypedDict, Literal
import toml
import xml.etree.ElementTree as ET


# Type definitions matching the spec
class AlgorithmInfo(TypedDict):
    name: str  # e.g. "ML-KEM-1024", "ML-DSA-87", "AES-256", "SHA-384"
    type: Literal["key-encapsulation", "signature", "hash", "encryption"]
    mode: Literal["classical", "PQC", "hybrid"]
    keySize: int  # e.g. 1024, 87, 256, 384
    cnsA20Grade: Literal["A", "B", "C", "D", "F"]
    breakYear: int  # NIST IR 8413 estimate


class ScanResult(TypedDict):
    algorithms: list[AlgorithmInfo]
    tls_endpoints: list[dict]
    dependencies: list[dict]
    pqc_grades: dict[str, str]  # algorithm -> grade


class ComponentInfo(TypedDict):
    name: str
    version: str
    ecosystem: str
    type: Literal["library", "application"]
    pqcClassification: Literal["PQC-native", "hybrid", "legacy", "unknown"]


class LockfileResult(TypedDict):
    ecosystem: str
    components: list[ComponentInfo]


class SBOM(TypedDict):
    bomFormat: str  # "CycloneDX"
    specVersion: str  # "1.6"
    info: dict
    components: list
    cryptoProperties: dict
    services: list
    tools: list
    dependencies: list


def scan_parser(parsed_scan: dict) -> ScanResult:
    """
    Parse `pqblocks-scan` CBOM JSON into a typed internal model.

    For each detected asset, extracts:
    - algorithm name (from {ML-KEM-512, ML-KEM-768, ML-KEM-1024, ML-DSA-44, ML-DSA-65, ML-DSA-87, LMS, XMSS, AES-256, SHA-384/512, SLH-DSA, etc.})
    - algorithm type (key-encapsulation, signature, hash, encryption)
    - mode (classical, PQC, hybrid)
    - key size
    - CNSA 2.0 grade (A/B/C/D/F)
    - break-year from NIST IR 8413.

    Args:
        parsed_scan: Dictionary containing pqblocks-scan CBOM JSON

    Returns:
        ScanResult typed dict with algorithms, tls_endpoints, dependencies, pqc_grades
    """
    # Initialize result with default values
    result: ScanResult = {
        "algorithms": [],
        "tls_endpoints": [],
        "dependencies": [],
        "pqc_grades": {}
    }

    # H3 FIX: Raise TypeError for non-dict input
    if not isinstance(parsed_scan, dict):
        raise TypeError(f"Expected dict for parsed_scan, got {type(parsed_scan)}")

    # Extract algorithms
    algorithms = parsed_scan.get("algorithms", [])
    if isinstance(algorithms, list):
        for algo in algorithms:
            if isinstance(algo, dict):
                # Extract fields with defaults
                name = str(algo.get("name", ""))
                algo_type = algo.get("type", "unknown")
                mode = algo.get("mode", "unknown")
                key_size = algo.get("key_size", algo.get("keySize", 0))
                grade = algo.get("cnsA20_grade", algo.get("cnsA20Grade", "F"))
                break_year = algo.get("break_year", algo.get("breakYear", 0))

                # Validate and normalize type
                type_mapping = {
                    "key-encapsulation": "key-encapsulation",
                    "kem": "key-encapsulation",
                    "signature": "signature",
                    "sig": "signature",
                    "hash": "hash",
                    "encryption": "encryption",
                    "encrypt": "encryption"
                }
                normalized_type = type_mapping.get(algo_type, algo_type)

                # Validate and normalize mode
                mode_mapping = {
                    "classical": "classical",
                    "pqc": "PQC",
                    "hybrid": "hybrid"
                }
                normalized_mode = mode_mapping.get(mode.lower(), "unknown")

                # Validate grade
                if grade not in ["A", "B", "C", "D", "F"]:
                    grade = "F"

                # Ensure key_size is integer; non-finite floats coerce to 0 (M1)
                import math
                try:
                    if isinstance(key_size, float) and not math.isfinite(key_size):
                        key_size_int = 0
                    else:
                        key_size_int = int(key_size)
                except (ValueError, TypeError, OverflowError):
                    key_size_int = 0

                # M2 FIX: Validate against FIPS 203/204/205 parameter sets / range check
                FIPS_PARAMETER_SETS = {
                    "ML-KEM-512": 512,
                    "ML-KEM-768": 768,
                    "ML-KEM-1024": 1024,
                    "ML-DSA-44": 44,
                    "ML-DSA-65": 65,
                    "ML-DSA-87": 87,
                }
                if name.upper() in FIPS_PARAMETER_SETS:
                    expected_size = FIPS_PARAMETER_SETS[name.upper()]
                    if key_size_int != 0 and key_size_int != expected_size:
                        grade = "F"
                if key_size_int < 0 or key_size_int > 16384:
                    key_size_int = 0
                    grade = "F"

                # M1 FIX: Finite guard for break_year (coerce non-finite to 0)
                try:
                    if isinstance(break_year, float) and not math.isfinite(break_year):
                        break_year_int = 0
                    else:
                        break_year_int = int(break_year)
                except (ValueError, TypeError):
                    break_year_int = 0

                algorithm_info: AlgorithmInfo = {
                    "name": name,
                    "type": normalized_type,
                    "mode": normalized_mode,
                    "keySize": key_size_int,
                    "cnsA20Grade": grade,
                    "breakYear": break_year_int
                }
                result["algorithms"].append(algorithm_info)

                # Also populate pqc_grades for convenience
                if name:
                    result["pqc_grades"][name] = grade

    # Extract TLS endpoints
    tls_endpoints = parsed_scan.get("tls_endpoints", [])
    if isinstance(tls_endpoints, list):
        result["tls_endpoints"] = tls_endpoints

    # H3 FIX: Validate dependencies entries are dicts (loud vs silent empty)
    dependencies = parsed_scan.get("dependencies", [])
    if isinstance(dependencies, list):
        validated_deps = []
        for dep in dependencies:
            if isinstance(dep, dict):
                if not any(k in dep for k in ("name", "version", "file_path")):
                    raise TypeError(f"Dependency entry carries no recognized keys, got {dep}")
                validated_deps.append(dep)
            else:
                raise TypeError(f"Dependency entry must be dict, got {type(dep)}: {dep}")
        result["dependencies"] = validated_deps

    # Extract pqc_grades if not already populated from algorithms
    pqc_grades = parsed_scan.get("pqc_grades", {})
    if isinstance(pqc_grades, dict):
        for algo, grade in pqc_grades.items():
            if isinstance(algo, str) and isinstance(grade, str) and grade in ["A", "B", "C", "D", "F"]:
                if algo not in result["pqc_grades"]:  # Don't overwrite if already set
                    result["pqc_grades"][algo] = grade

    return result


def _parse_python_requirements(content: str) -> List[Dict[str, Any]]:
    """Parse Python requirements.txt file."""
    components = []
    # Regex to match package==version or package>=version etc.
    # Handles: package, package==1.0, package>=1.0, package<2.0, package~=1.0
    pattern = r'^([a-zA-Z0-9][a-zA-Z0-9._-]*)\s*([=<>!~]+.*)?$'

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        match = re.match(pattern, line)
        if match:
            name = match.group(1)
            version_spec = match.group(2) or ""

            # Extract version from spec (simplified - takes first version-like thing)
            version = "0.0.0"
            if version_spec:
                # Look for version numbers in the spec
                version_match = re.search(r'[\d]+(?:[.][\d]+)*[a-zA-Z0-9]*', version_spec)
                if version_match:
                    version = version_match.group(0)
                else:
                    warnings.warn(
                        f"requirements entry {line!r} carries an unparseable "
                        f"version spec; recording version as 0.0.0 (unknown)",
                        UserWarning,
                        stacklevel=2,
                    )

            components.append({
                "name": name,
                "version": version,
                "ecosystem": "python",
                "type": "library",
                "pqcClassification": "unknown"  # Will be determined later by scan data
            })
        else:
            warnings.warn(
                f"requirements entry {line!r} skipped: not a parseable "
                f"package spec; it contributes no component",
                UserWarning,
                stacklevel=2,
            )

    return components


def _parse_python_setup_py(content: str) -> List[Dict[str, Any]]:
    """Parse Python setup.py file using basic AST parsing."""
    components = []
    try:
        # Simple approach: look for install_requires or similar patterns
        # This is a simplified parser - in reality we'd use ast or setuptools
        lines = content.splitlines()
        in_install_requires = False
        bracket_count = 0

        for line in lines:
            stripped = line.strip()
            if "install_requires" in stripped or "requires" in stripped:
                in_install_requires = True
                # Extract content after =
                if "=" in stripped:
                    after_equals = stripped.split("=", 1)[1].strip()
                    if after_equals.startswith("["):
                        bracket_count = 1
                        # Process the rest of this line
                        content_part = after_equals[1:]
                        # Simple extraction - look for quoted strings
                        quoted_matches = re.findall(r'["\']([^"\']*)["\']', content_part)
                        for match in quoted_matches:
                            if match and not match.startswith("#"):
                                # Parse package==version
                                parts = re.split(r'[=<>!~]', match, maxsplit=1)
                                name = parts[0].strip()
                                version = parts[1].strip() if len(parts) > 1 else "0.0.0"
                                # Clean version
                                version = re.sub(r'[<>=!~].*', '', version).strip()
                                if not version:
                                    version = "0.0.0"
                                components.append({
                                    "name": name,
                                    "version": version,
                                    "ecosystem": "python",
                                    "type": "library",
                                    "pqcClassification": "unknown"
                                })
            elif in_install_requires:
                # Look for quoted strings in this line
                quoted_matches = re.findall(r'["\']([^"\']*)["\']', stripped)
                for match in quoted_matches:
                    if match and not match.startswith("#"):
                        # Parse package==version
                        parts = re.split(r'[=<>!~]', match, maxsplit=1)
                        name = parts[0].strip()
                        version = parts[1].strip() if len(parts) > 1 else "0.0.0"
                        # Clean version
                        version = re.sub(r'[<>=!~].*', '', version).strip()
                        if not version:
                            version = "0.0.0"
                        components.append({
                            "name": name,
                            "version": version,
                            "ecosystem": "python",
                            "type": "library",
                            "pqcClassification": "unknown"
                        })

            # Check if we've exited the list
            if "]" in stripped:
                in_install_requires = False
    except Exception:
        # If parsing fails, return empty list
        pass

    return components


def _parse_python_pyproject_toml(content: str) -> List[Dict[str, Any]]:
    """Parse Python pyproject.toml file."""
    components = []
    # Try to parse TOML; silently return empty if not valid TOML
    # This allows combining with requirements.txt parsing without failures
    try:
        data = toml.loads(content)
    except Exception:
        # Not a valid TOML file - silently return empty list
        return []

    # Check [project] dependencies
    project_deps = data.get("project", {}).get("dependencies", [])
    for dep in project_deps:
        if isinstance(dep, str):
            # Parse package==version or package>=version etc.
            # Use regex to separate name from version spec
            match = re.match(r'^([a-zA-Z0-9][a-zA-Z0-9._-]*)\s*([=<>!~]+.*)?$', dep)
            if match:
                name = match.group(1)
                version_spec = match.group(2) or ""
                version = "0.0.0"
                if version_spec:
                    version_match = re.search(r'[\d]+(?:[.][\d]+)*[a-zA-Z0-9]*', version_spec)
                    if version_match:
                        version = version_match.group(0)
                components.append({
                    "name": name,
                    "version": version,
                    "ecosystem": "python",
                    "type": "library",
                    "pqcClassification": "unknown"
                })

    # Check [tool.poetry] dependencies
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for name, dep_spec in poetry_deps.items():
        if name == "python":
            continue
        if isinstance(dep_spec, str):
            version = dep_spec if dep_spec not in ["*", "^", "~"] else "0.0.0"
            # Clean up version spec
            version = re.sub(r'[\\^~]', '', version)
            if not version or version == "*":
                version = "0.0.0"
        elif isinstance(dep_spec, dict):
            version = dep_spec.get("version", "0.0.0")
        else:
            version = "0.0.0"

        components.append({
            "name": name,
            "version": version,
            "ecosystem": "python",
            "type": "library",
            "pqcClassification": "unknown"
        })
    return components


def _parse_go_mod(content: str) -> List[Dict[str, Any]]:
    """Parse Go go.mod file."""
    components = []
    lines = content.splitlines()
    in_require = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_require = True
            continue
        elif in_require and stripped == ")":
            in_require = False
            continue
        elif in_require:
            # Parse require line: github.com/user/repo v1.2.3 // indirect
            parts = stripped.split()
            if len(parts) >= 2:
                # First part is module path
                module_path = parts[0]
                # Second part might be version or "//"
                if parts[1] != "//":
                    version = parts[1]
                    # Skip if it's indicating indirect
                    if len(parts) > 2 and parts[2] == "//indirect":
                        pass  # Still include it
                    components.append({
                        "name": module_path,
                        "version": version,
                        "ecosystem": "go",
                        "type": "library",
                        "pqcClassification": "unknown"
                    })
        elif not in_require and stripped.startswith("require "):
            # Single line require: require github.com/user/repo v1.2.3
            parts = stripped.split()
            if len(parts) >= 3:
                module_path = parts[1]
                version = parts[2]
                components.append({
                    "name": module_path,
                    "version": version,
                    "ecosystem": "go",
                    "type": "library",
                    "pqcClassification": "unknown"
                })

    return components


def _parse_javascript_package_lock(content: str) -> List[Dict[str, Any]]:
    """Parse JavaScript package-lock.json file."""
    components = []
    try:
        data = json.loads(content)

        # Parse dependencies from the lockfile
        dependencies = data.get("dependencies", {})
        for name, dep_info in dependencies.items():
            if isinstance(dep_info, dict):
                version = dep_info.get("version", "0.0.0")
                # Clean version (remove leading ^, ~, etc.)
                version = re.sub(r'[\\^~]', '', version)
                if version.startswith("v"):
                    version = version[1:]
                if not version:
                    version = "0.0.0"

                components.append({
                    "name": name,
                    "version": version,
                    "ecosystem": "javascript",
                    "type": "library",
                    "pqcClassification": "unknown"
                })

                # Also parse nested dependencies if present
                nested_deps = dep_info.get("dependencies", {})
                for nested_name, nested_info in nested_deps.items():
                    if isinstance(nested_info, dict):
                        nested_version = nested_info.get("version", "0.0.0")
                        nested_version = re.sub(r'[\\^~]', '', nested_version)
                        if nested_version.startswith("v"):
                            nested_version = nested_version[1:]
                        if not nested_version:
                            nested_version = "0.0.0"

                        components.append({
                            "name": nested_name,
                            "version": nested_version,
                            "ecosystem": "javascript",
                            "type": "library",
                            "pqcClassification": "unknown"
                        })
    except Exception:
        # If parsing fails, return empty list
        pass

    return components


def lockfile_parser(ecosystem: str, lockfile_content: str) -> LockfileResult:
    """
    Parse lockfile for given ecosystem. Returns normalized component list:
    name, version, ecosystem, type (library/app), PQC classification.

    Args:
        ecosystem: One of "python", "java", "go", "javascript"
        lockfile_content: String content of the lockfile

    Returns:
        LockfileResult typed dict with ecosystem and components list
    """
    # H3 FIX: Raise ValueError for unknown ecosystem
    valid_ecosystems = ["python", "java", "go", "javascript"]
    if ecosystem not in valid_ecosystems:
        raise ValueError(f"Unknown ecosystem '{ecosystem}'. Supported ecosystems: {valid_ecosystems}")

    result: LockfileResult = {
        "ecosystem": ecosystem,
        "components": []
    }

    if not isinstance(lockfile_content, str): raise TypeError(f"Expected str for lockfile_content, got {type(lockfile_content)}")

    # Dispatch to appropriate parser based on ecosystem
    if ecosystem == "python":
        # Try multiple Python formats
        components = []
        components.extend(_parse_python_requirements(lockfile_content))
        components.extend(_parse_python_setup_py(lockfile_content))
        components.extend(_parse_python_pyproject_toml(lockfile_content))
        # Remove duplicates based on name+version
        seen = set()
        unique_components = []
        for comp in components:
            key = (comp["name"], comp["version"])
            if key not in seen:
                seen.add(key)
                unique_components.append(comp)
        if not unique_components and lockfile_content.strip():
            raise ValueError(
                "lockfile content for ecosystem 'python' yielded no parseable "
                "components: unrecognized format (not requirements.txt, "
                "setup.py, or pyproject.toml). Pass an empty string for a "
                "missing lockfile."
            )
        result["components"] = unique_components

    elif ecosystem == "java":
        result["components"] = _parse_java_maven(lockfile_content)

    elif ecosystem == "go":
        result["components"] = _parse_go_mod(lockfile_content)

    elif ecosystem == "javascript":
        result["components"] = _parse_javascript_package_lock(lockfile_content)

    # For unknown ecosystems, we already raised ValueError above
    return result


def _parse_java_maven(content: str) -> List[Dict[str, Any]]:
    """Parse Java Maven pom.xml file."""
    components = []
    try:
        # Simple XML parsing for dependencies
        import xml.etree.ElementTree as ET
        root = ET.fromstring(content)

        # Find all dependency elements, with or without the Maven namespace
        deps = list(root.iter('{http://maven.apache.org/POM/4.0.0}dependency'))
        if not deps:
            deps = list(root.iter('dependency'))
        for dependency in deps:
            def find_text(elem, tag):
                ns = elem.find(f'{{http://maven.apache.org/POM/4.0.0}}{tag}')
                if ns is None:
                    ns = elem.find(tag)
                return ns.text if ns is not None else None
            group_id = find_text(dependency, 'groupId') or ""
            artifact_id = find_text(dependency, 'artifactId') or ""
            version = find_text(dependency, 'version')

            if group_id and artifact_id:
                # Clean version
                version = re.sub(r'[<>=!~].*', '', version).strip() if version else "0.0.0"
                if not version:
                    version = "0.0.0"

                components.append({
                    "name": f"{group_id}:{artifact_id}",
                    "version": version,
                    "ecosystem": "java",
                    "type": "library",
                    "pqcClassification": "unknown"
                })
    except Exception:
        # If parsing fails, return empty list
        pass
    
    return components


def _need_dicts(**named):
    """Loud, named TypeError for a non-dict input (same contract as scan_parser)."""
    for name, value in named.items():
        if not isinstance(value, dict):
            raise TypeError(f"Expected dict for {name}, got {type(value)}")


def sbom_emitter(scan_result: dict, lockfile_result: dict) -> SBOM:
    """Assembles CycloneDX 1.6 SBOM with cryptoProperties.

    For each component, determines algorithm type and mode. cryptoProperties
    element follows §5.5 of CycloneDX 1.6 spec with algorithms list keyed by name,
    each entry having: name, type (key-encapsulation/signature/hash/encryption),
    mode (classical/PQC/hybrid), keySize, cnsA20Grade (A/B/C/D/F).

    Args:
        scan_result: ScanResult from scan_parser()
        lockfile_result: LockfileResult from lockfile_parser()

    Returns:
        SBOM dict with CycloneDX 1.6 structure including cryptoProperties
    """
    import json
    import hashlib
    _need_dicts(scan_result=scan_result, lockfile_result=lockfile_result)
    # SBOM type is already defined above

    # Initialize SBOM structure with standard CycloneDX 1.6 fields at top level
    sbom: SBOM = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": "1",
        "serialNumber": hashlib.sha256(json.dumps(scan_result, sort_keys=True).encode() + json.dumps(lockfile_result, sort_keys=True).encode()).hexdigest(),
        "info": {},  # Nested metadata container
        "components": [],
        "cryptoProperties": {"algorithms": []},
        "services": [],
        "tools": [],
        "dependencies": []
    }

    # Add tool info
    sbom["tools"].append({
        "name": "pqblocks-cnsa-evidence",
        "vendor": "pqblocks-cnsa-evidence",
        "version": "0.1.0"
    })

    # Gather algorithms from scan
    scan_algos = scan_result.get("algorithms", [])
    all_algos = []

    # Build a map of algorithm info from scan
    algo_map = {}
    for algo in scan_algos:
        name = algo.get("name", "")
        if name:
            algo_map[name] = {
                "type": algo.get("type", "unknown"),
                "mode": algo.get("mode", "unknown"),
                "keySize": algo.get("keySize", 0),
                "cnsA20Grade": algo.get("cnsA20Grade", "F")
            }
            all_algos.append(name)

    # Gather components from lockfile
    lockfile_components = lockfile_result.get("components", [])
    seen_comp_keys = set()

    for comp in lockfile_components:
        comp_name = comp.get("name", "")
        comp_version = comp.get("version", "0.0.0")
        comp_key = (comp_name, comp_version)

        if comp_key in seen_comp_keys:
            continue
        seen_comp_keys.add(comp_key)

        # Determine algorithm type and mode from lockfile component
        # Look up in algo_map or default
        algo_info = algo_map.get(comp_name, {
            "type": "unknown",
            "mode": "unknown",
            "keySize": 0,
            "cnsA20Grade": "F"
        })

        # Determine hybrid status - if component has PQC classification
        pqc_classification = comp.get("pqcClassification", "unknown")
        mode = algo_info["mode"]
        if pqc_classification in ["PQC-native", "hybrid"] and mode == "unknown":
            mode = pqc_classification

        comp_entry = {
            "name": comp_name,
            "version": comp_version,
            "type": comp.get("type", "library"),
            "pqcClassification": pqc_classification
        }

        # Add algorithm info to cryptoProperties if applicable
        if comp_name in algo_map or pqc_classification != "unknown":
            algo_entry = {
                "name": comp_name,
                "type": algo_info["type"],
                "mode": mode,
                "keySize": algo_info["keySize"],
                "cnsA20Grade": algo_info["cnsA20Grade"]
            }
            # Only add if not already in cryptoProperties algorithms
            existing_names = {a["name"] for a in sbom["cryptoProperties"]["algorithms"]}
            if comp_name not in existing_names:
                sbom["cryptoProperties"]["algorithms"].append(algo_entry)

        sbom["components"].append(comp_entry)

    # Also add any algorithms from scan that weren't in lockfile components
    for algo_name in all_algos:
        existing_names = {a["name"] for a in sbom["cryptoProperties"]["algorithms"]}
        if algo_name not in existing_names:
            algo_info = algo_map.get(algo_name, {
                "type": "unknown",
                "mode": "unknown",
                "keySize": 0,
                "cnsA20Grade": "F"
            })
            algo_entry = {
                "name": algo_name,
                "type": algo_info["type"],
                "mode": algo_info["mode"],
                "keySize": algo_info["keySize"],
                "cnsA20Grade": algo_info["cnsA20Grade"]
            }
            sbom["cryptoProperties"]["algorithms"].append(algo_entry)

    return sbom


def crypto_inventory_emitter(scan_result: dict, lockfile_result: dict) -> dict:
    """Produces flat algorithm-to-file inventory dict.

    For each detected algorithm from the scan, collects all file paths
    where it appears: TLS endpoints and lockfile components.

    Args:
        scan_result: ScanResult from scan_parser()
        lockfile_result: LockfileResult from lockfile_parser()

    Returns:
        dict mapping algorithm name -> {files: list, keySize: int, breakYear: int, cnsA20Grade: str}
        Empty dict if scan has no algorithms.
    """
    _need_dicts(scan_result=scan_result, lockfile_result=lockfile_result)
    # Handle empty scan
    scan_algos = scan_result.get("algorithms", [])
    if not scan_algos:
        return {}

    # Build a map of algorithm info from scan, keyed by name
    algo_map = {}
    for algo in scan_result.get("algorithms", []):
        if isinstance(algo, dict) and algo.get("name"):
            name = algo["name"]
            if name not in algo_map:
                algo_map[name] = {
                    "keySize": algo.get("keySize", 0),
                    "cnsA20Grade": algo.get("cnsA20Grade", "F"),
                    "mode": algo.get("mode", "unknown"),
                    "breakYear": algo.get("breakYear", 0),
                }

    # Collect file paths from TLS endpoints - associate ALL TLS endpoints with ALL algorithms
    tls_endpoints = scan_result.get("tls_endpoints", [])
    algo_files: dict[str, list[str]] = {name: [] for name in algo_map}

    for endpoint in tls_endpoints:
        if isinstance(endpoint, dict):
            file_path = endpoint.get("file_path", "") or endpoint.get("path", "")
            if not file_path:
                continue
            # Associate this file path with all algorithms in the scan
            for algo_name in algo_map:
                if file_path not in algo_files[algo_name]:
                    algo_files[algo_name].append(file_path)

    # Collect file paths from scan dependencies - associate ALL dependencies with ALL algorithms
    scan_deps = scan_result.get("dependencies", [])
    for dep in scan_deps:
        if isinstance(dep, dict):
            file_path = dep.get("file_path", "")
            if not file_path:
                continue
            # Associate this file path with all algorithms in the scan
            for algo_name in algo_map:
                if file_path not in algo_files[algo_name]:
                    algo_files[algo_name].append(file_path)

    # Collect file paths from lockfile components - associate ALL lockfile components with ALL algorithms
    lockfile_components = lockfile_result.get("components", [])
    for comp in lockfile_components:
        if isinstance(comp, dict):
            file_path = comp.get("file_path", "")
            if not file_path:
                continue
            # Associate this file path with all algorithms in the scan
            for algo_name in algo_map:
                if file_path not in algo_files[algo_name]:
                    algo_files[algo_name].append(file_path)

    # Convert to output format: flat dict mapping algo name -> inventory info
    inventory = {}
    for algo_name in algo_map:
        inventory[algo_name] = {
            "files": algo_files.get(algo_name, []),
            "keySize": algo_map[algo_name]["keySize"],
            "breakYear": algo_map[algo_name]["breakYear"],
            "cnsA20Grade": algo_map[algo_name]["cnsA20Grade"],
        }

    return inventory


def compliance_matrix_emitter(scan_result: dict) -> dict:
    """Produces CNSA 2.0 compliance matrix (5 requirements × evidence fields).
    Each requirement maps to: algorithm name found in codebase, evidence (yes/no/partial),
    grade (A/B/C/D/F, auto-derived from pqcframework MV-CBOM model), break-year
    (auto-derived from NIST IR 8413).

    Args:
        scan_result: ScanResult from scan_parser()

    Returns:
        dict mapping requirement -> {requirement, algorithm, evidence, grade, breakYear}
        Always returns exactly 5 entries for the 5 CNSA 2.0 requirements.
    """
    import math

    if not isinstance(scan_result, dict):
        raise TypeError(f"Expected dict for scan_result, got {type(scan_result)}")

    # Initialize result with default values for all 5 requirements
    compliance_matrix = {
        "key-establishment": {
            "requirement": "key-establishment",
            "algorithm": "",
            "evidence": "not-found",
            "grade": "F",
            "breakYear": 0
        },
        "signature": {
            "requirement": "signature",
            "algorithm": "",
            "evidence": "not-found",
            "grade": "F",
            "breakYear": 0
        },
        "encryption": {
            "requirement": "encryption",
            "algorithm": "",
            "evidence": "not-found",
            "grade": "F",
            "breakYear": 0
        },
        "hashing": {
            "requirement": "hashing",
            "algorithm": "",
            "evidence": "not-found",
            "grade": "F",
            "breakYear": 0
        },
        "fallback": {
            "requirement": "fallback",
            "algorithm": "",
            "evidence": "not-found",
            "grade": "F",
            "breakYear": 0
        }
    }

    # Handle empty scan
    algorithms = scan_result.get("algorithms", [])
    if not algorithms:
        return compliance_matrix

    # Build a map of algorithm info from scan, keyed by name
    algo_map = {}
    for algo in algorithms:
        if not isinstance(algo, dict):
            raise TypeError(
                f"Expected dict for algorithm entry, got {type(algo)}: {algo!r}"
            )
        if algo.get("name"):
            name = algo["name"]
            grade = algo.get("cnsA20Grade", algo.get("cnsA20_grade", "F"))
            if grade not in ["A", "B", "C", "D", "F"]:
                grade = "F"
            raw_break_year = algo.get("breakYear", algo.get("break_year", 0))
            try:
                if isinstance(raw_break_year, float) and not math.isfinite(raw_break_year):
                    break_year = 0
                else:
                    break_year = int(raw_break_year)
            except (ValueError, TypeError, OverflowError):
                break_year = 0
            algo_map[name] = {
                "type": algo.get("type", "unknown"),
                "grade": grade,
                "breakYear": break_year,
                "mode": algo.get("mode", "unknown")
            }

    # Map algorithm types to CNSA 2.0 requirements
    type_to_requirement = {
        "key-encapsulation": "key-establishment",
        "signature": "signature",
        "encryption": "encryption",
        "hash": "hashing"
    }

    # Track which requirements we've found evidence for
    found_requirements = set()

    # Process each algorithm to fill in the compliance matrix
    for algo_name, algo_info in algo_map.items():
        algo_type = algo_info["type"]
        grade = algo_info["grade"]
        break_year = algo_info["breakYear"]
        mode = algo_info["mode"]
        
        # Map algorithm type to requirement if it's a known type
        if algo_type in type_to_requirement:
            requirement = type_to_requirement[algo_type]
            
            # Only update if we haven't found evidence for this requirement yet
            current_entry = compliance_matrix[requirement]
            if current_entry["evidence"] == "not-found":
                # Determine evidence level based on algorithm completeness
                # Evidence is "found" only if ALL fields are valid/known
                is_partial = (
                    algo_type == "unknown" or 
                    grade == "F" or 
                    break_year == 0 or
                    mode == "unknown"
                )
                
                evidence = "partial" if is_partial else "found"
                
                compliance_matrix[requirement] = {
                    "requirement": requirement,
                    "algorithm": algo_name,
                    "evidence": evidence,
                    "grade": grade,
                    "breakYear": break_year
                }

    # Handle fallback requirement - for now, we don't have a specific algorithm type mapping
    # In a real implementation, this might look for specific fallback algorithms
    # or be filled based on policy decisions
    
    return compliance_matrix


def narrative_emitter(scan_result: dict, lockfile_result: dict) -> str:
    """Generates key-management narrative markdown.

    Covers: exposed keys inventory, retirement milestones per key/algorithm with
    concrete dates, migration strategy (classical → PQC hybrids → PQC-native),
    governance (ownership, approval workflow, audit schedule), exception
    handling (approved exceptions with risk acceptance).

    Args:
        scan_result: ScanResult from scan_parser()
        lockfile_result: LockfileResult from lockfile_parser()

    Returns:
        Markdown string with the 5 narrative sections.
    """
    lines = []
    lines.append("# Key Management Narrative")
    lines.append("")
    lines.append("## Exposed Keys")
    lines.append("")

    algorithms = scan_result.get("algorithms", []) or []
    if algorithms:
        for algo in algorithms:
            if isinstance(algo, dict):
                name = algo.get("name", "unknown")
                key_size = algo.get("keySize", 0)
                lines.append(f"- {name} (keySize: {key_size})")
    else:
        lines.append("No keys found in the provided scan data.")
    lines.append("")
    
    lines.append("## Retirement Milestones")
    lines.append("")
    timelines = []
    for algo in algorithms:
        if isinstance(algo, dict):
            name = algo.get("name", "unknown")
            break_year = algo.get("breakYear", 0)
            if break_year and break_year > 0:
                timelines.append(f"- {name}: retirement by year {break_year}")
    if timelines:
        lines.extend(timelines)
    else:
        lines.append("No retirement milestones available.")
    lines.append("")
    
    lines.append("## Migration Strategy")
    lines.append("")
    lines.append("- Transition from classical algorithms to PQC hybrids, then to PQC-native solutions, adhering to CNSA 2.0 guidelines.")
    lines.append("")
    
    lines.append("## Governance")
    lines.append("")
    lines.append("- Ownership: Security team oversees cryptographic migrations.")
    lines.append("- Approval workflow: All key retirements and migrations require security council approval.")
    lines.append("- Audit schedule: Annual audit of cryptographic practices and compliance with CNSA 2.0.")
    lines.append("")
    
    lines.append("## Exception Handling")
    lines.append("")
    lines.append("- Approved exceptions and associated risk acceptance documents must be filed within the governance framework.")
    lines.append("")
    
    return "\n".join(lines)


def executive_summary_emitter(compliance_matrix: dict, narrative: Any, migration_plan: Any) -> str:
    """Produces 1-page markdown summary for procurement officers.

    Covers: RFP compliance checkmarks, key findings (number of exposed keys,
    grade distribution), risk summary (harvest-now-decrypt-later exposure),
    migration timeline (high-level months), recommendation (go/no-go with conditions).

    Args:
        compliance_matrix: Compliance matrix from compliance_matrix_emitter()
        narrative: Narrative dict from narrative_emitter() or markdown string
        migration_plan: Migration plan YAML from migration_scheduler() or dict

    Returns:
        1-page markdown string for procurement officers.
    """
    import re

    # Parse compliance matrix entries
    cm = compliance_matrix
    requirements = cm.keys() if isinstance(cm, dict) else []

    # Determine grade distribution from compliance matrix
    grade_distribution = {}
    exposed_keys_count = 0
    for req_key, entry in cm.items():
        if isinstance(entry, dict):
            grade = entry.get("grade", "F")
            grade_distribution[grade] = grade_distribution.get(grade, 0) + 1
            algo = entry.get("algorithm", "")
            if algo and isinstance(algo, str):
                exposed_keys_count += 1

    # Parse key findings from narrative (support both str and dict)
    if isinstance(narrative, str):
        lower_narrative = narrative.lower()
    elif isinstance(narrative, dict):
        lower_narrative = json.dumps(narrative).lower()
    else:
        lower_narrative = str(narrative).lower() if narrative else ""

    # Parse migration timeline from migration plan (support both str and dict)
    months_covered = []
    if isinstance(migration_plan, str):
        month_matches = re.findall(r"20[2-9][0-9]-[01][0-9]", migration_plan)
        months_covered = list(set(month_matches))
    elif isinstance(migration_plan, dict):
        months_covered = migration_plan.get("months", [])
        if not months_covered:
            # Check for entries in dict values or list
            for v in migration_plan.values():
                if isinstance(v, str):
                    month_matches = re.findall(r"20[2-9][0-9]-[01][0-9]", v)
                    months_covered.extend(month_matches)
        months_covered = list(set(months_covered))

    # Build the 1-page executive summary markdown
    lines = []

    # Title
    lines.append("# Executive Summary")
    lines.append("")

    # RFP Compliance section
    lines.append("## RFP Compliance")
    lines.append("")
    lines.append("| Requirement | Status | Algorithm | Grade |")
    lines.append("|---|---|---|---|")
    for req in ["key-establishment", "signature", "encryption", "hashing", "fallback"]:
        if req in cm and isinstance(cm[req], dict):
            entry = cm[req]
            algo = entry.get("algorithm", "N/A")
            grade = entry.get("grade", "F")
            evidence = entry.get("evidence", "not-found")
            status = "✓" if evidence == "found" else "✗"
            lines.append(f"| {req.replace('-', ' ').title()} | {status} | {algo} | {grade} |")
        else:
            lines.append(f"| {req.replace('-', ' ').title()} | ✗ | N/A | F |")
    lines.append("")

    # Key Findings section
    lines.append("## Key Findings")
    lines.append("")
    if exposed_keys_count == 0:
        lines.append("- **No exposed keys found**")
    else:
        lines.append(f"- **Exposed keys detected:** {exposed_keys_count}")
    lines.append(f"- **Grade distribution:** {grade_distribution}")
    lines.append("")
    
    # Risk Summary section
    lines.append("## Risk Summary")
    lines.append("")
    has_harvest = "harvest" in lower_narrative or "harvest-now" in lower_narrative
    has_decrypt = "decrypt" in lower_narrative
    if has_harvest:
        lines.append("- **Harvest-now-decrypt-later exposure:** Detected during review.")
    else:
        lines.append("- **No harvest-now-decrypt-later risk identified.**")
    lines.append("")
    
    # Migration Timeline section
    lines.append("## Migration Timeline")
    lines.append("")
    if months_covered:
        sorted_months = sorted(months_covered)
        lines.append(f"- Migration spans: {', '.join(sorted_months)}")
        lines.append(f"- **Planning horizon:** {sorted_months[0]} to {sorted_months[-1]}")
    else:
        lines.append("- Migration plan: Not provided or empty")
    lines.append("")
    
    # Recommendation section
    lines.append("## Recommendation")
    lines.append("")
    has_a_or_b = any(g in ["A", "B"] for g in grade_distribution.keys())
    if has_a_or_b and not has_harvest:
        lines.append("- **Go:** PQC-ready configuration detected with grades A/B and no critical harvesting risk.")
    elif has_harvest and not has_a_or_b:
        lines.append("- **No-Go:** Critical classical algorithms with low grades expose harvest-now-decrypt-later risk. PQC migration required.")
    elif has_a_or_b and has_harvest:
        lines.append("- **Go with conditions:** PQC-ready configuration detected but harvest-now-decrypt-later risk identified. Accelerated PQC migration mandated.")
    else:
        lines.append("- **No-Go:** Insufficient PQC readiness for compliance with RFP requirements.")
    lines.append("")
    
    # Join with newlines
    result = "\n".join(lines)
    
    # Ensure output is not too long (1-page constraint)
    if len(result) > 1000:
        result = result[:950] + "\n\n*... (content truncated for page fit)*"
    
    return result


_MIGRATION_MONTH_RE = re.compile(r"^(\d{4})-(0[1-9]|1[0-2])$")
_MIGRATION_DEADLINE = "2031-12"
_MIGRATION_DEFAULT_START = "2027-01"
_MIGRATION_PRIORITY = {"legacy": 0, "unknown": 1, "hybrid": 2, "PQC-native": 3}


def _shift_month(start: str, offset: int) -> str:
    year = int(start[0:4])
    month = int(start[5:7])
    total = (year * 12 + (month - 1)) + offset
    return f"{total // 12:04d}-{total % 12 + 1:02d}"


def migration_scheduler(lockfile_result: dict, compliance_matrix: dict,
                        resource_constraints: dict | None = None) -> str:
    """Generates a dated YAML migration plan assigning every system to exactly one month.

    Systems are the lockfile components. Ordering is legacy-first: legacy (priority 0),
    unknown (1), hybrid (2), PQC-native (3), alphabetical within a priority. Months are
    filled sequentially from ``start_month`` (default 2027-01, after the Jan 1 2027
    acquisition gate) with at most ``max_systems_per_month`` systems each. No month may
    fall after 2031-12 (CNSA 2.0 mandatory by Dec 31 2031); a capacity/start combination
    that cannot fit raises instead of emitting an undated or double-booked plan.

    Args:
        lockfile_result: LockfileResult from lockfile_parser().
        compliance_matrix: Compliance matrix from compliance_matrix_emitter()
            (accepted for contract parity; scheduling keys off component
            PQC classification).
        resource_constraints: Optional dict with ``max_systems_per_month``
            (aliases: ``team_capacity_per_month``, ``capacity_per_month``) and
            ``start_month`` (\"YYYY-MM\").

    Returns:
        YAML string: list of {system, month, reason}. Empty components -> \"[]\\n\".
    """
    import yaml

    if not isinstance(lockfile_result, dict):
        raise TypeError(
            f"lockfile_result must be a dict, got {type(lockfile_result).__name__}"
        )
    if not isinstance(compliance_matrix, dict):
        raise TypeError(
            f"compliance_matrix must be a dict, got {type(compliance_matrix).__name__}"
        )
    if resource_constraints is None:
        resource_constraints = {}
    if not isinstance(resource_constraints, dict):
        raise TypeError(
            "resource_constraints must be a dict or None, "
            f"got {type(resource_constraints).__name__}"
        )

    components = lockfile_result.get("components", [])
    if not isinstance(components, list):
        raise TypeError(
            f"lockfile_result['components'] must be a list, got {type(components).__name__}"
        )

    start_month = resource_constraints.get("start_month", _MIGRATION_DEFAULT_START)
    if not isinstance(start_month, str) or not _MIGRATION_MONTH_RE.match(start_month):
        raise ValueError(
            f"resource_constraints['start_month'] must be 'YYYY-MM', got {start_month!r}"
        )

    cap = resource_constraints.get("max_systems_per_month",
          resource_constraints.get("team_capacity_per_month",
          resource_constraints.get("capacity_per_month", None)))
    if cap is None:
        cap = max(1, len(components))
    if isinstance(cap, bool) or not isinstance(cap, int) or cap < 1:
        raise ValueError(
            "resource_constraints capacity must be an int >= 1, got "
            f"{cap!r}"
        )

    systems: list[tuple[str, str, int]] = []
    seen: set[str] = set()
    for comp in components:
        if not isinstance(comp, dict):
            raise ValueError(f"lockfile component must be a dict, got {comp!r}")
        name = comp.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError(f"lockfile component is missing a valid 'name': {comp!r}")
        version = comp.get("version", "0.0.0")
        classification = comp.get("pqcClassification",
                         comp.get("pqc_classification", "unknown"))
        if classification not in _MIGRATION_PRIORITY:
            classification = "unknown"
        system = name
        if system in seen:
            system = f"{name}=={version}"
        suffix = 2
        while system in seen:
            system = f"{name}=={version}#{suffix}"
            suffix += 1
        seen.add(system)
        systems.append((system, classification, _MIGRATION_PRIORITY[classification]))

    systems.sort(key=lambda item: (item[2], item[0]))

    plan: list[dict] = []
    for index, (system, classification, priority) in enumerate(systems):
        month = _shift_month(start_month, index // cap)
        if month > _MIGRATION_DEADLINE:
            raise ValueError(
                f"migration plan does not fit before {_MIGRATION_DEADLINE}: "
                f"system {system!r} lands in {month} with capacity {cap}/month "
                f"from {start_month} (resource constraints conflict with the "
                "CNSA 2.0 Dec 31 2031 mandate)"
            )
        reason = (f"dependency ordering: {classification} (priority {priority}) "
                  "migrates before lower-priority systems")
        if index // cap > 0:
            reason += f"; resource constraint: capacity {cap}/month slots filled"
        plan.append({"system": system, "month": month, "reason": reason})

    return yaml.safe_dump(plan, sort_keys=False, default_flow_style=False)


def attestation_emitter(
    sbom_sha256: str,
    inventory_sha256: str,
    narrative_sha256: str,
    compliance_sha256: str,
    migration_plan_sha256: str,
    executive_summary_sha256: str,
    tool_version: str,
    tool_timestamp: str,
    scan_json_sha256: str,
    lockfile_hashes: dict,
) -> dict:
    """Produces attestation.json with all SHA256 hashes plus tool version and timestamp.

    The attestation.json SHA256 (excluding its own field) provides bit-identical
    verification across re-runs. All fields are checked for presence and correct
    type before assembly.

    Args:
        sbom_sha256: SHA256 hex digest of sbom.cdx.json (CycloneDX SBOM)
        inventory_sha256: SHA256 hex digest of crypto-inventory.json
        narrative_sha256: SHA256 hex digest of key-management-narrative.md
        compliance_sha256: SHA256 hex digest of cnsa20-compliance-matrix.json
        migration_plan_sha256: SHA256 hex digest of migration-plan.yaml
        executive_summary_sha256: SHA256 hex digest of executive-summary.md
        tool_version: Product version string (e.g. "0.1.0")
        tool_timestamp: ISO 8601 timestamp string (e.g. "2026-10-09T00:00:00Z")
        scan_json_sha256: SHA256 hex digest of the input scan JSON
        lockfile_hashes: Dict mapping lockfile filename -> SHA256 hex digest

    Returns:
        Attestation dict matching the AttestationJSON schema from the spec.
        Bit-identical across 3 runs with identical inputs (deterministic).
    """
    # Validate required hash fields are non-empty strings of correct length
    sha256_fields = {
        "sbom_sha256": sbom_sha256,
        "inventory_sha256": inventory_sha256,
        "narrative_sha256": narrative_sha256,
        "compliance_sha256": compliance_sha256,
        "migration_plan_sha256": migration_plan_sha256,
        "executive_summary_sha256": executive_summary_sha256,
        "scan_json_sha256": scan_json_sha256,
    }
    for field_name, value in sha256_fields.items():
        if not isinstance(value, str):
            raise TypeError(
                f"{field_name} must be a str, got {type(value).__name__}"
            )

    if not isinstance(tool_version, str):
        raise TypeError(
            f"tool_version must be a str, got {type(tool_version).__name__}"
        )
    # H2 FIX: Exclude tool_timestamp from attestation hash scope
    # Keep tool_timestamp in attestation for human readability but exclude from hash
    if not isinstance(tool_timestamp, str):
        raise TypeError(
            f"tool_timestamp must be a str, got {type(tool_timestamp).__name__}"
        )
    if not isinstance(lockfile_hashes, dict):
        raise TypeError(
            f"lockfile_hashes must be a dict, got {type(lockfile_hashes).__name__}"
        )
    # Validate lockfile_hashes values are strings
    for fname, fhash in lockfile_hashes.items():
        if not isinstance(fhash, str):
            raise TypeError(
                f"lockfile_hashes[{fname!r}] must be a str, got {type(fhash).__name__}"
            )

    attestation: dict = {
        "sbom_sha256": sbom_sha256,
        "inventory_sha256": inventory_sha256,
        "narrative_sha256": narrative_sha256,
        "compliance_sha256": compliance_sha256,
        "migration_plan_sha256": migration_plan_sha256,
        "executive_summary_sha256": executive_summary_sha256,
        "tool_version": tool_version,
        # H2 FIX: Keep tool_timestamp in attestation for human readability
        "tool_timestamp": tool_timestamp,
        "scan_json_sha256": scan_json_sha256,
        "lockfile_hashes": dict(lockfile_hashes),  # copy to avoid mutation
    }
    # H2: attestation_hash covers content fields only; tool_timestamp excluded
    # so the digest is bit-identical across runs with distinct timestamps.
    hashable = {k: v for k, v in attestation.items() if k != "tool_timestamp"}
    attestation["attestation_hash"] = hashlib.sha256(
        json.dumps(hashable, sort_keys=True, default=str).encode()
    ).hexdigest()

    return attestation