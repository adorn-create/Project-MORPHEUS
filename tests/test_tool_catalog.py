from morpheus.tool_catalog import TOOL_CATALOG, identify_known_tool


def test_catalog_recognizes_known_dual_use_tool_names_case_insensitively():
    match = identify_known_tool("NMAP.EXE", r"C:\Tools\nmap.exe")

    assert match == {
        "name": "Nmap",
        "category": "Network discovery and scanning",
        "process_name": "nmap.exe",
    }


def test_catalog_can_match_executable_path_when_process_name_is_unavailable():
    match = identify_known_tool(None, r"C:\Program Files\Wireshark\Wireshark.exe")

    assert match is not None
    assert match["name"] == "Wireshark"
    assert match["category"] == "Packet capture and wireless analysis"


def test_catalog_normalizes_windows_paths_on_any_host_platform():
    match = identify_known_tool(r"C:\Tools\Nmap.exe")

    assert match is not None
    assert match["name"] == "Nmap"


def test_catalog_does_not_flag_unlisted_process_names():
    assert identify_known_tool("not-a-tool.exe", r"C:\Apps\not-a-tool.exe") is None
    assert len(TOOL_CATALOG) >= 50
