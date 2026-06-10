import xml.etree.ElementTree as ET
import json
import argparse

namespaces = {
    'oval': 'http://oval.mitre.org/XMLSchema/oval-definitions-5',
    'red-def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#linux',
    'unix-def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#unix',
    'ind-def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#independent'
}


def load_xml(file_path):
    for prefix, uri in namespaces.items():
        ET.register_namespace(prefix, uri)
        tree = ET.parse(file_path)
        return tree.getroot()



def get_metadata(patch):
    patch_id = patch.get('id', '')
    metadata = patch.find('oval:metadata', namespaces)
    platform = metadata.find('.//oval:platform', namespaces)
    title_elem = metadata.find('oval:title', namespaces)
    title = title_elem.text
    references = []
    for ref in metadata.findall('.//oval:reference', namespaces):
        references.append(ref.get('ref_url'))
    cves = []
    for cve_elem in metadata.findall('.//oval:cve', namespaces):
        cve_id = cve_elem.text
        cvss3 = cve_elem.get('cvss3', '')
        cwe = cve_elem.get('cwe', '')
        impact = cve_elem.get('impact', '')
        public_date = cve_elem.get('public', '')
        href = cve_elem.get('href', '')
        cves.append({
            "id": cve_id,
            "cvss3": float(cvss3.split('/', 1)[0]),
            "cvss_vector": cvss3.split('/', 1)[1],
            "cwe": cwe,
            "impact": impact,
            "public_date": public_date,
            "href": href
        })
    affected = {
        "os": [],
    }
    affected["os"].append(platform.text)

    return {
        "id": patch_id,
        "title": title,
        "cves": cves,
        "references": references,
        "affected": affected
    }


def get_criteria(patch, tests_for_patch):
    criteria_list = patch.findall('.//oval:criteria', namespaces)
    tests_by_id = {}
    for test in tests_for_patch:
        test_id = test['test'].get('id')
        tests_by_id[test_id] = test
    detection = parse_criteria_recursive(criteria_list, tests_by_id)
    return detection


def parse_criteria_recursive(criteria_list, tests_by_id):
    criteria_elem = criteria_list[0]
    result = {
        "os_check": [],
        "files_check": [],
        "packages_check": [],
    }
    for criterion in criteria_elem.findall('oval:criterion', namespaces):
        test_ref = criterion.get('test_ref', '')
        comment = criterion.get('comment', '')
        if test_ref in tests_by_id:
            check = parse_test(test_ref, tests_by_id, comment)
            if check:
                if check.get("type") == "rpm_version":
                    result["packages_check"].append(check)
                elif check.get("type") == "package_signature":
                    signature_keyid = check.get("keyid")
                    for pkg in result["packages_check"]:
                        if "signature_keyid" not in pkg:
                            pkg["signature_keyid"] = signature_keyid
                elif check.get("type") == "file_check" and check.get("path", ""):
                    if "version" in check:
                        result['os_check'].append(check)
                elif check.get("type") == "file_content":
                    result["files_check"].append(check)

    for sub_criteria in criteria_elem.findall('oval:criteria', namespaces):
        sub_result = parse_criteria_recursive([sub_criteria], tests_by_id)
        for pkg in sub_result.get("packages_check", []):
            if pkg not in result["packages_check"]:
                result["packages_check"].append(pkg)
        for fc in sub_result.get("files_check", []):
            if fc not in result["files_check"]:
                result["files_check"].append(fc)
        for os in sub_result.get("os_check", []):
            if os not in result["os_check"]:
                result["os_check"].append(os)
    if not result.get("files_check"):
        del result["files_check"]
    return result


def parse_test(test_ref, tests_by_id, comment):
    test_info = tests_by_id.get(test_ref)

    test_obj = test_info['test']
    obj = test_info['obj']
    state = test_info['state']
    test_tag = test_obj.tag

    if 'rpminfo_test' in test_tag:
        name_elem = obj.find('red-def:name', namespaces)
        package_name = name_elem.text
        evr_elem = state.find('.//red-def:evr', namespaces)
        if evr_elem is not None and evr_elem.text:
            operator = evr_elem.get('operation', '')
            version = evr_elem.text
            check = {
                "type": "rpm_version",
                "name": package_name,
                "operator": operator,
                "value": version
            }

        elif state is not None:
            signature_elem = state.find('.//red-def:signature_keyid', namespaces)
            if signature_elem is not None:
                check = {
                    "type": "package_signature",
                    "keyid": signature_elem.text,
                }

    elif 'rpmverifyfile_test' in test_tag:
        filepath_elem = obj.find('red-def:filepath', namespaces)
        filepath = filepath_elem.text
        check = {
            "type": "file_check",
            "path": filepath,
        }

        if state is not None:
            name_elem = state.find('.//red-def:name', namespaces)
            if name_elem is not None:
                check["name"] = name_elem.text
            version_elem = state.find('.//red-def:version', namespaces)
            if version_elem is not None:
                check["version"] = version_elem.text


    elif 'textfilecontent54_test' in test_tag:
        filepath_elem = obj.find('.//red-def:filepath', namespaces) if obj.find('.//red-def:filepath',
                                                                                namespaces) is not None else obj.find(
            './/ind-def:filepath', namespaces)
        filepath = filepath_elem.text

        check = {
            "type": "file_content",
            "path": filepath,
        }

        if state is not None:
            text_elem = state.find('.//red-def:text', namespaces) if state.find('.//red-def:text',
                                                                                namespaces) is not None else state.find(
                './/ind-def:text', namespaces)
            if text_elem is not None:
                check["pattern"] = text_elem.text
        if comment:
            check["comment"] = comment

    return check


def get_tests_for_patch(patch, root):
    tests_for_patch = []
    for criterion in patch.findall('.//oval:criterion', namespaces):
        test_ref = criterion.get('test_ref', '')
        test = root.find(f".//*[@id='{test_ref}']")
        obj_el = test.find('.//red-def:object', namespaces) if test.find('.//red-def:object',
                                                                         namespaces) is not None else test.find(
            './/ind-def:object', namespaces)
        state_el = test.find('.//red-def:state', namespaces) if test.find('.//red-def:state',
                                                                          namespaces) is not None else test.find(
            './/ind-def:state', namespaces)

        obj_ref = obj_el.get('object_ref')
        stas_ref = state_el.get('state_ref')

        obj = root.find(f".//*[@id='{obj_ref}']")
        state = root.find(f".//*[@id='{stas_ref}']")
        tests_for_patch.append({
            'test': test,
            'obj': obj,
            'state': state,
            'criterion': criterion
        })
    return tests_for_patch


def get_patches(root):
    definitions = root.findall('.//oval:definition', namespaces)
    patches = [d for d in definitions if d.get('class') == 'patch'][0:3]
    result = []
    for patch in patches:
        metadata = get_metadata(patch)
        print()
        tests_for_patch = get_tests_for_patch(patch, root)
        detection = get_criteria(patch, tests_for_patch)
        patch_result = {
            **metadata,
            "detection": detection
        }
        print(json.dumps(patch_result, indent=2, ensure_ascii=False))
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('xml_file', nargs='?', default='rhel-8.oval.xml',
                        help='Путь к XML-файлу')
    xml_file = parser.parse_args().xml_file
    print(f"Обработка файла: {xml_file}")
    root = load_xml(xml_file)
    get_patches(root)

if __name__ == "__main__":
    main()
