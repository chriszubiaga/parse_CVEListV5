import json
import argparse
import sys
import re
import html
import os
from bs4 import BeautifulSoup


def clean_text(text: str) -> str:
    """
    Cleans a string by stripping HTML, decoding entities,
    and normalizing whitespace.
    """
    if not text:
        return ""
    try:
        soup = BeautifulSoup(text, "html.parser")
        text = soup.get_text()
    except Exception:
        pass
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def parse_cve_data(cve_json_data):
    """
    Parses a CVE JSON record, prioritizing CNA data and falling back to ADP,
    while merging cumulative fields.
    """
    cna_container = cve_json_data.get("containers", {}).get("cna", {})
    adp_container_list = cve_json_data.get("containers", {}).get("adp", [])
    prioritized_containers = [cna_container] + adp_container_list

    cve_metadata = cve_json_data.get("cveMetadata", {})
    cve_id = cve_metadata.get("cveId", "")
    date_published = cve_metadata.get("datePublished", "")
    date_updated = cve_metadata.get("dateUpdated", "")
    assigner_short_name = cve_metadata.get("assignerShortName", "")
    title = cna_container.get("title", "")

    def _find_first_text_field(containers, field_name):
        for container in containers:
            items = container.get(field_name, [])
            if not items:
                continue
            text_value = ""
            for item in items:
                if item.get("lang") == "en":
                    text_value = item.get("value", "")
                    break
            if not text_value and items:
                text_value = items[0].get("value", "")
            if text_value:
                return clean_text(text_value)
        return ""

    def _find_first_list_field(containers, field_name, processing_func):
        for container in containers:
            items = container.get(field_name, [])
            if items:
                return processing_func(items)
        return []

    description = _find_first_text_field(prioritized_containers, "descriptions")
    solution = _find_first_text_field(prioritized_containers, "solutions")
    workaround = _find_first_text_field(prioritized_containers, "workarounds")

    def _process_affected(items):
        products = []
        for item in items:
            product_info = {
                "vendor": item.get("vendor", ""),
                "product": item.get("product", ""),
                "versions": [],
            }
            for version_info in item.get("versions", []):
                product_info["versions"].append(
                    {
                        "status": version_info.get("status", ""),
                        "version": version_info.get("version", ""),
                        "less_than": version_info.get("lessThan", ""),
                    }
                )
            products.append(product_info)
        return products

    affected_products = _find_first_list_field(
        prioritized_containers, "affected", _process_affected
    )

    def _process_cvss(metrics_list):
        cvss_priority_order = ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]
        # Ensure metrics_list is not empty before sorting
        if not metrics_list:
            return {}
        sorted_metrics = sorted(
            metrics_list,
            key=lambda m: next(
                (cvss_priority_order.index(k) for k in cvss_priority_order if k in m),
                99,
            )
            if isinstance(m, dict)
            else 99,
        )
        for metric in sorted_metrics:
            if not isinstance(metric, dict):
                continue  # Skip if metric is not a dict
            for version_key in cvss_priority_order:
                if version_key in metric:
                    cvss_data = metric[version_key]
                    return {
                        "version": cvss_data.get("version", ""),
                        "vector_string": cvss_data.get("vectorString", ""),
                        "base_score": cvss_data.get("baseScore", 0),
                        "severity": cvss_data.get("baseSeverity")
                        or cvss_data.get("severity", ""),
                    }
        return {}

    cvss_metrics = _find_first_list_field(
        prioritized_containers, "metrics", _process_cvss
    )

    cwe_ids, all_ref_urls, exploit_ref_urls = set(), set(), set()
    for container in prioritized_containers:
        if not isinstance(container, dict):
            continue  # Ensure container is a dict
        for problem_type in container.get("problemTypes", []):
            if not isinstance(problem_type, dict):
                continue
            for desc in problem_type.get("descriptions", []):
                if isinstance(desc, dict) and "cweId" in desc:
                    cwe_ids.add(desc["cweId"])

        for ref in container.get("references", []):
            if not isinstance(ref, dict):
                continue
            url = ref.get("url")
            if url:
                all_ref_urls.add(url)
                if "exploit" in ref.get("tags", []):
                    exploit_ref_urls.add(url)

    ssvc_status, cisa_kev = {}, {}
    for adp_container in adp_container_list:
        if not isinstance(adp_container, dict):
            continue
        for metric in adp_container.get("metrics", []):
            if not isinstance(metric, dict):
                continue
            metric_content_obj = metric.get("other", {})
            if not isinstance(metric_content_obj, dict):
                continue
            metric_type = metric_content_obj.get("type")

            content = metric_content_obj.get("content", {})
            if not isinstance(content, dict):
                continue

            if metric_type == "kev":
                cisa_kev = {
                    "date_added": content.get("dateAdded", ""),
                    "reference": content.get("reference", ""),
                }
            if metric_type == "ssvc":
                for option in content.get("options", []):
                    if isinstance(option, dict):
                        for key, value in option.items():
                            ssvc_status[key.lower().replace(" ", "_")] = value

    return {
        "cve_id": cve_id,
        "title": title,
        "assigner": assigner_short_name,
        "published_date": date_published,
        "last_modified_date": date_updated,
        "description": description,
        "remediation": {"solution": solution, "workaround": workaround},
        "cwe_ids": sorted(list(cwe_ids)),
        "cvss": cvss_metrics,
        "ssvc_status": ssvc_status,
        "affected_products": affected_products,
        "references": sorted(list(all_ref_urls)),
        "exploit_references": sorted(list(exploit_ref_urls)),
        "cisa_kev": cisa_kev,
    }


def process_single_file(input_filepath, output_arg):
    """
    Processes a single CVE JSON file: reads, parses, and handles output.
    """
    try:
        with open(input_filepath, "r", encoding="utf-8") as f:
            cve_data = json.load(f)

        parsed_cve = parse_cve_data(cve_data)

        if output_arg is None:
            print(f"--- Parsed data for {os.path.basename(input_filepath)} ---")
            print(json.dumps(parsed_cve, indent=4))
            print("--- End of data ---")
            return

        output_path_to_use = output_arg

        if os.path.isdir(output_path_to_use):
            # If output_arg is a directory, create a default-named file inside it
            current_input_filename = os.path.basename(input_filepath)
            base_name = os.path.splitext(current_input_filename)[0]
            output_filename = f"{base_name}_parsed.json"
            output_path_to_use = os.path.join(output_path_to_use, output_filename)
        elif output_path_to_use == "DEFAULT_SAVE":
            # If -o flag used with no value, save with default name in current dir
            current_input_filename = os.path.basename(input_filepath)
            base_name = os.path.splitext(current_input_filename)[0]
            output_path_to_use = f"{base_name}_parsed.json"
        # Else, output_arg is a specific filename provided by the user.
        # If processing multiple files, this specific filename will be overwritten by each.

        with open(output_path_to_use, "w", encoding="utf-8") as outfile:
            json.dump(parsed_cve, outfile, indent=4)
        print(
            f"[=] Successfully saved parsed data for {os.path.basename(input_filepath)} to: {output_path_to_use}"
        )

    except FileNotFoundError:
        print(f"[!] Error: Input file not found at '{input_filepath}'", file=sys.stderr)
    except json.JSONDecodeError:
        print(
            f"[!] Error: Could not decode JSON from '{input_filepath}'. Please check the file format.",
            file=sys.stderr,
        )
    except IsADirectoryError:
        print(
            f"[!] Error: '{input_filepath}' is a directory, expected a file.",
            file=sys.stderr,
        )
    except Exception as e:
        print(
            f"[!] An unexpected error occurred while processing '{input_filepath}': {e}",
            file=sys.stderr,
        )


def main():
    """
    Main function to read, parse, and print or save CVE data from a file or directory.
    """
    parser = argparse.ArgumentParser(
        description="Parse CVE JSON 5.1 records from a file or directory."
    )
    parser.add_argument(
        "input_path", help="The path to the input CVE JSON file or directory."
    )
    parser.add_argument(
        "-o",
        "--output",
        nargs="?",
        const="DEFAULT_SAVE",
        default=None,
        help="Save output to a file. If a directory is provided, default-named files will be created inside it.",
    )
    args = parser.parse_args()

    if os.path.isdir(args.input_path):
        print(f"[*] Processing directory: {args.input_path}")
        for filename in os.listdir(args.input_path):
            # Consider only .json files or add other relevant extension checks
            if filename.lower().endswith(".json"):
                file_path_to_process = os.path.join(args.input_path, filename)
                if os.path.isfile(file_path_to_process):
                    print(f"[*] Processing file: {file_path_to_process}")
                    process_single_file(file_path_to_process, args.output)
            else:
                print(f"[*!] Skipping non-JSON file: {filename}")
    elif os.path.isfile(args.input_path):
        process_single_file(args.input_path, args.output)
    else:
        print(
            f"[!] Error: Input path '{args.input_path}' is not a valid file or directory.",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
