import argparse
import csv
import io
import requests #needs to be added to requirements
from stix2 import MemoryStore #needs to be added to requirements

from stix2 import TAXIICollectionSource, MemorySource, Filter
from taxii2client.v20 import Collection

import tqdm

def build_taxii_source(version):
    """Download latest enterprise or mobile att&ck content from github"""

    if version:
        collection_url = f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-{version}.json"
    else:
        collection_url = f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-11.3.json"

    stix_json = requests.get(collection_url).json()
    return MemoryStore(stix_data=stix_json["objects"])

def get_all_techniques(src, source_name, tactic=None):
    """Filters data source by attack-pattern which extracts all ATT&CK Techniques"""
    filters = [
        Filter("type", "=", "attack-pattern"),
        Filter("external_references.source_name", "=", source_name),
    ]
    if tactic:
        filters.append(Filter('kill_chain_phases.phase_name', '=', tactic))

    results = src.query(filters)
    return remove_deprecated(results)


def filter_for_term_relationships(src, relationship_type, object_id, target=True):
    """Filters data source by type, relationship_type and source or target"""
    filters = [
        Filter("type", "=", "relationship"),
        Filter("relationship_type", "=", relationship_type),
    ]
    if target:
        filters.append(Filter("target_ref", "=", object_id))
    else:
        filters.append(Filter("source_ref", "=", object_id))

    results = src.query(filters)
    return remove_deprecated(results)

def filter_by_type_and_id(src, object_type, object_id, source_name):
    """Filters data source by id and type"""
    filters = [
        Filter("type", "=", object_type),
        Filter("id", "=", object_id),
        Filter("external_references.source_name", "=", source_name),
    ]
    results = src.query(filters)
    return remove_deprecated(results)


def grab_external_id(stix_object, source_name):
    """Grab external id from STIX2 object"""
    for external_reference in stix_object.get("external_references", []):
        if external_reference.get("source_name") == source_name:
            return external_reference["external_id"]


def remove_deprecated(stix_objects):
    """Will remove any revoked or deprecated objects from queries made to the data source"""
    # Note we use .get() because the property may not be present in the JSON data. The default is False
    # if the property is not set.
    return list(
        filter(
            lambda x: x.get("x_mitre_deprecated", False) is False and x.get("revoked", False) is False,
            stix_objects
        )
    )


def escape_chars(a_string):
    """Some characters create problems when written to file"""
    return a_string.translate(str.maketrans({
        "\n": r"\\n",
    }))


def arg_parse():
    """Function to handle script arguments."""
    parser = argparse.ArgumentParser(description="Fetches the current ATT&CK content expressed as STIX2 and creates spreadsheet mapping Techniques with Mitigations, Groups or Software.")
    parser.add_argument("-d", "--domain", type=str, required=True, choices=["enterprise_attack", "mobile_attack"], help="Which ATT&CK domain to use (Enterprise, Mobile).")
    parser.add_argument("-m", "--mapping-type", type=str, required=True, choices=["groups", "mitigations", "software","full_mitigations"], help="Which type of object to output mappings for using ATT&CK content.")
    parser.add_argument("-t", "--tactic",  type=str, required=False,  help=" Filter based on this tactic name (e.g. initial-access) " )
    parser.add_argument("-s", "--save", type=str, required=False, help="Save the CSV file with a different filename.")
    return parser


def do_mapping(ds, fieldnames, relationship_type, type_filter, source_name, sorting_keys, full_mitigation, tactic=None):
    """Main logic to map techniques to mitigations, groups or software"""
    all_attack_patterns = get_all_techniques(ds, source_name, tactic)
    writable_results = []

    for attack_pattern in tqdm.tqdm(all_attack_patterns, desc="parsing data for techniques"):
        # Grabs relationships for identified techniques
        relationships = filter_for_term_relationships(ds, relationship_type, attack_pattern.id)
        found_relationship=False
        for relationship in relationships:
            # Groups are defined in STIX as intrusion-set objects
            # Mitigations are defined in STIX as course-of-action objects
            # Software are defined in STIX as malware objects

            stix_results = filter_by_type_and_id(ds, type_filter, relationship.source_ref, source_name)

            if stix_results:
                row_data = (
                    grab_external_id(attack_pattern, source_name),
                    attack_pattern.name,
                    attack_pattern.description, ## add the description of the technique to the fields
                    grab_external_id(stix_results[0], source_name),
                    stix_results[0].name,
                    escape_chars(stix_results[0].description),
                    escape_chars(relationship.description),
                )

                found_relationship=True
                writable_results.append(dict(zip(fieldnames, row_data)))

            if not (found_relationship) and full_mitigation:
                row_data=(
                    grab_external_id(attack_pattern, source_name),
                    attack_pattern.name,
                    attack_pattern.description,  ## add the description of the technique to the fields
                    "No Mitigation",
                    "None",
                    "None",
                    "None",
                )
                found_relationship = True
                writable_results.append(dict(zip(fieldnames, row_data)))


    return sorted(writable_results, key=lambda x: (x[sorting_keys[0]], x[sorting_keys[1]]))


def main(args):
    data_source = build_taxii_source(11.3)
    op = args.mapping_type

    source_map = {
        "enterprise_attack": "mitre-attack",
        "mobile_attack": "mitre-mobile-attack",
    }
    source_name = source_map[args.domain]
    tactic = args.tactic
    if op == "groups":
        filename = args.save or "groups.csv"
        fieldnames = ("TID", "Technique Name", "GID", "Group Name", "Group Description", "Usage")
        relationship_type = "uses"
        type_filter = "intrusion-set"
        sorting_keys = ("TID", "GID")
        full_mitigation = False
        rowdicts = do_mapping(data_source, fieldnames, relationship_type, type_filter, source_name, sorting_keys, full_mitigation, tactic)
    elif op == "mitigations":
        filename = args.save or "mitigations.csv"
        fieldnames = ("TID", "Technique Name","Technique Description", "MID", "Mitigation Name", "Mitigation Description", "Application") # added technique description
        relationship_type = "mitigates"
        type_filter = "course-of-action"
        sorting_keys = ("TID", "MID")
        full_mitigation = False
        rowdicts = do_mapping(data_source, fieldnames, relationship_type, type_filter, source_name, sorting_keys, full_mitigation,tactic)
    elif op == "software":
        filename = args.save or "software.csv"
        fieldnames = ("TID", "Technique Name", "SID", "Software Name", "Software Description", "Use")
        relationship_type = "uses"
        type_filter = "malware"
        sorting_keys = ("TID", "SID")
        full_mitigation = False
        rowdicts = do_mapping(data_source, fieldnames, relationship_type, type_filter, source_name, sorting_keys,full_mitigation, tactic)
    elif op == "full_mitigations":
        filename = args.save or "db_full.csv"
        fieldnames = ("TID", "Technique Name","Technique Description", "MID", "Mitigation Name", "Mitigation Description", "Application") # added technique description
        relationship_type = "mitigates"
        type_filter = "course-of-action"
        sorting_keys = ("TID", "MID")
        full_mitigation = True
        rowdicts = do_mapping(data_source, fieldnames, relationship_type, type_filter, source_name, sorting_keys, full_mitigation,tactic)
    else:
        raise RuntimeError("Unknown option: %s" % op)

    with io.open(filename, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rowdicts)


if __name__ == "__main__":
    parser = arg_parse()
    args = parser.parse_args()
    main(args)
