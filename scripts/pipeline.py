import subprocess
import yaml
import winrm
from datetime import datetime, timedelta, timezone
from sigma.collection import SigmaCollection
from sigma.backends.elasticsearch import LuceneBackend
from sigma.pipelines.elasticsearch import ecs_windows
from elasticsearch import Elasticsearch
import json
import os
import glob

es = Elasticsearch(
    "https://localhost:9200",
    basic_auth=("elastic", "RfvfKlIQkHXMKu1gxf9H"),
    verify_certs=False,
    ssl_show_warn=False
)

def lint_rule(rule_path):
    result = subprocess.run(
        ["sigma", "check", rule_path],
        capture_output=True,
        text=True
    )
    if result.returncode == 0:
        print(f"Rule is valid: {rule_path}")
        return True
    else:
        print(f"Rule is invalid: {rule_path}")
        print(result.stderr)
        return False

def validate_rule(rule_path):
    with open(rule_path, "r") as file:
        data = yaml.safe_load(file)
    imp = ["logsource", "detection", "id"]
    for field in imp:
        if field not in data:
            print(f"Missing: {field}")
            return False
    return True

def convert_rule(rule_path):
    with open(rule_path, "r") as file:
        yaml_text = file.read()
    collection = SigmaCollection.from_yaml(yaml_text)
    pipeline = ecs_windows()
    backend = LuceneBackend(pipeline)
    result = backend.convert_rule(collection[0])
    return result

def query_rule(lucene_query, minutes=10):
    search_body = {
        "bool": {
            "must": [
                {"query_string": {"query": lucene_query}},
                {"range": {
                    "@timestamp": {
                        "gte": (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat(),
                        "lte": datetime.now(timezone.utc).isoformat()
                    }
                }}
            ]
        }
    }
    response = es.search(index="winlogbeat-*", query=search_body)
    hit_count = response["hits"]["total"]["value"]
    return hit_count

def write_report(test_case, lint_result, validate_result, query, hit_count):
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    if lint_result and validate_result and hit_count > 0:
        verdict = "PASS"
    else:
        verdict = "FAIL"

    report = {
        "technique_id": test_case["technique_id"],
        "query": query,
        "lint_result": lint_result,
        "validate_result": validate_result,
        "hit_count": hit_count,
        "verdict": verdict
    }

    filename = f"results/{test_case['technique_id']}_{timestamp}.json"

    with open(filename, "w") as file:
        json.dump(report, file)

def trigger_atomic(session, command, args):
    result = session.run_cmd(command, args)
    print(result.std_out)
    print(result.std_err)
    return result

def get_latest_verdicts():
    files = glob.glob("results/*.json")
    latest_file = {}

    for filepath in files:
        with open(filepath, "r") as file:
            report = json.load(file)
        tech_id = report["technique_id"]

        if tech_id not in latest_file or os.path.getmtime(filepath) > os.path.getmtime(latest_file[tech_id]):
            latest_file[tech_id] = filepath

    return latest_file
    
def build_heatmap():
    latest_file = get_latest_verdicts()
    techniques = []

    for tech_id, filepath in latest_file.items():
        with open(filepath, "r") as file:
            report = json.load(file)

        if report["verdict"] == "PASS":
            color = "#66ff66"
        else:
            color = "#ff6666"

        techniques.append({
            "techniqueID": tech_id,
            "color": color,
            "comment": f"Verdict: {report['verdict']}, hit_count: {report['hit_count']}"
        })

    layer = {
        "name": "Detection Coverage",
        "versions": {"attack": "19", "navigator": "5.3.2", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Auto-generated from pipeline results",
        "techniques": techniques
    }

    with open("heatmap_layer.json", "w") as file:
        json.dump(layer, file)

if __name__ == "__main__":
    os.makedirs("results", exist_ok=True)
    session = winrm.Session(
        'http://192.168.86.128:5985/wsman',
        auth=('test',os.environ["WINRM_PASSWORD"]),
        transport='basic'
    )

    test_cases = [
        {
            "technique_id": "T1547.001",
            "sigma_rule_path": "rules/T1547.001.yml",
            "trigger_command": "reg",
            "trigger_args": [
                "ADD",
                r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "/V",
                '"Atomic Red Team"',
                "/t",
                "REG_SZ",
                "/F",
                "/D",
                r"C:\Path\AtomicRedTeam.exe"
            ]
        },
        {
            "technique_id": "T1053.005",
            "sigma_rule_path": "rules/T1053.005.yml",
            "trigger_command": "schtasks",
            "trigger_args": [
                "/create",
                "/tn",
                "T1053_005_200",
                "/sc",
                "onstart",
                "/ru",
                "system",
                "/tr",
                '"cmd.exe /c calc.exe"'
            ]
        },
        {
            "technique_id": "T1057",
            "sigma_rule_path": "rules/T1057.yml",
            "trigger_command": "tasklist",
            "trigger_args": []
        },
        {
            "technique_id": "T1059.001",
            "sigma_rule_path": "rules/T1059.001.yml",
            "trigger_command": "powershell.exe",
            "trigger_args": [
                "-e",
                "VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAGwAbABvACIA"
            ]
        }
    ]
        
    for test_case in test_cases:
        print(f"Working on: {test_case['technique_id']}")
        print(f"Triggering: {test_case['technique_id']}")
        trigger_atomic(session, test_case["trigger_command"], test_case["trigger_args"])
        lint_result = lint_rule(test_case["sigma_rule_path"])
        validate_result = validate_rule(test_case["sigma_rule_path"])
        query = convert_rule(test_case["sigma_rule_path"])[0]
        hit_count = query_rule(query)
        write_report(test_case, lint_result, validate_result, query, hit_count)
 
    build_heatmap() 
