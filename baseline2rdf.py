#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import json
import argparse
from transformers import pipeline
from huggingface_hub import login
import os

token = os.environ["HUGGINGFACE_TOKEN"]

login(token=token)

rdjson = {
    'source': {
        'name': 'detect-secrets',
        'url': 'https://github.com/Yelp/detect-secrets'
    },
    'severity': 'ERROR',
    'diagnostics': []
}


def main(skip_audited: bool = False, verbose: bool = False):
    baseline = json.load(sys.stdin)
    if not baseline['results']:
        baseline['results'] = {}

    with open("/tmp/.secrets.audit", "r") as audit_file:
        audit_data = json.load(audit_file)

        if not audit_data['results']:
            audit_data['results'] = {}

        # Use a pipeline as a high-level helper
        pipe = pipeline("text-classification", model="adeoservicesai/BERT_secret_classification")

        results = {}
        for detects in baseline['results'].values():
            for item in detects:
                if skip_audited and 'is_secret' in item and not item['is_secret']:
                    if verbose:
                        print('Skipping verified secret in : %s' % item['filename'])
                else:
                    for audit in audit_data['results']:
                        print(audit['filename'] == item['filename'] and str(item['line_number']) in list(audit['lines'].keys()))
                        print(audit['filename'])
                        print(item['filename'])
                        print(item['line_number'])
                        print(audit['lines'].keys())
                        if audit['filename'] == item['filename'] and str(item['line_number']) in list(audit['lines'].keys()):
                            print(pipe(audit['lines'][str(item['line_number'])]))
                            if pipe(audit['lines'][str(item['line_number'])])[0]['label'] == 'LABEL_1':
                                key = '%s:%s' % (item['filename'], item['line_number'])
                                if key in results:
                                    results[key]['message'] += '\n* ' + item['type']
                                else:
                                    results[key] = {
                                        'message': '\n* ' + item['type'],
                                        'location': {
                                            'path': item['filename'],
                                            'range': {
                                                'start': {
                                                    'line': item['line_number']
                                                }
                                            }
                                        }
                                    }

        print(results)

        for result in results.values():
            rdjson['diagnostics'].append(result)

        with open("/tmp/.secrets.rdf", "w") as rdf_file:
            rdf_file.write(json.dumps(rdjson, indent=2, ensure_ascii=False))
            rdf_file.close()

        audit_file.close()
        return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--skip-audited', dest='skip_audited', action='store_true')
    parser.add_argument('--no-skip-audited', dest='skip_audited', action='store_false')
    parser.set_defaults(skip_audited=False)
    parser.add_argument('--verbose', dest='verbose', action='store_true')
    parser.set_defaults(verbose=False)
    args = parser.parse_args()

    sys.exit(main(skip_audited=args.skip_audited, verbose=args.verbose))
