import argparse
from math import e
from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash
import requests
from pathlib import Path
import json
from base64 import b64decode
from urllib.parse import urlencode

BASE_URL = "https://rekor.sigstore.dev"

def get_entry(log_index, debug=False):
    resp = requests.get(f"{BASE_URL}/api/v1/log/entries?logIndex={log_index}")

    if resp.status_code != 200:
        raise ValueError(f"The following log_index is invalid: {log_index}")
    try:
        log_entry = resp.json()
    except:
        raise ValueError(f"The log index was not a valid json object")

    return log_entry

def get_log_entry(log_index, debug=False):
    # TODO: verify that log index value is sane

    log_entry = get_entry(log_index, debug)

    assert len(log_entry.values()) == 1
    entry_iter = iter(log_entry.values())
    entry = next(entry_iter)

    log_entry = {
        "body": entry['body'],
        "integratedTime": entry['integratedTime'],
        "logID": entry['logID'],
        "logIndex": entry['logIndex']
    }

    return log_entry

def get_verification_proof(log_index, debug=False):
    # TODO: verify that log index value is sane
    log_entry = get_entry(log_index, debug)

    assert len(log_entry.values()) == 1
    entry_iter = iter(log_entry.values())
    entry = next(entry_iter)
        
    return entry['verification']

def inclusion(log_index, artifact_filepath, debug=False):
    # TODO::
    # verify that log index and artifact filepath values are sane
    if log_index is None:
        print("Please enter a log index")
        exit(1)

    artifact_path = Path(artifact_filepath)
    if artifact_filepath is None or not artifact_path.exists():
        print("Please enter a valid artifact filepath")
        exit(1)

    try:
        log_entry = get_log_entry(log_index, debug=debug)
    except ValueError as e:
        print(e)
        exit(1)

    try:
        entry_body = json.loads(b64decode(log_entry['body']))
    except Exception as e:
        print(e)
        exit(1)

    try:
        x509_pem = b64decode(entry_body['spec']['signature']['publicKey']['content'])
    except Exception as e:
        print(e)
        exit(1)

    try:
        signature = b64decode(entry_body['spec']['signature']['content'])
    except Exception as e:
        print(e)
        exit(1)

    public_key = extract_public_key(x509_pem)
    verify_artifact_signature(signature, public_key, artifact_filepath)

    leaf_hash = compute_leaf_hash(log_entry['body'])

    verification_proof = get_verification_proof(log_index, debug=debug)
    verification_index = verification_proof['inclusionProof']['logIndex']
    verification_tree_size = verification_proof['inclusionProof']['treeSize']
    verification_root_hash = verification_proof['inclusionProof']['rootHash']
    verification_hashes = verification_proof['inclusionProof']['hashes']

    try:
        verify_inclusion(DefaultHasher,
                         verification_index,
                         verification_tree_size,
                         leaf_hash,
                         verification_hashes,
                         verification_root_hash,
                         debug=debug)
        print("Offline verification successful")
    except Exception as e:
        print(f"Inclusion proof verification failed: {e}")
        exit(1)

def get_latest_checkpoint(debug=False):
    # TODO: Fetch the latest checkpoint from rekor
    resp = requests.get(f"{BASE_URL}/api/v1/log/")

    try:
        checkpoint = resp.json()
    except Exception as e:
        print(f"Failed to get latest checkpoint: {e}")
        exit(1)

    del checkpoint['inactiveShards']

    return checkpoint

def consistency(prev_checkpoint, debug=False):
    '''
    Each checkpoint has the following fields:
    - treeID
    - treeSize
    - rootHash
    '''
    # TODO: 
    # verify that prev checkpoint is not empty
    latest_checkpoint = get_latest_checkpoint(debug)

    query_params = {
        'treeID': latest_checkpoint['treeID'],
        'firstSize': prev_checkpoint['treeSize'],
        'lastSize': latest_checkpoint['treeSize'],
    }

    rekor_url = f"{BASE_URL}/api/v1/log/proof?{urlencode(query_params)}"
    resp = requests.get(rekor_url)

    if resp.status_code != 200:
        print(f"Failed to get consistency proof: {resp.status_code}")
        exit(1)

    try:
        proof = resp.json()
    except Exception as e:
        print(f"Failed to get consistency proof: {e}")
        exit(1)

    try:
        verify_consistency(DefaultHasher,
                        prev_checkpoint['treeSize'],
                        latest_checkpoint['treeSize'],
                        proof['hashes'],
                        prev_checkpoint['rootHash'],
                        latest_checkpoint['rootHash'])
        print("Consistency verification successful")
    except Exception as e:
        print(f"Consistency proof verification failed: \n{e}")
        exit(1)

def main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode',
                        required=False, action='store_true') # Default false
    parser.add_argument('-c', '--checkpoint', help='Obtain latest checkpoint\
                        from Rekor Server public instance',
                        required=False, action='store_true')
    parser.add_argument('--inclusion', help='Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567',
                        required=False, type=int)
    parser.add_argument('--artifact', help='Artifact filepath for verifying\
                        signature',
                        required=False)
    parser.add_argument('--consistency', help='Verify consistency of a given\
                        checkpoint with the latest checkpoint.',
                        action='store_true')
    parser.add_argument('--tree-id', help='Tree ID for consistency proof',
                        required=False)
    parser.add_argument('--tree-size', help='Tree size for consistency proof',
                        required=False, type=int)
    parser.add_argument('--root-hash', help='Root hash for consistency proof',
                        required=False)
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion:
        inclusion(args.inclusion, args.artifact, debug)
    if args.consistency:
        if not args.tree_id:
            print("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for prev checkpoint")
            return

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, debug)

if __name__ == "__main__":
    main()
