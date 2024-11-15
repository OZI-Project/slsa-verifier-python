import json

import requests
from sigstore._internal.fulcio import FulcioClient
from sigstore._internal.rekor.client import RekorClient

REKOR_URL = "https://rekor.sigstore.dev"

REKOR_API_HEADERS = {'Content-Type': 'application/json', 'Accept': 'application/json'}


def search(email=None, pubkey=None, hash=None):
    if pubkey is not None:
        print("Pubkey not implemented...")
        # pubkey = _encode_pubkey(pubkey)
        # pubkey = {
        #     "format": "x509",
        #     "content": pubkey,
        # }
    if hash is not None:
        hash = f"sha256:{hash}"
    rekor_payload_search = {
        "email": email,
        "publicKey": pubkey,
        "hash": hash,
    }
    payload = json.dumps(rekor_payload_search)

    return requests.post(
        f"{REKOR_URL}/api/v1/index/retrieve", data=payload, headers=REKOR_API_HEADERS
    )


def get_rekor_client():
    return RekorClient.production()


def get_fulcio_client():
    return FulcioClient.production()
