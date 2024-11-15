import argparse
import base64
import hashlib
import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.extensions import Extensions

import ecdsa
import signing_spec
import sigstore_helpers

# from sigstore import


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-a',
        '--artifact',
        help='Local path of binary to verify',
        default=None,
        action='store',
    )
    parser.add_argument(
        '-p',
        '--provenance',
        help='Local path of binary provenance',
        default=None,
        action='store',
    )
    parser.add_argument(
        '-u',
        '--source-repo',
        help='Github source code repo',
        default=None,
        action='store',
    )
    parser.add_argument(
        '-t',
        '--source-tag',
        help='Tag used to create artifact',
        default=None,
        action='store',
    )
    parser.add_argument(
        '-b',
        '--source-trigger',
        help='Tag used to create artifact',
        default=None,
        action='store',
    )
    parser.add_argument(
        '-d',
        '--source-digest',
        help='Commit digest used to create artifact',
        default=None,
        action='store',
    )
    args = parser.parse_args()

    artifact = args.artifact
    provenance = args.provenance
    source_repo = args.source_repo
    source_tag = args.source_tag
    source_trigger = args.source_trigger
    source_digest = args.source_digest

    with open(artifact, 'rb') as f:
        artifact = f.read()

    with open(provenance, 'r') as f:
        provenance_bytes = f.read()

    provenance = json.loads(provenance_bytes)
    payload_decoded = base64.b64decode(provenance['payload']).decode()
    payload_json = json.loads(payload_decoded)

    binary_digest = hashlib.sha256(artifact).hexdigest()
    if payload_json['subject'][0]['digest']['sha256'] == binary_digest:
        print(f'{binary_digest}: SHAs match!')

    entries_result = sigstore_helpers.search(hash=binary_digest)
    entries = entries_result.json()

    rekor = sigstore_helpers.get_rekor_client()

    rekor_entry_api = rekor.log.entries

    for e in entries:
        # TODO: Actually verify the entry inclusion
        retrieved_entry = rekor_entry_api.get(uuid=e)
        body = json.loads(base64.b64decode(retrieved_entry.body).decode())

        # TODO: Actually verify the certificate against Fulcio
        certificate_bin = base64.b64decode(body['spec']['publicKey'])

        cert = x509.load_pem_x509_certificate(certificate_bin)

        pubkey = cert.public_key()

        verifier = ecdsa.Verifier(pubkey)

        result = signing_spec.Verify(provenance_bytes, [('mykey', verifier)])

        print(result)

        # TODO: Actually check if integrated_time is within expiry
        integrated_time = retrieved_entry.integrated_time

        print('cert info: ')
        print()

        extensions = cert.extensions
        caller_repository = get_extension(extensions, '1.3.6.1.4.1.57264.1.5')
        caller_repository = (
            caller_repository.decode() if caller_repository is not None else None
        )
        issuer = get_extension(extensions, '1.3.6.1.4.1.57264.1.1')
        issuer = issuer.decode() if issuer is not None else None
        trigger = get_extension(extensions, '1.3.6.1.4.1.57264.1.2')
        trigger = trigger.decode() if trigger is not None else None
        caller_hash = get_extension(extensions, '1.3.6.1.4.1.57264.1.3')
        caller_hash = caller_hash.decode() if caller_hash is not None else None

        for ext in extensions:
            if type(ext.value) == x509.SubjectAlternativeName:
                job_workflow_ref = ext.value.get_values_for_type(
                    x509.GeneralName  # pyright: ignore
                )[0]

        _, workflowTag = job_workflow_ref.split("@")

        workflowTag = workflowTag.split('/')[-1]

        if source_repo is not None and source_repo != caller_repository:
            print('--source-repo does not match source URI from certificate!')

        if source_tag is not None and source_tag != workflowTag:
            print('--source-tag does not match source tag from certificate!')

        if source_trigger is not None and source_trigger != trigger:
            print('--source-trigger does not match source trigger from certificate!')

        if source_digest is not None and source_digest != caller_hash:
            print('--source-digest does not match source digest from certificate!')

        if (
            issuer is not None
            and issuer != 'https://token.actions.githubusercontent.com'
        ):
            print('Certificate issuer is not Github!')


def get_extension(extensions: Extensions, oid: str) -> bytes | None:
    for ext in extensions:
        if ext.oid.dotted_string == oid:
            return ext.value.value


if __name__ == '__main__':
    main()
