from kdive.safety.secrets import SecretReference, SecretReferenceKind


def test_keyring_kind_exists_and_constructs():
    ref = SecretReference(kind=SecretReferenceKind.KEYRING, label="bmc", reference="svc/user")
    assert ref.kind is SecretReferenceKind.KEYRING
    assert SecretReferenceKind("keyring") is SecretReferenceKind.KEYRING
