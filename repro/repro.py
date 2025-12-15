import os
from pymongo import MongoClient
from pymongo.encryption_options import AutoEncryptionOpts

if "CRYPT_SHARED_PATH" not in os.environ:
    raise Exception("Set CRYPT_SHARED_PATH")

kms_providers = {"local": {"key": os.urandom(96)}}

auto_encryption_opts = AutoEncryptionOpts(
    kms_providers,
    "keyvault.datakeys",
    crypt_shared_lib_path=os.environ["CRYPT_SHARED_PATH"],
)
client = MongoClient(auto_encryption_opts=auto_encryption_opts)
client.db.drop_collection("coll")
coll = client.db.create_collection("coll")
coll.insert_one({"foo": "bar"})
