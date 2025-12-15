"""
To test, download:
- https://downloads.mongodb.com/linux/mongo_crypt_shared_v1-linux-x86_64-enterprise-ubuntu2204-7.0.25.tgz
- https://downloads.mongodb.com/linux/mongo_crypt_shared_v1-linux-x86_64-enterprise-ubuntu2404-8.0.15.tgz

To test an explicit path:

    CRYPT_SHARED_PATH=$HOME/crypt_shared/7.0.25/lib/mongo_crypt_v1.so python repro.py

To test a system path:

    rm -rf /usr/lib/mongo_crypt_v1.so
    sudo ln -s $HOME/crypt_shared/7.0.25/lib/mongo_crypt_v1.so /usr/lib/mongo_crypt_v1.so
    python repro.py
"""

import os
from pymongo import MongoClient
from pymongo.encryption_options import AutoEncryptionOpts

auto_encryption_opts = AutoEncryptionOpts(
    kms_providers={"local": {"key": os.urandom(96)}},
    key_vault_namespace="keyvault.datakeys",
    crypt_shared_lib_required=True,
    crypt_shared_lib_path=os.environ.get("CRYPT_SHARED_PATH"),
)
client = MongoClient(auto_encryption_opts=auto_encryption_opts)
client["db"]["coll"].insert_one({"foo": "bar"}) # Attempts auto encryption.
