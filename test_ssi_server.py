from os import name, read
from random import randint
import time

from indy import anoncreds, did, ledger, pool, wallet, blob_storage

import json
import logging

import argparse
import sys
from ctypes import *
from os.path import dirname

from indy.error import ErrorCode, IndyError

from src.utils import (
    get_pool_genesis_txn_path,
    run_coroutine,
    PROTOCOL_VERSION,
    ensure_previous_request_applied,
)

import socket

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

parser = argparse.ArgumentParser(
    description="Run python getting-started scenario (Alice/Faber)"
)
parser.add_argument("-t", "--storage_type", help="load custom wallet storage plug-in")
parser.add_argument("-l", "--library", help="dynamic library to load for plug-in")
parser.add_argument("-e", "--entrypoint", help="entry point for dynamic library")
parser.add_argument("-c", "--config", help="entry point for dynamic library")
parser.add_argument("-s", "--creds", help="entry point for dynamic library")

args = parser.parse_args()

# check if we need to dyna-load a custom wallet storage plug-in
if args.storage_type:
    if not (args.library and args.entrypoint):
        parser.print_help()
        sys.exit(0)
    stg_lib = CDLL(args.library)
    result = stg_lib[args.entrypoint]()
    if result != 0:
        print("Error unable to load wallet storage", result)
        parser.print_help()
        sys.exit(0)

    # for postgres storage, also call the storage init (non-standard)
    if args.storage_type == "postgres_storage":
        try:
            print("Calling init_storagetype() for postgres:", args.config, args.creds)
            init_storagetype = stg_lib["init_storagetype"]
            c_config = c_char_p(args.config.encode("utf-8"))
            c_credentials = c_char_p(args.creds.encode("utf-8"))
            result = init_storagetype(c_config, c_credentials)
            print(" ... returns ", result)
        except RuntimeError as e:
            print("Error initializing storage, ignoring ...", e)

    print("Success, loaded wallet storage", args.storage_type)


async def run():
    logger.info("Getting started -> started")

    host = socket.gethostname()  # get local machine name
    port = 8080  # Make sure it's within the > 1024 $$ <65535 range

    s = socket.socket()
    s.bind((host, port))

    pool_ = {"name": "pool1"}
    logger.info("Open Pool Ledger: {}".format(pool_["name"]))
    pool_["genesis_txn_path"] = get_pool_genesis_txn_path(pool_["name"])
    pool_["config"] = json.dumps({"genesis_txn": str(pool_["genesis_txn_path"])})

    # Set protocol version 2 to work with Indy Node 1.4
    await pool.set_protocol_version(PROTOCOL_VERSION)

    try:
        await pool.create_pool_ledger_config(pool_["name"], pool_["config"])
    except IndyError as ex:
        if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            pass
    pool_["handle"] = await pool.open_pool_ledger(pool_["name"], None)

    steward = {
        "name": "Sovrin Steward",
        "wallet_config": json.dumps({"id": "sovrin_steward_wallet"}),
        "wallet_credentials": json.dumps({"key": "steward_wallet_key"}),
        "pool": pool_["handle"],
        "seed": "000000000000000000000000Steward1",
    }

    await create_wallet(steward)

    logger.info(
        '"Sovrin Steward" -> Erstelle seedbasierte DID und lege sie ins Steward wallet'
    )
    steward["did_info"] = json.dumps({"seed": steward["seed"]})
    steward["did"], steward["key"] = await did.create_and_store_my_did(
        steward["wallet"], steward["did_info"]
    )
    logger.info("Steward DID:", steward["did"])

    logger.info("==============================")
    logger.info(
        "== Beziehe Trust Anchor credentials - Verinym für die Government  =="
    )  # Verinym is a tuple (DID,public key, private key) that is used to identify an actor on the ledger
    logger.info("------------------------------")

    government = {
        "name": "Government",
        "wallet_config": json.dumps({"id": "government_wallet"}),
        "wallet_credentials": json.dumps({"key": "government_wallet_key"}),
        "pool": pool_["handle"],
        "role": "TRUST_ANCHOR",
    }

    await getting_verinym(steward, government)

    logger.info("==============================")
    logger.info("== Beziehe Trust Anchor credentials - Verinym für die Ärztekammer  ==")
    logger.info("------------------------------")

    ak = {
        "name": "Ärztekammer",
        "wallet_config": json.dumps({"id": "ak_wallet"}),
        "wallet_credentials": json.dumps({"key": "ak_wallet_key"}),
        "pool": pool_["handle"],
        "role": "TRUST_ANCHOR",
    }

    await getting_verinym(steward, ak)

    logger.info("==============================")
    logger.info("== Beziehe Trust Anchor credentials - Verinym für Dr. Bob  ==")
    logger.info("------------------------------")

    dT = {
        "name": "DrBob",
        "wallet_config": json.dumps({"id": "dT_wallet"}),
        "wallet_credentials": json.dumps({"key": "dT_wallet_key"}),
        "pool": pool_["handle"],
        "role": "TRUST_ANCHOR",
    }

    await getting_verinym(steward, dT)

    logger.info("==============================")
    logger.info("== Beziehe Trust Anchor credentials - Verinym für den Acme  ==")
    logger.info("------------------------------")

    arbeitgeber = {
        "name": "Arbeitgeber",
        "wallet_config": json.dumps({"id": "arbeitgeber_wallet"}),
        "wallet_credentials": json.dumps({"key": "arbeitgeber_wallet_key"}),
        "pool": pool_["handle"],
        "role": "TRUST_ANCHOR",
    }

    await getting_verinym(steward, arbeitgeber)
    #############################################
    logger.info("==============================")
    logger.info("=== Erstellung der Schemata ==")
    logger.info("------------------------------")

    logger.info('"ak" -> Erstellt "Krankschreibung" Schema')
    krankschreibung = {
        "name": "Krankschreibung",
        "version": "1.2",
        "attributes": ["first_name", "last_name", "illness", "krankTage"],
    }
    (
        ak["krankschreibung_schema_id"],
        ak["krankschreibung_schema"],
    ) = await anoncreds.issuer_create_schema(
        ak["did"],
        krankschreibung["name"],
        krankschreibung["version"],
        json.dumps(krankschreibung["attributes"]),
    )
    krankschreibung_schema_id = ak["krankschreibung_schema_id"]

    logger.info('"ak" -> Sende "krankschreibung" Schema zum Ledger')
    await send_schema(ak["pool"], ak["wallet"], ak["did"], ak["krankschreibung_schema"])

    time.sleep(1)  # sleep 1 second before getting schema
    ####################################### Erstellung der Credential Definitions #######################################

    logger.info("==============================")
    logger.info("=== dT Credential Definition Setup ==")
    logger.info("------------------------------")

    logger.info('"dT" -> Get "krankschreibung" Schema from Ledger')
    (dT["krankschreibung_schema_id"], dT["krankschreibung_schema"]) = await get_schema(
        dT["pool"], dT["did"], krankschreibung_schema_id
    )

    logger.info(
        '"dT" -> Create and store in Wallet "dT krankschreibung" Credential Definition'
    )
    krankschreibung_cred_def = {
        "tag": "TAG1",
        "type": "CL",
        "config": {"support_revocation": False},
    }
    (
        dT["krankschreibung_cred_def_id"],
        dT["krankschreibung_cred_def"],
    ) = await anoncreds.issuer_create_and_store_credential_def(
        dT["wallet"],
        dT["did"],
        dT["krankschreibung_schema"],
        krankschreibung_cred_def["tag"],
        krankschreibung_cred_def["type"],
        json.dumps(krankschreibung_cred_def["config"]),
    )

    logger.info('"dT" -> Send  "dT krankschreibung" Credential Definition to Ledger')
    await send_cred_def(
        dT["pool"], dT["wallet"], dT["did"], dT["krankschreibung_cred_def"]
    )

    ####################################!!!!!!!!!!!!!!!!!!!

    s.listen(1)
    c, adress = s.accept()

    logger.warning(
        "Connection incoming!!! !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    )

    logger.warning("== Alice setup ==")
    logger.info("------------------------------")

    alice = {
        "name": "Alice",
        "wallet_config": json.dumps({"id": "alice_wallet"}),
        "wallet_credentials": json.dumps({"key": "alice_wallet_key"}),
        "pool": pool_["handle"],
    }
    await create_wallet(alice)
    (alice["did"], alice["key"]) = await did.create_and_store_my_did(
        alice["wallet"], "{}"
    )

    logger.warning("sending to alice : " + alice["did"])
    # c.send(alice["did"].encode("utf-8"))
    logger.warning(
        "=================== Alice Wallet erfolgreich angelegt/bezogen ==================="
    )

    #################################### Dr. Bob schreibt Schein für Alice
    async def create_ks():
        logger.info('"dT" -> Create "krankschreibung" Credential Offer for Alice')
        dT[
            "krankschreibung_cred_offer"
        ] = await anoncreds.issuer_create_credential_offer(
            dT["wallet"], dT["krankschreibung_cred_def_id"]
        )

        logger.info('"dT" -> Send "krankschreibung" Credential Offer to Alice')
        alice["krankschreibung_cred_offer"] = dT["krankschreibung_cred_offer"]
        krankschreibung_cred_offer_object = json.loads(
            alice["krankschreibung_cred_offer"]
        )

        alice["krankschreibung_schema_id"] = krankschreibung_cred_offer_object[
            "schema_id"
        ]
        alice["krankschreibung_cred_def_id"] = krankschreibung_cred_offer_object[
            "cred_def_id"
        ]

        logger.info('"Alice" -> Create and store "Alice" Master Secret in Wallet')
        alice["master_secret_id"] = await anoncreds.prover_create_master_secret(
            alice["wallet"], None
        )

        logger.info(
            '"Alice" -> Get "dT krankschreibung" Credential Definition from Ledger'
        )
        (
            alice["dT_krankschreibung_cred_def_id"],
            alice["dT_krankschreibung_cred_def"],
        ) = await get_cred_def(
            alice["pool"], alice["did"], alice["krankschreibung_cred_def_id"]
        )

        logger.info('"Alice" -> Create "krankschreibung" Credential Request for dT')
        (
            alice["krankschreibung_cred_request"],
            alice["krankschreibung_cred_request_metadata"],
        ) = await anoncreds.prover_create_credential_req(
            alice["wallet"],
            alice["did"],
            alice["krankschreibung_cred_offer"],
            alice["dT_krankschreibung_cred_def"],
            alice["master_secret_id"],
        )

        logger.info('"Alice" -> Send "krankschreibung" Credential Request to dT')
        dT["krankschreibung_cred_request"] = alice["krankschreibung_cred_request"]

        logger.info('"dT" -> Create "krankschreibung" Credential for Alice')
        dT["alice_krankschreibung_cred_values"] = json.dumps(
            {
                "first_name": {
                    "raw": "Alice",
                    "encoded": "1139481716457488690172217916278103335",
                },
                "last_name": {
                    "raw": "Garcia",
                    "encoded": "5321642780241790123587902456789123452",
                },
                "illness": {"raw": "schlimmeKrankheit", "encoded": "12434523576212321"},
                "krankTage": {"raw": "5", "encoded": "5"},
            }
        )
        dT["krankschreibung_cred"], _, _ = await anoncreds.issuer_create_credential(
            dT["wallet"],
            dT["krankschreibung_cred_offer"],
            dT["krankschreibung_cred_request"],
            dT["alice_krankschreibung_cred_values"],
            None,
            None,
        )

        logger.info('"dT" -> Send "krankschreibung" Credential to Alice')
        alice["krankschreibung_cred"] = dT["krankschreibung_cred"]

        logger.info('"Alice" -> Store "krankschreibung" Credential from dT')
        _, alice["krankschreibung_cred_def"] = await get_cred_def(
            alice["pool"], alice["did"], alice["krankschreibung_cred_def_id"]
        )

        alice["ks_id"] = await anoncreds.prover_store_credential(
            alice["wallet"],
            None,
            alice["krankschreibung_cred_request_metadata"],
            alice["krankschreibung_cred"],
            alice["krankschreibung_cred_def"],
            None,
        )
        logger.info(
            ' Alice hat nun eine Krankschreibung für "schlimme krankheit" von Dr. Bob mit ID {}'.format(
                alice["ks_id"]
            )
        )

    ################################### Verification der Krankschreibung ###################################

    async def ver_ks():
        logger.info("==============================")
        logger.info("== Alice beweist Arbeitgeber das sie krank ==")
        logger.info("------------------------------")

        logger.info('"arbeitgeber" -> Create "krankschreibung" Proof Request')
        nonce = await anoncreds.generate_nonce()
        arbeitgeber["krankschreibung_proof_request"] = json.dumps(
            {
                "nonce": nonce,
                "name": "krankschreibung",
                "version": "0.2",
                "requested_attributes": {
                    "attr1_referent": {"name": "first_name"},
                    "attr2_referent": {"name": "last_name"},
                    "attr3_referent": {
                        "name": "illness",
                        "restrictions": [
                            {"cred_def_id": dT["krankschreibung_cred_def_id"]}
                        ],
                    },
                },
                "requested_predicates": {
                    "predicate1_referent": {
                        "name": "krankTage",
                        "p_type": ">=",
                        "p_value": 1,
                        "restrictions": [
                            {"cred_def_id": dT["krankschreibung_cred_def_id"]}
                        ],
                    }
                },
            }
        )

        # Aus den DOCs : => Kann nur mit ">=" vergleichen -> es ist wahrscheinlich ein hilfsfeld mit "anzahl erkrankungen" oder "krankheitstage" benötigt
        #     #predicate_info: Describes requested attribute predicate
        # ///     {
        # ///         "name": attribute name, (case insensitive and ignore spaces)
        # ///         "p_type": predicate type (Currently >= only)
        # ///         "p_value": predicate value
        # ///         "restrictions": Optional<wql query>,
        # ///         "non_revoked": Optional<<non_revoc_interval>>, // see below,
        # ///                        // If specified prover must proof non-revocation
        # ///                        // for date in this interval this attribute
        # ///                        // (overrides proof level interval)
        # ///     }

        logger.info('"arbeitgeber" -> Send "krankschreibung" Proof Request to Alice')
        alice["krankschreibung_proof_request"] = arbeitgeber[
            "krankschreibung_proof_request"
        ]

        logger.info('"Alice" -> Get credentials for "krankschreibung" Proof Request')

        search_for_krankschreibung_proof_request = (
            await anoncreds.prover_search_credentials_for_proof_req(
                alice["wallet"], alice["krankschreibung_proof_request"], None
            )
        )

        cred_for_attr1 = await get_credential_for_referent(
            search_for_krankschreibung_proof_request, "attr1_referent"
        )
        cred_for_attr2 = await get_credential_for_referent(
            search_for_krankschreibung_proof_request, "attr2_referent"
        )
        cred_for_attr3 = await get_credential_for_referent(
            search_for_krankschreibung_proof_request, "attr3_referent"
        )
        cred_for_predicate1 = await get_credential_for_referent(
            search_for_krankschreibung_proof_request, "predicate1_referent"
        )

        await anoncreds.prover_close_credentials_search_for_proof_req(
            search_for_krankschreibung_proof_request
        )

        alice["creds_for_krankschreibung_proof"] = {
            cred_for_attr1["referent"]: cred_for_attr1,
            cred_for_attr2["referent"]: cred_for_attr2,
            cred_for_attr3["referent"]: cred_for_attr3,
            cred_for_predicate1["referent"]: cred_for_predicate1,
        }

        (
            alice["schemas_for_krankschreibung"],
            alice["cred_defs_for_krankschreibung"],
            alice["revoc_states_for_krankschreibung"],
        ) = await prover_get_entities_from_ledger(
            alice["pool"],
            alice["did"],
            alice["creds_for_krankschreibung_proof"],
            alice["name"],
        )

        logger.info('"Alice" -> Create "krankschreibung" Proof')
        alice["krankschreibung_requested_creds"] = json.dumps(
            {
                "self_attested_attributes": {
                    "attr1_referent": "Alice",
                    "attr2_referent": "Garcia",
                },
                "requested_attributes": {
                    "attr3_referent": {
                        "cred_id": cred_for_attr3["referent"],
                        "revealed": False,
                    },
                },
                "requested_predicates": {
                    "predicate1_referent": {"cred_id": cred_for_predicate1["referent"]}
                },
            }
        )

        alice["krankschreibung_proof"] = await anoncreds.prover_create_proof(
            alice["wallet"],
            alice["krankschreibung_proof_request"],
            alice["krankschreibung_requested_creds"],
            alice["master_secret_id"],
            alice["schemas_for_krankschreibung"],
            alice["cred_defs_for_krankschreibung"],
            alice["revoc_states_for_krankschreibung"],
        )

        logger.info('"Alice" -> Send "krankschreibung" Proof to arbeitgeber')
        arbeitgeber["krankschreibung_proof"] = alice["krankschreibung_proof"]

        krankschreibung_proof_object = json.loads(arbeitgeber["krankschreibung_proof"])

        logger.warning(krankschreibung_proof_object)

        (
            arbeitgeber["schemas_for_krankschreibung"],
            arbeitgeber["cred_defs_for_krankschreibung"],
            arbeitgeber["revoc_ref_defs_for_krankschreibung"],
            arbeitgeber["revoc_regs_for_krankschreibung"],
        ) = await verifier_get_entities_from_ledger(
            arbeitgeber["pool"],
            arbeitgeber["did"],
            krankschreibung_proof_object["identifiers"],
            arbeitgeber["name"],
        )

        logger.info('"arbeitgeber" -> Verify "krankschreibung" Proof from Alice')
        # assert (
        #     "schlimmeKrankheit"
        #     == krankschreibung_proof_object["requested_proof"]["revealed_attrs"][
        #         "attr3_referent"
        #     ]["raw"]
        # )

        assert (
            "Alice"
            == krankschreibung_proof_object["requested_proof"]["self_attested_attrs"][
                "attr1_referent"
            ]
        )
        assert (
            "Garcia"
            == krankschreibung_proof_object["requested_proof"]["self_attested_attrs"][
                "attr2_referent"
            ]
        )

        assert await anoncreds.verifier_verify_proof(
            arbeitgeber["krankschreibung_proof_request"],
            arbeitgeber["krankschreibung_proof"],
            arbeitgeber["schemas_for_krankschreibung"],
            arbeitgeber["cred_defs_for_krankschreibung"],
            arbeitgeber["revoc_ref_defs_for_krankschreibung"],
            arbeitgeber["revoc_regs_for_krankschreibung"],
        )

        logger.warning("Die Verification war erfolgreich,  !!!!")

    fails = 0

    while fails < 10:
        try:
            data = c.recv(1).decode("utf-8")
            if not data:
                pass  # time.sleep(1)
            if data == "1":
                await create_ks()
                c.send(
                    "Krankrschreibung erhalten und in das persönliche Wallet abgelegt!".encode(
                        "utf-8"
                    )
                )
                fails = 0
            elif data == "2":
                await ver_ks()
                c.send("Erfolgreich verifiziert!".encode("utf-8"))
                fails = 0
            elif data == "3":
                # logger.warning(
                #     "I AM HEEEEEEEEEEEEEEEEEEEEEEEEEEEEEREREEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
                # )
                res = await anoncreds.prover_get_credential(
                    alice["wallet"], alice["ks_id"]
                )
                logger.warning(res)
                c.send(res.encode("utf-8"))
                fails = 0
            elif data == "q":
                logger.warning("USER LOGOUT!!!!!!!!!!!!!!!")
                c.close()
                break
            elif data == "4":
                c.send(alice["key"].encode("utf-8"))
            else:
                logger.warning("Ungültige Eingabe, nochmal probieren!")
                c.send("Ungültige Eingabe, nochmal probieren!".encode("utf-8"))
                fails += 1
            # do something
        except socket.error:
            c.close()

    #################################################

    logger.info(
        ' "Sovrin Steward" -> Wallet schließen (von aktiver Benutzung entfernen)'
    )
    await wallet.close_wallet(steward["wallet"])
    # await wallet.delete_wallet(steward['wallet_config'], steward['wallet_credentials'])

    logger.info(' "Dr. Bob" -> Wallet schließen (von aktiver Benutzung entfernen)')
    await wallet.close_wallet(dT["wallet"])
    # await wallet.delete_wallet(dT['wallet_config'], dT['wallet_credentials'])

    logger.info('"Government" -> Wallet schließen (von aktiver Benutzung entfernen)')
    await wallet.close_wallet(government["wallet"])
    # await wallet.delete_wallet(wallet_config("delete", government['wallet_config']),
    #    wallet_credentials("delete", government['wallet_credentials']))

    logger.info('"Ärztekammer" -> Wallet schließen (von aktiver Benutzung entfernen)')
    await wallet.close_wallet(ak["wallet"])
    # await wallet.delete_wallet(wallet_config("delete", ak['wallet_config']),
    #    wallet_credentials("delete", ak['wallet_credentials']))

    logger.info('"Arbeitgeber" -> Wallet schließen (von aktiver Benutzung entfernen)')
    await wallet.close_wallet(arbeitgeber["wallet"])
    # await wallet.delete_wallet(wallet_config("delete", arbeitgeber['wallet_config']),
    #                            wallet_credentials("delete", arbeitgeber['wallet_credentials']))

    logger.info('"Alice" -> Wallet schließen (von aktiver Benutzung entfernen)')
    await wallet.close_wallet(alice["wallet"])
    await wallet.delete_wallet(
        wallet_config("delete", alice["wallet_config"]),
        wallet_credentials("delete", alice["wallet_credentials"]),
    )

    logger.info("Close and Delete pool")
    await pool.close_pool_ledger(pool_["handle"])
    # await pool.delete_pool_ledger_config(pool_['name'])


def wallet_config(operation, wallet_config_str):
    if not args.storage_type:
        return wallet_config_str
    wallet_config_json = json.loads(wallet_config_str)
    wallet_config_json["storage_type"] = args.storage_type
    if args.config:
        wallet_config_json["storage_config"] = json.loads(args.config)
    # print(operation, json.dumps(wallet_config_json))
    return json.dumps(wallet_config_json)


def wallet_credentials(operation, wallet_credentials_str):
    if not args.storage_type:
        return wallet_credentials_str
    wallet_credentials_json = json.loads(wallet_credentials_str)
    if args.creds:
        wallet_credentials_json["storage_credentials"] = json.loads(args.creds)
    # print(operation, json.dumps(wallet_credentials_json))
    return json.dumps(wallet_credentials_json)


async def create_wallet(identity):
    logger.info('"{}" -> Create wallet'.format(identity["name"]))
    try:
        await wallet.create_wallet(
            wallet_config("create", identity["wallet_config"]),
            wallet_credentials("create", identity["wallet_credentials"]),
        )
    except IndyError as ex:
        if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            print("Die zugehörige Wallet exisiert bereits, wird geöffnet")
    identity["wallet"] = await wallet.open_wallet(
        wallet_config("open", identity["wallet_config"]),
        wallet_credentials("open", identity["wallet_credentials"]),
    )


async def getting_verinym(from_, to):
    await create_wallet(to)

    (to["did"], to["key"]) = await did.create_and_store_my_did(to["wallet"], "{}")

    from_["info"] = {"did": to["did"], "verkey": to["key"], "role": to["role"] or None}

    await send_nym(
        from_["pool"],
        from_["wallet"],
        from_["did"],
        from_["info"]["did"],
        from_["info"]["verkey"],
        from_["info"]["role"],
    )


async def send_nym(pool_handle, wallet_handle, _did, new_did, new_key, role):
    nym_request = await ledger.build_nym_request(_did, new_did, new_key, None, role)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, nym_request)


async def send_schema(pool_handle, wallet_handle, _did, schema):
    schema_request = await ledger.build_schema_request(_did, schema)
    await ledger.sign_and_submit_request(
        pool_handle, wallet_handle, _did, schema_request
    )


async def send_cred_def(pool_handle, wallet_handle, _did, cred_def_json):
    cred_def_request = await ledger.build_cred_def_request(_did, cred_def_json)
    await ledger.sign_and_submit_request(
        pool_handle, wallet_handle, _did, cred_def_request
    )


async def get_schema(pool_handle, _did, schema_id):
    get_schema_request = await ledger.build_get_schema_request(_did, schema_id)
    get_schema_response = await ensure_previous_request_applied(
        pool_handle,
        get_schema_request,
        lambda response: response["result"]["data"] is not None,
    )
    return await ledger.parse_get_schema_response(get_schema_response)


async def get_cred_def(pool_handle, _did, cred_def_id):
    get_cred_def_request = await ledger.build_get_cred_def_request(_did, cred_def_id)
    get_cred_def_response = await ensure_previous_request_applied(
        pool_handle,
        get_cred_def_request,
        lambda response: response["result"]["data"] is not None,
    )
    return await ledger.parse_get_cred_def_response(get_cred_def_response)


async def get_credential_for_referent(search_handle, referent):
    credentials = json.loads(
        await anoncreds.prover_fetch_credentials_for_proof_req(
            search_handle, referent, 10
        )
    )
    return credentials[0]["cred_info"]


def get_timestamp_for_attribute(cred_for_attribute, revoc_states):
    if cred_for_attribute["rev_reg_id"] in revoc_states:
        return int(next(iter(revoc_states[cred_for_attribute["rev_reg_id"]])))
    else:
        return None


async def prover_get_entities_from_ledger(
    pool_handle, _did, identifiers, actor, timestamp_from=None, timestamp_to=None
):
    schemas = {}
    cred_defs = {}
    rev_states = {}
    for item in identifiers.values():
        logger.info('"{}" -> Get Schema from Ledger'.format(actor))
        (received_schema_id, received_schema) = await get_schema(
            pool_handle, _did, item["schema_id"]
        )
        schemas[received_schema_id] = json.loads(received_schema)

        logger.info('"{}" -> Get Claim Definition from Ledger'.format(actor))
        (received_cred_def_id, received_cred_def) = await get_cred_def(
            pool_handle, _did, item["cred_def_id"]
        )
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        if "rev_reg_id" in item and item["rev_reg_id"] is not None:
            # Create Revocations States
            logger.info(
                '"{}" -> Get Revocation Registry Definition from Ledger'.format(actor)
            )
            get_revoc_reg_def_request = await ledger.build_get_revoc_reg_def_request(
                _did, item["rev_reg_id"]
            )

            get_revoc_reg_def_response = await ensure_previous_request_applied(
                pool_handle,
                get_revoc_reg_def_request,
                lambda response: response["result"]["data"] is not None,
            )
            (
                rev_reg_id,
                revoc_reg_def_json,
            ) = await ledger.parse_get_revoc_reg_def_response(
                get_revoc_reg_def_response
            )

            logger.info(
                '"{}" -> Get Revocation Registry Delta from Ledger'.format(actor)
            )
            if not timestamp_to:
                timestamp_to = int(time.time())
            get_revoc_reg_delta_request = (
                await ledger.build_get_revoc_reg_delta_request(
                    _did, item["rev_reg_id"], timestamp_from, timestamp_to
                )
            )
            get_revoc_reg_delta_response = await ensure_previous_request_applied(
                pool_handle,
                get_revoc_reg_delta_request,
                lambda response: response["result"]["data"] is not None,
            )
            (
                rev_reg_id,
                revoc_reg_delta_json,
                t,
            ) = await ledger.parse_get_revoc_reg_delta_response(
                get_revoc_reg_delta_response
            )

            tails_reader_config = json.dumps(
                {
                    "base_dir": dirname(
                        json.loads(revoc_reg_def_json)["value"]["tailsLocation"]
                    ),
                    "uri_pattern": "",
                }
            )
            blob_storage_reader_cfg_handle = await blob_storage.open_reader(
                "default", tails_reader_config
            )

            logger.info("%s - Create Revocation State", actor)
            rev_state_json = await anoncreds.create_revocation_state(
                blob_storage_reader_cfg_handle,
                revoc_reg_def_json,
                revoc_reg_delta_json,
                t,
                item["cred_rev_id"],
            )
            rev_states[rev_reg_id] = {t: json.loads(rev_state_json)}

    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_states)


async def verifier_get_entities_from_ledger(
    pool_handle, _did, identifiers, actor, timestamp=None
):
    schemas = {}
    cred_defs = {}
    rev_reg_defs = {}
    rev_regs = {}
    for item in identifiers:
        logger.info('"{}" -> Get Schema from Ledger'.format(actor))
        (received_schema_id, received_schema) = await get_schema(
            pool_handle, _did, item["schema_id"]
        )
        schemas[received_schema_id] = json.loads(received_schema)

        logger.info('"{}" -> Get Claim Definition from Ledger'.format(actor))
        (received_cred_def_id, received_cred_def) = await get_cred_def(
            pool_handle, _did, item["cred_def_id"]
        )
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        if "rev_reg_id" in item and item["rev_reg_id"] is not None:
            # Get Revocation Definitions and Revocation Registries
            logger.info('"{}" -> Get Revocation Definition from Ledger'.format(actor))
            get_revoc_reg_def_request = await ledger.build_get_revoc_reg_def_request(
                _did, item["rev_reg_id"]
            )

            get_revoc_reg_def_response = await ensure_previous_request_applied(
                pool_handle,
                get_revoc_reg_def_request,
                lambda response: response["result"]["data"] is not None,
            )
            (
                rev_reg_id,
                revoc_reg_def_json,
            ) = await ledger.parse_get_revoc_reg_def_response(
                get_revoc_reg_def_response
            )

            logger.info('"{}" -> Get Revocation Registry from Ledger'.format(actor))
            if not timestamp:
                timestamp = item["timestamp"]
            get_revoc_reg_request = await ledger.build_get_revoc_reg_request(
                _did, item["rev_reg_id"], timestamp
            )
            get_revoc_reg_response = await ensure_previous_request_applied(
                pool_handle,
                get_revoc_reg_request,
                lambda response: response["result"]["data"] is not None,
            )
            (
                rev_reg_id,
                rev_reg_json,
                timestamp2,
            ) = await ledger.parse_get_revoc_reg_response(get_revoc_reg_response)

            rev_regs[rev_reg_id] = {timestamp2: json.loads(rev_reg_json)}
            rev_reg_defs[rev_reg_id] = json.loads(revoc_reg_def_json)

    return (
        json.dumps(schemas),
        json.dumps(cred_defs),
        json.dumps(rev_reg_defs),
        json.dumps(rev_regs),
    )


if __name__ == "__main__":
    run_coroutine(run)
    time.sleep(1)  # FIXME waiting for libindy thread complete
