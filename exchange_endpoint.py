from flask import Flask, request, g
from flask_restful import Resource, Api
from flask import jsonify

import eth_account
import algosdk

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from sqlalchemy.sql import text

import json
import math
import sys
import traceback
from hexbytes import HexBytes
from datetime import datetime

from algosdk.v2client import algod
from algosdk.v2client import indexer
from algosdk import mnemonic
from algosdk.future import transaction
from algosdk import account

from web3 import Web3
from web3.middleware import geth_poa_middleware
from web3.exceptions import TransactionNotFound

# TODO: make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth

from models import Base, Order, TX, Log
import gen_keys

engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

# mnemonic to generate the public key for the exchange server
eth_mnemonic = "midnight game play tail blossom cereal jacket cruel okay slim verify harbor"
algo_mnemonic = "half south great normal teach elephant tunnel grain monkey voice sentence express swear powder hawk valve grocery liar floor shoe come accuse nation abstract harsh"

""" Pre-defined methods (do not need to change) """


@app.before_request
def create_session():
    g.session = scoped_session(DBSession)


@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()


def connect_to_blockchains():
    try:
        # If g.acl has not been defined yet, then trying to query it fails
        acl_flag = False
        g.acl
    except AttributeError as ae:
        acl_flag = True

    try:
        if acl_flag or not g.acl.status():
            # Define Algorand client for the application
            g.acl = connect_to_algo()
    except Exception as e:
        print("Trying to connect to algorand client again")
        print(traceback.format_exc())
        g.acl = connect_to_algo()

    try:
        icl_flag = False
        g.icl
    except AttributeError as ae:
        icl_flag = True
    connect_to_algo
    try:
        if icl_flag or not g.icl.health():
            # Define the index client
            g.icl = connect_to_algo(connection_type='indexer')
    except Exception as e:
        print("Trying to connect to algorand indexer client again")
        print(traceback.format_exc())
        g.icl = connect_to_algo(connection_type='indexer')

    try:
        w3_flag = False
        g.w3
    except AttributeError as ae:
        w3_flag = True

    try:
        if w3_flag or not g.w3.isConnected():
            g.w3 = connect_to_eth()
    except Exception as e:
        print("Trying to connect to web3 again")
        print(traceback.format_exc())
        g.w3 = connect_to_eth()


""" End of pre-defined methods """

""" Helper Methods (skeleton code for you to implement) """


def verify(content):
    try:

        if content['payload']['platform'] == 'Ethereum':
            eth_sk = content['sig']
            eth_pk = content['payload']['sender_pk']

            payload = json.dumps(content['payload'])
            eth_encoded_msg = eth_account.messages.encode_defunct(text=payload)
            recovered_pk = eth_account.Account.recover_message(eth_encoded_msg, signature=eth_sk)

            # Check if signature is valid
            if recovered_pk == eth_pk:
                print(content, "eth order verified")
                result = True
            else:
                print(content, "eth order not verified")
                result = False

            return result  # bool value

        if content['payload']['platform'] == 'Algorand':
            algo_sig = content['sig']
            algo_pk = content['payload']['sender_pk']
            payload = json.dumps(content['payload'])

            result = algosdk.util.verify_bytes(payload.encode('utf-8'), algo_sig, algo_pk)
            print(content, result, "algo order verification result")

            return result  # bool value

    except Exception as e:
        import traceback
        print(traceback.format_exc())
        print(e)


def insert_order(content):
    try:

        # 1. Insert new order
        order_obj = Order(sender_pk=content['payload']['sender_pk'],
                          receiver_pk=content['payload']['receiver_pk'],
                          buy_currency=content['payload']['buy_currency'],
                          sell_currency=content['payload']['sell_currency'],
                          buy_amount=content['payload']['buy_amount'],
                          sell_amount=content['payload']['sell_amount'],
                          exchange_rate=(content['payload']['buy_amount'] / content['payload']['sell_amount']),
                          signature=content['sig'],
                          tx_id=content['payload']['tx_id'])

        g.session.add(order_obj)
        g.session.commit()

    except Exception as e:
        import traceback
        print(traceback.format_exc())
        print(e)


def process_order(content):
    order_obj = Order(sender_pk=content['payload']['sender_pk'],
                      receiver_pk=content['payload']['receiver_pk'],
                      buy_currency=content['payload']['buy_currency'],
                      sell_currency=content['payload']['sell_currency'],
                      buy_amount=content['payload']['buy_amount'],
                      sell_amount=content['payload']['sell_amount'],
                      exchange_rate=(content['payload']['buy_amount'] / content['payload']['sell_amount']),
                      tx_id=content['payload']['tx_id'],
                      signature=content['sig'])

    # check up if it works well and get the order id
    results = g.session.execute("select distinct id from orders where " +
                                " sender_pk = '" + str(order_obj.sender_pk) + "'" +
                                " and tx_id = '" + str(order_obj.tx_id) + "'" +
                                " and receiver_pk = '" + str(order_obj.receiver_pk) + "'")

    order_id = results.first()['id']
    print("new order_id: ", order_id)

    # print(" new order: ", order_id, order['buy_currency'], order['sell_currency'], order['buy_amount'], order['sell_amount'])

    # 2. Matching order
    results = g.session.execute("select count(id) " +
                                " from orders where orders.filled is null " +
                                " and orders.sell_currency = '" + order_obj.buy_currency + "'" +
                                " and orders.buy_currency = '" + order_obj.sell_currency + "'" +
                                " and exchange_rate <= " + str(order_obj.sell_amount / order_obj.buy_amount))

    if results.first()[0] == 0:
        print("::::no matching order::::")
        return

    results = g.session.execute(
        "select distinct id, sender_pk, receiver_pk, buy_currency, sell_currency, buy_amount, sell_amount, tx_id " +
        "from orders where orders.filled is null " +
        " and orders.sell_currency = '" + order_obj.buy_currency + "'" +
        " and orders.buy_currency = '" + order_obj.sell_currency + "'" +
        " and exchange_rate <= " + str(order_obj.sell_amount / order_obj.buy_amount))

    for row in results:
        m_order_id = row['id']
        m_sender_pk = row['sender_pk']
        m_receiver_pk = row['receiver_pk']
        m_buy_currency = row['buy_currency']
        m_sell_currency = row['sell_currency']
        m_buy_amount = row['buy_amount']
        m_sell_amount = row['sell_amount']
        m_tx_id = row['tx_id']

        print(" matched at ID: ", m_order_id)
        break

    print(" matching order: ", m_order_id, m_buy_currency, m_sell_currency, m_buy_amount, m_sell_amount)

    # update both the matching orders
    stmt = text("UPDATE orders SET counterparty_id=:id, filled=:curr_date WHERE id=:the_id and filled is null")
    stmt = stmt.bindparams(the_id=order_id, id=m_order_id, curr_date=datetime.now())
    g.session.execute(stmt)  # where session has already been defined

    stmt = text("UPDATE orders SET counterparty_id=:id, filled=:curr_date WHERE id=:the_id and filled is null")
    stmt = stmt.bindparams(the_id=m_order_id, id=order_id, curr_date=datetime.now())
    g.session.execute(stmt)  # where session has already been defined

    txes = list()  # list of transactions to execute

    # 3. Create derived order
    if order_obj.buy_amount > m_sell_amount:
        d_order_obj = Order(sender_pk=order_obj.sender_pk,
                            receiver_pk=order_obj.receiver_pk,
                            buy_currency=order_obj.buy_currency,
                            sell_currency=order_obj.sell_currency,
                            buy_amount=order_obj.buy_amount - m_sell_amount,
                            sell_amount=order_obj.sell_amount - (
                                    (order_obj.sell_amount / order_obj.buy_amount) * m_sell_amount),
                            exchange_rate=(order_obj.buy_amount - m_sell_amount) / (order_obj.sell_amount - (
                                    order_obj.sell_amount / order_obj.buy_amount * m_sell_amount)),
                            tx_id=order_obj.tx_id,
                            creator_id=order_id)
        g.session.add(d_order_obj)
        g.session.commit()

        # construct tx
        # 1st  transaction
        tx_dict = dict()
        tx_dict['platform'] = order_obj.buy_currency
        tx_dict['receiver_pk'] = order_obj.receiver_pk
        tx_dict['amount'] = m_sell_amount
        tx_dict['order_id'] = order_id
        tx_dict['tx_id'] = ""
        txes.append(tx_dict)

        # 2nd  transaction
        tx_dict = dict()
        tx_dict['platform'] = m_buy_currency
        tx_dict['receiver_pk'] = m_receiver_pk
        tx_dict['amount'] = m_buy_amount
        tx_dict['order_id'] = m_order_id
        tx_dict['tx_id'] = ""
        txes.append(tx_dict)

        print("case 1")
    elif order_obj.buy_amount < m_sell_amount:
        d_order_obj = Order(sender_pk=m_sender_pk,
                            receiver_pk=m_receiver_pk,
                            buy_currency=m_buy_currency,
                            sell_currency=m_sell_currency,
                            buy_amount=m_buy_amount - (m_buy_amount / m_sell_amount) * order_obj.buy_amount,
                            sell_amount=m_sell_amount - order_obj.buy_amount,
                            exchange_rate=(m_buy_amount - (m_buy_amount / m_sell_amount) * order_obj.buy_amount) / (
                                    m_sell_amount - order_obj.buy_amount),
                            tx_id=m_tx_id,
                            creator_id=m_order_id)
        g.session.add(d_order_obj)
        g.session.commit()

        # construct tx
        # 1st  transaction
        tx_dict = dict()
        tx_dict['platform'] = order_obj.buy_currency
        tx_dict['receiver_pk'] = order_obj.receiver_pk
        tx_dict['amount'] = order_obj.buy_amount
        tx_dict['order_id'] = order_id
        tx_dict['tx_id'] = ""
        txes.append(tx_dict)

        # 2nd  transaction
        tx_dict = dict()
        tx_dict['platform'] = m_buy_currency
        tx_dict['receiver_pk'] = m_receiver_pk
        tx_dict['amount'] = order_obj.sell_amount
        tx_dict['order_id'] = m_order_id
        tx_dict['tx_id'] = ""
        txes.append(tx_dict)

        print("case 2")

    else:  # perfect matched
        # construct tx
        # 1st  transaction
        tx_dict = dict()
        tx_dict['platform'] = order_obj.buy_currency
        tx_dict['receiver_pk'] = order_obj.receiver_pk
        tx_dict['amount'] = order_obj.buy_amount
        tx_dict['order_id'] = order_id
        tx_dict['tx_id'] = ""
        txes.append(tx_dict)

        # 2nd  transaction
        tx_dict = dict()
        tx_dict['platform'] = m_buy_currency
        tx_dict['receiver_pk'] = m_receiver_pk
        tx_dict['amount'] = m_buy_amount
        tx_dict['order_id'] = m_order_id
        tx_dict['tx_id'] = ""
        txes.append(tx_dict)

        print("case 3")

    print("execute_txes to begin")
    execute_txes(txes)


def execute_txes(txes):
    try:

        if txes is None:
            return True
        if len(txes) == 0:
            return True
        print(f"Trying to execute {len(txes)} transactions")
        print(f"IDs = {[tx['order_id'] for tx in txes]}")
        eth_sk, eth_pk = get_eth_keys()
        algo_sk, algo_pk = get_algo_keys()

        if not all(tx['platform'] in ["Algorand", "Ethereum"] for tx in txes):
            print("Error: execute_txes got an invalid platform!")
            print(tx['platform'] for tx in txes)

        algo_txes = [tx for tx in txes if tx['platform'] == "Algorand"]
        eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum"]

        print(algo_txes)
        print(eth_txes)

        # TODO:
        #       1. Send tokens on the Algorand and eth testnets, appropriately
        #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
        #       2. Add all transactions to the TX table

        # 1. Send tokens
        w3 = connect_to_eth()
        starting_nonce = w3.eth.get_transaction_count(eth_pk, "pending")

        # eth_tx_ids = send_tokens_eth(w3, eth_sk, eth_txes)
        print("eth_pk: ", eth_pk)
        print("eth_sk: ", eth_sk)
        print("receiver_pk: ", eth_txes[0]['receiver_pk'])

        tx_dict = {'nonce': starting_nonce + 0,  # Locally update nonce
                   'gasPrice': w3.eth.gas_price,
                   'gas': w3.eth.estimate_gas({'from': eth_pk, 'to': eth_txes[0]['receiver_pk'], 'data': b'', 'amount': eth_txes[0]['amount']}),
                   'to': eth_txes[0]['receiver_pk'],
                   'value': eth_txes[0]['amount'],
                   'data': b''}

        print(tx_dict)

        signed_txn = w3.eth.account.sign_transaction(tx_dict, eth_sk)
        tx_id = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
        eth_txes[0]['tx_id'] = tx_id.hex()
        print("tx_id ", tx_id.hex())

        acl = connect_to_algo()
        # algo_tx_ids = send_tokens_algo(acl, algo_sk, algo_txes)
        sp = acl.suggested_params()
        unsigned_tx = transaction.PaymentTxn(algo_pk, sp, algo_txes[0]['receiver_pk'], algo_txes[0]['amount'])
        signed_tx = unsigned_tx.sign(algo_sk)
        tx_id = acl.send_transaction(signed_tx)
        algo_txes[0]['tx_id'] = tx_id
        print("tx_id ", tx_id)

        # 2. Add all transactions to the TX table
        tx_obj = TX(platform=eth_txes[0]['platform'],
                    receiver_pk=eth_txes[0]['receiver_pk'],
                    order_id=eth_txes[0]['order_id'],
                    tx_id=eth_tx_ids)

        print(tx_obj)
        g.session.add(tx_obj)
        g.session.commit()

        tx_obj = TX(platform=algo_txes[0]['platform'],
                    receiver_pk=algo_txes[0]['receiver_pk'],
                    order_id=algo_txes[0]['order_id'],
                    tx_id=algo_tx_ids)

        print(tx_obj)
        g.session.add(tx_obj)
        g.session.commit()
        

    except Exception as e:
        import traceback
        print(traceback.format_exc())
        print(e)


def log_message(d):
    # Takes input dictionary d and writes it to the Log table
    payload = json.dumps(d['payload'])

    try:
        # Insert new log
        log_obj = Log(message=json.dumps(d['payload']))

        g.session.add(log_obj)
        g.session.commit()

    except Exception as e:
        import traceback
        print(traceback.format_exc())
        print(e)


def get_algo_keys():
    # TODO: Generate or read (using the mnemonic secret)
    # the algorand public/private keys

    # 이게 문맥상 맞나? exchange server의 SK, PK와 같은데....
    try:
        sender_sk = mnemonic.to_private_key(algo_mnemonic)
        sender_pk = mnemonic.to_public_key(algo_mnemonic)
    except Exception as e:
        print("Error: couldn't read sender address")
        print(e)
        return "", ""

    return sender_sk, sender_pk


def get_eth_keys(filename="eth_mnemonic.txt"):
    w3 = Web3()

    # TODO: Generate or read (using the mnemonic secret) 

    w3.eth.account.enable_unaudited_hdwallet_features()
    acct = w3.eth.account.from_mnemonic(eth_mnemonic)
    eth_pk = acct._address
    eth_sk = acct._private_key.hex()  # private key is of type HexBytes which is not JSON serializable, adding .hex() converts it to a string

    return eth_sk, eth_pk


def isPaidOrder(content):
    try:

        if content['payload']['platform'] == 'Ethereum':
            w3 = connect_to_eth()
            tx = w3.eth.get_transaction(content['payload']['tx_id'])

            if ((tx['from'] == content['payload']['sender_pk']) and
                    (tx['to'] == gen_keys.eth()) and
                    (tx['value'] == content['payload']['sell_amount'])):
                return True
            else:
                print("search eth tx_id result not found")
                return False

        if content['payload']['platform'] == 'Algorand':

            myIndexer = connect_to_algo(connection_type='indexer')
            result = myIndexer.search_transactions(txid=content['payload']['tx_id'])

            if len(result['transactions']) == 0:
                print("search algo tx_id result not found: ", content['payload']['tx_id'])
                return False

            if ((result['transactions'][0]['payment-transaction']['receiver'] == gen_keys.algo()) and
                    result['transactions'][0]['payment-transaction']['amount']):
                return True
            else:
                print("info of algo tx_id result not matched: ", content['payload']['tx_id'])
                return False

        return False  # neither platform is 'Ethereum' nor 'Algorand'

    except Exception as e:
        import traceback
        print(traceback.format_exc())
        print(e)


def fill_order(order, txes=[]):
    # TODO: 
    # Match orders (same as Exchange Server II)
    # Validate the order has a payment to back it (make sure the counterparty also made a payment)
    # Make sure that you end up executing all resulting transactions!

    pass




""" End of Helper methods"""


@app.route('/address', methods=['POST'])
def address():
    if request.method == "POST":
        content = request.get_json(silent=True)
        if 'platform' not in content.keys():
            print(f"Error: no platform provided")
            return jsonify("Error: no platform provided")
        if not content['platform'] in ["Ethereum", "Algorand"]:
            print(f"Error: {content['platform']} is an invalid platform")
            return jsonify(f"Error: invalid platform provided: {content['platform']}")

        if content['platform'] == "Ethereum":
            return jsonify(gen_keys.eth())

        if content['platform'] == "Algorand":
            return jsonify(gen_keys.algo())


@app.route('/trade', methods=['POST'])
def trade():
    print("In trade", file=sys.stderr)
    connect_to_blockchains()
    # get_keys()
    if request.method == "POST":
        content = request.get_json(silent=True)
        columns = ["buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform", "tx_id", "receiver_pk"]
        fields = ["sig", "payload"]
        error = False
        for field in fields:
            if not field in content.keys():
                print(f"{field} not received by Trade")
                error = True
        if error:
            print(json.dumps(content))
            return jsonify(False)

        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print(f"{column} not received by Trade")
                error = True
        if error:
            print(json.dumps(content))
            return jsonify(False)

        # 1. Check the signature
        if verify(content) is True:
            # 2. Add the order to the table
            insert_order(content)
        else:
            log_message(content)
            return jsonify(False)

        # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)
        if isPaidOrder(content) is True:
            print("well paid order checked!")
            # 3b. Fill the order (as in Exchange Server II) if the order is valid
            process_order(content)

            results = g.session.execute(
                "select distinct id, sender_pk, receiver_pk, buy_currency, sell_currency, buy_amount, sell_amount, counterparty_id, creator_id, filled, tx_id " +
                "from orders where filled is not null")

            for row in results:
                print(row)
                '''
                m_order_id = row['id']
                m_sender_pk = row['sender_pk']
                m_receiver_pk = row['receiver_pk']
                m_buy_currency = row['buy_currency']
                m_sell_currency = row['sell_currency']
                m_buy_amount = row['buy_amount']
                m_sell_amount = row['sell_amount']
                m_tx_id = row['tx_id']
                # print(" matched at ID: ", m_order_id)
                '''

        # 4. Execute the transactions
        # If all goes well, return jsonify(True). else return jsonify(False)

        return jsonify(True)


@app.route('/order_book')
def order_book():
    fields = ["buy_currency", "sell_currency", "buy_amount", "sell_amount", "signature", "tx_id", "receiver_pk",
              "sender_pk"]

    try:
        results = g.session.execute(
            "select sender_pk, receiver_pk, buy_currency, sell_currency, buy_amount, sell_amount, signature, tx_id " +
            "from orders ")

        result_list = list()
        for row in results:
            item = dict()
            item['sender_pk'] = row['sender_pk']
            item['receiver_pk'] = row['receiver_pk']
            item['buy_currency'] = row['buy_currency']
            item['sell_currency'] = row['sell_currency']
            item['buy_amount'] = row['buy_amount']
            item['sell_amount'] = row['sell_amount']
            item['signature'] = row['signature']
            item['tx_id'] = row['tx_id']

            result_list.append(item)

        result = dict()
        result['data'] = result_list

        return jsonify(result)

    except Exception as e:
        import traceback
        print(traceback.format_exc())
        print(e)


if __name__ == '__main__':
    app.run(port='5002')
