from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from sqlalchemy.sql import text
from datetime import datetime
import math
import sys
import traceback

from algosdk.v2client import algod
from algosdk.v2client import indexer
from algosdk import mnemonic
from algosdk.future import transaction
from algosdk import account

from web3 import Web3
from web3.middleware import geth_poa_middleware
from web3.exceptions import TransactionNotFound
import json
from hexbytes import HexBytes

# TODO: make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth

from models import Base, Order, TX
engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

algo_mnemonic = "avocado coil energy gallery health brief crime peanut coyote brother coach bullet december limit oblige answer town bar neck provide ivory cousin custom abstract demise"
eth_mnemonic = "midnight game play tail blossom cereal jacket cruel okay slim verify harbor"
	
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
                result = True
            else:
                result = False

            return result           # bool value

        if content['payload']['platform'] == 'Algorand':
            algo_sig = content['sig']
            algo_pk = content['payload']['sender_pk']
            payload = json.dumps(content['payload'])
            
            result = algosdk.util.verify_bytes(payload.encode('utf-8'), algo_sig, algo_pk)
            return result           # bool value 

    except Exception as e:
        import traceback
        print(traceback.format_exc())
        print(e)

def process_order(content):

    #1. Insert new order
    order_obj = Order(sender_pk=content['payload']['sender_pk'],
                      receiver_pk=content['payload']['receiver_pk'], 
                      buy_currency=content['payload']['buy_currency'], 
                      sell_currency=content['payload']['sell_currency'], 
                      buy_amount=content['payload']['buy_amount'], 
                      sell_amount=content['payload']['sell_amount'], 
                      exchange_rate=(content['payload']['buy_amount']/content['payload']['sell_amount']),
                      signature=content['sig'],
		      tx_id=content['payload']['tx_id']
		     )

    g.session.add(order_obj)
    g.session.commit()

    # check up if it works well and get the order id
    results = g.session.execute("select distinct id from orders where " + 
                            " sender_pk = '" + str(order_obj.sender_pk) + "'" +
                            " and receiver_pk = '" + str(order_obj.receiver_pk) + "'")

    order_id = results.first()['id']
    # print(" new order: ", order_id, order['buy_currency'], order['sell_currency'], order['buy_amount'], order['sell_amount'])

    # Point to modify!!!
    
    #2. Matching order
    results = g.session.execute("select count(id) " + 
                            " from orders where orders.filled is null " + 
                            " and orders.sell_currency = '" + order_obj.buy_currency + "'" +
                            " and orders.buy_currency = '" + order_obj.sell_currency + "'" +
                            " and exchange_rate <= " + str(order_obj.sell_amount/order_obj.buy_amount))

    if results.first()[0] == 0:
        # print("::::no matching order::::")
        return

    results = g.session.execute("select distinct id, sender_pk, receiver_pk, buy_currency, sell_currency, buy_amount, sell_amount " + 
                            "from orders where orders.filled is null " + 
                            " and orders.sell_currency = '" + order_obj.buy_currency + "'" +
                            " and orders.buy_currency = '" + order_obj.sell_currency + "'" +
                            " and exchange_rate <= " + str(order_obj.sell_amount/order_obj.buy_amount))

    for row in results:
        m_order_id = row['id']
        m_sender_pk = row['sender_pk']
        m_receiver_pk = row['receiver_pk'] 
        m_buy_currency = row['buy_currency'] 
        m_sell_currency = row['sell_currency'] 
        m_buy_amount = row['buy_amount']
        m_sell_amount = row['sell_amount']
        # print(" matched at ID: ", m_order_id)
        break

    # print(" matching order: ", m_order_id, m_buy_currency, m_sell_currency, m_buy_amount, m_sell_amount)
    # print(" order['sell_amount']/order['buy_amount']: ", order['sell_amount']/order['buy_amount'], ">=", "(buy_amount/sell_amount)", (m_buy_amount/m_sell_amount))

    # update both the matching orders 
    stmt = text("UPDATE orders SET counterparty_id=:id, filled=:curr_date WHERE id=:the_id")
    stmt = stmt.bindparams(the_id=order_id, id=m_order_id, curr_date=datetime.now())
    g.session.execute(stmt)  # where session has already been defined

    stmt = text("UPDATE orders SET counterparty_id=:id, filled=:curr_date WHERE id=:the_id")
    stmt = stmt.bindparams(the_id=m_order_id, id=order_id, curr_date=datetime.now())
    g.session.execute(stmt)  # where session has already been defined
  
    #3. Create derived order
    if order_obj.buy_amount > m_sell_amount:
        d_order_obj = Order(sender_pk=order_obj.sender_pk,
                            receiver_pk=order_obj.receiver_pk, 
                            buy_currency=order_obj.buy_currency, 
                            sell_currency=order_obj.sell_currency, 
                            buy_amount=order_obj.buy_amount - m_sell_amount, 
                            sell_amount=order_obj.sell_amount - ((order_obj.sell_amount/order_obj.buy_amount) * m_sell_amount),
                            exchange_rate = (order_obj.buy_amount - m_sell_amount)/(order_obj.sell_amount - (order_obj.sell_amount/order_obj.buy_amount * m_sell_amount)),
                            creator_id=order_id)
        g.session.add(d_order_obj)
        g.session.commit()

    elif order_obj.buy_amount < m_sell_amount:
        d_order_obj = Order(  sender_pk=m_sender_pk,
                            receiver_pk=m_receiver_pk, 
                            buy_currency=m_buy_currency, 
                            sell_currency=m_sell_currency, 
                            buy_amount= m_buy_amount - (m_buy_amount/m_sell_amount) * order_obj.buy_amount, 
                            sell_amount= m_sell_amount - order_obj.buy_amount,
                            exchange_rate = (m_buy_amount - (m_buy_amount/m_sell_amount) * order_obj.buy_amount)/(m_sell_amount - order_obj.buy_amount),
                            creator_id=m_order_id)
        g.session.add(d_order_obj)
        g.session.commit()

        
def log_message(d):

    # Takes input dictionary d and writes it to the Log table
    payload = json.dumps(d['payload'])

    try:
        # Insert new log
        log_obj = Log(message = json.dumps(d['payload']))

        g.session.add(log_obj)
        g.session.commit()

    except Exception as e:
        import traceback
        print(traceback.format_exc())
        print(e)


def IsPaidOrder(contect):
	
    try:

        if content['payload']['platform'] == 'Ethereum':
		w3 = connect_to_eth()
		tx = web3.eth.get_transaction(content['payload']['tx_id'])		

		if(tx['from'] == content['payload']['sender_pk'] && 
		   tx['to'] == content['payload']['receiver_pk'] && 
		   tx['value'] == content['payload']['sell_amount']):
			return true
		else
			return false
		
        if content['payload']['platform'] == 'Algorand':
	''' to be updated		
		algo_sig = content['sig']
            	algo_pk = content['payload']['sender_pk']
            	payload = json.dumps(content['payload'])
            
            	result = algosdk.util.verify_bytes(payload.encode('utf-8'), algo_sig, algo_pk)
	'''
		return true           # bool value 

	return false			# neither platform is 'Ethereum' nor 'Algorand'

    except Exception as e:
        import traceback
        print(traceback.format_exc())
        print(e)

	
def get_algo_keys():
    
	# TODO: Generate or read (using the mnemonic secret) 
	# the algorand public/private keys

	# 이게 문맥상 맞나? exchange server의 SK, PK
	try:
		sender_sk = mnemonic.to_private_key(algo_mnemonic)
		sender_pk = mnemonic.to_public_key(algo_mnemonic)
	except Exception as e:
		print( "Error: couldn't read sender address" )
		print( e )
		return "", ""

	return sender_sk, sender_pk


	return algo_sk, algo_pk


def get_eth_keys(filename = "eth_mnemonic.txt"):
	# TODO: Generate or read (using the mnemonic secret) 
	# the ethereum public/private keys

	w3 = Web3()

	w3.eth.account.enable_unaudited_hdwallet_features()
	acct = w3.eth.account.from_mnemonic(eth_mnemonic)
	eth_pk = acct._address
	eth_sk = acct._private_key.hex() 	#private key is of type HexBytes which is not JSON serializable, adding .hex() converts it to a string

	return eth_sk, eth_pk
  
def fill_order(order, txes=[]):
    # TODO: 
    # Match orders (same as Exchange Server II)
    # Validate the order has a payment to back it (make sure the counterparty also made a payment)
    # Make sure that you end up executing all resulting transactions!
    
    pass
  
def execute_txes(txes):
    if txes is None:
        return True
    if len(txes) == 0:
        return True
    print( f"Trying to execute {len(txes)} transactions" )
    print( f"IDs = {[tx['order_id'] for tx in txes]}" )
    eth_sk, eth_pk = get_eth_keys()
    algo_sk, algo_pk = get_algo_keys()
    
    if not all( tx['platform'] in ["Algorand","Ethereum"] for tx in txes ):
        print( "Error: execute_txes got an invalid platform!" )
        print( tx['platform'] for tx in txes )

    algo_txes = [tx for tx in txes if tx['platform'] == "Algorand" ]
    eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum" ]

    # TODO: 
    #       1. Send tokens on the Algorand and eth testnets, appropriately
    #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
    #       2. Add all transactions to the TX table

    pass

""" End of Helper methods"""
  
@app.route('/address', methods=['POST'])
def address():
    if request.method == "POST":
        content = request.get_json(silent=True)
        if 'platform' not in content.keys():
            print( f"Error: no platform provided" )
            return jsonify( "Error: no platform provided" )
        if not content['platform'] in ["Ethereum", "Algorand"]:
            print( f"Error: {content['platform']} is an invalid platform" )
            return jsonify( f"Error: invalid platform provided: {content['platform']}"  )
        
        if content['platform'] == "Ethereum":
		try:

			w3 = Web3()
			w3.eth.account.enable_unaudited_hdwallet_features()
			acct = w3.eth.account.from_mnemonic(eth_mnemonic)
			eth_pk = acct._address

			return jsonify(eth_pk)

		except Exception as e:
			print("Couldn't get Ethereum server pk: ", eth_pk)
			print(e)
                
        if content['platform'] == "Algorand":
            #Your code here
		try:

			algo_pk = mnemonic.to_public_key(algo_mnemonic)

			return jsonify(algo_pk)

		except Exception as e:
			print("Couldn't get Ethereum server pk: ", eth_pk)
			print(e)

@app.route('/trade', methods=['POST'])
def trade():
    print( "In trade", file=sys.stderr )
    connect_to_blockchains()
    get_keys()
    if request.method == "POST":
        content = request.get_json(silent=True)
        columns = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform", "tx_id", "receiver_pk"]
        fields = [ "sig", "payload" ]
        error = False
        for field in fields:
            if not field in content.keys():
                print( f"{field} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print( f"{column} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
	# 1. Check the signature
        if verify(content) is True: 
	        # 2. Add the order to the table
		process_order(content)
        else:
		log_message(content)

        # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)
	if IsPaidOrder(contect) is True:
		# 3b. Fill the order (as in Exchange Server II) if the order is valid
        	pass
	
        # 4. Execute the transactions
        
        # If all goes well, return jsonify(True). else return jsonify(False)
        return jsonify(True)

@app.route('/order_book')
def order_book():
	# fields = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "signature", "tx_id", "receiver_pk", "sender_pk" ]
    
	try:
		results = g.session.execute("select sender_pk, receiver_pk, buy_currency, sell_currency, buy_amount, sell_amount, signature, tx_id " + 
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
