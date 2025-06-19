"""

instructions: 

$ uv venv
# activate your virtual environment based on your OS
$ source .venv/bin/activate  # On Windows use `venv\Scripts\activate`
$ uv pip install -r requirements.txt

# additionally, update information in your .env file

$ uv run CreateOrderWithFeeAndWhitelist_v4.py
"""


import secrets
from eth_account.messages import encode_typed_data
from web3 import Web3
import requests
import time
import json
from typing import List, Union
import os
from dotenv import load_dotenv
load_dotenv()

nullAddress = Web3.to_checksum_address("0x0000000000000000000000000000000000000000")
chain_id = 1  # Mainnet, change as needed
INCH_API_KEY = os.getenv("INCH_API_KEY")
wallet_key = os.getenv("WALLET_PRIVATE_KEY")  # Your wallet private key from .env
w3 = Web3(Web3.HTTPProvider(os.getenv("RPC_URL", "https://eth.llamarpc.com")))
wallet_address = os.getenv("WALLET_ADDRESS")  # Your wallet address from .env

if not wallet_address:
    raise ValueError("WALLET_ADDRESS not found in environment variables")

if not INCH_API_KEY:
    raise ValueError("INCH_API_KEY not found in environment variables")
if not wallet_key:
    wallet_key = "965e092fdfc08940d2bd05c7b5c7e1c51e283e92c7f52bbf1408973ae9a9acb7" # well known key for testing
    raise ValueError("WALLET_PRIVATE_KEY not found in environment variables")

last_api_call_time = 0


def getOffsets(interaction_list: List[Union[int, bytes]]) -> int:
    interactions = interaction_list[:8] if len(interaction_list) > 8 else interaction_list[:]
    if len(interactions) < 8:
        interactions = interactions + [0] * (8 - len(interactions))
        
    length_map = []
    for interaction in interactions:
        if isinstance(interaction, bytes):
            length_map.append(len(interaction) if len(interaction) > 0 else 0)
        elif isinstance(interaction, int):
            length_map.append((interaction.bit_length() + 7) // 8 if interaction != 0 else 0)
        else:
            raise TypeError("interaction_list elements must be int or bytes")

    cumulative = 0
    offsets = 0
    for index, length in enumerate(length_map):
        cumulative += length
        offsets |= cumulative << (32 * index)
        

    return offsets

# expected, an array of ints for the following interactions, see https://github.com/1inch/limit-order-protocol/blob/ecb2ae03148e8a3c80c25e75a0e1226256b71ac7/contracts/libraries/ExtensionLib.sol
# MakerAssetSuffix, TakerAssetSuffix, MakingAmountData, TakingAmountData, Predicate, MakerPermit, PreInteractionData, PostInteractionData, CustomData
def build_interactions(interaction_list):
    """Build concatenated interactions string (without customData for main interactions)"""
    interactions_concat = ""
    
    # Process first 8 interactions
    main_interactions = interaction_list[:8] if len(interaction_list) >= 8 else interaction_list
    
    for interaction in main_interactions:
        if interaction == 0 or interaction == b'':
            continue
        if isinstance(interaction, int):
            hex_str = hex(interaction)[2:]
            interactions_concat += hex_str
        elif isinstance(interaction, bytes):
            hex_str = interaction.hex()
            interactions_concat += hex_str
        else:
            raise ValueError("Interaction must be an integer or bytes")
    
    # Add customData if present (9th element)
    if len(interaction_list) > 8 and interaction_list[8] != 0:
        custom_data = interaction_list[8]
        if isinstance(custom_data, int):
            interactions_concat += hex(custom_data)[2:]
        elif isinstance(custom_data, bytes):
            interactions_concat += custom_data.hex()
    
    return interactions_concat

def build_extension(interaction_list: List[Union[int, bytes]]) -> str:
    """Build extension following the SDK's exact logic"""
    if len(interaction_list) < 9:
        interaction_list = interaction_list + [0] * (9 - len(interaction_list))
    
    # Build concatenated interactions
    interactions_concat = build_interactions(interaction_list)
    
    # If no interactions, return empty extension
    if len(interactions_concat) == 0:
        return '0x'
    
    # Calculate offsets for first 8 interactions only
    offsets = getOffsets(interaction_list[:8])
    
    # Build extension: 64-char hex offsets + interactions
    extension = '0x'
    extension += format(offsets, '064x')  # 32 bytes = 64 hex chars
    extension += interactions_concat
    
    return extension

# this function will fix the order_data to be a typed object instead of only strings
def fix_data_types(data, types):
    """
    Order data values are all strings as this is what the API expects. This function fixes their types for
    encoding purposes.
    """
    fixed_data = {}
    for dictionary in types:
        if "bytes" in dictionary["type"]:
            fixed_data[dictionary["name"]] = (Web3.to_bytes(hexstr=data[dictionary["name"]]))
        elif "int" in dictionary["type"]:
            fixed_data[dictionary["name"]] = lambda x: int(x, 16) if isinstance(x, str) and all(c in '0123456789abcdefABCDEF' for c in x.strip('0x')) else (0 if x == '0x' else int(x))
        else: # address
            fixed_data[dictionary["name"]] = data[dictionary["name"]]
    return fixed_data

# Constants, found at https://github.com/1inch/limit-order-protocol/blob/ecb2ae03148e8a3c80c25e75a0e1226256b71ac7/contracts/libraries/MakerTraitsLib.sol#L7-L28
_NO_PARTIAL_FILLS_FLAG = 255
_ALLOW_MULTIPLE_FILLS_FLAG = 254
_NEED_PREINTERACTION_FLAG = 252
_NEED_POSTINTERACTION_FLAG = 251
_NEED_EPOCH_CHECK_FLAG = 250
_HAS_EXTENSION_FLAG = 249
_USE_PERMIT2_FLAG = 248
_UNWRAP_WETH_FLAG = 247

# see https://github.com/1inch/limit-order-protocol/blob/ecb2ae03148e8a3c80c25e75a0e1226256b71ac7/contracts/libraries/MakerTraitsLib.sol
def build_makerTraits(allowedSender, shouldCheckEpoch, usePermit2, unwrapWeth, hasExtension, hasPreInteraction, hasPostInteraction, expiry, nonce, series):
    if expiry >= 2**40:
        raise ValueError("expiry must be less than 40 bits")
    if nonce >= 2**40:
        raise ValueError("nonce must be less than 40 bits")
    if series >= 2**40:
        raise ValueError("series must be less than 40 bits")
    tempPredicate = (series << 160 | nonce << 120 | expiry << 80 | int(allowedSender, 16) & ((1 << 80) - 1))
    if unwrapWeth: # then set the _UNWRAP_WETH_FLAG bit to 1
        tempPredicate = tempPredicate | (1 << _UNWRAP_WETH_FLAG)
    # MUST BE SET for 1inch's API, therefore conditional is commented out
    # if allowMultipleFills: 
    tempPredicate = tempPredicate | (1 << _ALLOW_MULTIPLE_FILLS_FLAG)
    # MUST BE NOT SET for 1inch's API, therefore conditional is commented out
    #if allowPartialFill:
    #    tempPredicate = tempPredicate | (1 << _NO_PARTIAL_FILLS_FLAG)
    if shouldCheckEpoch:
        tempPredicate = tempPredicate | (1 << _NEED_EPOCH_CHECK_FLAG)
    if usePermit2:
        tempPredicate = tempPredicate | (1 << _USE_PERMIT2_FLAG)
    if hasExtension:
        tempPredicate = tempPredicate | (1 << _HAS_EXTENSION_FLAG)
    if hasPreInteraction:
        tempPredicate = tempPredicate | (1 << _NEED_PREINTERACTION_FLAG)
    if hasPostInteraction:
        tempPredicate = tempPredicate | (1 << _NEED_POSTINTERACTION_FLAG)
    return tempPredicate

def getSalt(extension, source=None, use_random=False):
    salt = 0
    tracking_code_mask = (2**32 - 1) << 224
    salt |= (int.from_bytes(Web3.keccak(text=source or 'sdk'), 'big') & tracking_code_mask)
    
    # Generate middle 64 bits (bits 160-223)
    middle_bits = secrets.randbits(64) if use_random else int(time.time()) & ((1 << 64) - 1)
    
    if extension == '0x':
        # If there is no extension, salt can be anything for the lower bits
        salt |= middle_bits << 160
    else:
        # If there is an extension, the salt's lower 160 bits must be the lower 160 bits of the keccak256 hash of the extension
        salt |= (int.from_bytes(Web3.keccak(hexstr=extension), 'big') & ((1 << 160) - 1)) 
        # Add middle bits (either timestamp or random)
        salt |= middle_bits << 160
    
    return salt



# note: The returned value is an integer, this means if the length of the whitelist is less than 16
# then there will an odd number of hex digits if converted to a hex string and it must be padded with a leading 0
# this also means any binary data must also include the leading 0 bits!
def encode_whitelist(whitelist):
    if len(whitelist) == 0:
        return 0
    # length must be 1 byte only
    elif len(whitelist) > 255:
        raise ValueError("whitelist can have at most 255 addresses")
    encoded = len(whitelist) 
    for address in whitelist:
        encoded = (encoded << 80) | (int(address, 16) & ((1 << 80) - 1))
    return encoded 

# Packs the fee parameter into a 48-bit integer
"""
example fee parameter:
integrator_fee = {
                    "fee": 1, # 0.0001 (1 bps)
                    "share": 500 # 5% of the fee goes to the integrator
                 }
resolver_fee =   {
                    "fee": 50, # 0.0050 (50 bps)
                    "whitelistDiscount": 50 # 50% discount for whitelisted addresses
                 }
"""
def pack_fee_parameter(integrator_fee=None, resolver_fee=None):
    integrator_fee_value = integrator_fee["fee"] * 10 if integrator_fee else 0  # 2 bytes
    integrator_share = integrator_fee["share"] // 100 if integrator_fee else 0  # 1 byte
    resolver_fee_value = resolver_fee["fee"] * 10 if resolver_fee else 0  # 2 bytes
    resolver_discount = 100 - (resolver_fee["whitelistDiscount"]) if resolver_fee else 0 # 1 byte
    
    # range check to make sure the values are within the expected limits
    if not (0 <= integrator_fee_value < 0xffff): raise ValueError("Integrator fee value must be between 0 and 65535")
    if not (0 <= integrator_share < 0xff): raise ValueError("Integrator share must be between 0 and 255")
    if not (0 <= resolver_fee_value < 0xffff): raise ValueError("Resolver fee value must be between 0 and 65535")
    if not (0 <= resolver_discount < 0xff): raise ValueError("Resolver discount must be between 0 and 255")

    # Pack as integer: 48 bits total (6 bytes)
    # Layout: [2 bytes integrator_fee][1 byte integrator_share][2 bytes resolver_fee][1 byte resolver_discount]
    pack_fee_parameter_value = (
        (integrator_fee_value << 32) |  # bits 47-32 (16 bits)
        (integrator_share << 24) |      # bits 31-24 (8 bits)
        (resolver_fee_value << 8) |     # bits 23-8 (16 bits)
        resolver_discount               # bits 7-0 (8 bits)
    ) 
    return pack_fee_parameter_value

# the * means that the following parameters must be named parameters
# returns a tuple of (fee_and_whitelist, length_in_bits)
def concat_fee_and_whitelist(whitelist, *, integrator_fee=None, resolver_fee=None):
    # first 48 bits are the fee_parameter, everything after is the whitelist length and addresses
    fee_parameter = pack_fee_parameter(integrator_fee=integrator_fee, resolver_fee=resolver_fee)
    whitelist_encoded = encode_whitelist(whitelist)

    whitelist_bit_length = 0 if (len(whitelist) == 0) else (8 + len(whitelist) * 80)
    fee_and_whitelist = (fee_parameter << whitelist_bit_length) | whitelist_encoded
    # the padding is important so we will return the fee_and_whitelist AND the bit_length
    return fee_and_whitelist, (48 + whitelist_bit_length)


"""
highest byte, flags 
    - lowest bit `CUSTOM_RECEIVER_FLAG` - set to 1 if order has custom reciever address
next 20 bytes, integrator fee recipient
next 20 bytes, protocol fee recipient
[20 bytes] - reciever of taking tokens (optional, if not set, maker is used). See CUSTOM_RECEIVER_FLAG
next bytes, fee and whitelist data
[bytes20, bytes] - optional extra interaction
"""
def build_fee_postInteraction_data(custom_reciever=False, custom_reciever_address=nullAddress, integrator_fee=None, resolver_fee=None, whitelist=None, extraInteractionTarget=nullAddress, extraInteractionData=b''):
    if whitelist is None:
        whitelist = []
    # we use ff as a placeholder in the high byte so that was if `inregrator`'s address is nullAddress, we actually apply it
    # we'll flip this if we do not have a custom receiver address
    postInteraction = 0xff
    postInteraction = (postInteraction << 160) | (int(integrator_fee["integrator"], 16) & ((1 << 160) - 1))
    postInteraction = (postInteraction << 160) | (int(resolver_fee["receiver"], 16) & ((1 << 160) - 1))
    if custom_reciever and custom_reciever_address != nullAddress:
        postInteraction = (postInteraction << 160) | (int(custom_reciever_address, 16) & ((1 << 160) - 1))
    (fee_and_whitelist, fee_and_whitelist_length) = concat_fee_and_whitelist(whitelist, integrator_fee=integrator_fee, resolver_fee=resolver_fee)
    postInteraction = (postInteraction << fee_and_whitelist_length) | fee_and_whitelist
    if extraInteractionTarget != nullAddress and extraInteractionData != b'':
        postInteraction = (postInteraction << 160) | (int(extraInteractionTarget, 16) & ((1 << 160) - 1))
        # Use len(extraInteractionData) * 8 to preserve all bits including leading zeros
        postInteraction = (postInteraction << (len(extraInteractionData) * 8)) | int.from_bytes(extraInteractionData, 'big')
    postInteraction_bytes = postInteraction.to_bytes((postInteraction.bit_length() + 7) // 8, 'big')
    # if there is no custom reciever, we need to flip the first byte with 0xff
    # if there is a custom reciever, we need to flip it with 0xfe to leave 0x01
    if custom_reciever:
        postInteraction_bytes = bytes([0x01]) + postInteraction_bytes[1:]
    else:
        postInteraction_bytes = bytes([0x00]) + postInteraction_bytes[1:]
    return postInteraction_bytes


# note, extraInteraction will be called after `FeeTaker.postInteraction` which can be any custom data sent to the extension_target
def build_order_extension(extension_target, integrator_fee, resolver_fee, whitelist, makerPermit=None, customReceiver=None, extraInteraction=b'', customData=None):
    fee_post_interaction = build_fee_postInteraction_data(
        custom_reciever=customReceiver is not None,
        custom_reciever_address=customReceiver,
        integrator_fee=integrator_fee,
        resolver_fee=resolver_fee,
        whitelist=whitelist,
        extraInteractionTarget=extension_target if extraInteraction != b'' else nullAddress,  # if extraInteractionData is empty, we don't need to set the target address
        extraInteractionData=extraInteraction
    )
    (making_taking_amount_data, making_taking_amount_data_length) = concat_fee_and_whitelist(whitelist, integrator_fee=integrator_fee, resolver_fee=resolver_fee)
    # the amount_data and post_interaction must be prepended with the extension target address
    making_taking_amount_data = int(extension_target, 16).to_bytes(20, 'big') + making_taking_amount_data.to_bytes((making_taking_amount_data_length) // 8, 'big')
    fee_post_interaction = int(extension_target, 16).to_bytes(20, 'big') + fee_post_interaction
    # MakerAssetSuffix, TakerAssetSuffix, MakingAmountData, TakingAmountData, Predicate, MakerPermit, PreInteractionData, PostInteractionData, CustomData
    interactions = [0, 0, making_taking_amount_data, making_taking_amount_data, 0, makerPermit or 0, 0, fee_post_interaction, customData or 0]
    extension = build_extension(interactions)
    return extension


# Example usage, assuming you have neccessary allowance to the aggregation router v6
AGGREGATION_ROUTER_V6 = Web3.to_checksum_address("0x111111125421ca6dc452d289314280a0f8842a65")
makerAddress = Web3.to_checksum_address(wallet_address)
makerAsset = Web3.to_checksum_address("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48") # the address of the token you want to sell
takerAsset = Web3.to_checksum_address("0xc5102fe9359fd9a28f877a67e36b0f050d81a3cc") # the address of the token you want to buy
makingAmount = 10000 # the amount of the token you want to sell in wei
takingAmount = 1000000000000000000000 # the amount of the token you want to buy in wei

expiration = int(time.time()) + 60 * 5  # 5 minutes from now

# The 1inch limit order API expects you to fetch fee info, if you're on the free tier you may need to add a 1 second delay due to rate limiting
fee_info_endpoint = f"https://api.1inch.dev/orderbook/v4.0/{chain_id}/fee-info?makerAsset={makerAsset}&takerAsset={takerAsset}&makerAmount={makingAmount}&takerAmount={takingAmount}"
# fetch with requests.get and the header Content-Type application/json and Authorization Bearer {INCH_API_KEY}

fee_info = requests.get(
    fee_info_endpoint,
    headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {INCH_API_KEY}"
    }
)
# after the API call we'll store the time for later use
last_api_call_time = time.time()


fee_info = fee_info.json()

print(fee_info)
# grab the Object.values(fee_info["whitelist"])
whitelist_array = list(fee_info["whitelist"].values())

# Integrator gets `share` of `fee` to `integrator` and the rest goes to `protocol`
Integrator_Fee = {"integrator": nullAddress, "protocol": nullAddress, "fee": 0, "share": 0}
# Fee paid by resolver to `receiver`
# Resolver_Fee = {"receiver": fee_info["protocolFeeReceiver"], "fee": fee_info["feeBps"], "whitelistDiscount": fee_info["whitelistDiscountPercent"]}
Resolver_Fee = {"receiver": fee_info["protocolFeeReceiver"], "fee": 50, "whitelistDiscount": 50}

nonceOrEpoch = 0                # you should dynamically fetch the nonce from the blockchain, this is a placeholder
series = 0                      # the series of nonces or epochs you want to use
has_extension = True            # whether the order has an extension or not   
should_unwrap_wETH = False      # use when the maker wants the output token in terms of ETH. 
# the following is an example permit for USDC, you'll need to generate this on your own if you want to use permits
makerPermitData = None # bytes.fromhex('a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000002c9b2DBdbA8A9c969Ac24153f5C1c23CB0e63914000000000000000000000000111111125421ca6dc452d289314280a0f8842a6500000000000000000000000000000000000000000000000000b1a2bc2ec500000000000000000000000000000000000000000000000000000000000068534122000000000000000000000000000000000000000000000000000000000000001cc9c44c49a06b6144b329239a6feaf949773e852f3756abc3f0f01717434ad1a10f6d90f2d563aa3bc6d6aa46084766a5b36367d417c254580b8192f065d69fdd')

makerTraits = build_makerTraits(nullAddress, False, False, False, has_extension, False, False if makerPermitData == None else True, expiry=expiration, nonce=nonceOrEpoch, series=series)

extension = build_order_extension(
    extension_target=fee_info["extensionAddress"],
    integrator_fee=Integrator_Fee,
    resolver_fee=Resolver_Fee,
    whitelist=whitelist_array,
    makerPermit=makerPermitData,           # if you have a permit, you can pass it here
    customReceiver=None,        # Make sure to set this to your address
    extraInteraction=b'',       # if you have an extra interaction, you can pass it here, target will be the same extension_target
    customData=None             # if you have custom data, you can pass it here
)

salt = getSalt(extension, source=wallet_address, use_random=True)

order_data = {
    "salt": (salt),
    "makerAsset": makerAsset,
    "takerAsset": takerAsset,
    "maker": makerAddress,
    "receiver": fee_info["extensionAddress"],  # the receiver must be the extension address
    "makingAmount": makingAmount,
    "takingAmount": takingAmount,
    "makerTraits": makerTraits,
    "extension": extension,
}

order_types = order_types = [
    {"name": "salt", "type": "uint256"},
    {"name": "maker", "type": "address"},
    {"name": "receiver", "type": "address"},
    {"name": "makerAsset", "type": "address"},
    {"name": "takerAsset", "type": "address"},
    {"name": "makingAmount", "type": "uint256"},
    {"name": "takingAmount", "type": "uint256"},
    {"name": "makerTraits", "type": "uint256"},
]

domain_data = {
    "name": "1inch Aggregation Router",
    "version":  "6",
    "chainId": chain_id, # 1 for ethereum network. 
    "verifyingContract": AGGREGATION_ROUTER_V6,
}

fixed_data = fix_data_types(order_data, order_types)

eip712_data = {
    "primaryType": "Order",
    "types": {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"},
        ],
        "Order": order_types
    },
    "domain": domain_data,
    "message": fixed_data
}

message_types = {
    "Order": order_types
}

encoded_message = encode_typed_data(domain_data, message_types, order_data ) #new method, but doesn't work, tests fail
signed_message = w3.eth.account.sign_message(encoded_message, wallet_key)

# make sure everything in the order_data is a string for the API
for key in order_data:
    order_data[key] = str(order_data[key])

limit_order = {
    "orderHash": signed_message.messageHash.hex(),
    "signature": signed_message.signature.hex(),
    "data": order_data,
}

# print the order data
print("Order Data:")
for key, value in limit_order["data"].items():
    print(f"{key}: {value}")
# print the order hash and signature
print(f"Order Hash: {limit_order['orderHash']}")
print(f"Signature: {limit_order['signature']}")



# send the order to the 1inch API
url = f"https://api.1inch.dev/orderbook/v4.0/{chain_id}"
headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {INCH_API_KEY}"
}

stringified_order = json.dumps(limit_order)

try:
    response = requests.post(url, headers=headers, data=stringified_order)
    response.raise_for_status()  # Raise an error for bad status codes
    print("Order successfully submitted to 1inch order book.")
    print("Response:", response.json())
except requests.exceptions.RequestException as e:
    print("Error submitting order to 1inch order book:", e)
    if e.response is not None:
        print("Response JSON:", e.response.json())
