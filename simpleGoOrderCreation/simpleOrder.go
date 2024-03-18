package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// Define the EIP712Domain type
type EIP712Domain struct {
	Name              string         `json:"name"`
	Version           string         `json:"version"`
	ChainId           *big.Int       `json:"chainId"`
	VerifyingContract common.Address `json:"verifyingContract"`
}

// Define the Order type
type Order struct {
	Salt          *big.Int       `json:"salt"`
	MakerAsset    common.Address `json:"makerAsset"`
	TakerAsset    common.Address `json:"takerAsset"`
	Maker         common.Address `json:"maker"`
	Receiver      common.Address `json:"receiver"`
	AllowedSender common.Address `json:"allowedSender"`
	MakingAmount  *big.Int       `json:"makingAmount"`
	TakingAmount  *big.Int       `json:"takingAmount"`
	Offsets       *big.Int       `json:"offsets"`
	Interactions  []byte         `json:"interactions"`
}

func main() {

	// Assuming the `order_data` is provided as in your Python example and converted to Go types
	order_data := map[string]string{
		"salt":          "20595572",
		"makerAsset":    "0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063",
		"takerAsset":    "0x7ceb23fd6bc0add59e62ac25578270cff1b9f619",
		"maker":         "0x2c9b2DBdbA8A9c969Ac24153f5C1c23CB0e63914",
		"receiver":      "0x0000000000000000000000000000000000000000",
		"allowedSender": "0x0000000000000000000000000000000000000000",
		"makingAmount":  "1000000",
		"takingAmount":  "1000000000",
		"offsets":       "4421431254442149611168492388118363282642987198110904030635476664713216",
		"interactions":  "0xbf15fcd8000000000000000000000000a5eb255ef45dfb48b5d133d08833def69871691d000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000242cc2878d006545545f000000000000002c9b2dbdba8a9c969ac24153f5c1c23cb0e6391400000000000000000000000000000000000000000000000000000000",
	}

	chainIdInt := 137                                     // Polygon
	chainId := math.NewHexOrDecimal256(int64(chainIdInt)) // Polygon
	apiKey := "get from https://1inch.dev/"

	/**
	output from javascript we're trying to reproduce:
	{
		"orderHash": "0xeaea16aa7ec23a7e5a7bff4218d64d0cc767f10a5d3295632b19f3a3f9170207",
		"signature": "0x3f06d06ae3f176a3faee82ef839b620b72233d9eb08fdcc6e7fc4c55a3c6a0aa49d96f7ca862e6615f05f0686e480753521bfc9bf65137dcff1e239427e922431c",
		"data": {
			"salt": "25733282",
			"makerAsset": "0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063",
			"takerAsset": "0x7ceb23fd6bc0add59e62ac25578270cff1b9f619",
			"maker": "0x2c9b2DBdbA8A9c969Ac24153f5C1c23CB0e63914",
			"receiver": "0x0000000000000000000000000000000000000000",
			"allowedSender": "0x0000000000000000000000000000000000000000",
			"makingAmount": "1000000",
			"takingAmount": "1000000000",
			"offsets": "4421431254442149611168492388118363282642987198110904030635476664713216",
			"interactions": "0xbf15fcd8000000000000000000000000a5eb255ef45dfb48b5d133d08833def69871691d000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000242cc2878d00654533ce000000000000002c9b2dbdba8a9c969ac24153f5c1c23cb0e6391400000000000000000000000000000000000000000000000000000000"
		}
	}
	*/

	// Set up the domain data
	domainData := apitypes.TypedDataDomain{
		Name:              "1inch Aggregation Router",
		Version:           "5",
		ChainId:           chainId, // Mainnet
		VerifyingContract: "0x1111111254eeb25477b68fb85ed929f73a960582",
	}

	// Convert order_data to Order struct with appropriate types
	salt := new(big.Int)
	salt.SetString(order_data["salt"], 10)

	makingAmount := new(big.Int)
	makingAmount.SetString(order_data["makingAmount"], 10)

	takingAmount := new(big.Int)
	takingAmount.SetString(order_data["takingAmount"], 10)

	offsets := new(big.Int)
	offsets.SetString(order_data["offsets"], 10)

	saltBigInt, success := new(big.Int).SetString(order_data["salt"], 10)
	if !success {
		fmt.Println("error converting salt to big int")
		return
	}
	makingAmountBigInt, success := new(big.Int).SetString(order_data["makingAmount"], 10)
	if !success {
		fmt.Println("error converting makingAmount to big int")
		return
	}
	takingAmountBigInt, success := new(big.Int).SetString(order_data["takingAmount"], 10)
	if !success {
		fmt.Println("error converting takingAmount to big int")
		return
	}
	offsetsBigInt, success := new(big.Int).SetString(order_data["offsets"], 10)
	if !success {
		fmt.Println("error converting offsets to big int")
		return
	}
	orderMessage := apitypes.TypedDataMessage{
		"salt":          saltBigInt,
		"makerAsset":    order_data["makerAsset"],
		"takerAsset":    order_data["takerAsset"],
		"maker":         order_data["maker"],
		"receiver":      order_data["receiver"],
		"allowedSender": order_data["allowedSender"],
		"makingAmount":  makingAmountBigInt,
		"takingAmount":  takingAmountBigInt,
		// offsets is an int and NOT hex so we need to convert it to a big.Int
		"offsets":      offsetsBigInt,
		"interactions": common.FromHex(order_data["interactions"]),
	}

	typedData := apitypes.TypedData{
		Types: map[string][]apitypes.Type{
			"EIP712Domain": {
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"Order": {
				{Name: "salt", Type: "uint256"},
				{Name: "makerAsset", Type: "address"},
				{Name: "takerAsset", Type: "address"},
				{Name: "maker", Type: "address"},
				{Name: "receiver", Type: "address"},
				{Name: "allowedSender", Type: "address"},
				{Name: "makingAmount", Type: "uint256"},
				{Name: "takingAmount", Type: "uint256"},
				{Name: "offsets", Type: "uint256"},
				{Name: "interactions", Type: "bytes"},
			},
		},
		PrimaryType: "Order",
		Domain: apitypes.TypedDataDomain{
			Name:              domainData.Name,
			Version:           domainData.Version,
			ChainId:           domainData.ChainId,
			VerifyingContract: domainData.VerifyingContract,
		},
		Message: orderMessage,
	}

	//print out the typed data
	typedDataHash, _ := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	domainSeparator, _ := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())

	rawData := []byte(fmt.Sprintf("\x19\x01%s%s", string(domainSeparator), string(typedDataHash)))
	challengeHash := crypto.Keccak256Hash(rawData)
	challengeHashHex := challengeHash.Hex()
	fmt.Println("challengeHash:", challengeHashHex)

	privateKey, err := crypto.HexToECDSA("private key without 0x")
	if err != nil {
		fmt.Println("error converting private key to ECDSA:", err)
		return
	}

	// Sign the challenge hash
	signature, err := crypto.Sign(challengeHash.Bytes(), privateKey)
	if err != nil {
		fmt.Println("error signing challenge hash:", err)
		return
	}

	// add 27 to `v` value (last byte) because reasons I don't care to understand
	signature[64] += 27

	// convert signature to hex string
	signatureHex := fmt.Sprintf("0x%x", signature)
	fmt.Println("signature:", signatureHex)

	// Construct the body
	body := map[string]interface{}{
		// for `data` we need to convert salt to an int but the rest need to be strings
		"data":      order_data,
		"signature": signatureHex,
		"orderHash": challengeHashHex,
	}

	// Convert the body to JSON
	jsonBody, err := json.Marshal(body)
	if err != nil {
		fmt.Printf("Error marshaling JSON: %v\n", err)
		return
	}

	// Print the JSON body to be sent
	fmt.Println("JSON Body to be sent:", string(jsonBody)) // fine here

	// Define the URL
	// convert chainId to string
	url := "https://api.1inch.dev/orderbook/v3.0/" + fmt.Sprintf("%d", chainIdInt)

	// Create a new request using http
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		return
	}

	// Read and print the request body
	reqBody, err := ioutil.ReadAll(req.Body)
	if err != nil {
		fmt.Printf("Error reading request body: %v\n", err)
		return
	}
	// Replace the body for future use
	req.Body = ioutil.NopCloser(bytes.NewBuffer(reqBody))

	// Now print the body
	fmt.Println("Request Body:", string(reqBody)) // This should print the actual body content

	// Add the required headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("accept", "application/json, text/plain, */*")

	// Send the request via a client
	// Send the request via a client
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error sending request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	fmt.Println("\n\nresponse Status:", resp)

}
