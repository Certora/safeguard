package dashboard

import (
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
)

/*
 Utility methods for interacting with the Safeguard dashboard. Is use is totally optional.
*/

/*
  Used to control the field names in the invariant status messages. Currently only
  used to control how the ID of the monitor target is formatted.
*/

type FieldNameSelector interface {
	FieldName() string
}

/*
*

	Type used to select "id" as the field name to hold monitor target IDs.
*/
type PlainId string

func (p PlainId) FieldName() string {
	return "id"
}

/*
Returns an condition object suitable for JSON serialization. `name` is the name of the condition,
`status` indicates whether the condition (i.e., invariant) holds. values is a flattened list of
the key/value pairs stored in the condition's "values" dictionary.
The first such value is expected to be a string key under which to
store the second value, the third value is the string key under which to store the fourth value,
and so on.

For example, passing "hello", 3, "world", true will create the following values dictionary:
`{ "hello": 3, "world": true }`

Thus, every other value starting from index must be a string. If there is an element
at an even index that is not a string, `BADKEY!k` is used where `k` is the index in the values array.
Every other value starting from index 1 must be a value that can be encoded into JSON. Currently strings, bools,
ints, uint64, and uint256.Int pointers can be converted. Due to limitations in the JSON format, the hex representation
(as returned by `Hex()`) of the uint256.Int is used. Any other value will be associated with
"BADVALUE!k" where k is the index of the bad values.

If the values array is of odd length, then the last key in the sequence will be associated with `!MISSING`.
*/
func GetConditionResult(name string, status bool, values ...any) map[string]interface{} {
	vDict := make(map[string]interface{})
	var currKey string
	for i, r := range values {
		if i%2 == 0 {
			k, ok := r.(string)
			if !ok {
				currKey = fmt.Sprintf("BADKEY!%d", i)
			} else {
				currKey = k
			}
		} else {
			switch v := r.(type) {
			case int:
				vDict[currKey] = v
			case string:
				vDict[currKey] = v
			case bool:
				vDict[currKey] = v
			case uint64:
				vDict[currKey] = v
			case *uint256.Int:
				vDict[currKey] = v.Hex()
			default:
				vDict[currKey] = fmt.Sprintf("BADVALUE!%d", i)
			}
		}
	}
	if len(values)%2 == 1 {
		vDict[currKey] = "!MISSING"
	}
	return map[string]interface{}{
		"condition": name,
		"status":    status,
		"values":    vDict,
	}
}

/*
A dummy type to make string implement fmt.Stringer.
dummy is the operative word here.
*/
type PlainString string

func (p PlainString) String() string {
	return string(p)
}

/*
A fmt.Stringer that lowercases its argument.
*/
type LowerString string

func (l LowerString) String() string {
	return strings.ToLower(string(l))
}

/*
A wrapper around common.Address that lowercases the hex representation
of the address.
*/
type NormalizedAddress common.Address

func (n NormalizedAddress) String() string {
	return strings.ToLower(common.Address(n).Hex())
}

/*
A generic status message constructor. The ID of the monitor target is selected using IDField, the monitor target `id“
is of type ID. The status is success or failure depending on whether holds is true or false resp.
At least one condition object must be passed in (cond), additional conditions may be passed in with others.

blockNumber is the block number on which the invariant check ran.

The result is a invariant status message object, suitable for JSON serialization and sending to the dashboard app.
*/
func GetDashboardMessageGen[IDField FieldNameSelector, ID fmt.Stringer](blockNumber big.Int, id ID, holds bool, cond map[string]interface{}, others ...map[string]interface{}) map[string]interface{} {
	var impl IDField
	var statusString string
	if holds {
		statusString = "success"
	} else {
		statusString = "failure"
	}
	std := map[string]interface{}{
		"invariantStatus":      statusString,
		"blockNumber":          blockNumber.Uint64(),
		"calculationTimestamp": time.Now().Unix(),
		"conditionsChecked":    append([]map[string]interface{}{cond}, others...),
	}
	std[impl.FieldName()] = id.String()
	return std
}

/*
A simple version of GetDashboardMessage, where monitor target ids are stored under the key "id", and the ID is just a string.
*/
func GetDashboardMessage(blockNumber big.Int, id string, holds bool, cond map[string]interface{}, others ...map[string]interface{}) map[string]interface{} {
	return GetDashboardMessageGen[PlainId](blockNumber, PlainString(id), holds, cond)
}

/*
Generic error message constructor. The IDField, ID, id, and blockNumber parameters, have the same interpretation as in GetDashboardMessageGen.
err is an error which is passed along as the error message using "Error()".
*/
func GetDashboardErrorMessageGen[IDField FieldNameSelector, ID fmt.Stringer](blockNumber big.Int, id ID, err error) map[string]interface{} {
	std := map[string]interface{}{
		"invariantStatus":      "error",
		"blockNumber":          blockNumber.Uint64(),
		"calculationTimestamp": time.Now().Unix(),
		"error":                err.Error(),
	}
	var impl IDField
	std[impl.FieldName()] = id.String()
	return std
}

/*
Simple version of GetDashboardMessageGen where ids are just strings, and the monitor target id is stored
under the key "id".
*/
func GetDashboardErrorMessage(blockNumber big.Int, id string, err error) map[string]interface{} {
	return GetDashboardErrorMessageGen[PlainId, PlainString](blockNumber, PlainString(id), err)
}
